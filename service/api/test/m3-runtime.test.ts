import assert from "node:assert/strict";
import test from "node:test";

import { M3Runtime } from "../src/m3-runtime.ts";

const ORIGIN = "https://rootpermit.example";
const TENANT_A = "11111111-1111-4111-8111-111111111111";
const ACCOUNT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TENANT_B = "22222222-2222-4222-8222-222222222222";
const ACCOUNT_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const PAIRING = "AAAAAAAAAAAAAAAAAAAAAA";
const DEVICE = "AQEBAQEBAQEBAQEBAQEBAQ";
const REQUEST = "AgICAgICAgICAgICAgICAg";
const CREDENTIAL = "AwMDAwMDAwMDAwMDAwMDAw";

function runtime(now: number | (() => number) = 1_800_000_000_000): M3Runtime {
  return new M3Runtime({
    officialOrigin: ORIGIN,
    now: typeof now === "function" ? now : () => now,
    authenticateAccount: async (email, password) => {
      if (password !== "correct") return null;
      if (email === "a@example.test") return { tenantId: TENANT_A, accountId: ACCOUNT_A };
      if (email === "b@example.test") return { tenantId: TENANT_B, accountId: ACCOUNT_B };
      return null;
    },
    authenticateRelay: async (request) => request.headers.get("x-rp-relay-auth") === "mutual-authenticated-relay",
    verifyCeremony: async (_requestId, value) => {
      const body = value as { decision?: unknown; assertion?: unknown; credentialBindingPublicId?: unknown };
      if ((body.decision !== "approve" && body.decision !== "deny") || body.credentialBindingPublicId !== CREDENTIAL || body.assertion !== "valid") return null;
      return { credentialBindingPublicId: CREDENTIAL, decision: body.decision, assertionBytes: new Uint8Array([1, 2, 3]) };
    },
  });
}

async function session(service: M3Runtime, email = "a@example.test"): Promise<{ cookie: string; csrf: string }> {
  const response = await service.handle(new Request(`${ORIGIN}/v1/account/session`, {
    method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" }, body: JSON.stringify({ email, password: "correct" }),
  }));
  assert.equal(response.status, 201);
  return { cookie: response.headers.get("set-cookie")!.split(";")[0]!, csrf: (await response.json() as { csrfToken: string }).csrfToken };
}

function authed(url: string, auth: { cookie: string; csrf?: string }, body?: unknown): Request {
  return new Request(`${ORIGIN}${url}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { cookie: auth.cookie, origin: ORIGIN, ...(auth.csrf === undefined ? {} : { "x-rp-csrf": auth.csrf }), ...(body === undefined ? {} : { "content-type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

test("session runtime applies official-origin, session, CSRF, CSP and no-store boundaries", async () => {
  const service = runtime();
  const auth = await session(service);
  const response = await service.handle(authed("/v1/devices", auth));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  const missingCsrf = await service.handle(new Request(`${ORIGIN}/v1/account/session`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "a@example.test", password: "correct" }) }));
  assert.equal(missingCsrf.status, 403);
});

test("expired sessions and pairings fail closed, and no web execution route exists", async () => {
  let now = 1_800_000_000_000;
  const service = runtime(() => now);
  const auth = await session(service);
  now += (8 * 60 * 60 * 1_000) + 1;
  assert.equal((await service.handle(authed("/v1/devices", auth))).status, 401);

  service.preparePairing({ pairingId: PAIRING, devicePublicId: DEVICE, brokerPublicKey: new Uint8Array(32).fill(1), nonce: new Uint8Array(32).fill(2), comparisonCode: "123456", expiresAt: now + 1 });
  now += 1;
  const freshAuth = await session(service);
  assert.equal((await service.handle(authed(`/v1/pairings/${PAIRING}/claim`, freshAuth, {}))).status, 404);
  assert.equal((await service.handle(authed(`/v1/requests/${REQUEST}/execute`, freshAuth, {}))).status, 404);
});

test("only matching broker and web confirmations activate a root-started single-use pairing", async () => {
  const service = runtime();
  service.preparePairing({ pairingId: PAIRING, devicePublicId: DEVICE, brokerPublicKey: new Uint8Array(32).fill(1), nonce: new Uint8Array(32).fill(2), comparisonCode: "123456", expiresAt: 1_800_000_100_000 });
  const auth = await session(service);
  assert.equal((await service.handle(authed(`/v1/pairings/${PAIRING}/claim`, auth, {}))).status, 200);
  assert.equal((await service.handle(authed(`/v1/pairings/${PAIRING}/confirm`, auth, { comparisonCode: "123456" }))).status, 200);
  assert.deepEqual(await (await service.handle(authed("/v1/devices", auth))).json(), { devices: [] });
  service.confirmPairingFromBroker(PAIRING, new Uint8Array(32).fill(2), new Uint8Array(32).fill(1));
  const devices = await (await service.handle(authed("/v1/devices", auth))).json() as { devices: { id: string; enrollmentState: string }[] };
  assert.deepEqual(devices.devices, [{ id: DEVICE, displayName: "RootPermit device", enrollmentState: "active" }]);
  assert.equal((await service.handle(authed(`/v1/pairings/${PAIRING}/claim`, auth, {}))).status, 404);
});

test("pairings cannot cross tenant boundaries and a mismatch consumes the transcript", async () => {
  const service = runtime();
  service.preparePairing({ pairingId: PAIRING, devicePublicId: DEVICE, brokerPublicKey: new Uint8Array(32).fill(1), nonce: new Uint8Array(32).fill(2), comparisonCode: "123456", expiresAt: 1_800_000_100_000 });
  const a = await session(service);
  const b = await session(service, "b@example.test");
  await service.handle(authed(`/v1/pairings/${PAIRING}/claim`, a, {}));
  assert.equal((await service.handle(authed(`/v1/pairings/${PAIRING}/claim`, b, {}))).status, 404);
  assert.equal((await service.handle(authed(`/v1/pairings/${PAIRING}/confirm`, a, { comparisonCode: "000000" }))).status, 404);
  assert.equal((await service.handle(authed(`/v1/pairings/${PAIRING}/confirm`, a, { comparisonCode: "123456" }))).status, 404);
});

test("a verified ceremony is queued to the broker without granting service execution authority", async () => {
  const service = runtime();
  service.preparePairing({ pairingId: PAIRING, devicePublicId: DEVICE, brokerPublicKey: new Uint8Array(32).fill(1), nonce: new Uint8Array(32).fill(2), comparisonCode: "123456", expiresAt: 1_800_000_100_000 });
  const auth = await session(service);
  await service.handle(authed(`/v1/pairings/${PAIRING}/claim`, auth, {}));
  await service.handle(authed(`/v1/pairings/${PAIRING}/confirm`, auth, { comparisonCode: "123456" }));
  service.confirmPairingFromBroker(PAIRING, new Uint8Array(32).fill(2), new Uint8Array(32).fill(1));
  service.enrollCredential({ publicId: CREDENTIAL, tenantId: TENANT_A, devicePublicId: DEVICE, generation: 1 });
  service.ingestVerifiedRequest({ publicId: REQUEST, tenantId: TENANT_A, devicePublicId: DEVICE, envelope: new Uint8Array([0xd2]), expiresAt: 1_800_000_100_000 });
  const decision = await service.handle(authed(`/v1/requests/${REQUEST}/decisions`, auth, { decision: "approve", assertion: "valid", credentialBindingPublicId: CREDENTIAL }));
  assert.equal(decision.status, 202);
  const outbox = await service.handle(new Request(`${ORIGIN}/v1/relay/outbox`, { headers: { "x-rp-relay-auth": "mutual-authenticated-relay" } }));
  const messages = await outbox.json() as { messages: { payload: string }[] };
  assert.equal(messages.messages.length, 1);
  assert.match(Buffer.from(messages.messages[0]!.payload, "base64url").toString("utf8"), /assertionReference/);
  assert.doesNotMatch(Buffer.from(messages.messages[0]!.payload, "base64url").toString("utf8"), /execute|package\.install/);
  service.ingestVerifiedBrokerReceipt(REQUEST, "succeeded");
  assert.deepEqual(await (await service.handle(authed(`/v1/requests/${REQUEST}/status`, auth))).json(), { projection: "terminal", expiresAt: 1_800_000_100_000 });
});

test("revocation quarantines immediately, locks a device after its last credential, and relay inbox is opaque/idempotent", async () => {
  const service = runtime();
  service.preparePairing({ pairingId: PAIRING, devicePublicId: DEVICE, brokerPublicKey: new Uint8Array(32).fill(1), nonce: new Uint8Array(32).fill(2), comparisonCode: "123456", expiresAt: 1_800_000_100_000 });
  const auth = await session(service);
  await service.handle(authed(`/v1/pairings/${PAIRING}/claim`, auth, {}));
  await service.handle(authed(`/v1/pairings/${PAIRING}/confirm`, auth, { comparisonCode: "123456" }));
  service.confirmPairingFromBroker(PAIRING, new Uint8Array(32).fill(2), new Uint8Array(32).fill(1));
  service.enrollCredential({ publicId: CREDENTIAL, tenantId: TENANT_A, devicePublicId: DEVICE, generation: 1 });
  const revoke = await service.handle(authed(`/v1/credentials/${CREDENTIAL}/revocations`, auth, {}));
  assert.deepEqual(await revoke.json(), { quarantined: true, enrollmentState: "approval_locked" });
  const relay = new Request(`${ORIGIN}/v1/relay/inbox`, { method: "POST", headers: { "x-rp-relay-auth": "mutual-authenticated-relay", "content-type": "application/json" }, body: JSON.stringify({ envelopeId: "BAQEBAQEBAQEBAQEBAQEBA", idempotencyKey: "x".repeat(43), payload: "AQ" }) });
  const duplicateRelay = relay.clone();
  assert.equal((await service.handle(relay)).status, 202);
  assert.equal((await service.handle(duplicateRelay)).status, 202);
});
