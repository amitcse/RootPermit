import assert from "node:assert/strict";
import test from "node:test";

import {
  approvalPageFromVerifiedRequest,
  invalidEnvelopePage,
  sequenceGapPage,
} from "../src/approval-page.ts";
import { renderApprovalHtml } from "../src/render-html.ts";
import {
  type BrokerEnvelopeVerifier,
  type BrokerRequestClaims,
  EnvelopeVerificationError,
  verifyBrokerEnvelope,
} from "../src/verified-envelope.ts";
import {
  approvalContextFromVerifiedRequest,
  browserCeremonyRequest,
  CeremonyUnavailableError,
} from "../src/webauthn-ceremony.ts";

const NOW = 1_800_000_000_000;
const REQUEST_ID = "AAAAAAAAAAAAAAAAAAAAAA";
const DEVICE_ID = "AQEBAQEBAQEBAQEBAQEBAQ";
const CREDENTIAL_A = "AgICAgICAgICAgICAgICAg";
const CREDENTIAL_B = "AwMDAwMDAwMDAwMDAwMDAw";

class FixtureVerifier implements BrokerEnvelopeVerifier {
  private readonly claims: BrokerRequestClaims | Error;

  public constructor(claims: BrokerRequestClaims | Error) {
    this.claims = claims;
  }
  public verifyRequestEnvelope(_envelope: Uint8Array): BrokerRequestClaims {
    if (this.claims instanceof Error) throw this.claims;
    return this.claims;
  }
}

function requestClaims(overrides: Partial<BrokerRequestClaims> = {}): BrokerRequestClaims {
  const digest = new Uint8Array(32).fill(4);
  const common = {
    requestId: REQUEST_ID,
    requestDigest: digest,
    deviceId: DEVICE_ID,
    policyId: "default-install",
    policyVersion: 12,
    expiresAtUnixMs: NOW + 300_000,
  } as const;
  return {
    requestId: common.requestId,
    requestDigest: common.requestDigest,
    device: { id: common.deviceId, displayName: "build-vm-01" },
    policy: { id: common.policyId, version: common.policyVersion },
    expiresAtUnixMs: common.expiresAtUnixMs,
    consequences: {
      target: { name: "ffmpeg", version: "7:6.1.1-3ubuntu5" },
      dependencies: [{ name: "libavcodec60", version: "7:6.1.1-3ubuntu5" }],
      removals: [],
      downgrades: [],
      origin: "Ubuntu noble / amd64",
      archiveBytes: 42_000_000,
      diskBytes: 94_000_000,
    },
    agentNote: "Install <b>media tooling</b> for the build.",
    webauthn: {
      rpId: "rootpermit.example",
      origin: "https://rootpermit.example",
      credentials: [
        { id: CREDENTIAL_A, algorithm: "ES256" },
        { id: CREDENTIAL_B, algorithm: "ES256" },
      ],
      contexts: {
        approve: { ...common, decision: "approve", contextDigest: new Uint8Array(32).fill(8), webauthnChallenge: new Uint8Array(32).fill(9) },
        deny: { ...common, decision: "deny", contextDigest: new Uint8Array(32).fill(10), webauthnChallenge: new Uint8Array(32).fill(11) },
      },
    },
    ...overrides,
  };
}

function verified(claims: BrokerRequestClaims = requestClaims()) {
  return verifyBrokerEnvelope(new Uint8Array([0xd2, 0x84]), new FixtureVerifier(claims));
}

test("the verified envelope is the only input that can produce a ready approval page", () => {
  const request = verified();
  const page = approvalPageFromVerifiedRequest(request, NOW);
  assert.equal(page.kind, "ready");
  if (page.kind !== "ready") return;
  assert.equal(page.consequences.target.name, "ffmpeg");
  assert.equal(page.request.device, "build-vm-01");
  assert.equal(page.untrustedAgentNote?.text, "Install <b>media tooling</b> for the build.");

  const forged = { ...request };
  assert.throws(() => approvalPageFromVerifiedRequest(forged, NOW), EnvelopeVerificationError);
});

test("invalid COSE/schema input fails closed and cannot render an agent supplied request", () => {
  assert.throws(
    () => verifyBrokerEnvelope(new Uint8Array([1]), new FixtureVerifier(new Error("bad signature"))),
    (error: unknown) => error instanceof EnvelopeVerificationError && error.code === "invalid_envelope",
  );
  const html = renderApprovalHtml(invalidEnvelopePage());
  assert.match(html, /Request could not be verified/);
  assert.doesNotMatch(html, /ffmpeg|agent/i);
});

test("authoritative consequences are rendered before an escaped, isolated agent note", () => {
  const page = approvalPageFromVerifiedRequest(verified(), NOW);
  const html = renderApprovalHtml(page);
  assert.match(html, /Broker-verified transaction/);
  assert.match(html, /Agent explanation \(untrusted\)/);
  assert.match(html, /Install &lt;b&gt;media tooling&lt;\/b&gt;/);
  assert.ok(html.indexOf("Broker-verified transaction") < html.indexOf("Agent explanation (untrusted)"));
  assert.doesNotMatch(html, /<b>media tooling<\/b>/);
});

test("expiry and a verified event sequence gap are fail-closed states", () => {
  const expired = approvalPageFromVerifiedRequest(verified(), NOW + 300_000);
  assert.deepEqual(expired, {
    kind: "blocked",
    code: "request_expired",
    heading: "Request expired",
    message: "This request can no longer be approved or denied. Ask the agent to create a new request.",
  });
  const gap = sequenceGapPage();
  assert.equal(gap.kind, "blocked");
  assert.equal(gap.code, "sequence_gap");
  assert.doesNotMatch(renderApprovalHtml(gap), /data-decision/);
});

test("approve and deny use distinct broker contexts and the exact pinned credentials", () => {
  const request = verified();
  const approve = approvalContextFromVerifiedRequest(request, "approve", NOW);
  const deny = approvalContextFromVerifiedRequest(request, "deny", NOW);
  assert.notDeepEqual(approve.contextDigest, deny.contextDigest);
  assert.notDeepEqual(approve.webauthnChallenge, deny.webauthnChallenge);

  const browserRequest = browserCeremonyRequest(request, approve, "https://rootpermit.example", NOW);
  assert.equal(browserRequest.publicKey.userVerification, "required");
  assert.deepEqual(browserRequest.publicKey.challenge, new Uint8Array(32).fill(9));
  assert.deepEqual(browserRequest.publicKey.allowCredentials.map((credential) => credential.id), [
    new Uint8Array(16).fill(2),
    new Uint8Array(16).fill(3),
  ]);
  assert.throws(
    () => browserCeremonyRequest(request, deny, "https://evil.example", NOW),
    (error: unknown) => error instanceof CeremonyUnavailableError && error.code === "webauthn_origin_mismatch",
  );
});

test("a context cannot be recycled after expiry or forged from a request body", () => {
  const request = verified();
  const context = approvalContextFromVerifiedRequest(request, "approve", NOW);
  assert.throws(
    () => browserCeremonyRequest(request, context, "https://rootpermit.example", NOW + 300_000),
    (error: unknown) => error instanceof CeremonyUnavailableError && error.code === "request_expired",
  );
  const fake = { ...context, webauthnChallenge: new Uint8Array(32).fill(1) };
  assert.throws(() => browserCeremonyRequest(request, fake, "https://rootpermit.example", NOW), /not verified/);
});

test("the verifier rejects a decision context that does not bind the signed request", () => {
  const claims = requestClaims();
  const mismatched = {
    ...claims,
    webauthn: {
      ...claims.webauthn,
      contexts: {
        ...claims.webauthn.contexts,
        approve: { ...claims.webauthn.contexts.approve, requestId: DEVICE_ID },
      },
    },
  };
  assert.throws(() => verified(mismatched), EnvelopeVerificationError);
});
