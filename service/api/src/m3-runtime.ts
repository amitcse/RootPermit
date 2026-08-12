import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import {
  verifiedApprovalCeremonyFromWebAuthn,
  type DecisionValue,
  type VerifiedCeremonyInput,
} from "./approval-boundary.ts";

const PUBLIC_ID = /^[A-Za-z0-9_-]{22}$/;
const MAX_RELAY_BYTES = 262_144;
const SESSION_TTL_MS = 8 * 60 * 60 * 1_000;

export interface AccountIdentity {
  readonly tenantId: string;
  readonly accountId: string;
}

export interface M3RuntimeOptions {
  readonly officialOrigin: string;
  readonly authenticateAccount: (email: string, password: string) => Promise<AccountIdentity | null>;
  /** Mutual TLS/session validation happens in the hosting adapter, before this callback returns true. */
  readonly authenticateRelay: (request: Request) => Promise<boolean>;
  /** The service uses this adapter only to produce a bounded assertion reference. */
  readonly verifyCeremony: (
    requestId: string,
    payload: unknown,
  ) => Promise<VerifiedCeremonyInput | null>;
  readonly now?: () => number;
}

interface Session extends AccountIdentity {
  readonly token: string;
  readonly csrfToken: string;
  readonly expiresAt: number;
}

interface Pairing {
  readonly id: string;
  readonly devicePublicId: string;
  readonly brokerKeyDigest: Uint8Array;
  readonly nonceDigest: Uint8Array;
  readonly comparisonCodeDigest: Uint8Array;
  readonly expiresAt: number;
  claimedBy: AccountIdentity | null;
  rootConfirmed: boolean;
  webConfirmed: boolean;
  consumed: boolean;
}

interface Device {
  readonly publicId: string;
  readonly tenantId: string;
  readonly displayName: string;
  enrollmentState: "active" | "approval_locked";
}

interface Credential {
  readonly publicId: string;
  readonly tenantId: string;
  readonly devicePublicId: string;
  readonly generation: number;
  quarantined: boolean;
}

interface RequestRecord {
  readonly publicId: string;
  readonly tenantId: string;
  readonly devicePublicId: string;
  readonly envelope: Uint8Array;
  readonly expiresAt: number;
  projection: "pending" | "approved" | "denied" | "frozen_gap" | "terminal";
}

interface RelayMessage {
  readonly direction: "broker_to_service" | "service_to_broker";
  readonly envelopeId: string;
  readonly idempotencyKey: string;
  readonly payload: Uint8Array;
}

/**
 * A small HTTP runtime for M3's disposable single-tenant evidence path.
 * It intentionally owns projections and mailbox routing only: it has no
 * operation that creates a package request or selects broker execution.
 */
export class M3Runtime {
  private readonly officialOrigin: string;
  private readonly authenticateAccount: M3RuntimeOptions["authenticateAccount"];
  private readonly authenticateRelay: M3RuntimeOptions["authenticateRelay"];
  private readonly verifyCeremony: M3RuntimeOptions["verifyCeremony"];
  private readonly now: () => number;
  private readonly sessions = new Map<string, Session>();
  private readonly pairings = new Map<string, Pairing>();
  private readonly devices = new Map<string, Device>();
  private readonly credentials = new Map<string, Credential>();
  private readonly requests = new Map<string, RequestRecord>();
  private readonly relayInbox = new Map<string, RelayMessage>();
  private readonly relayOutbox: RelayMessage[] = [];

  public constructor(options: M3RuntimeOptions) {
    const origin = new URL(options.officialOrigin);
    if (origin.origin !== options.officialOrigin || origin.protocol !== "https:") {
      throw new Error("official origin must be an absolute HTTPS origin without a path");
    }
    this.officialOrigin = options.officialOrigin;
    this.authenticateAccount = options.authenticateAccount;
    this.authenticateRelay = options.authenticateRelay;
    this.verifyCeremony = options.verifyCeremony;
    this.now = options.now ?? Date.now;
  }

  /** Trusted broker/relay ingress. A browser route cannot create a pairing. */
  public preparePairing(input: {
    readonly pairingId: string;
    readonly devicePublicId: string;
    readonly brokerPublicKey: Uint8Array;
    readonly nonce: Uint8Array;
    readonly comparisonCode: string;
    readonly expiresAt: number;
  }): void {
    requirePublicId(input.pairingId, "pairing id");
    requirePublicId(input.devicePublicId, "device id");
    requireBytes(input.brokerPublicKey, 32, "broker public key");
    requireBytes(input.nonce, 32, "pairing nonce");
    if (!/^[0-9]{6}$/.test(input.comparisonCode) || input.expiresAt <= this.now()) throw new Error("invalid pairing transcript");
    if (this.pairings.has(input.pairingId)) throw new Error("pairing_replayed");
    this.pairings.set(input.pairingId, {
      id: input.pairingId,
      devicePublicId: input.devicePublicId,
      brokerKeyDigest: digest("broker-key", input.brokerPublicKey),
      nonceDigest: digest("pairing-nonce", input.nonce),
      comparisonCodeDigest: digestText("comparison-code", input.comparisonCode),
      expiresAt: input.expiresAt,
      claimedBy: null,
      rootConfirmed: false,
      webConfirmed: false,
      consumed: false,
    });
  }

  /** A trusted broker confirmation is necessary but still cannot activate a device alone. */
  public confirmPairingFromBroker(pairingId: string, nonce: Uint8Array, brokerPublicKey: Uint8Array): void {
    const pairing = this.livePairing(pairingId);
    if (!equalBytes(pairing.nonceDigest, digest("pairing-nonce", nonce))
      || !equalBytes(pairing.brokerKeyDigest, digest("broker-key", brokerPublicKey))) {
      pairing.consumed = true;
      throw new Error("pairing_mismatch");
    }
    pairing.rootConfirmed = true;
    this.tryActivate(pairing);
  }

  /** Root-pinned enrollment is the only path that can add an approval credential. */
  public enrollCredential(input: {
    readonly publicId: string;
    readonly tenantId: string;
    readonly devicePublicId: string;
    readonly generation: number;
  }): void {
    requirePublicId(input.publicId, "credential id");
    const device = this.devices.get(input.devicePublicId);
    if (device === undefined || device.tenantId !== input.tenantId || device.enrollmentState !== "active") {
      throw new Error("device_not_active");
    }
    if (!Number.isSafeInteger(input.generation) || input.generation < 1) throw new Error("invalid credential generation");
    const existing = [...this.credentials.values()].filter((credential) => credential.devicePublicId === input.devicePublicId && !credential.quarantined);
    if (existing.length >= 5 || this.credentials.has(input.publicId)) throw new Error("credential_limit_reached");
    this.credentials.set(input.publicId, { ...input, quarantined: false });
  }

  /** Trusted broker envelope ingestion. Hosted state remains a projection. */
  public ingestVerifiedRequest(input: {
    readonly publicId: string;
    readonly tenantId: string;
    readonly devicePublicId: string;
    readonly envelope: Uint8Array;
    readonly expiresAt: number;
  }): void {
    requirePublicId(input.publicId, "request id");
    const device = this.devices.get(input.devicePublicId);
    if (device === undefined || device.tenantId !== input.tenantId || input.envelope.byteLength < 1 || input.envelope.byteLength > MAX_RELAY_BYTES) {
      throw new Error("invalid_envelope");
    }
    this.requests.set(input.publicId, { ...input, envelope: new Uint8Array(input.envelope), projection: "pending" });
  }

  /** Trusted relay ingestion for a broker-signed terminal fake-execution receipt. */
  public ingestVerifiedBrokerReceipt(requestPublicId: string, terminalState: "succeeded" | "failed" | "denied"): void {
    const request = this.requests.get(requestPublicId);
    if (request === undefined) throw new Error("invalid_receipt");
    request.projection = terminalState === "denied" ? "denied" : "terminal";
  }

  public async handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/v1/account/session" && request.method === "POST") return await this.createSession(request);
      if (url.pathname === "/v1/relay/inbox" && request.method === "POST") return await this.relayInboxRoute(request);
      if (url.pathname === "/v1/relay/outbox" && request.method === "GET") return await this.relayOutboxRoute(request);

      const session = this.requireSession(request);
      if (url.pathname === "/v1/devices" && request.method === "GET") return this.devicesRoute(session);
      const pairing = /^\/v1\/pairings\/([A-Za-z0-9_-]{22})\/(claim|confirm)$/.exec(url.pathname);
      if (pairing !== null && request.method === "POST") return await this.pairingRoute(session, pairing[1]!, pairing[2]!, request);
      const requestRoute = /^\/v1\/requests\/([A-Za-z0-9_-]{22})(?:\/(status|decisions))?$/.exec(url.pathname);
      if (requestRoute !== null) return await this.requestRoute(session, requestRoute[1]!, requestRoute[2], request);
      const revocation = /^\/v1\/credentials\/([A-Za-z0-9_-]{22})\/revocations$/.exec(url.pathname);
      if (revocation !== null && request.method === "POST") return this.revocationRoute(session, revocation[1]!, request);
      return problem(404, "not_found_or_not_authorized", "The requested RootPermit resource is unavailable.");
    } catch (error) {
      return this.mapError(error);
    }
  }

  private async createSession(request: Request): Promise<Response> {
    this.requireOfficialOrigin(request);
    const body = await jsonObject(request);
    const email = stringField(body, "email", 320);
    const password = stringField(body, "password", 1024);
    const identity = await this.authenticateAccount(email, password);
    if (identity === null) return problem(401, "authentication_failed", "Sign in could not be completed.");
    const session: Session = {
      ...identity,
      token: randomToken(),
      csrfToken: randomToken(),
      expiresAt: this.now() + SESSION_TTL_MS,
    };
    this.sessions.set(session.token, session);
    return json({ csrfToken: session.csrfToken, expiresAt: session.expiresAt }, 201, {
      "set-cookie": `rp_session=${session.token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1_000}`,
    });
  }

  private async pairingRoute(session: Session, pairingId: string, action: string, request: Request): Promise<Response> {
    this.requireCsrf(request, session);
    const pairing = this.livePairing(pairingId);
    if (action === "claim") {
      if (pairing.claimedBy !== null && !sameAccount(pairing.claimedBy, session)) throw new Error("not_found_or_not_authorized");
      pairing.claimedBy = { tenantId: session.tenantId, accountId: session.accountId };
      return json({ state: "web_claimed" });
    }
    if (pairing.claimedBy === null || !sameAccount(pairing.claimedBy, session)) throw new Error("not_found_or_not_authorized");
    const code = stringField(await jsonObject(request), "comparisonCode", 6);
    if (!equalBytes(pairing.comparisonCodeDigest, digestText("comparison-code", code))) {
      pairing.consumed = true;
      throw new Error("pairing_mismatch");
    }
    pairing.webConfirmed = true;
    this.tryActivate(pairing);
    return json({ state: pairing.consumed ? "active" : "codes_confirmed" });
  }

  private async requestRoute(session: Session, requestId: string, suffix: string | undefined, request: Request): Promise<Response> {
    const record = this.scopedRequest(session, requestId);
    if (suffix === undefined && request.method === "GET") {
      return json({ envelope: Buffer.from(record.envelope).toString("base64url"), projection: record.projection, expiresAt: record.expiresAt });
    }
    if (suffix === "status" && request.method === "GET") {
      return json({ projection: record.projection, expiresAt: record.expiresAt });
    }
    if (suffix === "decisions" && request.method === "POST") {
      this.requireCsrf(request, session);
      if (record.projection !== "pending" || record.expiresAt <= this.now()) throw new Error("request_not_pending");
      const ceremonyInput = await this.verifyCeremony(requestId, await jsonObject(request));
      if (ceremonyInput === null) throw new Error("invalid_decision");
      const credential = this.credentials.get(ceremonyInput.credentialBindingPublicId);
      if (credential === undefined || credential.tenantId !== session.tenantId || credential.devicePublicId !== record.devicePublicId) {
        throw new Error("not_found_or_not_authorized");
      }
      if (credential.quarantined) throw new Error("credential_quarantined");
      const ceremony = verifiedApprovalCeremonyFromWebAuthn(ceremonyInput);
      const decisionId = randomPublicId();
      this.queueToBroker({
        requestPublicId: requestId,
        decisionPublicId: decisionId,
        decision: ceremony.decision,
        credentialBindingPublicId: ceremony.credentialBindingPublicId,
        assertionReference: Buffer.from(ceremony.assertionReference).toString("base64url"),
      });
      record.projection = ceremony.decision === "approve" ? "approved" : "denied";
      return json({ decisionId, accepted: true }, 202);
    }
    throw new Error("not_found_or_not_authorized");
  }

  private revocationRoute(session: Session, credentialId: string, request: Request): Response {
    this.requireCsrf(request, session);
    const credential = this.credentials.get(credentialId);
    if (credential === undefined || credential.tenantId !== session.tenantId) throw new Error("not_found_or_not_authorized");
    credential.quarantined = true;
    const remaining = [...this.credentials.values()].filter((candidate) => candidate.devicePublicId === credential.devicePublicId && !candidate.quarantined).length;
    const device = this.devices.get(credential.devicePublicId)!;
    if (remaining === 0) device.enrollmentState = "approval_locked";
    this.queueToBroker({ type: "revocation", credentialBindingPublicId: credentialId, devicePublicId: credential.devicePublicId });
    return json({ quarantined: true, enrollmentState: device.enrollmentState }, 202);
  }

  private devicesRoute(session: Session): Response {
    const devices = [...this.devices.values()]
      .filter((device) => device.tenantId === session.tenantId)
      .map((device) => ({ id: device.publicId, displayName: device.displayName, enrollmentState: device.enrollmentState }));
    return json({ devices });
  }

  private async relayInboxRoute(request: Request): Promise<Response> {
    if (!await this.authenticateRelay(request)) throw new Error("relay_authentication_failed");
    const body = await jsonObject(request);
    const envelopeId = stringField(body, "envelopeId", 22);
    const idempotencyKey = stringField(body, "idempotencyKey", 43);
    const payload = base64UrlField(body, "payload", MAX_RELAY_BYTES);
    requirePublicId(envelopeId, "envelope id");
    if (this.relayInbox.has(`${envelopeId}:${idempotencyKey}`)) return new Response(null, { status: 202, headers: secureHeaders() });
    this.relayInbox.set(`${envelopeId}:${idempotencyKey}`, { direction: "broker_to_service", envelopeId, idempotencyKey, payload });
    return new Response(null, { status: 202, headers: secureHeaders() });
  }

  private async relayOutboxRoute(request: Request): Promise<Response> {
    if (!await this.authenticateRelay(request)) throw new Error("relay_authentication_failed");
    const messages = this.relayOutbox.map((message) => ({
      envelopeId: message.envelopeId,
      idempotencyKey: message.idempotencyKey,
      payload: Buffer.from(message.payload).toString("base64url"),
    }));
    return json({ messages });
  }

  private queueToBroker(value: Record<string, unknown>): void {
    const payload = new TextEncoder().encode(JSON.stringify(value));
    this.relayOutbox.push({ direction: "service_to_broker", envelopeId: randomPublicId(), idempotencyKey: randomToken(), payload });
  }

  private requireSession(request: Request): Session {
    const token = cookieValue(request.headers.get("cookie"), "rp_session");
    const session = token === null ? undefined : this.sessions.get(token);
    if (session === undefined || session.expiresAt <= this.now()) throw new Error("session_expired");
    return session;
  }

  private requireCsrf(request: Request, session: Session): void {
    this.requireOfficialOrigin(request);
    const supplied = request.headers.get("x-rp-csrf");
    if (supplied === null || !safeEqualText(supplied, session.csrfToken)) throw new Error("csrf_failed");
  }

  private requireOfficialOrigin(request: Request): void {
    if (request.headers.get("origin") !== this.officialOrigin) throw new Error("csrf_failed");
  }

  private livePairing(pairingId: string): Pairing {
    const pairing = this.pairings.get(pairingId);
    if (pairing === undefined || pairing.consumed || pairing.expiresAt <= this.now()) {
      if (pairing !== undefined) pairing.consumed = true;
      throw new Error("not_found_or_not_authorized");
    }
    return pairing;
  }

  private tryActivate(pairing: Pairing): void {
    if (pairing.rootConfirmed && pairing.webConfirmed && pairing.claimedBy !== null && !pairing.consumed) {
      this.devices.set(pairing.devicePublicId, {
        publicId: pairing.devicePublicId,
        tenantId: pairing.claimedBy.tenantId,
        displayName: "RootPermit device",
        enrollmentState: "active",
      });
      pairing.consumed = true;
    }
  }

  private scopedRequest(session: Session, requestId: string): RequestRecord {
    const record = this.requests.get(requestId);
    if (record === undefined || record.tenantId !== session.tenantId) throw new Error("not_found_or_not_authorized");
    return record;
  }

  private mapError(error: unknown): Response {
    const code = error instanceof Error ? error.message : "service_unavailable";
    if (["session_expired", "authentication_failed"].includes(code)) return problem(401, code, "Sign in is required.");
    if (["csrf_failed", "relay_authentication_failed"].includes(code)) return problem(403, code, "This request was rejected by RootPermit security checks.");
    if (["not_found_or_not_authorized", "pairing_mismatch"].includes(code)) return problem(404, "not_found_or_not_authorized", "The requested RootPermit resource is unavailable.");
    if (["credential_quarantined", "request_not_pending", "invalid_decision", "pairing_replayed", "credential_limit_reached"].includes(code)) return problem(409, code, "This RootPermit action is no longer available.");
    return problem(400, "invalid_input", "RootPermit could not process that request.");
  }
}

function json(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(value), { status, headers: { ...secureHeaders(), "content-type": "application/problem+json; charset=utf-8", ...headers } });
}

function problem(status: number, code: string, detail: string): Response {
  return json({ type: `https://rootpermit.example/problems/${code}`, title: code, status, detail }, status);
}

function secureHeaders(): Record<string, string> {
  return {
    "cache-control": "no-store",
    "content-security-policy": "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  };
}

async function jsonObject(request: Request): Promise<Record<string, unknown>> {
  const value: unknown = await request.json();
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("invalid_input");
  return value as Record<string, unknown>;
}

function stringField(value: Record<string, unknown>, name: string, maximum: number): string {
  const item = value[name];
  if (typeof item !== "string" || item.length < 1 || item.length > maximum) throw new Error("invalid_input");
  return item;
}

function base64UrlField(value: Record<string, unknown>, name: string, maximum: number): Uint8Array {
  const text = stringField(value, name, Math.ceil(maximum * 4 / 3));
  if (!/^[A-Za-z0-9_-]+$/.test(text)) throw new Error("invalid_input");
  const bytes = new Uint8Array(Buffer.from(text, "base64url"));
  if (bytes.byteLength < 1 || bytes.byteLength > maximum) throw new Error("invalid_input");
  return bytes;
}

function cookieValue(header: string | null, name: string): string | null {
  if (header === null) return null;
  const entry = header.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return entry === undefined ? null : entry.slice(name.length + 1);
}

function randomToken(): string { return randomBytes(32).toString("base64url"); }
function randomPublicId(): string { return randomBytes(16).toString("base64url"); }
function requirePublicId(value: string, name: string): void { if (!PUBLIC_ID.test(value)) throw new Error(`${name} is invalid`); }
function requireBytes(value: Uint8Array, length: number, name: string): void { if (!(value instanceof Uint8Array) || value.byteLength !== length) throw new Error(`${name} is invalid`); }
function digest(domain: string, value: Uint8Array): Uint8Array { return createHash("sha256").update(`rootpermit/${domain}/v1\0`).update(value).digest(); }
function digestText(domain: string, value: string): Uint8Array { return digest(domain, new TextEncoder().encode(value)); }
function equalBytes(left: Uint8Array, right: Uint8Array): boolean { return left.byteLength === right.byteLength && timingSafeEqual(left, right); }
function safeEqualText(left: string, right: string): boolean { return safeEqualBytes(new TextEncoder().encode(left), new TextEncoder().encode(right)); }
function safeEqualBytes(left: Uint8Array, right: Uint8Array): boolean { return left.byteLength === right.byteLength && timingSafeEqual(left, right); }
function sameAccount(left: AccountIdentity, right: AccountIdentity): boolean { return left.tenantId === right.tenantId && left.accountId === right.accountId; }
