/**
 * The browser never treats a service projection, URL parameter, push payload,
 * local storage value, or agent message as an approval request.  The one entry
 * point below accepts opaque bytes and a shared COSE verifier.  A verifier is
 * intentionally injected: the production adapter is the shared TS/WASM
 * protocol verifier, while tests use a deterministic fake.
 */

const verifiedRequests = new WeakSet<object>();
const PUBLIC_ID = /^[A-Za-z0-9_-]{22}$/;
const PACKAGE_NAME = /^[a-z0-9][a-z0-9+.-]{0,127}$/;
const MAX_AGENT_NOTE_LENGTH = 4_096;
const MAX_PACKAGE_CHANGES = 1_024;
const MAX_CREDENTIALS = 5;

export type Decision = "approve" | "deny";

export interface BrokerEnvelopeVerifier {
  /** Throws when CBOR, COSE headers, keyset, signature, or schema is invalid. */
  verifyRequestEnvelope(envelope: Uint8Array): BrokerRequestClaims;
}

/**
 * This is the decoded output of the shared protocol verifier, never a JSON
 * response body. Its shape is deliberately narrow: the hosted service cannot
 * add consequences or a credential to it after verification.
 */
export interface BrokerRequestClaims {
  readonly requestId: string;
  readonly requestDigest: Uint8Array;
  readonly device: { readonly id: string; readonly displayName: string };
  readonly policy: { readonly id: string; readonly version: number };
  readonly expiresAtUnixMs: number;
  readonly consequences: {
    readonly target: PackageChange;
    readonly dependencies: readonly PackageChange[];
    readonly removals: readonly PackageChange[];
    readonly downgrades: readonly PackageChange[];
    readonly origin: string;
    readonly archiveBytes: number;
    readonly diskBytes: number;
  };
  /** Text from the agent; it has no authority and is rendered after the plan. */
  readonly agentNote: string | null;
  readonly webauthn: {
    readonly rpId: string;
    readonly origin: string;
    readonly credentials: readonly BrokerPinnedCredential[];
    readonly contexts: Readonly<Record<Decision, BrokerApprovalContext>>;
  };
}

export interface PackageChange {
  readonly name: string;
  readonly version: string;
}

export interface BrokerPinnedCredential {
  /** 16-byte base64url public ID, pinned by the broker for this device. */
  readonly id: string;
  readonly algorithm: "ES256";
}

export interface BrokerApprovalContext {
  readonly requestId: string;
  readonly requestDigest: Uint8Array;
  readonly deviceId: string;
  readonly policyId: string;
  readonly policyVersion: number;
  readonly expiresAtUnixMs: number;
  readonly decision: Decision;
  /** Domain-separated digest of the canonical ApprovalContext. */
  readonly contextDigest: Uint8Array;
  /** The challenge is encoded in the signed broker context, not service data. */
  readonly webauthnChallenge: Uint8Array;
}

export interface VerifiedBrokerRequest {
  readonly requestId: string;
  readonly requestDigest: Uint8Array;
  readonly device: Readonly<{ readonly id: string; readonly displayName: string }>;
  readonly policy: Readonly<{ readonly id: string; readonly version: number }>;
  readonly expiresAtUnixMs: number;
  readonly consequences: Readonly<BrokerRequestClaims["consequences"]>;
  readonly agentNote: string | null;
  readonly webauthn: Readonly<BrokerRequestClaims["webauthn"]>;
}

export class EnvelopeVerificationError extends Error {
  public readonly code = "invalid_envelope";

  public constructor() {
    super("The request could not be verified. No approval is available.");
  }
}

/** Verifies and brands an immutable request. All render/action APIs require it. */
export function verifyBrokerEnvelope(
  envelope: Uint8Array,
  verifier: BrokerEnvelopeVerifier,
): VerifiedBrokerRequest {
  if (!(envelope instanceof Uint8Array) || envelope.byteLength < 1 || envelope.byteLength > 512 * 1024) {
    throw new EnvelopeVerificationError();
  }
  try {
    const claims = verifier.verifyRequestEnvelope(envelope);
    validateClaims(claims);
    const verified = freezeRequest(claims);
    verifiedRequests.add(verified);
    return verified;
  } catch (error) {
    if (error instanceof EnvelopeVerificationError) {
      throw error;
    }
    throw new EnvelopeVerificationError();
  }
}

/** Runtime protection against a caller type-casting a service or route object. */
export function assertVerifiedBrokerRequest(value: VerifiedBrokerRequest): void {
  if (!verifiedRequests.has(value as object)) {
    throw new EnvelopeVerificationError();
  }
}

function validateClaims(claims: BrokerRequestClaims): void {
  requirePublicId(claims.requestId, "request id");
  requireDigest(claims.requestDigest, "request digest");
  requirePublicId(claims.device.id, "device id");
  requireText(claims.device.displayName, "device display name", 128);
  requireText(claims.policy.id, "policy id", 128);
  requireSafeInteger(claims.policy.version, "policy version", 1);
  requireSafeInteger(claims.expiresAtUnixMs, "expiry", 1);
  validateConsequences(claims.consequences);
  if (claims.agentNote !== null) requireText(claims.agentNote, "agent note", MAX_AGENT_NOTE_LENGTH);
  validateWebAuthn(claims);
}

function validateConsequences(consequences: BrokerRequestClaims["consequences"]): void {
  validatePackage(consequences.target);
  for (const collection of [consequences.dependencies, consequences.removals, consequences.downgrades]) {
    if (collection.length > MAX_PACKAGE_CHANGES) throw new Error("too many package changes");
    for (const item of collection) validatePackage(item);
  }
  requireText(consequences.origin, "origin", 256);
  requireSafeInteger(consequences.archiveBytes, "archive impact", 0);
  if (!Number.isSafeInteger(consequences.diskBytes)) throw new Error("disk impact must be a safe integer");
}

function validatePackage(change: PackageChange): void {
  if (!PACKAGE_NAME.test(change.name)) throw new Error("package name is invalid");
  requireText(change.version, "package version", 256);
}

function validateWebAuthn(claims: BrokerRequestClaims): void {
  const webauthn = claims.webauthn;
  if (!isRpId(webauthn.rpId) || !isOrigin(webauthn.origin)) throw new Error("invalid WebAuthn relying-party binding");
  if (webauthn.credentials.length < 1 || webauthn.credentials.length > MAX_CREDENTIALS) {
    throw new Error("broker must pin one through five credentials");
  }
  const seen = new Set<string>();
  for (const credential of webauthn.credentials) {
    requirePublicId(credential.id, "credential id");
    if (credential.algorithm !== "ES256" || seen.has(credential.id)) throw new Error("invalid pinned credential");
    seen.add(credential.id);
  }
  for (const decision of ["approve", "deny"] as const) {
    const context = webauthn.contexts[decision];
    if (context === undefined || context.decision !== decision) throw new Error("missing decision context");
    if (context.requestId !== claims.requestId || context.deviceId !== claims.device.id
      || context.policyId !== claims.policy.id || context.policyVersion !== claims.policy.version
      || context.expiresAtUnixMs !== claims.expiresAtUnixMs || !equalBytes(context.requestDigest, claims.requestDigest)) {
      throw new Error("approval context does not bind this request");
    }
    requireDigest(context.contextDigest, "approval context digest");
    requireDigest(context.webauthnChallenge, "WebAuthn challenge");
  }
  const approve = webauthn.contexts.approve;
  const deny = webauthn.contexts.deny;
  if (equalBytes(approve.contextDigest, deny.contextDigest) || equalBytes(approve.webauthnChallenge, deny.webauthnChallenge)) {
    throw new Error("approve and deny contexts must be distinct");
  }
}

function freezeRequest(claims: BrokerRequestClaims): VerifiedBrokerRequest {
  const contexts = {
    approve: freezeContext(claims.webauthn.contexts.approve),
    deny: freezeContext(claims.webauthn.contexts.deny),
  } as const;
  return Object.freeze({
    requestId: claims.requestId,
    requestDigest: copyBytes(claims.requestDigest),
    device: Object.freeze({ ...claims.device }),
    policy: Object.freeze({ ...claims.policy }),
    expiresAtUnixMs: claims.expiresAtUnixMs,
    consequences: Object.freeze({
      target: Object.freeze({ ...claims.consequences.target }),
      dependencies: freezeChanges(claims.consequences.dependencies),
      removals: freezeChanges(claims.consequences.removals),
      downgrades: freezeChanges(claims.consequences.downgrades),
      origin: claims.consequences.origin,
      archiveBytes: claims.consequences.archiveBytes,
      diskBytes: claims.consequences.diskBytes,
    }),
    agentNote: claims.agentNote,
    webauthn: Object.freeze({
      rpId: claims.webauthn.rpId,
      origin: claims.webauthn.origin,
      credentials: Object.freeze(claims.webauthn.credentials.map((credential) => Object.freeze({ ...credential }))),
      contexts: Object.freeze(contexts),
    }),
  });
}

function freezeContext(context: BrokerApprovalContext): Readonly<BrokerApprovalContext> {
  return Object.freeze({ ...context, requestDigest: copyBytes(context.requestDigest), contextDigest: copyBytes(context.contextDigest), webauthnChallenge: copyBytes(context.webauthnChallenge) });
}
function freezeChanges(changes: readonly PackageChange[]): readonly Readonly<PackageChange>[] {
  return Object.freeze(changes.map((change) => Object.freeze({ ...change })));
}
function copyBytes(bytes: Uint8Array): Uint8Array { return new Uint8Array(bytes); }
function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}
function requirePublicId(value: string, name: string): void { if (!PUBLIC_ID.test(value)) throw new Error(`${name} is not opaque`); }
function requireDigest(value: Uint8Array, name: string): void { if (!(value instanceof Uint8Array) || value.byteLength !== 32) throw new Error(`${name} must be SHA-256`); }
function requireText(value: string, name: string, max: number): void { if (typeof value !== "string" || value.length < 1 || value.length > max) throw new Error(`${name} must be bounded text`); }
function requireSafeInteger(value: number, name: string, min: number): void { if (!Number.isSafeInteger(value) || value < min) throw new Error(`${name} must be a safe integer`); }
function isRpId(value: string): boolean { return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(value); }
function isOrigin(value: string): boolean { try { const url = new URL(value); return url.protocol === "https:" && url.pathname === "/" && url.search === "" && url.hash === ""; } catch { return false; } }
