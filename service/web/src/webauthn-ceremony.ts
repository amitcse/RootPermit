import {
  assertVerifiedBrokerRequest,
  type Decision,
  type VerifiedBrokerRequest,
} from "./verified-envelope.ts";

const verifiedContexts = new WeakSet<object>();

export interface VerifiedApprovalContext {
  readonly decision: Decision;
  readonly requestId: string;
  readonly requestDigest: Uint8Array;
  readonly deviceId: string;
  readonly policyId: string;
  readonly policyVersion: number;
  readonly expiresAtUnixMs: number;
  readonly contextDigest: Uint8Array;
  readonly webauthnChallenge: Uint8Array;
}

export interface BrowserCeremonyRequest {
  readonly publicKey: {
    readonly challenge: Uint8Array;
    readonly rpId: string;
    readonly timeout: number;
    readonly userVerification: "required";
    readonly allowCredentials: readonly { readonly type: "public-key"; readonly id: Uint8Array }[];
  };
}

export class CeremonyUnavailableError extends Error {
  public readonly code: "request_expired" | "webauthn_origin_mismatch";

  public constructor(code: "request_expired" | "webauthn_origin_mismatch") {
    super(code === "request_expired"
      ? "This request has expired and cannot be signed."
      : "Open RootPermit at its official website before using a passkey.");
    this.code = code;
  }
}

/**
 * Selects the broker-signed, decision-specific ApprovalContext. Approve and
 * deny are intentionally not a boolean attached to one reusable challenge.
 */
export function approvalContextFromVerifiedRequest(
  request: VerifiedBrokerRequest,
  decision: Decision,
  nowUnixMs: number,
): VerifiedApprovalContext {
  assertVerifiedBrokerRequest(request);
  if (nowUnixMs >= request.expiresAtUnixMs) throw new CeremonyUnavailableError("request_expired");
  const context = request.webauthn.contexts[decision];
  const verified = Object.freeze({
    decision,
    requestId: context.requestId,
    requestDigest: new Uint8Array(context.requestDigest),
    deviceId: context.deviceId,
    policyId: context.policyId,
    policyVersion: context.policyVersion,
    expiresAtUnixMs: context.expiresAtUnixMs,
    contextDigest: new Uint8Array(context.contextDigest),
    webauthnChallenge: new Uint8Array(context.webauthnChallenge),
  });
  verifiedContexts.add(verified);
  return verified;
}

/**
 * Builds navigator.credentials.get options only from the verified context and
 * the exact ES256 credential IDs broker-pinned for the target device.
 */
export function browserCeremonyRequest(
  request: VerifiedBrokerRequest,
  context: VerifiedApprovalContext,
  browserOrigin: string,
  nowUnixMs: number,
): BrowserCeremonyRequest {
  assertVerifiedBrokerRequest(request);
  if (!verifiedContexts.has(context as object)) throw new Error("approval context is not verified");
  if (nowUnixMs >= context.expiresAtUnixMs) throw new CeremonyUnavailableError("request_expired");
  if (browserOrigin !== request.webauthn.origin) throw new CeremonyUnavailableError("webauthn_origin_mismatch");
  const credentials = request.webauthn.credentials.map((credential) => Object.freeze({
    type: "public-key" as const,
    id: base64UrlBytes(credential.id),
  }));
  return Object.freeze({
    publicKey: Object.freeze({
      challenge: new Uint8Array(context.webauthnChallenge),
      rpId: request.webauthn.rpId,
      timeout: boundedTimeout(context.expiresAtUnixMs - nowUnixMs),
      userVerification: "required" as const,
      allowCredentials: Object.freeze(credentials),
    }),
  });
}

function boundedTimeout(remainingMs: number): number {
  return Math.max(1_000, Math.min(remainingMs, 120_000));
}

function base64UrlBytes(value: string): Uint8Array {
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + padding;
  const bytes = Buffer.from(base64, "base64");
  if (bytes.byteLength !== 16) throw new Error("pinned credential id must decode to 16 bytes");
  return new Uint8Array(bytes);
}
