import {
  assertVerifiedBrokerRequest,
  type PackageChange,
  type VerifiedBrokerRequest,
} from "./verified-envelope.ts";

export type ApprovalPage = ReadyApprovalPage | BlockedApprovalPage;

export interface ReadyApprovalPage {
  readonly kind: "ready";
  readonly request: {
    readonly id: string;
    readonly digest: string;
    readonly device: string;
    readonly policy: string;
    readonly expiresAtUnixMs: number;
  };
  /** Consequences always precede the isolated agent note in the rendering order. */
  readonly consequences: {
    readonly target: PackageChange;
    readonly dependencies: readonly PackageChange[];
    readonly removals: readonly PackageChange[];
    readonly downgrades: readonly PackageChange[];
    readonly origin: string;
    readonly archiveBytes: number;
    readonly diskBytes: number;
  };
  readonly untrustedAgentNote: { readonly text: string } | null;
  readonly allowedDecisions: readonly ["approve", "deny"];
}

export interface BlockedApprovalPage {
  readonly kind: "blocked";
  readonly code: "invalid_envelope" | "request_expired" | "sequence_gap";
  readonly heading: string;
  readonly message: string;
}

/** A checked envelope is the only source of authoritative display content. */
export function approvalPageFromVerifiedRequest(
  request: VerifiedBrokerRequest,
  nowUnixMs: number,
): ApprovalPage {
  assertVerifiedBrokerRequest(request);
  if (!Number.isSafeInteger(nowUnixMs) || nowUnixMs < 0) throw new Error("clock must be a Unix-millisecond safe integer");
  if (nowUnixMs >= request.expiresAtUnixMs) return expiredPage();
  return Object.freeze({
    kind: "ready",
    request: Object.freeze({
      id: request.requestId,
      digest: hex(request.requestDigest),
      device: request.device.displayName,
      policy: `${request.policy.id} v${request.policy.version}`,
      expiresAtUnixMs: request.expiresAtUnixMs,
    }),
    consequences: Object.freeze({
      target: request.consequences.target,
      dependencies: request.consequences.dependencies,
      removals: request.consequences.removals,
      downgrades: request.consequences.downgrades,
      origin: request.consequences.origin,
      archiveBytes: request.consequences.archiveBytes,
      diskBytes: request.consequences.diskBytes,
    }),
    untrustedAgentNote: request.agentNote === null ? null : Object.freeze({ text: request.agentNote }),
    allowedDecisions: Object.freeze(["approve", "deny"] as const),
  });
}

/** A verified event-stream gap freezes decisions and intentionally shows no plan. */
export function sequenceGapPage(): BlockedApprovalPage {
  return Object.freeze({
    kind: "blocked",
    code: "sequence_gap",
    heading: "Request status needs resync",
    message: "Approval is paused until RootPermit verifies a complete broker update.",
  });
}

export function invalidEnvelopePage(): BlockedApprovalPage {
  return Object.freeze({
    kind: "blocked",
    code: "invalid_envelope",
    heading: "Request could not be verified",
    message: "No approval is available. Open RootPermit again or wait for a new request.",
  });
}

function expiredPage(): BlockedApprovalPage {
  return Object.freeze({
    kind: "blocked",
    code: "request_expired",
    heading: "Request expired",
    message: "This request can no longer be approved or denied. Ask the agent to create a new request.",
  });
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
