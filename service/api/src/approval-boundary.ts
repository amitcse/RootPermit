import { createHash, randomUUID } from "node:crypto";

import type { TenantScope, TenantTransaction } from "./tenant-context.ts";
import { TenantScopedDatabase } from "./tenant-context.ts";

const PUBLIC_ID = /^[A-Za-z0-9_-]{22}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_ASSERTION_BYTES = 64 * 1024;
const ceremonyBrand: unique symbol = Symbol("VerifiedApprovalCeremony");

export type DecisionValue = "approve" | "deny";

/**
 * This is intentionally not an account session. It can only be created by a
 * WebAuthn verifier after it has checked the broker-derived challenge, RP ID,
 * origin, UV and a currently broker-pinned credential.
 */
export interface VerifiedApprovalCeremony {
  readonly credentialBindingPublicId: string;
  readonly assertionReference: Uint8Array;
  readonly decision: DecisionValue;
  readonly [ceremonyBrand]: true;
}

export interface VerifiedCeremonyInput {
  readonly credentialBindingPublicId: string;
  readonly assertionBytes: Uint8Array;
  readonly decision: DecisionValue;
}

/**
 * Boundary called only by the WebAuthn adapter after cryptographic checks.
 * The database stores a digest/reference, never raw assertion bytes.
 */
export function verifiedApprovalCeremonyFromWebAuthn(
  input: VerifiedCeremonyInput,
): VerifiedApprovalCeremony {
  requirePublicId(input.credentialBindingPublicId, "credential binding public id");
  if (input.decision !== "approve" && input.decision !== "deny") {
    throw new Error("decision must be approve or deny");
  }
  if (input.assertionBytes.byteLength < 1 || input.assertionBytes.byteLength > MAX_ASSERTION_BYTES) {
    throw new Error("WebAuthn assertion exceeds bounded decision input");
  }
  return Object.freeze({
    credentialBindingPublicId: input.credentialBindingPublicId,
    assertionReference: createHash("sha256")
      .update("rootpermit/webauthn-assertion-reference/v1\0", "utf8")
      .update(input.assertionBytes)
      .digest(),
    decision: input.decision,
    [ceremonyBrand]: true as const,
  });
}

export interface BrokerForwardDecision {
  readonly requestPublicId: string;
  readonly decisionPublicId: string;
  readonly decision: DecisionValue;
  readonly credentialBindingPublicId: string;
  readonly assertionReference: Uint8Array;
}

interface DecisionRelationRow {
  readonly request_id: string;
  readonly request_public_id: string;
  readonly device_id: string;
  readonly credential_id: string;
  readonly credential_public_id: string;
  readonly quarantined_at: Date | null;
  readonly projection_state: string | null;
  readonly frozen_gap: boolean;
}

/**
 * The hosted service records and forwards a verified human ceremony. It cannot
 * construct a root-executable approval: no broker private key, execution
 * transition, or locally authoritative DecisionSubmission is available here.
 */
export class DecisionSubmissionRepository {
  private readonly database: TenantScopedDatabase;

  public constructor(database: TenantScopedDatabase) {
    this.database = database;
  }

  public async recordVerifiedCeremony(
    scope: TenantScope,
    requestPublicId: string,
    ceremony: VerifiedApprovalCeremony,
    decisionPublicId: string,
  ): Promise<BrokerForwardDecision> {
    requirePublicId(requestPublicId, "request public id");
    requirePublicId(decisionPublicId, "decision public id");
    assertCeremony(ceremony);
    return this.database.withTenant(scope, async (transaction) => {
      const relation = await this.findPinnedRelation(transaction, requestPublicId, ceremony.credentialBindingPublicId);
      if (relation === null) {
        throw new Error("not_found_or_not_authorized");
      }
      if (relation.quarantined_at !== null) {
        throw new Error("credential_quarantined");
      }
      if (relation.frozen_gap || relation.projection_state !== "pending") {
        throw new Error("request_not_pending");
      }
      const result = await transaction.query<{ public_id: string }>(
        `INSERT INTO decisions
           (id, tenant_id, public_id, request_envelope_id, credential_binding_id,
            assertion_reference, decision_value, verification_result)
         VALUES ($1, rootpermit.current_tenant_id(), $2, $3, $4, $5, $6, 'webauthn_verified')
         ON CONFLICT (tenant_id, public_id) DO NOTHING
         RETURNING public_id`,
        [
          randomUUID(),
          decisionPublicId,
          relation.request_id,
          relation.credential_id,
          ceremony.assertionReference,
          ceremony.decision === "approve" ? 1 : 2,
        ],
      );
      if (result.rows.length !== 1) {
        throw new Error("decision_replayed");
      }
      return Object.freeze({
        requestPublicId: relation.request_public_id,
        decisionPublicId,
        decision: ceremony.decision,
        credentialBindingPublicId: relation.credential_public_id,
        assertionReference: ceremony.assertionReference,
      });
    });
  }

  private async findPinnedRelation(
    transaction: TenantTransaction,
    requestPublicId: string,
    credentialPublicId: string,
  ): Promise<DecisionRelationRow | null> {
    const result = await transaction.query<DecisionRelationRow>(
      `SELECT request_envelopes.id AS request_id,
              request_envelopes.public_id AS request_public_id,
              request_envelopes.device_id,
              credential_bindings.id AS credential_id,
              credential_bindings.public_id AS credential_public_id,
              credential_bindings.quarantined_at,
              latest_projection.state AS projection_state,
              COALESCE(projection_sync_states.frozen_gap, false) AS frozen_gap
         FROM request_envelopes
         JOIN credential_bindings
           ON credential_bindings.tenant_id = request_envelopes.tenant_id
          AND credential_bindings.device_id = request_envelopes.device_id
         LEFT JOIN LATERAL (
           SELECT state
             FROM lifecycle_projections
            WHERE lifecycle_projections.tenant_id = request_envelopes.tenant_id
              AND lifecycle_projections.request_envelope_id = request_envelopes.id
            ORDER BY lifecycle_projections.broker_sequence DESC
            LIMIT 1
         ) AS latest_projection ON true
         LEFT JOIN projection_sync_states
           ON projection_sync_states.tenant_id = request_envelopes.tenant_id
          AND projection_sync_states.request_envelope_id = request_envelopes.id
        WHERE request_envelopes.tenant_id = rootpermit.current_tenant_id()
          AND request_envelopes.public_id = $1
          AND credential_bindings.public_id = $2
        LIMIT 1
        FOR UPDATE OF request_envelopes, credential_bindings`,
      [requestPublicId, credentialPublicId],
    );
    return result.rows[0] ?? null;
  }
}

function assertCeremony(ceremony: VerifiedApprovalCeremony): void {
  if (ceremony[ceremonyBrand] !== true || ceremony.assertionReference.byteLength !== 32) {
    throw new Error("decision requires a verified bounded WebAuthn ceremony");
  }
}

function requirePublicId(value: string, name: string): void {
  if (!PUBLIC_ID.test(value)) {
    throw new Error(`${name} must be a 16-byte base64url value`);
  }
}

export function isInternalUuid(value: string): boolean {
  return UUID.test(value);
}
