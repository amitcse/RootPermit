import { createHash, randomUUID } from "node:crypto";

import {
  type TenantScope,
  type TenantTransaction,
  TenantScopedDatabase,
} from "./tenant-context.ts";

const PUBLIC_ID = /^[A-Za-z0-9_-]{22}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TERMINAL_STATES = new Set(["succeeded", "failed", "cancelled", "expired", "stale", "recovery_required"]);
const LIFECYCLE_STATES = new Set([
  "awaiting_event", "pending", "approved", "executing", "succeeded", "failed", "cancelled", "expired", "stale", "recovery_required",
]);

export type ProjectionApplyResult = "applied" | "duplicate" | "frozen_gap";

export interface VerifiedLifecycleEvent {
  /** Data from an already verified broker COSE object; routing hints are not authority. */
  readonly requestPublicId: string;
  readonly sequence: number;
  readonly eventDigest: Uint8Array;
  readonly previousEventDigest: Uint8Array | null;
  readonly state: string;
}

interface RequestRow {
  readonly id: string;
}

interface ProjectionRow {
  readonly broker_sequence: number;
  readonly event_digest: Uint8Array;
  readonly state: string;
}

/**
 * Applies broker events as a cache/projection only. It deliberately has no
 * operation capable of selecting an approval or changing broker authority.
 */
export class LifecycleProjectionRepository {
  private readonly database: TenantScopedDatabase;

  public constructor(database: TenantScopedDatabase) {
    this.database = database;
  }

  public async applyVerifiedEvent(
    scope: TenantScope,
    event: VerifiedLifecycleEvent,
  ): Promise<ProjectionApplyResult> {
    validateEvent(event);
    return this.database.withTenant(scope, (transaction) => this.apply(transaction, event));
  }

  /**
   * A verified resync replaces a derived cache only after a complete chain
   * starting at sequence zero has been supplied. This never sends a command
   * to the broker and it clears the resync outbox row in the same transaction.
   */
  public async replaceFromVerifiedResync(
    scope: TenantScope,
    requestPublicId: string,
    events: readonly VerifiedLifecycleEvent[],
  ): Promise<void> {
    requirePublicId(requestPublicId);
    if (events.length === 0) {
      throw new Error("verified resync must contain at least one lifecycle event");
    }
    for (const event of events) {
      validateEvent(event);
      if (event.requestPublicId !== requestPublicId) {
        throw new Error("verified resync contains a different request");
      }
    }
    validateContiguousChain(events);

    await this.database.withTenant(scope, async (transaction) => {
      const request = await scopedRequestForUpdate(transaction, requestPublicId);
      if (request === null) {
        throw new Error("not_found_or_not_authorized");
      }
      await transaction.query(
        `DELETE FROM lifecycle_projections
          WHERE tenant_id = rootpermit.current_tenant_id()
            AND request_envelope_id = $1`,
        [request.id],
      );
      for (const event of events) {
        await insertProjection(transaction, request.id, event, false);
      }
      await transaction.query(
        `INSERT INTO projection_sync_states
           (tenant_id, request_envelope_id, frozen_gap, last_verified_sequence)
         VALUES (rootpermit.current_tenant_id(), $1, false, $2)
         ON CONFLICT (tenant_id, request_envelope_id)
         DO UPDATE SET frozen_gap = false,
                       last_verified_sequence = EXCLUDED.last_verified_sequence,
                       updated_at = now()`,
        [request.id, events.at(-1)?.sequence],
      );
      await transaction.query(
        `DELETE FROM outbox
          WHERE tenant_id = rootpermit.current_tenant_id()
            AND relation_type = 'request_envelope'
            AND relation_id = $1
            AND dedupe_key = 'projection-resync'`,
        [request.id],
      );
    });
  }

  private async apply(transaction: TenantTransaction, event: VerifiedLifecycleEvent): Promise<ProjectionApplyResult> {
    const request = await scopedRequestForUpdate(transaction, event.requestPublicId);
    if (request === null) {
      throw new Error("not_found_or_not_authorized");
    }
    const sameSequence = await transaction.query<ProjectionRow>(
      `SELECT broker_sequence, event_digest, state
         FROM lifecycle_projections
        WHERE tenant_id = rootpermit.current_tenant_id()
          AND request_envelope_id = $1
          AND broker_sequence = $2
        FOR UPDATE`,
      [request.id, event.sequence],
    );
    const existing = sameSequence.rows[0];
    if (existing !== undefined) {
      if (bytesEqual(existing.event_digest, event.eventDigest)) {
        return "duplicate";
      }
      await freezeAndQueueResync(transaction, request.id, event.eventDigest);
      return "frozen_gap";
    }

    const tail = await transaction.query<ProjectionRow>(
      `SELECT broker_sequence, event_digest, state
         FROM lifecycle_projections
        WHERE tenant_id = rootpermit.current_tenant_id()
          AND request_envelope_id = $1
        ORDER BY broker_sequence DESC
        LIMIT 1
        FOR UPDATE`,
      [request.id],
    );
    const last = tail.rows[0];
    const expectedSequence = last === undefined ? 0 : last.broker_sequence + 1;
    const previousMatches = (last === undefined && event.previousEventDigest === null)
      || (last !== undefined && event.previousEventDigest !== null && bytesEqual(last.event_digest, event.previousEventDigest));
    if (event.sequence !== expectedSequence || !previousMatches) {
      await freezeAndQueueResync(transaction, request.id, event.eventDigest);
      return "frozen_gap";
    }

    await insertProjection(transaction, request.id, event, false);
    await transaction.query(
      `INSERT INTO projection_sync_states
         (tenant_id, request_envelope_id, frozen_gap, last_verified_sequence)
       VALUES (rootpermit.current_tenant_id(), $1, false, $2)
       ON CONFLICT (tenant_id, request_envelope_id)
       DO UPDATE SET frozen_gap = false,
                     last_verified_sequence = EXCLUDED.last_verified_sequence,
                     updated_at = now()`,
      [request.id, event.sequence],
    );
    return "applied";
  }
}

async function scopedRequestForUpdate(
  transaction: TenantTransaction,
  requestPublicId: string,
): Promise<RequestRow | null> {
  const result = await transaction.query<RequestRow>(
    `SELECT id
       FROM request_envelopes
      WHERE tenant_id = rootpermit.current_tenant_id()
        AND public_id = $1
      LIMIT 1
      FOR UPDATE`,
    [requestPublicId],
  );
  return result.rows[0] ?? null;
}

async function insertProjection(
  transaction: TenantTransaction,
  requestId: string,
  event: VerifiedLifecycleEvent,
  frozenGap: boolean,
): Promise<void> {
  await transaction.query(
    `INSERT INTO lifecycle_projections
       (id, tenant_id, request_envelope_id, broker_sequence, event_digest, state, frozen_gap)
     VALUES ($1, rootpermit.current_tenant_id(), $2, $3, $4, $5, $6)`,
    [randomUUID(), requestId, event.sequence, event.eventDigest, event.state, frozenGap],
  );
}

async function freezeAndQueueResync(
  transaction: TenantTransaction,
  requestId: string,
  observedDigest: Uint8Array,
): Promise<void> {
  await transaction.query(
    `INSERT INTO projection_sync_states
       (tenant_id, request_envelope_id, frozen_gap, last_verified_sequence)
     VALUES (rootpermit.current_tenant_id(), $1, true, -1)
     ON CONFLICT (tenant_id, request_envelope_id)
     DO UPDATE SET frozen_gap = true,
                   updated_at = now()`,
    [requestId],
  );
  await transaction.query(
    `INSERT INTO outbox
       (id, tenant_id, relation_type, relation_id, event_type, payload_digest, dedupe_key)
     VALUES ($1, rootpermit.current_tenant_id(), 'request_envelope', $2, 'projection_resync_requested', $3, 'projection-resync')
     ON CONFLICT (tenant_id, relation_type, relation_id, dedupe_key) WHERE dedupe_key IS NOT NULL
     DO UPDATE SET visible_after = now()`,
    [randomUUID(), requestId, resyncDigest(requestId, observedDigest)],
  );
}

function resyncDigest(requestId: string, observedDigest: Uint8Array): Uint8Array {
  return createHash("sha256")
    .update("rootpermit/projection-resync/v1\0", "utf8")
    .update(requestId, "utf8")
    .update(observedDigest)
    .digest();
}

function validateEvent(event: VerifiedLifecycleEvent): void {
  requirePublicId(event.requestPublicId);
  if (!Number.isSafeInteger(event.sequence) || event.sequence < 0) {
    throw new Error("lifecycle sequence must be a non-negative safe integer");
  }
  if (event.eventDigest.byteLength !== 32) {
    throw new Error("lifecycle event digest must be SHA-256");
  }
  if (event.previousEventDigest !== null && event.previousEventDigest.byteLength !== 32) {
    throw new Error("previous lifecycle event digest must be SHA-256");
  }
  if (!LIFECYCLE_STATES.has(event.state) || event.state === "frozen_gap") {
    throw new Error("lifecycle state is not a broker state");
  }
}

function validateContiguousChain(events: readonly VerifiedLifecycleEvent[]): void {
  let prior: Uint8Array | null = null;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (event === undefined || event.sequence !== index || !nullableBytesEqual(event.previousEventDigest, prior)) {
      throw new Error("verified resync must be a contiguous event chain starting at sequence zero");
    }
    prior = event.eventDigest;
  }
}

function requirePublicId(value: string): void {
  if (!PUBLIC_ID.test(value)) {
    throw new Error("public id must be a 16-byte base64url value");
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let mismatch = 0;
  for (let index = 0; index < left.byteLength; index += 1) mismatch |= left[index]! ^ right[index]!;
  return mismatch === 0;
}

function nullableBytesEqual(left: Uint8Array | null, right: Uint8Array | null): boolean {
  return left === null || right === null ? left === right : bytesEqual(left, right);
}

export function isTerminalProjectionState(value: string): boolean {
  return TERMINAL_STATES.has(value);
}
