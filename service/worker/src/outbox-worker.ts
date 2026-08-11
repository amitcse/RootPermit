/**
 * The worker is deliberately a tenant-aware dispatcher, not a global queue
 * consumer. `rootpermit.claim_outbox` is the only cross-tenant operation; it
 * must be a narrowly audited database function that atomically leases rows.
 */

export interface QueryResult<Row> {
  readonly rows: readonly Row[];
}

export interface TenantTransaction {
  query<Row>(sql: string, parameters?: readonly unknown[]): Promise<QueryResult<Row>>;
}

export interface WorkerDatabase {
  transaction<Result>(work: (transaction: TenantTransaction) => Promise<Result>): Promise<Result>;
  query<Row>(sql: string, parameters?: readonly unknown[]): Promise<QueryResult<Row>>;
}

interface ClaimedOutboxRow {
  id: string;
  tenant_id: string;
  relation_type: string;
  relation_id: string;
  event_type: string;
  payload_digest: Uint8Array;
}

const claimedOutboxItemBrand: unique symbol = Symbol("ClaimedOutboxItem");

export interface ClaimedOutboxItem {
  readonly id: string;
  readonly tenantId: string;
  readonly relationType: string;
  readonly relationId: string;
  readonly eventType: string;
  readonly payloadDigest: Uint8Array;
  readonly [claimedOutboxItemBrand]: true;
}

export interface OutboxDelivery {
  deliver(item: ClaimedOutboxItem): Promise<void>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const LABEL = /^[a-z][a-z0-9_.-]{0,63}$/;

function requireUuid(value: string, name: string): string {
  if (!UUID.test(value)) {
    throw new Error(`${name} must be a UUID`);
  }
  return value;
}

function requireLabel(value: string, name: string): string {
  if (!LABEL.test(value)) {
    throw new Error(`${name} is not a bounded safe label`);
  }
  return value;
}

function claimedItem(row: ClaimedOutboxRow): ClaimedOutboxItem {
  if (row.payload_digest.byteLength !== 32) {
    throw new Error("claimed outbox payload digest must be SHA-256");
  }
  return Object.freeze({
    id: requireUuid(row.id, "outbox id"),
    tenantId: requireUuid(row.tenant_id, "outbox tenant id"),
    relationType: requireLabel(row.relation_type, "relation type"),
    relationId: requireUuid(row.relation_id, "relation id"),
    eventType: requireLabel(row.event_type, "event type"),
    payloadDigest: row.payload_digest,
    [claimedOutboxItemBrand]: true as const,
  });
}

/**
 * Calls the one database function permitted to claim work across tenants. The
 * function must not return payloads without their original tenant and relation
 * tuple, and its lease prevents a second worker from delivering the same row.
 */
export class TransactionalOutboxWorker {
  private readonly database: WorkerDatabase;

  public constructor(database: WorkerDatabase) {
    this.database = database;
  }

  public async runOnce(limit: number, delivery: OutboxDelivery): Promise<readonly string[]> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new Error("claim limit must be an integer from 1 through 100");
    }

    const claim = await this.database.query<ClaimedOutboxRow>(
      `SELECT id, tenant_id, relation_type, relation_id, event_type, payload_digest
         FROM rootpermit.claim_outbox($1)`,
      [limit],
    );
    const completed: string[] = [];

    for (const row of claim.rows) {
      const item = claimedItem(row);
      try {
        await delivery.deliver(item);
        await this.complete(item);
        completed.push(item.id);
      } catch (error) {
        await this.reschedule(item, retryDelay(error));
      }
    }
    return completed;
  }

  private async complete(item: ClaimedOutboxItem): Promise<void> {
    await this.withClaimTenant(item, async (transaction) => {
      const result = await transaction.query<{ id: string }>(
        `DELETE FROM outbox
          WHERE tenant_id = rootpermit.current_tenant_id()
            AND id = $1
            AND relation_type = $2
            AND relation_id = $3
            AND event_type = $4
          RETURNING id`,
        [item.id, item.relationType, item.relationId, item.eventType],
      );
      if (result.rows.length !== 1) {
        throw new Error("outbox completion lost its tenant/relation lease");
      }
    });
  }

  private async reschedule(item: ClaimedOutboxItem, retryAfterMs: number): Promise<void> {
    await this.withClaimTenant(item, async (transaction) => {
      const result = await transaction.query<{ id: string }>(
        `UPDATE outbox
            SET attempts = attempts + 1,
                visible_after = now() + ($5::bigint * interval '1 millisecond')
          WHERE tenant_id = rootpermit.current_tenant_id()
            AND id = $1
            AND relation_type = $2
            AND relation_id = $3
            AND event_type = $4
          RETURNING id`,
        [item.id, item.relationType, item.relationId, item.eventType, retryAfterMs],
      );
      if (result.rows.length !== 1) {
        throw new Error("outbox retry lost its tenant/relation lease");
      }
    });
  }

  private async withClaimTenant<Result>(
    item: ClaimedOutboxItem,
    work: (transaction: TenantTransaction) => Promise<Result>,
  ): Promise<Result> {
    return this.database.transaction(async (transaction) => {
      await transaction.query(
        "SELECT set_config('app.tenant_id', $1, true)",
        [item.tenantId],
      );
      return work(transaction);
    });
  }
}

function retryDelay(error: unknown): number {
  // The worker does not expose arbitrary error text. A delivery adapter can
  // attach an explicit bounded retry delay for expected transport failures.
  if (isRetryableDeliveryError(error)) {
    return error.retryAfterMs;
  }
  return 60_000;
}

function isRetryableDeliveryError(error: unknown): error is { readonly retryAfterMs: number } {
  return typeof error === "object"
    && error !== null
    && "retryAfterMs" in error
    && typeof error.retryAfterMs === "number"
    && Number.isInteger(error.retryAfterMs)
    && error.retryAfterMs >= 1_000
    && error.retryAfterMs <= 300_000;
}
