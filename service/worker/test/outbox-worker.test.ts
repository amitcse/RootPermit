import assert from "node:assert/strict";
import test from "node:test";

import {
  TransactionalOutboxWorker,
  type TenantTransaction,
} from "../src/outbox-worker.ts";

const TENANT_A = "11111111-1111-4111-8111-111111111111";
const TENANT_B = "22222222-2222-4222-8222-222222222222";
const OUTBOX_A = "33333333-3333-4333-8333-333333333333";
const RELATION_A = "44444444-4444-4444-8444-444444444444";
const OUTBOX_B = "55555555-5555-4555-8555-555555555555";
const RELATION_B = "66666666-6666-4666-8666-666666666666";

interface Statement {
  readonly sql: string;
  readonly parameters: readonly unknown[] | undefined;
}

class RecordingDatabase {
  public readonly statements: Statement[] = [];
  public rows: readonly unknown[] = [];
  public deleteRows = 1;

  public async query<Row>(sql: string, parameters?: readonly unknown[]): Promise<{ readonly rows: readonly Row[] }> {
    this.statements.push({ sql, parameters });
    if (sql.includes("claim_outbox")) {
      return { rows: this.rows as readonly Row[] };
    }
    return { rows: [] };
  }

  public async transaction<Result>(work: (transaction: TenantTransaction) => Promise<Result>): Promise<Result> {
    return work({
      query: async <Row>(sql: string, parameters?: readonly unknown[]) => {
        this.statements.push({ sql, parameters });
        if (sql.includes("DELETE FROM outbox")) {
          return { rows: (this.deleteRows === 1 ? [{ id: OUTBOX_A }] : []) as readonly Row[] };
        }
        if (sql.includes("UPDATE outbox")) {
          return { rows: [{ id: OUTBOX_A }] as readonly Row[] };
        }
        return { rows: [] as readonly Row[] };
      },
    });
  }
}

function claimedRow(id: string, tenantId: string, relationId: string) {
  return {
    id,
    tenant_id: tenantId,
    relation_type: "request_envelope",
    relation_id: relationId,
    event_type: "decision_ready",
    payload_digest: new Uint8Array(32),
  };
}

test("completion retains the exact claimed tenant and relation tuple", async () => {
  const database = new RecordingDatabase();
  database.rows = [claimedRow(OUTBOX_A, TENANT_A, RELATION_A)];
  const worker = new TransactionalOutboxWorker(database);
  const delivered: string[] = [];

  const completed = await worker.runOnce(10, {
    deliver: async (item) => { delivered.push(`${item.tenantId}:${item.relationId}`); },
  });

  assert.deepEqual(completed, [OUTBOX_A]);
  assert.deepEqual(delivered, [`${TENANT_A}:${RELATION_A}`]);
  const context = database.statements.find((statement) => statement.sql.includes("set_config"));
  const completion = database.statements.find((statement) => statement.sql.includes("DELETE FROM outbox"));
  assert.deepEqual(context?.parameters, [TENANT_A]);
  assert.match(completion?.sql ?? "", /tenant_id = rootpermit\.current_tenant_id\(\)/);
  assert.deepEqual(completion?.parameters, [OUTBOX_A, "request_envelope", RELATION_A, "decision_ready"]);
});

test("each claimed event re-establishes its own tenant; no tenant is inherited across rows", async () => {
  const database = new RecordingDatabase();
  database.rows = [
    claimedRow(OUTBOX_A, TENANT_A, RELATION_A),
    claimedRow(OUTBOX_B, TENANT_B, RELATION_B),
  ];
  const worker = new TransactionalOutboxWorker(database);

  await worker.runOnce(2, { deliver: async () => undefined });

  const contexts = database.statements
    .filter((statement) => statement.sql.includes("set_config"))
    .map((statement) => statement.parameters?.[0]);
  const deletes = database.statements.filter((statement) => statement.sql.includes("DELETE FROM outbox"));
  assert.deepEqual(contexts, [TENANT_A, TENANT_B]);
  assert.deepEqual(deletes[0]?.parameters, [OUTBOX_A, "request_envelope", RELATION_A, "decision_ready"]);
  assert.deepEqual(deletes[1]?.parameters, [OUTBOX_B, "request_envelope", RELATION_B, "decision_ready"]);
});

test("delivery failure is rescheduled under the original tenant and relation tuple", async () => {
  const database = new RecordingDatabase();
  database.rows = [claimedRow(OUTBOX_A, TENANT_A, RELATION_A)];
  const worker = new TransactionalOutboxWorker(database);

  const completed = await worker.runOnce(1, {
    deliver: async () => { throw { retryAfterMs: 1_000 }; },
  });

  assert.deepEqual(completed, []);
  const retry = database.statements.find((statement) => statement.sql.includes("UPDATE outbox"));
  assert.match(retry?.sql ?? "", /tenant_id = rootpermit\.current_tenant_id\(\)/);
  assert.deepEqual(retry?.parameters, [OUTBOX_A, "request_envelope", RELATION_A, "decision_ready", 1_000]);
});

test("invalid claimed tenant or relation data fails before any delivery", async () => {
  const database = new RecordingDatabase();
  database.rows = [{ ...claimedRow(OUTBOX_A, "tenant-a", RELATION_A) }];
  const worker = new TransactionalOutboxWorker(database);
  let deliveries = 0;

  await assert.rejects(worker.runOnce(1, { deliver: async () => { deliveries += 1; } }), /outbox tenant id/);
  assert.equal(deliveries, 0);
});
