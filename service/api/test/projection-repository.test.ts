import assert from "node:assert/strict";
import test from "node:test";

import { LifecycleProjectionRepository } from "../src/projection-repository.ts";
import { TenantScopedDatabase, tenantScopeFromVerifiedSession, type TenantTransaction } from "../src/tenant-context.ts";

const TENANT = "11111111-1111-4111-8111-111111111111";
const ACCOUNT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const REQUEST = "AbCdEfGhIjKlMnOpQrStUw";
const REQUEST_ID = "33333333-3333-4333-8333-333333333333";
const DIGEST = new Uint8Array(32).fill(7);

interface Statement { readonly sql: string; readonly parameters: readonly unknown[] | undefined }

class RecordingDatabase {
  public readonly statements: Statement[] = [];
  public mode: "apply" | "duplicate" | "conflict" = "apply";

  public async transaction<Result>(work: (transaction: TenantTransaction) => Promise<Result>): Promise<Result> {
    return work({ query: async <Row>(sql: string, parameters?: readonly unknown[]) => {
      this.statements.push({ sql, parameters });
      if (sql.includes("SELECT id\n       FROM request_envelopes")) {
        return { rows: [{ id: REQUEST_ID }] as readonly Row[] };
      }
      if (sql.includes("AND broker_sequence = $2")) {
        if (this.mode === "duplicate") return { rows: [{ broker_sequence: 0, event_digest: DIGEST, state: "pending" }] as readonly Row[] };
        if (this.mode === "conflict") return { rows: [{ broker_sequence: 0, event_digest: new Uint8Array(32).fill(8), state: "pending" }] as readonly Row[] };
      }
      return { rows: [] as readonly Row[] };
    }});
  }
}

function event(sequence = 0, previousEventDigest: Uint8Array | null = null) {
  return { requestPublicId: REQUEST, sequence, eventDigest: DIGEST, previousEventDigest, state: "pending" };
}

function repository(database: RecordingDatabase): LifecycleProjectionRepository {
  return new LifecycleProjectionRepository(new TenantScopedDatabase(database));
}

const scope = tenantScopeFromVerifiedSession({ tenantId: TENANT, accountId: ACCOUNT });

test("a verified successor is written only under the transaction tenant", async () => {
  const database = new RecordingDatabase();
  assert.equal(await repository(database).applyVerifiedEvent(scope, event()), "applied");
  assert.deepEqual(database.statements[0], {
    sql: "SELECT set_config('app.tenant_id', $1, true)", parameters: [TENANT],
  });
  const insert = database.statements.find((statement) => statement.sql.includes("INSERT INTO lifecycle_projections"));
  assert.match(insert?.sql ?? "", /tenant_id, request_envelope_id/);
  assert.match(insert?.sql ?? "", /rootpermit\.current_tenant_id\(\)/);
  assert.deepEqual(insert?.parameters?.slice(1), [REQUEST_ID, 0, DIGEST, "pending", false]);
});

test("a byte-identical duplicate is ignored without creating an outbox command", async () => {
  const database = new RecordingDatabase();
  database.mode = "duplicate";
  assert.equal(await repository(database).applyVerifiedEvent(scope, event()), "duplicate");
  assert.equal(database.statements.some((statement) => statement.sql.includes("INSERT INTO outbox")), false);
});

test("a conflicting duplicate freezes the projection and queues one tenant-bound resync", async () => {
  const database = new RecordingDatabase();
  database.mode = "conflict";
  assert.equal(await repository(database).applyVerifiedEvent(scope, event()), "frozen_gap");
  const freeze = database.statements.find((statement) => statement.sql.includes("INSERT INTO projection_sync_states"));
  const outbox = database.statements.find((statement) => statement.sql.includes("INSERT INTO outbox"));
  assert.match(freeze?.sql ?? "", /rootpermit\.current_tenant_id\(\)/);
  assert.match(outbox?.sql ?? "", /ON CONFLICT \(tenant_id, relation_type, relation_id, dedupe_key\) WHERE dedupe_key IS NOT NULL/);
  assert.deepEqual(outbox?.parameters?.[1], REQUEST_ID);
});

test("resync refuses incomplete chains before opening a database transaction", async () => {
  const database = new RecordingDatabase();
  await assert.rejects(
    repository(database).replaceFromVerifiedResync(scope, REQUEST, [event(1, DIGEST)]),
    /contiguous event chain/,
  );
  assert.equal(database.statements.length, 0);
});

test("a contiguous verified resync atomically replaces the derived cache and clears its own outbox intent", async () => {
  const database = new RecordingDatabase();
  await repository(database).replaceFromVerifiedResync(scope, REQUEST, [event(), event(1, DIGEST)]);
  assert.equal(database.statements.filter((statement) => statement.sql.includes("INSERT INTO lifecycle_projections")).length, 2);
  const clear = database.statements.find((statement) => statement.sql.includes("DELETE FROM outbox"));
  assert.match(clear?.sql ?? "", /tenant_id = rootpermit\.current_tenant_id\(\)/);
  assert.deepEqual(clear?.parameters, [REQUEST_ID]);
});
