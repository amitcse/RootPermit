import assert from "node:assert/strict";
import test from "node:test";

import {
  RequestRepository,
} from "../src/request-repository.ts";
import {
  TenantScopedDatabase,
  tenantScopeFromVerifiedSession,
  type TenantTransaction,
} from "../src/tenant-context.ts";

const TENANT_A = "11111111-1111-4111-8111-111111111111";
const REQUEST_A = "AbCdEfGhIjKlMnOpQrStUw";
const DEVICE_A = "ZyXwVuTsRqPoNmLkJiHgFe";

class RecordingDatabase {
  public readonly statements: Array<{ sql: string; parameters: readonly unknown[] | undefined }> = [];

  public async transaction<Result>(work: (transaction: TenantTransaction) => Promise<Result>): Promise<Result> {
    return work({
      query: async <Row>(sql: string, parameters?: readonly unknown[]) => {
        this.statements.push({ sql, parameters });
        if (sql.includes("FROM request_envelopes")) {
          return {
            rows: [{
              public_id: REQUEST_A,
              device_public_id: DEVICE_A,
              projection_state: "pending",
              frozen_gap: false,
              terminal: false,
              expires_at: new Date("2026-08-12T00:00:00.000Z"),
            }] as readonly Row[],
          };
        }
        return { rows: [] as readonly Row[] };
      },
    });
  }
}

test("repository sets a transaction-local server-derived tenant before lookup", async () => {
  const rawDatabase = new RecordingDatabase();
  const repository = new RequestRepository(new TenantScopedDatabase(rawDatabase));
  const scope = tenantScopeFromVerifiedSession({ tenantId: TENANT_A, accountId: "account-from-session" });

  const result = await repository.getByPublicId(scope, REQUEST_A);

  assert.equal(result?.publicId, REQUEST_A);
  assert.deepEqual(rawDatabase.statements[0], {
    sql: "SELECT set_config('app.tenant_id', $1, true)",
    parameters: [TENANT_A],
  });
  assert.match(rawDatabase.statements[1]?.sql ?? "", /request_envelopes\.tenant_id = rootpermit\.current_tenant_id\(\)/);
  assert.match(rawDatabase.statements[1]?.sql ?? "", /request_envelopes\.public_id = \$1/);
  assert.deepEqual(rawDatabase.statements[1]?.parameters, [REQUEST_A]);
});

test("repository rejects invalid public IDs and bounded-list violations before querying", async () => {
  const rawDatabase = new RecordingDatabase();
  const repository = new RequestRepository(new TenantScopedDatabase(rawDatabase));
  const scope = tenantScopeFromVerifiedSession({ tenantId: TENANT_A, accountId: "account-from-session" });

  await assert.rejects(repository.getByPublicId(scope, "tenant-a-request"), /16-byte base64url/);
  await assert.rejects(repository.listForDevice(scope, DEVICE_A, 101), /1 through 100/);
  assert.equal(rawDatabase.statements.length, 0);
});
