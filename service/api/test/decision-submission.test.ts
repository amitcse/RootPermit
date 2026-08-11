import assert from "node:assert/strict";
import test from "node:test";

import { DecisionSubmissionRepository, verifiedApprovalCeremonyFromWebAuthn } from "../src/approval-boundary.ts";
import { TenantScopedDatabase, tenantScopeFromVerifiedSession, type TenantTransaction } from "../src/tenant-context.ts";

const TENANT = "11111111-1111-4111-8111-111111111111";
const ACCOUNT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const REQUEST = "AbCdEfGhIjKlMnOpQrStUw";
const CREDENTIAL = "ZyXwVuTsRqPoNmLkJiHgFe";
const DECISION = "MnOpQrStUvWxYz01234567";
const REQUEST_ID = "33333333-3333-4333-8333-333333333333";
const CREDENTIAL_ID = "44444444-4444-4444-8444-444444444444";

interface Statement { readonly sql: string; readonly parameters: readonly unknown[] | undefined }

class RecordingDatabase {
  public readonly statements: Statement[] = [];
  public quarantined = false;

  public async transaction<Result>(work: (transaction: TenantTransaction) => Promise<Result>): Promise<Result> {
    return work({ query: async <Row>(sql: string, parameters?: readonly unknown[]) => {
      this.statements.push({ sql, parameters });
      if (sql.includes("FROM request_envelopes")) {
        return { rows: [{
          request_id: REQUEST_ID,
          request_public_id: REQUEST,
          device_id: "55555555-5555-4555-8555-555555555555",
          credential_id: CREDENTIAL_ID,
          credential_public_id: CREDENTIAL,
          quarantined_at: this.quarantined ? new Date() : null,
          projection_state: "pending",
          frozen_gap: false,
        }] as readonly Row[] };
      }
      if (sql.includes("INSERT INTO decisions")) return { rows: [{ public_id: DECISION }] as readonly Row[] };
      return { rows: [] as readonly Row[] };
    }});
  }
}

const scope = tenantScopeFromVerifiedSession({ tenantId: TENANT, accountId: ACCOUNT });
const ceremony = verifiedApprovalCeremonyFromWebAuthn({
  credentialBindingPublicId: CREDENTIAL,
  assertionBytes: new Uint8Array([1, 2, 3]),
  decision: "deny",
});

test("a verified ceremony is recorded only after request/device/credential tenant relation checks", async () => {
  const database = new RecordingDatabase();
  const result = await new DecisionSubmissionRepository(new TenantScopedDatabase(database))
    .recordVerifiedCeremony(scope, REQUEST, ceremony, DECISION);

  assert.equal(result.decision, "deny");
  assert.deepEqual(database.statements[0], {
    sql: "SELECT set_config('app.tenant_id', $1, true)", parameters: [TENANT],
  });
  const relation = database.statements.find((statement) => statement.sql.includes("FROM request_envelopes"));
  assert.match(relation?.sql ?? "", /credential_bindings\.tenant_id = request_envelopes\.tenant_id/);
  assert.match(relation?.sql ?? "", /request_envelopes\.tenant_id = rootpermit\.current_tenant_id\(\)/);
  assert.deepEqual(relation?.parameters, [REQUEST, CREDENTIAL]);
  const insert = database.statements.find((statement) => statement.sql.includes("INSERT INTO decisions"));
  assert.equal(insert?.parameters?.includes(TENANT), false);
  assert.deepEqual(insert?.parameters?.slice(1), [DECISION, REQUEST_ID, CREDENTIAL_ID, ceremony.assertionReference, 2]);
});

test("a quarantined credential cannot produce a decision row or broker-forwarding object", async () => {
  const database = new RecordingDatabase();
  database.quarantined = true;
  await assert.rejects(
    new DecisionSubmissionRepository(new TenantScopedDatabase(database)).recordVerifiedCeremony(scope, REQUEST, ceremony, DECISION),
    /credential_quarantined/,
  );
  assert.equal(database.statements.some((statement) => statement.sql.includes("INSERT INTO decisions")), false);
});
