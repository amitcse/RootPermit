import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

const testPath = fileURLToPath(
  new URL("./live-tenant-isolation.sql", import.meta.url),
);
const sql = await readFile(testPath, "utf8");

test("live tenant-isolation gate exercises a non-owner RLS subject", () => {
  assert.match(sql, /CREATE ROLE rp_ci_tenant_api NOLOGIN NOSUPERUSER/);
  assert.match(sql, /GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public/);
  assert.match(sql, /SET ROLE rp_ci_tenant_api/);
  assert.match(sql, /RESET ROLE/);
  assert.match(sql, /relrowsecurity/);
  assert.match(sql, /relforcerowsecurity/);
  assert.match(sql, /polname = 'tenant_isolation'/);
});

test("live tenant-isolation gate covers foreign read, write, and context reset", () => {
  assert.match(sql, /SELECT set_config\('app\.tenant_id', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', true\)/);
  assert.match(sql, /tenant A could read tenant B account by bare ID/);
  assert.match(sql, /tenant A inserted a tenant B account/);
  assert.match(sql, /WHEN insufficient_privilege/);
  assert.match(sql, /COMMIT;/);
  assert.match(sql, /transaction-local tenant context leaked after commit/);
  assert.match(sql, /request without tenant context could read an account/);
});
