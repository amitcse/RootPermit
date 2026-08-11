import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

const migrationPath = fileURLToPath(
  new URL("../0002_outbox_claim_function.sql", import.meta.url),
);
const sql = await readFile(migrationPath, "utf8");

test("outbox claim contract has a narrow, safe definer boundary", () => {
  assert.match(sql, /CREATE FUNCTION rootpermit\.claim_outbox\(p_limit integer\)/);
  assert.match(sql, /SECURITY DEFINER/);
  assert.match(sql, /SET search_path = pg_catalog, rootpermit/);
  assert.match(sql, /REVOKE ALL ON FUNCTION rootpermit\.claim_outbox\(integer\) FROM PUBLIC/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION rootpermit\.claim_outbox\(integer\) TO rp_worker/);
  assert.doesNotMatch(sql, /claim_outbox\([^)]*tenant/i);
});

test("outbox claim contract uses atomic skip-locked due-row leasing", () => {
  assert.match(sql, /FOR UPDATE SKIP LOCKED/);
  assert.match(sql, /outbox\.visible_after <= clock_timestamp\(\)/);
  assert.match(sql, /outbox\.leased_until IS NULL OR outbox\.leased_until <= clock_timestamp\(\)/);
  assert.match(sql, /SET leased_until = clock_timestamp\(\) \+ interval '5 minutes'/);
  assert.match(sql, /lease_generation = outbox\.lease_generation \+ 1/);
  assert.match(sql, /UPDATE public\.outbox/);
});
