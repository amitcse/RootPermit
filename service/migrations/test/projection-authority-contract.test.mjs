import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

const migrationPath = fileURLToPath(
  new URL("../0003_projection_and_authority_boundaries.sql", import.meta.url),
);
const sql = await readFile(migrationPath, "utf8");

test("projection gap state is tenant-isolated and separate from append-only events", () => {
  assert.match(sql, /CREATE TABLE projection_sync_states/);
  assert.match(sql, /FOREIGN KEY \(tenant_id, request_envelope_id\)/);
  assert.match(sql, /ALTER TABLE projection_sync_states ENABLE ROW LEVEL SECURITY/);
  assert.match(sql, /ALTER TABLE projection_sync_states FORCE ROW LEVEL SECURITY/);
  assert.match(sql, /tenant_id = rootpermit\.current_tenant_id\(\)/);
});

test("resync coalescing and audit evidence retain their security boundaries", () => {
  assert.match(sql, /CREATE UNIQUE INDEX outbox_tenant_relation_dedupe_idx/);
  assert.match(sql, /WHERE dedupe_key IS NOT NULL/);
  assert.match(sql, /CREATE TRIGGER audit_events_no_update_delete/);
  assert.match(sql, /audit_events are append-only/);
});

test("credential route identifiers are opaque and tenant unique", () => {
  assert.match(sql, /ADD COLUMN public_id text NOT NULL/);
  assert.match(sql, /credential_bindings_public_id_format/);
  assert.match(sql, /credential_bindings_tenant_public_id_idx/);
});
