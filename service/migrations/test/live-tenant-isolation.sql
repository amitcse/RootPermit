-- Live PostgreSQL regression for the migration-owned tenant boundary.
--
-- This script is intentionally run as an isolated database owner, then drops
-- privileges to a non-owner, non-BYPASSRLS application role.  The role can
-- issue normal SELECT/INSERT/UPDATE/DELETE statements but cannot alter tables,
-- policies, or roles.  That makes the assertions exercise FORCE RLS rather
-- than the database owner's implicit bypass.
--
-- It is not an API, worker, cache, notification, export, or WebSocket test.
-- Those paths need separate M5 integration evidence before RootPermit can
-- claim the hosted multi-tenant isolation gate is complete.

\set ON_ERROR_STOP on
\pset pager off

CREATE ROLE rp_ci_tenant_api NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
GRANT USAGE ON SCHEMA public, rootpermit TO rp_ci_tenant_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO rp_ci_tenant_api;

-- A future migration must protect every tenant-bearing table with FORCE RLS
-- and the same fail-closed current-tenant policy.  This checks catalog state
-- after all migration files have been applied, rather than relying on text.
DO $$
DECLARE
  missing_protection text[];
BEGIN
  SELECT array_agg(expected.table_name ORDER BY expected.table_name)
    INTO missing_protection
    FROM unnest(ARRAY[
      'accounts', 'devices', 'web_sessions', 'credential_bindings', 'pairings',
      'request_envelopes', 'decisions', 'service_proofs', 'lifecycle_projections',
      'receipt_projections', 'outbox', 'notifications', 'audit_events', 'exports',
      'deletion_requests', 'projection_sync_states'
    ]) AS expected(table_name)
    LEFT JOIN pg_class AS table_class
      ON table_class.relname = expected.table_name
     AND table_class.relnamespace = 'public'::regnamespace
    LEFT JOIN pg_policy AS policy
      ON policy.polrelid = table_class.oid
     AND policy.polname = 'tenant_isolation'
   WHERE table_class.oid IS NULL
      OR NOT table_class.relrowsecurity
      OR NOT table_class.relforcerowsecurity
      OR policy.polname IS NULL;

  IF missing_protection IS NOT NULL THEN
    RAISE EXCEPTION 'tenant RLS/force-policy missing for: %', missing_protection;
  END IF;
END
$$;

-- Fixed synthetic IDs prevent fixture drift and contain no customer data.
INSERT INTO accounts (id, tenant_id, public_id, email_verification_state)
VALUES
  ('10000000-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'tenant-a-account', 'verified'),
  ('20000000-0000-4000-8000-000000000001', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'tenant-b-account', 'verified');

SET ROLE rp_ci_tenant_api;

-- A transaction-local context exposes only tenant A.  The foreign read must
-- be indistinguishable from absence, so it returns zero rows rather than a
-- tenant-specific error.
BEGIN;
SELECT set_config('app.tenant_id', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', true);

DO $$
BEGIN
  IF rootpermit.current_tenant_id() <> 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid THEN
    RAISE EXCEPTION 'tenant A transaction context was not established';
  END IF;

  IF (SELECT count(*) FROM accounts) <> 1 THEN
    RAISE EXCEPTION 'tenant A observed a foreign account';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM accounts
     WHERE id = '20000000-0000-4000-8000-000000000001'::uuid
  ) THEN
    RAISE EXCEPTION 'tenant A could read tenant B account by bare ID';
  END IF;

  -- An explicit foreign tenant_id is a write attempt, not a lookup.  RLS must
  -- reject it even though the role was granted normal INSERT privilege.
  BEGIN
    INSERT INTO accounts (id, tenant_id, public_id, email_verification_state)
    VALUES (
      '30000000-0000-4000-8000-000000000001',
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      'tenant-b-forged-account',
      'verified'
    );
    RAISE EXCEPTION 'tenant A inserted a tenant B account';
  EXCEPTION
    WHEN insufficient_privilege THEN
      NULL; -- expected SQLSTATE 42501: RLS WITH CHECK denial
  END;
END
$$;
COMMIT;

-- set_config(..., true) is SET LOCAL.  On a reused connection, a later
-- transaction with no authenticated tenant must fail closed rather than
-- inherit tenant A's context.
DO $$
BEGIN
  IF rootpermit.current_tenant_id() IS NOT NULL THEN
    RAISE EXCEPTION 'transaction-local tenant context leaked after commit';
  END IF;

  IF EXISTS (SELECT 1 FROM accounts) THEN
    RAISE EXCEPTION 'request without tenant context could read an account';
  END IF;
END
$$;

RESET ROLE;

-- The failed RLS write did not create a hidden cross-tenant row.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM accounts
     WHERE id = '30000000-0000-4000-8000-000000000001'::uuid
  ) THEN
    RAISE EXCEPTION 'rejected foreign insert persisted';
  END IF;
END
$$;
