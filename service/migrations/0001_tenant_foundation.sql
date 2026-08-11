-- RootPermit hosted control-plane foundation.
--
-- The API must set `app.tenant_id` with `set_config(..., true)` only after it
-- has authenticated an account session and derived that account's tenant.
-- RLS intentionally fails closed when the setting is absent.

BEGIN;

CREATE SCHEMA IF NOT EXISTS rootpermit;

CREATE FUNCTION rootpermit.current_tenant_id()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
$$;

CREATE TABLE accounts (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  public_id text NOT NULL,
  email_verification_state text NOT NULL CHECK (email_verification_state IN ('pending', 'verified')),
  disabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, public_id)
);

CREATE TABLE devices (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  public_id text NOT NULL,
  broker_key_kid bytea NOT NULL,
  broker_public_key bytea NOT NULL CHECK (octet_length(broker_public_key) = 32),
  projection_state text NOT NULL,
  enrollment_state text NOT NULL CHECK (enrollment_state IN ('unpaired', 'pairing_pending', 'active', 'approval_locked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, public_id)
);

CREATE TABLE web_sessions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  account_id uuid NOT NULL,
  session_digest bytea NOT NULL UNIQUE,
  authentication_strength text NOT NULL,
  recovery_hold_until timestamptz,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id) ON DELETE CASCADE,
  UNIQUE (tenant_id, id)
);

CREATE TABLE credential_bindings (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  device_id uuid NOT NULL,
  credential_id_digest bytea NOT NULL,
  public_cose_key bytea NOT NULL,
  generation bigint NOT NULL CHECK (generation >= 0),
  quarantined_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE CASCADE,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, device_id, credential_id_digest)
);

CREATE TABLE pairings (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  public_id text NOT NULL,
  device_id uuid NOT NULL,
  nonce_digest bytea NOT NULL UNIQUE,
  comparison_code_digest bytea NOT NULL,
  expires_at timestamptz NOT NULL,
  root_confirmed_at timestamptz,
  web_confirmed_at timestamptz,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE CASCADE,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, public_id)
);

CREATE TABLE request_envelopes (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  public_id text NOT NULL,
  device_id uuid NOT NULL,
  broker_cose bytea NOT NULL,
  envelope_digest bytea NOT NULL CHECK (octet_length(envelope_digest) = 32),
  terminal boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE RESTRICT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, public_id),
  UNIQUE (tenant_id, device_id, envelope_digest)
);

CREATE TABLE decisions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  public_id text NOT NULL,
  request_envelope_id uuid NOT NULL,
  credential_binding_id uuid NOT NULL,
  assertion_reference bytea NOT NULL,
  decision_value smallint NOT NULL CHECK (decision_value IN (1, 2)),
  verification_result text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, request_envelope_id) REFERENCES request_envelopes (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, credential_binding_id) REFERENCES credential_bindings (tenant_id, id) ON DELETE RESTRICT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, public_id),
  UNIQUE (tenant_id, request_envelope_id, credential_binding_id, assertion_reference)
);

CREATE TABLE service_proofs (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  request_envelope_id uuid,
  device_id uuid NOT NULL,
  cose_bytes bytea NOT NULL,
  signer_kid bytea NOT NULL,
  proof_sequence bigint NOT NULL CHECK (proof_sequence >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, request_envelope_id) REFERENCES request_envelopes (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE RESTRICT,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, device_id, signer_kid, proof_sequence)
);

CREATE TABLE lifecycle_projections (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  request_envelope_id uuid NOT NULL,
  broker_sequence bigint NOT NULL CHECK (broker_sequence >= 0),
  event_digest bytea NOT NULL CHECK (octet_length(event_digest) = 32),
  state text NOT NULL,
  frozen_gap boolean NOT NULL DEFAULT false,
  applied_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, request_envelope_id) REFERENCES request_envelopes (tenant_id, id) ON DELETE CASCADE,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, request_envelope_id, broker_sequence),
  UNIQUE (tenant_id, request_envelope_id, event_digest)
);

CREATE TABLE receipt_projections (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  request_envelope_id uuid NOT NULL,
  broker_receipt_cose bytea NOT NULL,
  terminal_state text NOT NULL,
  completed_at timestamptz NOT NULL,
  FOREIGN KEY (tenant_id, request_envelope_id) REFERENCES request_envelopes (tenant_id, id) ON DELETE CASCADE,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, request_envelope_id)
);

CREATE TABLE outbox (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  relation_type text NOT NULL,
  relation_id uuid NOT NULL,
  event_type text NOT NULL,
  payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  visible_after timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id)
);

CREATE TABLE notifications (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  account_id uuid NOT NULL,
  device_id uuid,
  request_envelope_id uuid,
  channel text NOT NULL,
  delivery_state text NOT NULL,
  idempotency_key text NOT NULL,
  safe_template_data jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE SET NULL (device_id),
  FOREIGN KEY (tenant_id, request_envelope_id) REFERENCES request_envelopes (tenant_id, id) ON DELETE SET NULL (request_envelope_id),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE audit_events (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  actor_kind text NOT NULL,
  actor_public_id text,
  relation_type text,
  relation_public_id text,
  action_code text NOT NULL,
  result_code text NOT NULL,
  safe_metadata_digest bytea NOT NULL CHECK (octet_length(safe_metadata_digest) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id)
);

CREATE TABLE exports (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  account_id uuid NOT NULL,
  public_id text NOT NULL,
  scope text NOT NULL,
  state text NOT NULL,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id) ON DELETE CASCADE,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, public_id)
);

CREATE TABLE deletion_requests (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  account_id uuid NOT NULL,
  public_id text NOT NULL,
  scope text NOT NULL,
  state text NOT NULL,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, id) ON DELETE CASCADE,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, public_id)
);

-- Policy creation is intentionally generated once for the full hosted schema:
-- future tables must add the same FORCE RLS policy in their own migration.
DO $$
DECLARE
  protected_table text;
BEGIN
  FOREACH protected_table IN ARRAY ARRAY[
    'accounts', 'devices', 'web_sessions', 'credential_bindings', 'pairings',
    'request_envelopes', 'decisions', 'service_proofs', 'lifecycle_projections',
    'receipt_projections', 'outbox', 'notifications', 'audit_events', 'exports',
    'deletion_requests'
  ]
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', protected_table);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', protected_table);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = rootpermit.current_tenant_id()) WITH CHECK (tenant_id = rootpermit.current_tenant_id())',
      protected_table
    );
  END LOOP;
END
$$;

CREATE INDEX request_envelopes_tenant_device_created_idx
  ON request_envelopes (tenant_id, device_id, created_at DESC);
CREATE INDEX lifecycle_projections_tenant_request_sequence_idx
  ON lifecycle_projections (tenant_id, request_envelope_id, broker_sequence DESC);
CREATE INDEX outbox_tenant_visible_after_idx
  ON outbox (tenant_id, visible_after, created_at);
CREATE INDEX notifications_tenant_account_created_idx
  ON notifications (tenant_id, account_id, created_at DESC);

COMMIT;
