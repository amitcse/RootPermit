-- Hosted control-plane invariants added before multi-tenant use. A lifecycle
-- projection remains a derived cache; a frozen marker is a separate mutable
-- coordination record, so the signed/broker-derived projection rows remain
-- append-only.

BEGIN;

CREATE TABLE projection_sync_states (
  tenant_id uuid NOT NULL,
  request_envelope_id uuid NOT NULL,
  frozen_gap boolean NOT NULL DEFAULT false,
  last_verified_sequence bigint NOT NULL DEFAULT -1 CHECK (last_verified_sequence >= -1),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, request_envelope_id),
  FOREIGN KEY (tenant_id, request_envelope_id)
    REFERENCES request_envelopes (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE projection_sync_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE projection_sync_states FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON projection_sync_states
  USING (tenant_id = rootpermit.current_tenant_id())
  WITH CHECK (tenant_id = rootpermit.current_tenant_id());

-- The root-created/broker-pinned credential binding has a separate opaque
-- public ID. Account sessions can route to it but cannot create a binding or
-- alter a device generation.
ALTER TABLE credential_bindings
  ADD COLUMN public_id text NOT NULL;
ALTER TABLE credential_bindings
  ADD CONSTRAINT credential_bindings_public_id_format
  CHECK (public_id ~ '^[A-Za-z0-9_-]{22}$');
CREATE UNIQUE INDEX credential_bindings_tenant_public_id_idx
  ON credential_bindings (tenant_id, public_id);

-- Resync requests coalesce per request while retaining tenant context. Other
-- outbox events may omit dedupe_key and preserve normal at-least-once rows.
ALTER TABLE outbox ADD COLUMN dedupe_key text;
CREATE UNIQUE INDEX outbox_tenant_relation_dedupe_idx
  ON outbox (tenant_id, relation_type, relation_id, dedupe_key)
  WHERE dedupe_key IS NOT NULL;

CREATE INDEX projection_sync_states_tenant_frozen_idx
  ON projection_sync_states (tenant_id, frozen_gap, updated_at);

-- Audit records are evidence, not an updateable application cache.
CREATE FUNCTION rootpermit.reject_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'audit_events are append-only' USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER audit_events_no_update_delete
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION rootpermit.reject_audit_event_mutation();

COMMIT;
