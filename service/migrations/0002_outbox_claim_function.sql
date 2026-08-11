-- The worker is the only hosted component that needs to discover work across
-- tenants. This narrow definer function is its sole cross-tenant entry point;
-- all subsequent reads/writes run with app.tenant_id set by the worker.

BEGIN;

ALTER TABLE public.outbox
  ADD COLUMN leased_until timestamptz,
  ADD COLUMN lease_generation bigint NOT NULL DEFAULT 0 CHECK (lease_generation >= 0);

CREATE INDEX outbox_claim_due_idx
  ON public.outbox (visible_after, leased_until, created_at);

-- A worker retry changes visible_after. Release the lease at that point so the
-- requested retry delay, rather than the old lease duration, controls pickup.
CREATE FUNCTION rootpermit.release_outbox_lease_on_reschedule()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, rootpermit
AS $$
BEGIN
  IF NEW.visible_after IS DISTINCT FROM OLD.visible_after
     AND NEW.leased_until IS NOT DISTINCT FROM OLD.leased_until THEN
    NEW.leased_until := NULL;
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER outbox_release_lease_on_reschedule
BEFORE UPDATE OF visible_after ON public.outbox
FOR EACH ROW
EXECUTE FUNCTION rootpermit.release_outbox_lease_on_reschedule();

CREATE FUNCTION rootpermit.claim_outbox(p_limit integer)
RETURNS TABLE (
  id uuid,
  tenant_id uuid,
  relation_type text,
  relation_id uuid,
  event_type text,
  payload_digest bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, rootpermit
AS $$
BEGIN
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
    RAISE EXCEPTION 'outbox claim limit must be between 1 and 100'
      USING ERRCODE = '22023';
  END IF;

  -- `public.outbox` is fully qualified: an attacker-controlled schema can
  -- never shadow the table while this SECURITY DEFINER function is executing.
  RETURN QUERY
  WITH candidates AS MATERIALIZED (
    SELECT outbox.id
      FROM public.outbox AS outbox
     WHERE outbox.visible_after <= clock_timestamp()
       AND (outbox.leased_until IS NULL OR outbox.leased_until <= clock_timestamp())
     ORDER BY outbox.visible_after, outbox.created_at, outbox.id
     LIMIT p_limit
     FOR UPDATE SKIP LOCKED
  ), claimed AS (
    UPDATE public.outbox AS outbox
       SET leased_until = clock_timestamp() + interval '5 minutes',
           lease_generation = outbox.lease_generation + 1
      FROM candidates
     WHERE outbox.id = candidates.id
     RETURNING outbox.id,
               outbox.tenant_id,
               outbox.relation_type,
               outbox.relation_id,
               outbox.event_type,
               outbox.payload_digest,
               outbox.visible_after,
               outbox.created_at
  )
  SELECT claimed.id,
         claimed.tenant_id,
         claimed.relation_type,
         claimed.relation_id,
         claimed.event_type,
         claimed.payload_digest
    FROM claimed
   ORDER BY claimed.visible_after, claimed.created_at, claimed.id;
END
$$;

-- Public and API roles do not gain table access through this function. The
-- production provisioning path must make the function owner a dedicated,
-- non-login role with only the privilege needed to bypass RLS for this one
-- audited relation. The function itself has no tenant argument or dynamic SQL.
REVOKE ALL ON FUNCTION rootpermit.claim_outbox(integer) FROM PUBLIC;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rp_worker') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION rootpermit.claim_outbox(integer) TO rp_worker';
  END IF;
END
$$;

COMMIT;
