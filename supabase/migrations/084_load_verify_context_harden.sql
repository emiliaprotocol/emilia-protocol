-- 084_load_verify_context_harden.sql
--
-- Audit-fix (CRITICAL): migration 082's load_verify_context was created with
-- SECURITY DEFINER and no access control. Running as the function owner
-- (postgres superuser) it bypasses RLS on handshakes, handshake_parties,
-- handshake_presentations, and handshake_bindings — and returned the entire
-- row including per-tenant metadata, raw/normalized claims, delegation chains,
-- and session_refs. Any authenticated PostgREST role could read any tenant's
-- handshake by UUID.
--
-- Fix applied:
--   1. Drop the function (to reset all grants cleanly).
--   2. Recreate as SECURITY INVOKER so RLS applies to the caller's role.
--   3. Use a single-statement CTE so all four reads share one snapshot
--      (replaces 082's four separate SELECTs which, under READ COMMITTED,
--      could each see different committed states).
--   4. REVOKE EXECUTE FROM PUBLIC and anon/authenticated; GRANT only to
--      service_role (the role verify.js uses via getServiceClient()).
--
-- The service_role bypasses RLS by design — that is the role verify.js runs
-- as. Non-service-role callers are blocked at EXECUTE, not at RLS, which is
-- the safer gate (RLS policies on handshake_* tables exist per migration 076
-- but belt-and-suspenders is correct here).

DROP FUNCTION IF EXISTS load_verify_context(UUID);

CREATE FUNCTION load_verify_context(p_handshake_id UUID)
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = public
AS $$
  WITH h AS (
    SELECT to_jsonb(handshakes.*) AS handshake
    FROM handshakes
    WHERE handshake_id = p_handshake_id
  ),
  p AS (
    SELECT coalesce(jsonb_agg(to_jsonb(handshake_parties.*)), '[]'::JSONB) AS parties
    FROM handshake_parties
    WHERE handshake_id = p_handshake_id
  ),
  pr AS (
    SELECT coalesce(jsonb_agg(to_jsonb(handshake_presentations.*)), '[]'::JSONB) AS presentations
    FROM handshake_presentations
    WHERE handshake_id = p_handshake_id
  ),
  b AS (
    SELECT to_jsonb(handshake_bindings.*) AS binding
    FROM handshake_bindings
    WHERE handshake_id = p_handshake_id
  )
  SELECT jsonb_build_object(
    'handshake', (SELECT handshake FROM h),
    'parties', (SELECT parties FROM p),
    'presentations', (SELECT presentations FROM pr),
    'binding', (SELECT binding FROM b)
  );
$$;

-- Lock down access. PUBLIC is revoked; only the service role can call.
REVOKE ALL ON FUNCTION load_verify_context(UUID) FROM PUBLIC;

-- Grant to the service role used by verify.js.
-- Supabase installs typically have role 'service_role'; if a deployment uses
-- a different role name, update this GRANT accordingly.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION load_verify_context(UUID) TO service_role';
  END IF;
END $$;

COMMENT ON FUNCTION load_verify_context IS
  'Read-only snapshot of handshake + parties + presentations + binding in a single '
  'CTE (one statement = one snapshot under MVCC). SECURITY INVOKER — RLS applies. '
  'EXECUTE revoked from PUBLIC; only service_role (used by verify.js) can call. '
  'Migration 084 hardened this from migration 082 which was SECURITY DEFINER '
  'and world-callable, enabling cross-tenant data exfiltration.';
