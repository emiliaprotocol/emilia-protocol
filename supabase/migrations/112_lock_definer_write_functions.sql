-- 112_lock_definer_write_functions.sql
--
-- Closes an RLS-bypass surface flagged by the Supabase security advisor.
--
-- EP's protocol write-path functions are SECURITY DEFINER, so they run as their
-- owner and bypass RLS. Postgres grants EXECUTE to PUBLIC by default, and the
-- Supabase bootstrap also grants anon/authenticated -- so anyone holding the
-- public anon key could call them directly via PostgREST RPC and forge handshake,
-- signoff, challenge, attestation, or receipt-anchor state, bypassing all
-- route-level authentication.
--
-- EP invokes every one of these server-side through the service-role client
-- (lib/supabase.js), so restricting EXECUTE to service_role changes no app
-- behavior. Revoke from PUBLIC/anon/authenticated across ALL overloads, then
-- (re)grant to service_role.
--
-- Scope is deliberately limited to EP's own functions. Other products co-resident
-- in this database (hc_*, rk_*, submit_claim, accept_invitation_once, verified-
-- number flows, trigger functions) are intentionally NOT touched here -- some are
-- legitimate anon RPC endpoints and must be reviewed by their owning apps.

DO $$
DECLARE
  fn regprocedure;
  target_names TEXT[] := ARRAY[
    'approve_attestation_atomic',
    'bulk_update_receipt_anchors',
    'consume_handshake_atomic',
    'consume_signoff_atomic',
    'create_handshake_atomic',
    'create_test_fixtures',
    'issue_challenge_atomic',
    'present_handshake_writes',
    'resolve_authenticated_actor',
    'verify_handshake_writes'
  ];
BEGIN
  FOR fn IN
    SELECT p.oid::regprocedure
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.prosecdef
      AND p.proname = ANY (target_names)
  LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, anon, authenticated;', fn);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role;', fn);
    RAISE NOTICE 'locked %', fn;
  END LOOP;
END $$;
