-- Migration 077: Harden search_path for all SECURITY DEFINER functions
--
-- Functions with mutable search_path are vulnerable to search_path injection:
-- a malicious schema earlier in the path could shadow pg_catalog or public
-- functions and intercept calls. Setting search_path = public pins all
-- unqualified name resolution to the public schema.
--
-- This DO block dynamically finds all SECURITY DEFINER functions in the
-- public schema that lack an explicit search_path setting and fixes them
-- in a single pass. This handles all overloads automatically.
--
-- Affected at time of authoring (27 functions / 31 overloads):
--   accept_invitation_once, approve_attestation_atomic, assign_verified_number,
--   complete_verified_activation (×2), confirm_resolution, consume_signoff_atomic,
--   create_handshake_atomic (×3), create_profile_on_user_insert,
--   create_test_fixtures, has_paid_verification, hc_accept_invitation,
--   hc_ensure_notification_prefs, hc_log_audit, hc_mark_notifications_read,
--   hc_merchant_trust_history, issue_challenge_atomic, present_handshake_writes,
--   promote_provisional_claims, reserve_next_number, resolve_authenticated_actor,
--   rk_create_notification, rk_open_moderation_case, submit_claim,
--   submit_resolution, verify_handshake_writes

DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT p.proname,
           pg_get_function_identity_arguments(p.oid) AS args
    FROM   pg_proc p
    JOIN   pg_namespace n ON n.oid = p.pronamespace
    WHERE  n.nspname = 'public'
      AND  p.prosecdef = true
      AND  NOT EXISTS (
             SELECT 1
             FROM   unnest(p.proconfig) cfg
             WHERE  cfg LIKE 'search_path=%'
           )
  LOOP
    EXECUTE format(
      'ALTER FUNCTION public.%I(%s) SET search_path = public',
      r.proname,
      r.args
    );
  END LOOP;
END $$;
