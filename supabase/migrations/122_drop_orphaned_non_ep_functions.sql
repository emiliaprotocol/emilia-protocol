-- 122_drop_orphaned_non_ep_functions.sql
--
-- DB isolation cleanup. EP runs on its own dedicated Supabase project and shares
-- NO tables with other products (verified: zero non-EP base tables present).
-- The only co-mingling was ~22 orphaned functions from other products
-- (hc_* = redflag, rk_* = rekkn, plus claim/merchant/verified-number helpers)
-- that were created here from copied migrations. They reference tables that do
-- NOT exist in this project, so they are already non-functional dead code — and
-- they were the bulk of the anon-executable SECURITY DEFINER advisory findings.
--
-- Safe to drop: no EP code calls hc_/rk_/claim functions (EP calls only EP RPCs);
-- no triggers on EP tables reference them; other products have their own project
-- copies and are unaffected. Dropped without CASCADE (fail-safe). See
-- docs/DB-ISOLATION-PLAN.md.

DO $$
DECLARE fn regprocedure; n int := 0;
BEGIN
  FOR fn IN
    SELECT p.oid::regprocedure
    FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
    WHERE ns.nspname = 'public'
      AND (p.proname ~* '^(hc_|rk_)'
           OR p.proname ~* '(submit_claim|submit_resolution|confirm_resolution|merchant_trust|verified_number|reserve_next_number|has_paid_verification|promote_provisional|accept_invitation)')
  LOOP
    EXECUTE format('DROP FUNCTION IF EXISTS %s;', fn);
    n := n + 1;
  END LOOP;
  RAISE NOTICE 'dropped % orphaned non-EP functions', n;
END $$;
