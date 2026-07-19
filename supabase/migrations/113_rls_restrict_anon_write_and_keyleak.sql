-- 113_rls_restrict_anon_write_and_keyleak.sql
--
-- INCIDENT FIX. Several RLS policies were named "service role only" / "service
-- role bypass" but were actually scoped to PUBLIC with USING(true). Because anon
-- holds the default table GRANTs, the public anon key could:
--   * SELECT every row of api_keys (164 key hashes/prefixes/entity links)
--   * SELECT the waitlist (emails/PII)
--   * INSERT/UPDATE entities, receipts, score_history, needs, anchor_batches
--     directly via PostgREST, bypassing all API-route auth.
--
-- Verified empirically: `set role anon; select count(*) from api_keys` returned
-- 164 rows before this migration.
--
-- Fix: re-scope these policies to the service_role role only. EP's server uses
-- the service-role client (lib/supabase.js), which bypasses RLS, so application
-- behavior is unchanged. Intentionally-public access is preserved untouched:
--   * entities SELECT (status='active'), receipts SELECT, score_history SELECT,
--     needs SELECT, anchor_batches SELECT  -> stay PUBLIC (EP is publicly verifiable)
--   * waitlist INSERT, investor_inquiries INSERT, partner_inquiries INSERT
--     -> stay public (signup / contact forms)

DO $$
DECLARE
  rec RECORD;
  fixes TEXT[][] := ARRAY[
    -- table,                policy name
    ARRAY['api_keys',        'API keys via service role only'],
    ARRAY['entities',        'Service role can insert entities'],
    ARRAY['entities',        'Service role can update entities'],
    ARRAY['receipts',        'Receipts can be inserted'],
    ARRAY['score_history',   'Score history can be inserted'],
    ARRAY['needs',           'Needs can be inserted'],
    ARRAY['needs',           'Needs can be updated'],
    ARRAY['anchor_batches',  'anchor_batches_insert'],
    ARRAY['waitlist',        'waitlist_read']
  ];
  f TEXT[];
BEGIN
  FOREACH f SLICE 1 IN ARRAY fixes LOOP
    IF EXISTS (
      SELECT 1 FROM pg_policy p
      JOIN pg_class c ON c.oid = p.polrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname='public' AND c.relname = f[1] AND p.polname = f[2]
    ) THEN
      EXECUTE format('ALTER POLICY %I ON public.%I TO service_role;', f[2], f[1]);
      RAISE NOTICE 'rescoped %.% -> service_role', f[1], f[2];
    ELSE
      RAISE NOTICE 'skip (absent): %.%', f[1], f[2];
    END IF;
  END LOOP;
END $$;
