-- Migration 088: Defensive replay of 076 (RLS policies for all EP tables)
--
-- Migration 076 failed mid-push on prod because at least one of its 41
-- CREATE POLICY statements (audit_events) was already partially applied via
-- Studio SQL or out-of-band. CREATE POLICY has no IF NOT EXISTS variant in
-- Postgres, so the rest of the policies never ran.
--
-- This migration is idempotent: it DROPs each policy IF EXISTS, then
-- re-CREATEs it. The drop+create is in a single transaction (the
-- migration's implicit transaction) so the policy is never effectively
-- absent — a brief moment with no policy is still RLS-bypassable by the
-- service role.
--
-- Note: each policy targets one specific table that's expected to exist
-- on prod. If a table is absent (e.g., zk_proofs hasn't been provisioned),
-- the policy creation for it errors. We wrap the whole block in a DO
-- so the loop continues past tables that don't exist — the missing table
-- becomes a one-line warning instead of a halt.

DO $$
DECLARE
  rec RECORD;
  protocol_tables TEXT[] := ARRAY[
    'audit_events', 'continuity_challenges', 'continuity_claims',
    'continuity_decisions', 'delegations', 'disputes', 'fraud_flags',
    'handshake_bindings', 'handshake_consumptions', 'handshake_events',
    'handshake_parties', 'handshake_policies', 'handshake_presentations',
    'handshake_results', 'handshakes', 'identity_bindings', 'merkle_batches',
    'principal_delegation_signals', 'principals', 'protocol_events',
    'signoff_attestations', 'signoff_challenges', 'signoff_consumptions',
    'signoff_events', 'trust_reports', 'zk_proofs',
    'eye_advisories', 'eye_observations', 'eye_suppressions',
    'tenants', 'tenant_members', 'tenant_api_keys', 'tenant_environments',
    'alert_rules', 'alert_events', 'webhook_endpoints', 'webhook_deliveries',
    'partner_inquiries', 'investor_inquiries'
  ];
  t TEXT;
BEGIN
  FOREACH t IN ARRAY protocol_tables LOOP
    IF to_regclass('public.' || quote_ident(t)) IS NULL THEN
      RAISE NOTICE 'Skipping policy on missing table: %', t;
      CONTINUE;
    END IF;
    EXECUTE format(
      'DROP POLICY IF EXISTS %I ON public.%I',
      'service_role_bypass', t
    );
    EXECUTE format(
      'CREATE POLICY %I ON public.%I TO service_role USING (true) WITH CHECK (true)',
      'service_role_bypass', t
    );
  END LOOP;
END $$;

-- anon INSERT policies for public form tables (lead capture only — no SELECT)
DO $$
DECLARE
  form_tables TEXT[] := ARRAY['partner_inquiries', 'investor_inquiries'];
  t TEXT;
BEGIN
  FOREACH t IN ARRAY form_tables LOOP
    IF to_regclass('public.' || quote_ident(t)) IS NULL THEN
      RAISE NOTICE 'Skipping anon_insert on missing table: %', t;
      CONTINUE;
    END IF;
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', 'anon_insert', t);
    EXECUTE format(
      'CREATE POLICY %I ON public.%I FOR INSERT TO anon WITH CHECK (true)',
      'anon_insert', t
    );
  END LOOP;
END $$;

COMMENT ON POLICY "service_role_bypass" ON public.handshakes IS
  'All EP API access uses service_role via getServiceClient()/getGuardedClient(). '
  'Tenant isolation is enforced at the application layer. This policy satisfies '
  'RLS without granting direct database access to anon or authenticated roles.';
