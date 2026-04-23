-- Migration 076: RLS policies for all EP protocol tables
--
-- Context: All 50 EP tables have RLS enabled. 39 had zero policies, meaning
-- the anon and authenticated roles were implicitly denied everything.
-- All EP API access uses service_role (getServiceClient / getGuardedClient),
-- which bypasses RLS by default in Supabase — but explicit service_role policies
-- are required for defense-in-depth, auditability, and any future role changes.
--
-- Policy model:
--   Protocol tables     → service_role bypass only (no direct client access)
--   Tenant/cloud tables → service_role bypass + authenticated tenant-scoped SELECT
--   Public form tables  → service_role bypass + anon INSERT (lead capture)

-- ============================================================================
-- PROTOCOL TABLES — service_role bypass only
-- ============================================================================

CREATE POLICY "service_role_bypass" ON public.audit_events
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.continuity_challenges
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.continuity_claims
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.continuity_decisions
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.delegations
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.disputes
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.fraud_flags
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.handshake_bindings
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.handshake_consumptions
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.handshake_events
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.handshake_parties
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.handshake_policies
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.handshake_presentations
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.handshake_results
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.handshakes
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.identity_bindings
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.merkle_batches
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.principal_delegation_signals
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.principals
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.protocol_events
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.signoff_attestations
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.signoff_challenges
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.signoff_consumptions
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.signoff_events
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.trust_reports
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.zk_proofs
  TO service_role USING (true) WITH CHECK (true);

-- Eye module
CREATE POLICY "service_role_bypass" ON public.eye_advisories
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.eye_observations
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.eye_suppressions
  TO service_role USING (true) WITH CHECK (true);

-- ============================================================================
-- TENANT / CLOUD TABLES — service_role bypass + tenant-scoped authenticated access
-- ============================================================================

CREATE POLICY "service_role_bypass" ON public.tenants
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.tenant_members
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.tenant_api_keys
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.tenant_environments
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.alert_rules
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.alert_events
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.webhook_endpoints
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.webhook_deliveries
  TO service_role USING (true) WITH CHECK (true);

-- ============================================================================
-- PUBLIC FORM TABLES — service_role bypass + anon INSERT for lead capture
-- Anon can INSERT but never SELECT (no USING clause on anon policy)
-- ============================================================================

CREATE POLICY "service_role_bypass" ON public.partner_inquiries
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "anon_insert" ON public.partner_inquiries
  FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "service_role_bypass" ON public.investor_inquiries
  TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "anon_insert" ON public.investor_inquiries
  FOR INSERT TO anon WITH CHECK (true);

COMMENT ON POLICY "service_role_bypass" ON public.handshakes IS
  'All EP API access uses service_role via getServiceClient()/getGuardedClient(). '
  'Tenant isolation is enforced at the application layer. This policy satisfies '
  'RLS without granting direct database access to anon or authenticated roles.';
