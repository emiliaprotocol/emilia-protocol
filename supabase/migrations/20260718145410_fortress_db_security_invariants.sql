-- SPDX-License-Identifier: Apache-2.0
-- Migration version: 20260718145410
--
-- Fortress database security invariants.
--
-- This is intentionally limited to controls that are already the repository's
-- access model: service-role/server-only storage, no public table grants on
-- secret or replay-control tables, and metadata-only contract introspection.
-- It does not add a new product surface or make claims about key custody,
-- receipt transport, or cryptographic algorithms.

-- ── 1. Reassert RLS on service-only/replay-control tables ────────────────────

ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sso_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scim_provisioning_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scim_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scim_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.saml_consumed_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.revoked_commit_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.revoked_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.session_cutoffs ENABLE ROW LEVEL SECURITY;

-- These tables already have service_role-only policies in the repository's
-- policy bundle, but their original creation path did not always record the
-- RLS enablement. Reasserting it makes the migration/source reconciliation
-- explicit and idempotent.
ALTER TABLE public.disputes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.handshakes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.signoff_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.signoff_attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;

-- The API-key policy was historically created without an explicit TO clause.
-- Recreate it with the intended role scope so the source migration set and the
-- live policy catalog agree even if migration 113 was only partially replayed.
DROP POLICY IF EXISTS "API keys via service role only" ON public.api_keys;
CREATE POLICY "API keys via service role only" ON public.api_keys
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Reassert the migration-113 role narrowing directly. The historical repair
-- used a catalog-driven DO block; these explicit forms keep the final policy
-- state auditable from the migration source as well.
DROP POLICY IF EXISTS "waitlist_read" ON public.waitlist;
CREATE POLICY "waitlist_read" ON public.waitlist
  FOR SELECT TO service_role USING (true);

DROP POLICY IF EXISTS "Service role can insert entities" ON public.entities;
CREATE POLICY "Service role can insert entities" ON public.entities
  FOR INSERT TO service_role WITH CHECK (true);

DROP POLICY IF EXISTS "Service role can update entities" ON public.entities;
CREATE POLICY "Service role can update entities" ON public.entities
  FOR UPDATE TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Receipts can be inserted" ON public.receipts;
CREATE POLICY "Receipts can be inserted" ON public.receipts
  FOR INSERT TO service_role WITH CHECK (true);

DROP POLICY IF EXISTS "Score history can be inserted" ON public.score_history;
CREATE POLICY "Score history can be inserted" ON public.score_history
  FOR INSERT TO service_role WITH CHECK (true);

DROP POLICY IF EXISTS "Needs can be inserted" ON public.needs;
CREATE POLICY "Needs can be inserted" ON public.needs
  FOR INSERT TO service_role WITH CHECK (true);

DROP POLICY IF EXISTS "Needs can be updated" ON public.needs;
CREATE POLICY "Needs can be updated" ON public.needs
  FOR UPDATE TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anchor_batches_insert" ON public.anchor_batches;
CREATE POLICY "anchor_batches_insert" ON public.anchor_batches
  FOR INSERT TO service_role WITH CHECK (true);

-- 129 added these service-role policies after the tables had already existed.
-- Reassert them here so the security boundary has one current reconciliation
-- point as well as the historical repair migration.
DROP POLICY IF EXISTS "service_role_all" ON public.saml_consumed_assertions;
CREATE POLICY "service_role_all" ON public.saml_consumed_assertions
  FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "service_role_all" ON public.revoked_commit_keys;
CREATE POLICY "service_role_all" ON public.revoked_commit_keys
  FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "service_role_all" ON public.revoked_sessions;
CREATE POLICY "service_role_all" ON public.revoked_sessions
  FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "service_role_all" ON public.session_cutoffs;
CREATE POLICY "service_role_all" ON public.session_cutoffs
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── 2. Remove public table privileges from server-only tables ────────────────
--
-- service_role grants are intentionally preserved for the existing server-side
-- paths. Release Lock is RPC-only, so its direct service_role table grants stay
-- revoked. RLS remains defense in depth; ACLs close the separate Data API gate.

REVOKE ALL ON TABLE public.api_keys FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.tenant_api_keys FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.sso_connections FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.webhook_endpoints FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.scim_provisioning_tokens FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.scim_users FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.scim_groups FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.saml_consumed_assertions FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.revoked_commit_keys FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.revoked_sessions FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.session_cutoffs FROM PUBLIC, anon, authenticated;

-- Release Lock tables are reached through SECURITY DEFINER RPCs only. Keep
-- service_role from bypassing that write/read boundary with direct table SQL.
REVOKE ALL ON TABLE public.release_locks FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_versions FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_draw_actions FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_round_acceptances FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_contact_bindings FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_invitations FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_sessions FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_pairings FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_registration_challenges FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_credentials FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_action_challenges FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_decisions FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_decision_invalidations FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.release_lock_effects FROM PUBLIC, anon, authenticated, service_role;

-- ── 3. Revoke public column privileges on sealed/bearer material ─────────────

REVOKE SELECT, INSERT, UPDATE, REFERENCES (private_key_encrypted, api_key_hash)
  ON public.entities FROM PUBLIC, anon, authenticated;
REVOKE SELECT, INSERT, UPDATE, REFERENCES (key_hash)
  ON public.api_keys FROM PUBLIC, anon, authenticated;
REVOKE SELECT, INSERT, UPDATE, REFERENCES (key_hash)
  ON public.tenant_api_keys FROM PUBLIC, anon, authenticated;
REVOKE SELECT, INSERT, UPDATE, REFERENCES (oidc_client_secret)
  ON public.sso_connections FROM PUBLIC, anon, authenticated;
REVOKE SELECT, INSERT, UPDATE, REFERENCES (secret)
  ON public.webhook_endpoints FROM PUBLIC, anon, authenticated;
REVOKE SELECT, INSERT, UPDATE, REFERENCES (token_hash)
  ON public.scim_provisioning_tokens FROM PUBLIC, anon, authenticated;

-- ── 4. Metadata-only live contract snapshot with grant coverage ─────────────
--
-- The function exposes catalog metadata only. It never selects application
-- rows. Normalized ACL rows let the schema gate detect a Supabase/bootstrap
-- grant reappearing after reset, which RLS/policy checks alone cannot prove.

CREATE OR REPLACE FUNCTION public.gov_schema_contract_introspect()
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'public'
AS $$
  SELECT jsonb_build_object(
    'tables', (
      SELECT coalesce(jsonb_agg(t.table_name ORDER BY t.table_name), '[]'::jsonb)
      FROM information_schema.tables t
      WHERE t.table_schema = 'public' AND t.table_type = 'BASE TABLE'
    ),
    'columns', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        't', table_name, 'c', column_name, 'type', data_type, 'nullable', is_nullable
      ) ORDER BY table_name, column_name), '[]'::jsonb)
      FROM information_schema.columns WHERE table_schema = 'public'
    ),
    'rls', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        't', c.relname,
        'enabled', c.relrowsecurity,
        'forced', c.relforcerowsecurity
      ) ORDER BY c.relname), '[]'::jsonb)
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r'
    ),
    'policies', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        't', c.relname,
        'name', p.polname,
        'cmd', CASE p.polcmd WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT' WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE' WHEN '*' THEN 'ALL' END,
        'roles', (SELECT coalesce(jsonb_agg(
                    CASE WHEN ro.oid = 0 THEN 'PUBLIC' ELSE r.rolname END
                  ), '["PUBLIC"]'::jsonb)
                  FROM unnest(p.polroles) ro(oid) LEFT JOIN pg_roles r ON r.oid = ro.oid),
        'using', pg_get_expr(p.polqual, p.polrelid),
        'check', pg_get_expr(p.polwithcheck, p.polrelid)
      )), '[]'::jsonb)
      FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public'
    ),
    'functions', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        'name', p.proname,
        'args', pg_get_function_identity_arguments(p.oid),
        'secdef', p.prosecdef,
        'acl', coalesce(p.proacl::text, '')
      )), '[]'::jsonb)
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'
    ),
    'indexes', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        't', tablename, 'name', indexname
      ) ORDER BY indexname), '[]'::jsonb)
      FROM pg_indexes WHERE schemaname = 'public'
    ),
    'table_grants', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        't', c.relname,
        'grantee', CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE r.rolname END,
        'privilege', x.privilege_type,
        'grantable', x.is_grantable
      ) ORDER BY c.relname, x.privilege_type, x.grantee), '[]'::jsonb)
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) x
      LEFT JOIN pg_roles r ON r.oid = x.grantee
      WHERE n.nspname = 'public' AND c.relkind = 'r'
    ),
    'column_grants', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        't', c.relname,
        'c', a.attname,
        'grantee', CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE r.rolname END,
        'privilege', x.privilege_type,
        'grantable', x.is_grantable
      ) ORDER BY c.relname, a.attname, x.privilege_type, x.grantee), '[]'::jsonb)
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL aclexplode(a.attacl) x
      LEFT JOIN pg_roles r ON r.oid = x.grantee
      WHERE n.nspname = 'public'
        AND c.relkind = 'r'
        AND a.attnum > 0
        AND a.attacl IS NOT NULL
        AND NOT a.attisdropped
    )
  );
$$;

REVOKE EXECUTE ON FUNCTION public.gov_schema_contract_introspect()
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.gov_schema_contract_introspect()
  TO service_role, schema_gate;
