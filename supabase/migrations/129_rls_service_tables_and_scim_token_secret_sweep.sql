-- 129_rls_service_tables_and_scim_token_secret_sweep.sql
--
-- DRIFT / DR SAFETY. This migration encodes two controls that currently exist
-- only OUT-OF-BAND in prod — enabled by hand during response, never journaled as
-- a migration. A fresh restore or a rebuild-from-repo would come up WITHOUT them,
-- reopening the exposure. This makes them reproducible from the repo.
--
-- Source: the same live secret/RLS sweep that produced 126/127/128 (2026-07-02)
-- and the 113/114 anon-grant incident review.
--
-- PART 1 — service_role-only RLS on four security tables created without it.
-- Migrations 103 (saml_consumed_assertions), 104 (revoked_commit_keys) and
-- 105 (revoked_sessions, session_cutoffs) created these tables but never ran
-- ENABLE ROW LEVEL SECURITY or a policy. With Supabase's default anon/
-- authenticated table GRANTs that leaves them world-readable/writable via
-- PostgREST — the exact class of bug fixed in 113/114. These are replay/
-- revocation control tables: anon write is a security-bypass vector (forge a
-- session cutoff, un-revoke a jti, poison the SAML replay cache, plant a
-- revoked commit kid). They are reached exclusively via the service-role client
-- (getGuardedClient / lib/supabase.js), which bypasses RLS, so app behavior is
-- unchanged. Pattern mirrors 114 exactly: ENABLE RLS + a service_role ALL policy
-- created idempotently (DROP POLICY IF EXISTS then CREATE POLICY).
--
-- PART 2 — extend the 127 secret-column sweep to the missed column.
-- scim_provisioning_tokens.token_hash (095) is a bearer-token sha256 — the same
-- key_hash/secret class 127 revoked on api_keys/tenant_api_keys/sso_connections/
-- webhook_endpoints — but was missed by that sweep. 095 enabled RLS on the table
-- but left the Supabase-bootstrap column/table GRANTs, so anon/authenticated
-- still hold SELECT/INSERT/UPDATE on the hash column and table-level write. It is
-- read/written exclusively via service_role (SCIM IdP auth). We close both the
-- column read/write (127-style) and the table-level write (128-style) grants.
-- service_role and postgres retain their grants, so the SCIM auth path is
-- unaffected.
--
-- Idempotent: ENABLE RLS is safe to re-run; policy create guards on DROP IF
-- EXISTS; REVOKE on an already-revoked privilege is a no-op.

-- ── PART 1: service_role-only RLS ────────────────────────────────────────────

-- saml_consumed_assertions (from 103)
ALTER TABLE saml_consumed_assertions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON saml_consumed_assertions;
CREATE POLICY "service_role_all" ON saml_consumed_assertions
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- revoked_commit_keys (from 104)
ALTER TABLE revoked_commit_keys ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON revoked_commit_keys;
CREATE POLICY "service_role_all" ON revoked_commit_keys
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- revoked_sessions (from 105)
ALTER TABLE revoked_sessions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON revoked_sessions;
CREATE POLICY "service_role_all" ON revoked_sessions
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- session_cutoffs (from 105)
ALTER TABLE session_cutoffs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON session_cutoffs;
CREATE POLICY "service_role_all" ON session_cutoffs
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── PART 2: scim_provisioning_tokens secret sweep (127/128 continuation) ──────

-- column-level read/write on the secret column (127-style)
REVOKE SELECT, INSERT, UPDATE (token_hash)
  ON public.scim_provisioning_tokens FROM anon, authenticated;

-- table-level write (128-style)
REVOKE INSERT, UPDATE, DELETE ON public.scim_provisioning_tokens FROM anon, authenticated;
