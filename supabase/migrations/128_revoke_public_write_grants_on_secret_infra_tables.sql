-- 128_revoke_public_write_grants_on_secret_infra_tables.sql
--
-- Revoke TABLE-level write grants from anon/authenticated on service_role-only
-- secret-bearing infra tables.
--
-- Migration 127 revoked the COLUMN-level SELECT/INSERT/UPDATE on secret columns,
-- which closed the disclosure (read) vector. But these tables' write grants are
-- TABLE-level (a Supabase bootstrap default: GRANT ALL ON <table> TO anon,
-- authenticated), so a column-level REVOKE UPDATE left an inherited table-level
-- UPDATE. A live check (2026-07-02) confirmed anon still held table UPDATE on all
-- four.
--
-- All four are written exclusively via service_role (auth RPC; cloud tenant auth
-- via getGuardedClient; SSO connection management; webhook delivery). No
-- anon/authenticated write path exists. Notably webhook_endpoints and
-- sso_connections are NOT in the noAnonWrite RLS contract, so a table-level anon
-- write grant on a webhook URL/secret (SSRF / secret swap) or an OIDC client
-- secret is a genuine integrity vector — not just least-privilege hygiene.
--
-- service_role and postgres retain all privileges; the app paths are unaffected.
-- entities is intentionally handled at the column level (mig 126/127) — its
-- writes are RLS-asserted (noAnonWrite) and it is far more central, so a
-- table-level revoke there is deliberately out of scope here.
--
-- Idempotent: REVOKE on an already-revoked privilege is a no-op.

REVOKE INSERT, UPDATE, DELETE ON public.api_keys        FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.tenant_api_keys FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.sso_connections FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.webhook_endpoints FROM anon, authenticated;
