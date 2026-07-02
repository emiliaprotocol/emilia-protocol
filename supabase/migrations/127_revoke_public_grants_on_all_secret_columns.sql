-- 127_revoke_public_grants_on_all_secret_columns.sql
--
-- Operational-boundary hardening — least privilege on ALL secret-bearing columns.
--
-- Migration 126 revoked public-role grants on entities.{private_key_encrypted,
-- api_key_hash}. A full live sweep (2026-07-02) for secret-bearing columns
-- (private_key|api_key_hash|secret|encrypted|seed|password|signing_key|key_hash)
-- found the same Supabase-bootstrap column grants on ADJACENT tables — anon +
-- authenticated still held SELECT/INSERT/UPDATE on:
--   - api_keys.key_hash                 (the API-key hash — read must be service_role only)
--   - tenant_api_keys.key_hash          (tenant API-key hash)
--   - sso_connections.oidc_client_secret(OIDC client secret)
--   - webhook_endpoints.secret          (webhook HMAC signing secret)
--
-- All four are read/written exclusively via service_role (auth RPC, cloud tenant
-- auth, SSO connection management, webhook delivery). RLS gates rows on several
-- of these already, but a column GRANT is an independent second gate; revoking it
-- closes the exposure even under RLS-policy drift and blocks any future SELECT *
-- on a public-role connection. service_role and postgres retain their grants, so
-- the signing/auth paths are unaffected.
--
-- Idempotent: REVOKE on an already-revoked privilege is a no-op. entities is
-- re-asserted here so the whole secret-column contract lives in one place.

-- entities (re-assert; 126 already applied these)
REVOKE SELECT, INSERT, UPDATE (private_key_encrypted, api_key_hash)
  ON public.entities FROM anon, authenticated;

-- api_keys
REVOKE SELECT, INSERT, UPDATE (key_hash)
  ON public.api_keys FROM anon, authenticated;

-- tenant_api_keys
REVOKE SELECT, INSERT, UPDATE (key_hash)
  ON public.tenant_api_keys FROM anon, authenticated;

-- sso_connections
REVOKE SELECT, INSERT, UPDATE (oidc_client_secret)
  ON public.sso_connections FROM anon, authenticated;

-- webhook_endpoints
REVOKE SELECT, INSERT, UPDATE (secret)
  ON public.webhook_endpoints FROM anon, authenticated;
