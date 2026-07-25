-- 095_scim_provisioning.sql
--
-- SCIM 2.0 (RFC 7643 / RFC 7644) provisioning surface.
--
-- Enterprise and government buyers provision the *named humans* who can sign off
-- (and deprovision them on offboarding) through their IdP — Okta, Azure AD,
-- Ping, etc. — over SCIM, not by hand. This is the storage for that:
--
--   scim_provisioning_tokens — the long-lived bearer token the IdP uses to
--     authenticate to EP's SCIM endpoints, scoped to one tenant.
--   scim_users  — provisioned humans (the SCIM User resource).
--   scim_groups — provisioned groups / authority classes (the SCIM Group).
--
-- SCIM `id` is EP's resource id (uuid). `external_id` is the IdP's own id for
-- the resource. Everything is scoped by tenant_id so one customer's directory
-- never sees another's.

-- ── Provisioning tokens ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scim_provisioning_tokens (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     TEXT NOT NULL,
  token_hash    TEXT NOT NULL UNIQUE,        -- sha256(token), never the token itself
  token_prefix  TEXT NOT NULL,               -- first chars, for display/audit
  label         TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at  TIMESTAMPTZ,
  revoked_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_scim_tokens_hash
  ON scim_provisioning_tokens (token_hash) WHERE revoked_at IS NULL;

-- ── Users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scim_users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     TEXT NOT NULL,
  external_id   TEXT,                         -- the IdP's id
  user_name     TEXT NOT NULL,                -- SCIM userName (login, often email/UPN)
  active        BOOLEAN NOT NULL DEFAULT true, -- deprovision flips this to false
  formatted_name TEXT,
  given_name    TEXT,
  family_name   TEXT,
  display_name  TEXT,
  emails        JSONB NOT NULL DEFAULT '[]'::jsonb,
  phone_numbers JSONB NOT NULL DEFAULT '[]'::jsonb,
  title         TEXT,
  -- Full original resource as sent by the IdP, so attributes EP does not model
  -- explicitly are preserved on round-trip (SCIM compliance).
  raw           JSONB NOT NULL DEFAULT '{}'::jsonb,
  version       INTEGER NOT NULL DEFAULT 1,   -- bumped on every write → ETag
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, user_name)
);
CREATE INDEX IF NOT EXISTS idx_scim_users_tenant ON scim_users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scim_users_external ON scim_users (tenant_id, external_id);

-- ── Groups ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scim_groups (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    TEXT NOT NULL,
  external_id  TEXT,
  display_name TEXT NOT NULL,
  -- [{ value: <user id>, display: <user_name> }, ...]
  members      JSONB NOT NULL DEFAULT '[]'::jsonb,
  version      INTEGER NOT NULL DEFAULT 1,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, display_name)
);
CREATE INDEX IF NOT EXISTS idx_scim_groups_tenant ON scim_groups (tenant_id);

COMMENT ON TABLE scim_users IS
  'SCIM 2.0 (RFC 7643) User resources — the named humans an IdP provisions for signoff. active=false is a deprovision.';
COMMENT ON TABLE scim_provisioning_tokens IS
  'Bearer tokens an IdP uses to authenticate to EP SCIM endpoints, scoped per tenant. Stored as sha256 hashes.';

-- Service-role-only tables (token hashes + directory PII): enable RLS with no
-- policy so anon/authenticated are denied by default. The SCIM routes reach
-- these exclusively via getGuardedClient() (service role), which bypasses RLS.
ALTER TABLE scim_provisioning_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_users  ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_groups ENABLE ROW LEVEL SECURITY;
