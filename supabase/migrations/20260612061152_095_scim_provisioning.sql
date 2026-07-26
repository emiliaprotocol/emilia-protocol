-- 095_scim_provisioning.sql
-- SCIM 2.0 (RFC 7643 / RFC 7644) provisioning surface. Service-role-only tables.

CREATE TABLE IF NOT EXISTS scim_provisioning_tokens (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     TEXT NOT NULL,
  token_hash    TEXT NOT NULL UNIQUE,
  token_prefix  TEXT NOT NULL,
  label         TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at  TIMESTAMPTZ,
  revoked_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_scim_tokens_hash
  ON scim_provisioning_tokens (token_hash) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS scim_users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     TEXT NOT NULL,
  external_id   TEXT,
  user_name     TEXT NOT NULL,
  active        BOOLEAN NOT NULL DEFAULT true,
  formatted_name TEXT,
  given_name    TEXT,
  family_name   TEXT,
  display_name  TEXT,
  emails        JSONB NOT NULL DEFAULT '[]'::jsonb,
  phone_numbers JSONB NOT NULL DEFAULT '[]'::jsonb,
  title         TEXT,
  raw           JSONB NOT NULL DEFAULT '{}'::jsonb,
  version       INTEGER NOT NULL DEFAULT 1,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, user_name)
);
CREATE INDEX IF NOT EXISTS idx_scim_users_tenant ON scim_users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scim_users_external ON scim_users (tenant_id, external_id);

CREATE TABLE IF NOT EXISTS scim_groups (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    TEXT NOT NULL,
  external_id  TEXT,
  display_name TEXT NOT NULL,
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

ALTER TABLE scim_provisioning_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_users  ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_groups ENABLE ROW LEVEL SECURITY;;
