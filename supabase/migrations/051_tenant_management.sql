-- ============================================================================
-- Tenant Management — Multi-tenant support for the cloud control plane
--
-- Provides organization-level isolation: tenants own environments, members,
-- and API keys. Each tenant maps to a billing plan and can be suspended or
-- archived without data loss.
-- ============================================================================

-- ============================================================================
-- 1. Tenants
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenants (
  tenant_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  slug        TEXT NOT NULL UNIQUE,
  status      TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'suspended', 'archived')),
  plan        TEXT NOT NULL DEFAULT 'free'
                CHECK (plan IN ('free', 'team', 'enterprise')),
  settings    JSONB DEFAULT '{}',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE tenants IS 'Top-level organizational unit for multi-tenant isolation. Each tenant owns environments, members, and API keys.';

-- ============================================================================
-- 2. Tenant Environments
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenant_environments (
  environment_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(tenant_id),
  name            TEXT NOT NULL DEFAULT 'production'
                    CHECK (name IN ('development', 'staging', 'production')),
  config          JSONB DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(tenant_id, name)
);

COMMENT ON TABLE tenant_environments IS 'Per-tenant deployment environments (dev/staging/production). Each tenant gets a default production environment on creation.';

CREATE INDEX idx_tenant_environments_tenant
  ON tenant_environments(tenant_id);

-- ============================================================================
-- 3. Tenant Members
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenant_members (
  member_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(tenant_id),
  user_ref     TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'member'
                 CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
  invited_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  accepted_at  TIMESTAMPTZ,
  UNIQUE(tenant_id, user_ref)
);

COMMENT ON TABLE tenant_members IS 'Membership roster for a tenant. user_ref is an opaque reference to an auth identity (e.g. Clerk user ID, email).';

CREATE INDEX idx_tenant_members_tenant
  ON tenant_members(tenant_id);

CREATE INDEX idx_tenant_members_user_ref
  ON tenant_members(user_ref);

-- ============================================================================
-- 4. Tenant API Keys
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenant_api_keys (
  key_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(tenant_id),
  environment  TEXT NOT NULL DEFAULT 'production',
  key_hash     TEXT NOT NULL,
  key_prefix   TEXT NOT NULL,
  name         TEXT NOT NULL,
  permissions  TEXT[] DEFAULT '{read,write}',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ,
  revoked_at   TIMESTAMPTZ
);

COMMENT ON TABLE tenant_api_keys IS 'Hashed API keys scoped to a tenant + environment. The full key is returned exactly once on creation; only the prefix is stored for display.';

CREATE INDEX idx_tenant_api_keys_tenant
  ON tenant_api_keys(tenant_id);

CREATE INDEX idx_tenant_api_keys_hash
  ON tenant_api_keys(key_hash);

-- ============================================================================
-- 5. Auto-update updated_at on tenants
-- ============================================================================

CREATE OR REPLACE FUNCTION update_tenant_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_tenant_updated_at
  BEFORE UPDATE ON tenants
  FOR EACH ROW EXECUTE FUNCTION update_tenant_updated_at();

-- ============================================================================
-- Summary
-- ============================================================================
-- Tables:
--   tenants              — organizational unit with plan and status
--   tenant_environments  — dev/staging/production per tenant
--   tenant_members       — membership with role-based access
--   tenant_api_keys      — hashed API keys scoped to tenant + environment
--
-- Indexes:
--   idx_tenant_environments_tenant  — lookup environments by tenant
--   idx_tenant_members_tenant       — lookup members by tenant
--   idx_tenant_members_user_ref     — lookup tenants by user
--   idx_tenant_api_keys_tenant      — lookup keys by tenant
--   idx_tenant_api_keys_hash        — resolve key from hash
--
-- Triggers:
--   set_tenant_updated_at           — auto-update updated_at on tenants
