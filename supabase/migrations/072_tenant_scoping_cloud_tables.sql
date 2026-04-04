-- EP Cloud — Tenant isolation for cloud-facing tables
--
-- Problem: signoff_challenges and signoff_attestations have no tenant_id.
-- Cloud routes that query these tables expose data cross-tenant.
-- Similarly, handshake_policies is shared (protocol-level) but cloud routes
-- must scope policy operations to the requesting tenant's domain.
--
-- Fix: Add nullable tenant_id columns to cloud-facing tables. Existing rows
-- get NULL (pre-tenant data). New rows created through cloud routes will carry
-- the authenticated tenant's ID. Cloud route queries filter by tenant_id.

-- 1. signoff_challenges
ALTER TABLE signoff_challenges
  ADD COLUMN IF NOT EXISTS tenant_id UUID;

CREATE INDEX IF NOT EXISTS idx_signoff_challenges_tenant
  ON signoff_challenges(tenant_id) WHERE tenant_id IS NOT NULL;

-- 2. signoff_attestations
ALTER TABLE signoff_attestations
  ADD COLUMN IF NOT EXISTS tenant_id UUID;

CREATE INDEX IF NOT EXISTS idx_signoff_attestations_tenant
  ON signoff_attestations(tenant_id) WHERE tenant_id IS NOT NULL;

-- 3. handshake_policies (allows per-tenant policies in multi-tenant deployments)
ALTER TABLE handshake_policies
  ADD COLUMN IF NOT EXISTS tenant_id UUID;

CREATE INDEX IF NOT EXISTS idx_handshake_policies_tenant
  ON handshake_policies(tenant_id) WHERE tenant_id IS NOT NULL;

-- 4. policy_versions (scoped to the tenant that owns the policy)
-- Check if policy_versions has tenant_id already
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'policy_versions' AND column_name = 'tenant_id'
  ) THEN
    ALTER TABLE policy_versions ADD COLUMN tenant_id UUID;
    CREATE INDEX idx_policy_versions_tenant ON policy_versions(tenant_id) WHERE tenant_id IS NOT NULL;
  END IF;
END $$;
