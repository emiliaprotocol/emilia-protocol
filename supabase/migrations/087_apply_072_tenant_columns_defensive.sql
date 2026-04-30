-- Migration 087: Defensive replay of 072 (tenant scoping for cloud tables)
--
-- Migration 072 failed to apply on prod because step 4 references the
-- `policy_versions` table, which doesn't exist on prod (and isn't created by
-- any migration in this repo — likely was created via Studio SQL editor in
-- a now-removed migration). The DO block in 072 checks for the *column*
-- but not the table, so when the table is absent the inner ALTER errors.
--
-- This migration replays the safe portions of 072 (signoff_challenges,
-- signoff_attestations, handshake_policies — all already use IF NOT EXISTS)
-- and adds a `to_regclass()` guard around the policy_versions branch so it
-- becomes a no-op when the table is absent.
--
-- This is idempotent: re-running has no effect if the columns/indexes
-- already exist.

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

-- 4. policy_versions (only if the table exists). If a future migration
-- introduces the table, re-applying this is harmless (column will already
-- have been created at that point or we'll add it here).
DO $$
BEGIN
  IF to_regclass('public.policy_versions') IS NOT NULL THEN
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_name = 'policy_versions' AND column_name = 'tenant_id'
    ) THEN
      ALTER TABLE policy_versions ADD COLUMN tenant_id UUID;
      CREATE INDEX IF NOT EXISTS idx_policy_versions_tenant
        ON policy_versions(tenant_id) WHERE tenant_id IS NOT NULL;
    END IF;
  END IF;
END $$;
