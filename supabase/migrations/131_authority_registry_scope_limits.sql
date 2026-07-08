-- 131_authority_registry_scope_limits.sql
--
-- EP-AUTHORITY-REGISTRY-v1. Extend the authorities registry (033/102/118) from
-- "this subject is authorized, in this role, at this assurance class" into
-- SCOPED authority: which actions, up to what amount, in what currency, under
-- which policy, delegated from whom. This is what turns "a named human
-- approved" into "the right human had authority for THIS exact action."
--
-- All new columns are NULLABLE so existing rows are unaffected. The resolver
-- (lib/authority/resolver.js) treats a NULL scope as "unscoped" and a NULL
-- ceiling as "unbounded"; the staged-enforcement layer decides whether an
-- unscoped/unbounded grant may stand for a critical action. Nothing here
-- changes behavior until EP_AUTHORITY_ENFORCEMENT is advanced past 'shadow'.
--
-- Fail-closed rollout: the live store (lib/authority/store.js) requires the
-- per-org registry epoch row below. Until this migration is applied, the epoch
-- lookup errors and the resolver returns `registry_unavailable` (which blocks
-- nothing in the default 'shadow' mode). Applying this migration is what makes
-- the registry resolvable; advancing EP_AUTHORITY_ENFORCEMENT is what makes it
-- enforced.

-- ── 1. Scope / limits / delegation / policy binding ─────────────────────────
ALTER TABLE authorities
  ADD COLUMN IF NOT EXISTS action_scopes     TEXT[],           -- action_type values this grant covers; NULL = unscoped
  ADD COLUMN IF NOT EXISTS max_amount_usd     NUMERIC,          -- amount ceiling in `currency`; NULL = unbounded
  ADD COLUMN IF NOT EXISTS currency           TEXT DEFAULT 'USD',
  ADD COLUMN IF NOT EXISTS delegation_parent  TEXT,             -- authority_id of the grant this one narrows; NULL = root
  ADD COLUMN IF NOT EXISTS policy_hash        TEXT;             -- when set, the action's policy_hash must match

COMMENT ON COLUMN authorities.action_scopes IS
  'EP-AUTHORITY-REGISTRY-v1: action_type values this authority may approve. NULL = unscoped (enforcement decides if that stands for a critical action).';
COMMENT ON COLUMN authorities.max_amount_usd IS
  'EP-AUTHORITY-REGISTRY-v1: amount ceiling, denominated in `currency`. NULL = unbounded. Amounts in a different currency fail closed (no FX oracle).';
COMMENT ON COLUMN authorities.delegation_parent IS
  'EP-AUTHORITY-REGISTRY-v1: authority_id this grant is delegated from. A child may only narrow scope/ceiling; widening is delegation_broken.';
COMMENT ON COLUMN authorities.policy_hash IS
  'EP-AUTHORITY-REGISTRY-v1: when set, pins the grant to a specific policy; a mismatching action policy_hash is policy_mismatch.';

CREATE INDEX IF NOT EXISTS idx_authorities_delegation_parent ON authorities (delegation_parent);

-- ── 2. Per-org registry epoch (monotonic version of the org's authority set) ─
-- The receipt binds this epoch + a head computed in JS over the org's rows.
-- A relying party can pin "epoch >= N" to refuse a stale registry. The epoch is
-- a trivial monotonic counter here; the cryptographic head is computed in the
-- application layer (lib/authority/registry-head.js) so canonicalization stays
-- byte-identical to the verifier and the vectors.
CREATE TABLE IF NOT EXISTS authority_registry_epoch (
  organization_id TEXT PRIMARY KEY,
  epoch           BIGINT NOT NULL DEFAULT 1,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE authority_registry_epoch ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON authority_registry_epoch;
CREATE POLICY "service_role_all" ON authority_registry_epoch
  FOR ALL TO service_role USING (true) WITH CHECK (true);

COMMENT ON TABLE authority_registry_epoch IS
  'EP-AUTHORITY-REGISTRY-v1: monotonic per-org version counter bumped on any authorities change. Bound into receipts as authority_registry_epoch for staleness pinning.';

-- ── 3. Bump the epoch on any authorities change ─────────────────────────────
CREATE OR REPLACE FUNCTION bump_authority_registry_epoch()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_org TEXT := COALESCE(NEW.organization_id, OLD.organization_id);
BEGIN
  IF v_org IS NULL THEN
    RETURN COALESCE(NEW, OLD);
  END IF;
  INSERT INTO authority_registry_epoch (organization_id, epoch, updated_at)
  VALUES (v_org, 1, now())
  ON CONFLICT (organization_id)
  DO UPDATE SET epoch = authority_registry_epoch.epoch + 1, updated_at = now();
  RETURN COALESCE(NEW, OLD);
END;
$$;

DROP TRIGGER IF EXISTS trg_bump_authority_registry_epoch ON authorities;
CREATE TRIGGER trg_bump_authority_registry_epoch
  AFTER INSERT OR UPDATE OR DELETE ON authorities
  FOR EACH ROW
  EXECUTE FUNCTION bump_authority_registry_epoch();

-- ── 4. Seed epoch rows for orgs that already have authorities ───────────────
-- Existing rows predate the trigger, so seed each org at epoch 1. New/changed
-- rows advance it from there.
INSERT INTO authority_registry_epoch (organization_id, epoch)
SELECT DISTINCT organization_id, 1
FROM authorities
WHERE organization_id IS NOT NULL
ON CONFLICT (organization_id) DO NOTHING;
