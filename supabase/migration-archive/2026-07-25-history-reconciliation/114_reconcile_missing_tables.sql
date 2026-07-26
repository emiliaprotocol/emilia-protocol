-- 114_reconcile_missing_tables.sql
--
-- DRIFT RECONCILIATION. Migrations 022 (operator_applications) and 068
-- (policy_rollouts) are journaled as applied in prod, but the tables were never
-- actually created — so /api/operators/apply and
-- /api/cloud/policies/[id]/rollout 500 in production. Recreate both idempotently.
--
-- 068 originally enabled NO RLS; with Supabase's default anon/authenticated
-- table grants that would leave policy_rollouts world-readable/writable (the
-- same class of bug fixed in migration 113). This migration creates it with
-- service_role-only RLS from the start. operator_applications keeps its original
-- service_role-only policy from 022.
--
-- NOTE: the `authorities` table (033/102) is ALSO missing in prod but is
-- deliberately NOT reconciled here — its guard path is in a dual-mode rollout
-- and creating it could change fail-open/closed behavior before approver
-- backfill. Handle separately.

-- operator_applications (from 022) ------------------------------------------
CREATE TABLE IF NOT EXISTS operator_applications (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE,
  background    TEXT,
  motivation    TEXT,
  status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'waitlisted')),
  reviewed_by   TEXT,
  review_notes  TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reviewed_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_operator_applications_status ON operator_applications(status);
CREATE INDEX IF NOT EXISTS idx_operator_applications_email ON operator_applications(email);
ALTER TABLE operator_applications ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON operator_applications;
CREATE POLICY "service_role_all" ON operator_applications
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- policy_rollouts (from 068) + RLS it originally lacked -----------------------
CREATE TABLE IF NOT EXISTS policy_rollouts (
  rollout_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id       UUID NOT NULL REFERENCES handshake_policies(policy_id),
  version         INTEGER NOT NULL,
  environment     TEXT NOT NULL,
  strategy        TEXT NOT NULL DEFAULT 'immediate'
                    CHECK (strategy IN ('immediate', 'canary')),
  status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'rolled_back', 'superseded', 'failed')),
  initiated_by    TEXT NOT NULL,
  tenant_id       TEXT,
  canary_pct      SMALLINT DEFAULT NULL
                    CHECK (canary_pct IS NULL OR (canary_pct BETWEEN 1 AND 99)),
  initiated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at    TIMESTAMPTZ,
  metadata        JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_policy_rollouts_policy  ON policy_rollouts(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_rollouts_env     ON policy_rollouts(environment, status);
CREATE INDEX IF NOT EXISTS idx_policy_rollouts_tenant  ON policy_rollouts(tenant_id) WHERE tenant_id IS NOT NULL;
ALTER TABLE policy_rollouts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON policy_rollouts;
CREATE POLICY "service_role_all" ON policy_rollouts
  FOR ALL TO service_role USING (true) WITH CHECK (true);
