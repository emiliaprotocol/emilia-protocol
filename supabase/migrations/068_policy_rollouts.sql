-- EP Cloud Layer — Policy Rollout Tracking
--
-- Tracks the deployment history of policy versions across environments.
-- The rollout route transitions from stub to a real persistent record
-- so operators can audit which policy version is live where and when.

CREATE TABLE IF NOT EXISTS policy_rollouts (
  rollout_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id       UUID NOT NULL REFERENCES handshake_policies(policy_id),
  version         INTEGER NOT NULL,
  environment     TEXT NOT NULL,
  strategy        TEXT NOT NULL DEFAULT 'immediate'
                    CHECK (strategy IN ('immediate', 'canary')),
  status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'rolled_back', 'superseded', 'failed')),
  initiated_by    TEXT NOT NULL,           -- operator / principal / system ID
  tenant_id       TEXT,
  canary_pct      SMALLINT DEFAULT NULL    -- % of traffic for canary rollouts (1–99)
                    CHECK (canary_pct IS NULL OR (canary_pct BETWEEN 1 AND 99)),
  initiated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at    TIMESTAMPTZ,
  metadata        JSONB DEFAULT '{}'
);

CREATE INDEX idx_policy_rollouts_policy  ON policy_rollouts(policy_id);
CREATE INDEX idx_policy_rollouts_env     ON policy_rollouts(environment, status);
CREATE INDEX idx_policy_rollouts_tenant  ON policy_rollouts(tenant_id) WHERE tenant_id IS NOT NULL;

COMMENT ON TABLE policy_rollouts IS
  'Append-only rollout log. Active rollouts have status=active; '
  'when a new immediate rollout lands, the previous active one is set to superseded.';
