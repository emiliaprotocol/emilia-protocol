-- 124_org_quorum_policies.sql
-- Organization-pinned quorum policy templates — trust anchor for the multi-party
-- "two-person rule." A receipt quorum_policy is only honored when it meets or
-- exceeds the row for its (organization_id, action_type). Created empty; no
-- behavior change until a row exists. service_role-only RLS.

CREATE TABLE IF NOT EXISTS org_quorum_policies (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id         TEXT NOT NULL,
  action_type             TEXT NOT NULL,
  min_required            INTEGER CHECK (min_required IS NULL OR min_required > 0),
  max_window_sec          INTEGER CHECK (max_window_sec IS NULL OR max_window_sec > 0),
  require_distinct_humans BOOLEAN NOT NULL DEFAULT TRUE,
  quorum_required         BOOLEAN NOT NULL DEFAULT FALSE,
  allowed_approvers       JSONB,
  allowed_modes           JSONB,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (organization_id, action_type)
);

CREATE INDEX IF NOT EXISTS idx_org_quorum_policies_lookup
  ON org_quorum_policies (organization_id, action_type);

COMMENT ON TABLE org_quorum_policies IS
  'Org-pinned quorum policy templates keyed by (organization_id, action_type). A receipt quorum_policy is only honored when it meets or exceeds the row (min threshold, window ceiling, distinct-humans floor, allowed roster). Closes the creator-declared quorum-strength gap.';

ALTER TABLE org_quorum_policies ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON org_quorum_policies;
CREATE POLICY "service_role_all" ON org_quorum_policies
  FOR ALL TO service_role USING (true) WITH CHECK (true);;
