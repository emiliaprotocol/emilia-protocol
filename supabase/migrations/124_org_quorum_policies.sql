-- 124_org_quorum_policies.sql
--
-- Organization-pinned quorum policy templates — the trust anchor for the
-- multi-party "two-person rule."
--
-- WHY. Quorum verification (packages/verify/quorum.js) proves a quorum document
-- is internally consistent against WHATEVER policy it is handed. Until now that
-- policy was chosen by the receipt CREATOR at issuance, with nothing binding it
-- to org intent — so a creator could declare `required: 1` (or a hand-picked
-- roster) for their own high-stakes receipt where the org rule is 2-of-3.
-- Separation-of-duties still held and no enrolled key could be forged, but the
-- guarantee was only as strong as a per-receipt, creator-set field.
--
-- This table is the out-of-band source of the EXPECTED quorum for an action.
-- The create and consume paths (lib/guard-quorum-template.js) enforce that a
-- receipt's quorum_policy MEETS OR EXCEEDS the row for its
-- (organization_id, action_type): threshold >= min_required, window <=
-- max_window_sec, distinct_humans not disabled below require_distinct_humans,
-- and every declared approver inside allowed_approvers. A creator may make a
-- quorum stronger than the floor, never weaker.
--
-- Created EMPTY. An empty table is behaviourally equivalent to the prior state
-- (no template → no meet-or-exceed floor; the resolver treats a missing row and
-- a not-yet-applied table the same way). Enforcement activates per action_type
-- as soon as an org inserts a row. service_role-only RLS from the start.

CREATE TABLE IF NOT EXISTS org_quorum_policies (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id         TEXT NOT NULL,
  action_type             TEXT NOT NULL,
  -- Minimum threshold M (>=). NULL = no floor.
  min_required            INTEGER CHECK (min_required IS NULL OR min_required > 0),
  -- Ceiling on the approval window in seconds (<=). NULL = no ceiling.
  max_window_sec          INTEGER CHECK (max_window_sec IS NULL OR max_window_sec > 0),
  -- Separation-of-duties floor. TRUE (default) forbids a per-receipt policy from
  -- disabling distinct_humans.
  require_distinct_humans BOOLEAN NOT NULL DEFAULT TRUE,
  -- When TRUE, a receipt for this action_type MUST carry a quorum_policy.
  quorum_required         BOOLEAN NOT NULL DEFAULT FALSE,
  -- Allowed roster: [{ "role": "...", "approver": "..." }]. Submitted approvers
  -- must be a subset. NULL/empty = unrestricted roster.
  allowed_approvers       JSONB,
  -- Optional allowed modes, e.g. ["ordered"]. NULL/empty = any mode.
  allowed_modes           JSONB,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- One template per (org, action_type).
  UNIQUE (organization_id, action_type)
);

CREATE INDEX IF NOT EXISTS idx_org_quorum_policies_lookup
  ON org_quorum_policies (organization_id, action_type);

COMMENT ON TABLE org_quorum_policies IS
  'Org-pinned quorum policy templates keyed by (organization_id, action_type). A receipt quorum_policy is only honored when it meets or exceeds the row (min threshold, window ceiling, distinct-humans floor, allowed roster). Closes the creator-declared quorum-strength gap.';

ALTER TABLE org_quorum_policies ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON org_quorum_policies;
CREATE POLICY "service_role_all" ON org_quorum_policies
  FOR ALL TO service_role USING (true) WITH CHECK (true);
