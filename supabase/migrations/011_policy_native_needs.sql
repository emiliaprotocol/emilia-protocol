-- ============================================================================
-- EMILIA Protocol — Migration 011: Policy-Native Needs
-- ============================================================================
-- Adds trust_policy column to needs so need creators can specify
-- a trust policy instead of (or in addition to) a raw score threshold.
-- ============================================================================

ALTER TABLE needs ADD COLUMN IF NOT EXISTS trust_policy JSONB DEFAULT NULL;

COMMENT ON COLUMN needs.trust_policy IS 
  'Trust policy: either a string name ("strict") or a full JSON policy object. '
  'When set, need-claim evaluates against this policy instead of min_emilia_score.';
