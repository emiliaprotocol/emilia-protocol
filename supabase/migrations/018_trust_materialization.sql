-- ============================================================================
-- EMILIA Protocol — Migration 018: Trust Profile Materialization
-- ============================================================================
-- Adds a materialized trust snapshot to entities.
-- The canonical writer updates this after every receipt/dispute/bilateral write.
-- The canonical evaluator checks it before doing a full recompute.
-- ============================================================================

-- Materialized trust snapshot — updated on every trust-changing write
ALTER TABLE entities ADD COLUMN IF NOT EXISTS trust_snapshot JSONB DEFAULT NULL;
ALTER TABLE entities ADD COLUMN IF NOT EXISTS trust_materialized_at TIMESTAMPTZ DEFAULT NULL;

COMMENT ON COLUMN entities.trust_snapshot IS
  'Materialized trust profile snapshot. Updated by canonical writer on every '
  'receipt submission, dispute resolution, or bilateral confirmation. '
  'Read path uses this if fresh (< 5 min), recomputes if stale.';
