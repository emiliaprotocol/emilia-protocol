-- ============================================================================
-- EMILIA Protocol — Migration 012: Structured Context on Needs
-- ============================================================================
-- Changes needs.context from TEXT to JSONB so context-aware claim evaluation
-- works end-to-end with structured context keys.
--
-- Context key structure (same as receipts):
--   { task_type, category, geo, modality, value_band, risk_class }
-- ============================================================================

-- Drop the old text column and recreate as JSONB
-- (existing data was freeform text descriptions, not structured — safe to convert)
ALTER TABLE needs ALTER COLUMN context TYPE JSONB USING
  CASE
    WHEN context IS NULL THEN NULL
    WHEN context::text LIKE '{%' THEN context::jsonb
    ELSE jsonb_build_object('description', context)
  END;

COMMENT ON COLUMN needs.context IS
  'Structured context key for context-aware trust evaluation. '
  'Format: { task_type, category, geo, modality, value_band, risk_class }. '
  'Used by claim evaluation to filter receipts by matching context.';

-- Index for context-based queries
CREATE INDEX IF NOT EXISTS idx_needs_context ON needs USING GIN (context) WHERE context IS NOT NULL;
