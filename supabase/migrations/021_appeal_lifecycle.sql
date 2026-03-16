-- ============================================================================
-- EMILIA Protocol — Migration 021: Appeal Lifecycle States
-- ============================================================================
-- The state machine in procedural-justice.js defines 10 dispute states,
-- but the DB CHECK constraint only allows 6. This migration adds the
-- 4 missing appeal + withdrawal states so the constitutional principle
-- "trust must never be more powerful than appeal" can actually execute.
--
-- New states: appealed, appeal_upheld, appeal_reversed, appeal_dismissed, withdrawn
-- ============================================================================

-- Widen the disputes.status CHECK to match the full state machine
ALTER TABLE disputes DROP CONSTRAINT IF EXISTS disputes_status_check;
ALTER TABLE disputes ADD CONSTRAINT disputes_status_check
  CHECK (status IN (
    'open',
    'under_review',
    'upheld',
    'reversed',
    'dismissed',
    'superseded',
    'appealed',
    'appeal_upheld',
    'appeal_reversed',
    'appeal_dismissed',
    'withdrawn'
  ));

-- Widen the receipts.dispute_status CHECK to include appeal outcomes
ALTER TABLE receipts DROP CONSTRAINT IF EXISTS receipts_dispute_status_check;
ALTER TABLE receipts ADD CONSTRAINT receipts_dispute_status_check
  CHECK (dispute_status IS NULL OR dispute_status IN (
    'challenged',
    'under_review',
    'upheld',
    'reversed',
    'superseded',
    'dismissed',
    'appealed',
    'appeal_upheld',
    'appeal_reversed',
    'appeal_dismissed'
  ));

-- Add appeal tracking columns to disputes
ALTER TABLE disputes ADD COLUMN IF NOT EXISTS appeal_reason TEXT DEFAULT NULL;
ALTER TABLE disputes ADD COLUMN IF NOT EXISTS appeal_evidence JSONB DEFAULT NULL;
ALTER TABLE disputes ADD COLUMN IF NOT EXISTS appealed_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE disputes ADD COLUMN IF NOT EXISTS appealed_by UUID DEFAULT NULL REFERENCES entities(id);
ALTER TABLE disputes ADD COLUMN IF NOT EXISTS appeal_resolution TEXT DEFAULT NULL;
ALTER TABLE disputes ADD COLUMN IF NOT EXISTS appeal_rationale TEXT DEFAULT NULL;
ALTER TABLE disputes ADD COLUMN IF NOT EXISTS appeal_resolved_by TEXT DEFAULT NULL;
ALTER TABLE disputes ADD COLUMN IF NOT EXISTS appeal_resolved_at TIMESTAMPTZ DEFAULT NULL;

-- Index for finding open appeals
CREATE INDEX IF NOT EXISTS idx_disputes_appealed ON disputes(status) WHERE status = 'appealed';

COMMENT ON COLUMN disputes.appeal_reason IS
  'Why the original resolution is being challenged. Required when status transitions to appealed.';
COMMENT ON COLUMN disputes.appeal_resolution IS
  'Final appeal outcome: appeal_upheld (original stands), appeal_reversed (original overturned), appeal_dismissed.';
