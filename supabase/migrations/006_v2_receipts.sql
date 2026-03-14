-- ============================================================================
-- EMILIA Protocol — Migration 006: V2 Receipt Support
-- ============================================================================
-- Adds claims JSONB column for evidence-based scoring (Phase 1.5)
-- Adds submitter_score for submitter-weighted scoring
-- ============================================================================

-- Claims: structured claims from v2 receipts
-- { delivered: true, on_time: { promised: "...", actual: "..." }, ... }
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS claims JSONB;

-- Submitter's EMILIA score at time of submission (for weighted scoring)
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS submitter_score NUMERIC(5,1) DEFAULT 50;

-- Whether submitter was established at time of submission (for Sybil resistance)
-- Unestablished submitters' receipts carry 0.1x weight instead of score/100
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS submitter_established BOOLEAN DEFAULT FALSE;

-- Outcome field for v2 receipts: completed | partial | failed | disputed
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS outcome TEXT;

-- Index for finding receipts with claims (v2 format)
CREATE INDEX IF NOT EXISTS idx_receipts_has_claims
  ON receipts (created_at)
  WHERE claims IS NOT NULL;
