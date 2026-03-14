-- ============================================================================
-- EMILIA Protocol — Migration 017: Write-Path Hardening
-- ============================================================================
-- Adds database-level deduplication guarantee.
-- Same transaction_ref + same submitter + same entity = unique.
-- Application-level check exists in create-receipt.js; this is defense in depth.
-- ============================================================================

CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_dedup
  ON receipts (entity_id, submitted_by, transaction_ref);

-- Add protocol_version column for output traceability
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS protocol_version TEXT DEFAULT 'EP/1.1-v2';
