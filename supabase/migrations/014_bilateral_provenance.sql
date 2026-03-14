-- ============================================================================
-- EMILIA Protocol — Migration 014: Bilateral Attestations + Provenance Tiers
-- ============================================================================
-- Bilateral: both parties confirm an event happened. Huge truth quality jump.
-- Provenance: classifies how trustworthy the evidence source is.
-- These two features together make receipts much harder to fake.
-- ============================================================================

-- Provenance tier on receipts
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS provenance_tier TEXT DEFAULT 'self_attested'
  CHECK (provenance_tier IN (
    'self_attested',        -- 0.3x — one party says it happened
    'identified_signed',    -- 0.5x — submitter identity verified
    'bilateral',            -- 0.8x — both parties confirmed
    'platform_originated',  -- 0.9x — platform webhook/API data
    'carrier_verified',     -- 0.95x — carrier/payment provider confirmed
    'oracle_verified'       -- 1.0x — independent oracle confirmed
  ));

-- Bilateral confirmation tracking
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS bilateral_status TEXT DEFAULT NULL
  CHECK (bilateral_status IS NULL OR bilateral_status IN (
    'pending_confirmation',  -- submitter created, awaiting counterparty
    'confirmed',             -- counterparty confirmed
    'disputed',              -- counterparty disagreed
    'expired'                -- confirmation window expired (48h)
  ));

ALTER TABLE receipts ADD COLUMN IF NOT EXISTS confirmed_by UUID DEFAULT NULL REFERENCES entities(id);
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS confirmation_deadline TIMESTAMPTZ DEFAULT NULL;

-- Provenance weight multipliers (used in scoring alongside graph_weight)
-- The scoring engine multiplies: submitter_weight × time_weight × graph_weight × provenance_weight
COMMENT ON COLUMN receipts.provenance_tier IS
  'Evidence provenance tier. Affects trust weight: '
  'self_attested=0.3, identified_signed=0.5, bilateral=0.8, '
  'platform_originated=0.9, carrier_verified=0.95, oracle_verified=1.0';

-- Index for bilateral status queries
CREATE INDEX IF NOT EXISTS idx_receipts_bilateral ON receipts(bilateral_status) 
  WHERE bilateral_status IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_receipts_provenance ON receipts(provenance_tier);
