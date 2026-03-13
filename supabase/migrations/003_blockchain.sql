-- ============================================================================
-- EMILIA Protocol — Migration 003: Blockchain Verification Tables
-- ============================================================================
-- Adds anchor_batches table and receipt columns for Merkle proof storage.
-- ============================================================================

-- Anchor batches: one row per Merkle root published to Base L2
CREATE TABLE IF NOT EXISTS anchor_batches (
  id              BIGSERIAL PRIMARY KEY,
  batch_id        TEXT UNIQUE NOT NULL,
  merkle_root     TEXT NOT NULL,
  leaf_count      INTEGER NOT NULL DEFAULT 0,
  tree_layers     JSONB,                          -- full tree for proof regeneration
  transaction_hash TEXT,                           -- Base L2 tx hash (null if skipped)
  chain_id        INTEGER DEFAULT 84532,          -- 8453 = Base mainnet, 84532 = Base Sepolia
  block_number    BIGINT,
  explorer_url    TEXT,
  skipped_onchain BOOLEAN DEFAULT FALSE,          -- true if EP_WALLET_PRIVATE_KEY not set
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Add anchor columns to receipts table
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS anchor_batch_id   TEXT REFERENCES anchor_batches(batch_id);
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS merkle_proof      JSONB;
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS merkle_leaf_index INTEGER;

-- Index for finding unanchored receipts efficiently
CREATE INDEX IF NOT EXISTS idx_receipts_unanchored
  ON receipts (created_at)
  WHERE anchor_batch_id IS NULL;

-- Index for batch lookups
CREATE INDEX IF NOT EXISTS idx_anchor_batches_batch_id
  ON anchor_batches (batch_id);

-- RLS: anchor_batches are read-only public (anyone can verify)
ALTER TABLE anchor_batches ENABLE ROW LEVEL SECURITY;

CREATE POLICY "anchor_batches_read" ON anchor_batches
  FOR SELECT USING (true);

CREATE POLICY "anchor_batches_insert" ON anchor_batches
  FOR INSERT WITH CHECK (true);
