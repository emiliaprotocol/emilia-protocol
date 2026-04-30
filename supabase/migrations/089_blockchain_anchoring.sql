-- Migration 089: Blockchain anchoring (renamed from 003b — defensive)
--
-- Originally authored as 003b_blockchain_anchoring.sql. The supabase CLI
-- rejects filenames matching `<digits>b_*` so this migration was never
-- tracked despite its tables (merkle_batches) existing on prod (applied
-- via Studio SQL editor in the pre-tracking era). Renaming to 089 with
-- defensive IF NOT EXISTS guards so:
--   • prod (where tables already exist) treats this as a no-op
--   • a hypothetical fresh deploy still gets the schema, just out of
--     historical order (after migration 086 instead of after 003)
--
-- The historical-order quirk does NOT matter on prod because the
-- objects are already there. For a future fresh deploy, follow-up
-- work can either inline this into an earlier migration or accept
-- the ordering — merkle_batches isn't referenced by any earlier
-- migration that requires it.

CREATE TABLE IF NOT EXISTS merkle_batches (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  merkle_root     TEXT NOT NULL,
  leaf_count      INTEGER NOT NULL,
  receipt_ids     UUID[] NOT NULL,
  layers_json     TEXT NOT NULL,
  tx_hash         TEXT,
  block_number    BIGINT,
  status          TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'anchored', 'failed')),
  error_message   TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  anchored_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_merkle_batches_status
  ON merkle_batches (status);
CREATE INDEX IF NOT EXISTS idx_merkle_batches_root
  ON merkle_batches (merkle_root);
CREATE INDEX IF NOT EXISTS idx_merkle_batches_tx
  ON merkle_batches (tx_hash) WHERE tx_hash IS NOT NULL;

-- Add merkle_batch_id to receipts (defensive: skip if column exists, skip
-- entirely if receipts table itself doesn't exist).
DO $$
BEGIN
  IF to_regclass('public.receipts') IS NOT NULL THEN
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'receipts'
        AND column_name = 'merkle_batch_id'
    ) THEN
      ALTER TABLE receipts
        ADD COLUMN merkle_batch_id UUID REFERENCES merkle_batches(id);
    END IF;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_receipts_batch
  ON receipts (merkle_batch_id) WHERE merkle_batch_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_receipts_unanchored
  ON receipts (created_at) WHERE merkle_batch_id IS NULL;
