ALTER TABLE anchor_batches ADD COLUMN IF NOT EXISTS merkle_alg TEXT;
UPDATE anchor_batches SET merkle_alg = 'EP-MERKLE-v1' WHERE merkle_alg IS NULL;
COMMENT ON COLUMN anchor_batches.merkle_alg IS
  'Merkle construction for this batch: EP-MERKLE-v1 (legacy sorted-pair) or EP-MERKLE-v2 (domain-separated 0x00 leaf / 0x01 branch, positional). Verifiers select per-batch.';;
