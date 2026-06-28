-- 108_anchor_merkle_alg.sql
--
-- #8 Blockchain anchor v1 -> v2 (domain separation).
--
-- New on-chain anchor batches use EP-MERKLE-v2 (RFC-6962-style domain separation:
-- 0x00 leaf tag, 0x01 branch tag, positional) — closing the leaf/branch
-- second-preimage class on the on-chain Merkle anchor, consistent with the
-- document-anchor v2 in @emilia-protocol/verify. Pre-existing batches stay v1
-- (sorted-pair) and keep verifying as v1; the verifier (verifyMerkleProof +
-- /api/verify) selects the algorithm per-batch from this column.
--
-- Defense-in-depth only: the Ed25519 receipt signature remains the primary
-- integrity guarantee; the on-chain root is a transparency/timestamp anchor.

ALTER TABLE anchor_batches ADD COLUMN IF NOT EXISTS merkle_alg TEXT;

-- Existing batches were built sorted-pair (v1). Make that explicit.
UPDATE anchor_batches SET merkle_alg = 'EP-MERKLE-v1' WHERE merkle_alg IS NULL;

COMMENT ON COLUMN anchor_batches.merkle_alg IS
  'Merkle construction for this batch: EP-MERKLE-v1 (legacy sorted-pair) or EP-MERKLE-v2 (domain-separated 0x00 leaf / 0x01 branch, positional). Verifiers select per-batch.';
