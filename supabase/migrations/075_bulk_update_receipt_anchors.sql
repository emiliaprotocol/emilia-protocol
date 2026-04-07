-- Migration 075: Bulk receipt anchor update RPC
--
-- Replaces the N+1 serial UPDATE loop in runAnchorBatch().
-- A single RPC call updates all receipts in a batch atomically,
-- eliminating the risk of partial updates leaving receipts with a
-- dangling anchor_batch_id if the loop errors mid-way.
--
-- Input: JSONB array of objects with shape:
--   { receipt_id: text, anchor_batch_id: text, merkle_proof: jsonb, merkle_leaf_index: int }

CREATE OR REPLACE FUNCTION bulk_update_receipt_anchors(
  p_updates JSONB
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_item JSONB;
BEGIN
  FOR v_item IN SELECT * FROM jsonb_array_elements(p_updates) LOOP
    UPDATE receipts
    SET
      anchor_batch_id    = v_item->>'anchor_batch_id',
      merkle_proof       = v_item->'merkle_proof',
      merkle_leaf_index  = (v_item->>'merkle_leaf_index')::integer
    WHERE receipt_id = v_item->>'receipt_id'
      AND anchor_batch_id IS NULL; -- idempotency guard: skip already-anchored rows
  END LOOP;
END;
$$;

COMMENT ON FUNCTION bulk_update_receipt_anchors IS
  'Bulk-updates receipt rows with anchor batch ID, merkle proof, and leaf index. '
  'Replaces the N+1 serial UPDATE loop in runAnchorBatch(). '
  'Skips already-anchored rows (anchor_batch_id IS NOT NULL) for idempotency.';
