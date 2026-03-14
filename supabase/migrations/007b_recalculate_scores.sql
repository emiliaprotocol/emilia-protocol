-- ============================================================================
-- Run AFTER migration 007 to recalculate all existing scores
-- This will bring Rex/Ruby scores down from their inflated values
-- because the unestablished submitter receipts now carry 0.1x weight
-- ============================================================================

UPDATE entities SET
  emilia_score = compute_emilia_score(id),
  updated_at = NOW()
WHERE status = 'active' AND total_receipts > 0;

-- Verify
SELECT entity_id, display_name, emilia_score, total_receipts
FROM entities
WHERE status = 'active'
ORDER BY emilia_score DESC;
