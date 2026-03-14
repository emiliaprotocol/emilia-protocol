-- ============================================================================
-- EMILIA Protocol — Migration 008: Protocol Hardening
-- ============================================================================

-- 1. Make transaction_ref mandatory at the DB level
UPDATE receipts SET transaction_ref = 'legacy-' || receipt_id WHERE transaction_ref IS NULL;
ALTER TABLE receipts ALTER COLUMN transaction_ref SET NOT NULL;

-- Replace partial dedup index with hard one
DROP INDEX IF EXISTS idx_receipts_dedup;
CREATE UNIQUE INDEX idx_receipts_dedup ON receipts (entity_id, submitted_by, transaction_ref);

-- 2. Immutability: ONE trigger that allows ONLY anchor metadata updates
DROP TRIGGER IF EXISTS trg_receipts_no_update ON receipts;
DROP TRIGGER IF EXISTS trg_receipts_immutable_content ON receipts;
DROP TRIGGER IF EXISTS trg_receipts_no_delete ON receipts;
DROP FUNCTION IF EXISTS reject_receipt_modification() CASCADE;
DROP FUNCTION IF EXISTS reject_receipt_content_modification() CASCADE;

CREATE OR REPLACE FUNCTION enforce_receipt_immutability()
RETURNS trigger AS
$fn$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Receipts are append-only. DELETE is not permitted.';
    RETURN NULL;
  END IF;

  -- UPDATE: only allow anchor metadata fields to change
  IF TG_OP = 'UPDATE' THEN
    IF OLD.receipt_hash IS DISTINCT FROM NEW.receipt_hash
      OR OLD.entity_id IS DISTINCT FROM NEW.entity_id
      OR OLD.submitted_by IS DISTINCT FROM NEW.submitted_by
      OR OLD.transaction_ref IS DISTINCT FROM NEW.transaction_ref
      OR OLD.transaction_type IS DISTINCT FROM NEW.transaction_type
      OR OLD.composite_score IS DISTINCT FROM NEW.composite_score
      OR OLD.delivery_accuracy IS DISTINCT FROM NEW.delivery_accuracy
      OR OLD.product_accuracy IS DISTINCT FROM NEW.product_accuracy
      OR OLD.price_integrity IS DISTINCT FROM NEW.price_integrity
      OR OLD.return_processing IS DISTINCT FROM NEW.return_processing
      OR OLD.agent_satisfaction IS DISTINCT FROM NEW.agent_satisfaction
      OR OLD.agent_behavior IS DISTINCT FROM NEW.agent_behavior
      OR OLD.evidence::text IS DISTINCT FROM NEW.evidence::text
      OR OLD.claims::text IS DISTINCT FROM NEW.claims::text
      OR OLD.submitter_score IS DISTINCT FROM NEW.submitter_score
      OR OLD.submitter_established IS DISTINCT FROM NEW.submitter_established
      OR OLD.previous_hash IS DISTINCT FROM NEW.previous_hash
    THEN
      RAISE EXCEPTION 'Receipt content is immutable. Only anchor_batch_id, merkle_proof, and merkle_leaf_index can be updated.';
    END IF;
    -- If we get here, only anchor fields changed — allow it
    RETURN NEW;
  END IF;

  RETURN NEW;
END;
$fn$
LANGUAGE plpgsql;

CREATE TRIGGER trg_receipts_immutable
  BEFORE UPDATE OR DELETE ON receipts
  FOR EACH ROW
  EXECUTE FUNCTION enforce_receipt_immutability();

-- 3. Canonical is_entity_established() function
--
-- DESIGN NOTE: Establishment vs Scoring Windows
-- This function uses ALL receipts (no window limit).
-- compute_emilia_score() uses a rolling 200-receipt window.
--
-- These are deliberately different:
--   - Establishment is a HISTORICAL property: "has this entity ever built enough
--     credible history to be considered real?" Once established, the entity
--     retains that status even if recent receipts are sparse.
--   - Scoring is a CURRENT property: "how is this entity performing right now?"
--     Only recent receipts (200 window + time decay) affect the score.
--
-- An entity can be established (from past history) but have a low current score
-- (recent performance is poor). That is correct behavior — the confidence state
-- system communicates this: established + low score = "real entity, declining."
--
CREATE OR REPLACE FUNCTION is_entity_established(p_entity_id uuid)
RETURNS TABLE(
  total_receipts integer,
  unique_submitters integer,
  effective_evidence float,
  established boolean
) AS
$fn$
DECLARE
  v_total integer;
  v_unique integer;
  v_effective float;
BEGIN
  SELECT COUNT(*) INTO v_total FROM receipts WHERE entity_id = p_entity_id;
  SELECT COUNT(DISTINCT submitted_by) INTO v_unique FROM receipts WHERE entity_id = p_entity_id;

  SELECT COALESCE(SUM(
    CASE WHEN submitter_established = TRUE
      THEN GREATEST(0.1, LEAST(1.0, COALESCE(submitter_score, 50) / 100.0))
      ELSE 0.1
    END
    * GREATEST(0.05, POWER(0.5, EXTRACT(EPOCH FROM (NOW() - created_at)) / 86400.0 / 90.0))
    * COALESCE(graph_weight, 1.0)
  ), 0)
  INTO v_effective
  FROM receipts WHERE entity_id = p_entity_id;

  total_receipts := v_total;
  unique_submitters := v_unique;
  effective_evidence := ROUND(v_effective::numeric, 2);
  established := v_effective >= 5.0 AND v_unique >= 3;

  RETURN NEXT;
END;
$fn$
LANGUAGE plpgsql STABLE;
