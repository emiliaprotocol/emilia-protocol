-- ============================================================================
-- EMILIA Protocol — Migration 008: Protocol Hardening
-- ============================================================================
-- Fixes identified by code audit:
--   1. transaction_ref NOT NULL (was optional, allowing receipt spam)
--   2. Immutability triggers (reject UPDATE/DELETE on receipts)
--   3. Canonical is_established() function used everywhere
-- ============================================================================

-- 1. Make transaction_ref mandatory at the DB level
-- First, update any existing NULL values (from test data)
UPDATE receipts SET transaction_ref = 'legacy-' || receipt_id WHERE transaction_ref IS NULL;
ALTER TABLE receipts ALTER COLUMN transaction_ref SET NOT NULL;

-- Replace the partial unique index with a hard one
DROP INDEX IF EXISTS idx_receipts_dedup;
CREATE UNIQUE INDEX idx_receipts_dedup ON receipts (entity_id, submitted_by, transaction_ref);

-- 2. Immutability: reject UPDATE and DELETE on receipts
CREATE OR REPLACE FUNCTION reject_receipt_modification()
RETURNS trigger AS
$fn$
BEGIN
  RAISE EXCEPTION 'Receipts are append-only. UPDATE and DELETE are not permitted.';
  RETURN NULL;
END;
$fn$
LANGUAGE plpgsql;

-- Drop existing triggers if they exist (idempotent)
DROP TRIGGER IF EXISTS trg_receipts_no_update ON receipts;
DROP TRIGGER IF EXISTS trg_receipts_no_delete ON receipts;

CREATE TRIGGER trg_receipts_no_update
  BEFORE UPDATE ON receipts
  FOR EACH ROW
  WHEN (OLD.anchor_batch_id IS DISTINCT FROM NEW.anchor_batch_id
    OR OLD.merkle_proof IS DISTINCT FROM NEW.merkle_proof
    OR OLD.merkle_leaf_index IS DISTINCT FROM NEW.merkle_leaf_index)
  EXECUTE FUNCTION reject_receipt_modification();

-- Allow anchor metadata updates but block all other updates
-- Actually: block ALL updates except anchor fields
CREATE OR REPLACE FUNCTION reject_receipt_content_modification()
RETURNS trigger AS
$fn$
BEGIN
  -- Only allow anchor metadata to be updated
  IF OLD.receipt_hash IS DISTINCT FROM NEW.receipt_hash
    OR OLD.entity_id IS DISTINCT FROM NEW.entity_id
    OR OLD.submitted_by IS DISTINCT FROM NEW.submitted_by
    OR OLD.transaction_ref IS DISTINCT FROM NEW.transaction_ref
    OR OLD.composite_score IS DISTINCT FROM NEW.composite_score
    OR OLD.delivery_accuracy IS DISTINCT FROM NEW.delivery_accuracy
    OR OLD.product_accuracy IS DISTINCT FROM NEW.product_accuracy
    OR OLD.price_integrity IS DISTINCT FROM NEW.price_integrity
    OR OLD.return_processing IS DISTINCT FROM NEW.return_processing
    OR OLD.agent_satisfaction IS DISTINCT FROM NEW.agent_satisfaction
    OR OLD.agent_behavior IS DISTINCT FROM NEW.agent_behavior
    OR OLD.evidence::text IS DISTINCT FROM NEW.evidence::text
    OR OLD.claims::text IS DISTINCT FROM NEW.claims::text
  THEN
    RAISE EXCEPTION 'Receipt content is immutable. Only anchor metadata can be updated.';
  END IF;
  RETURN NEW;
END;
$fn$
LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_receipts_immutable_content ON receipts;
CREATE TRIGGER trg_receipts_immutable_content
  BEFORE UPDATE ON receipts
  FOR EACH ROW
  EXECUTE FUNCTION reject_receipt_content_modification();

-- Block all deletes
CREATE TRIGGER trg_receipts_no_delete
  BEFORE DELETE ON receipts
  FOR EACH ROW
  EXECUTE FUNCTION reject_receipt_modification();

-- 3. Canonical is_established() function
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
  SELECT COUNT(*)
  INTO v_total
  FROM receipts WHERE entity_id = p_entity_id;

  SELECT COUNT(DISTINCT submitted_by)
  INTO v_unique
  FROM receipts WHERE entity_id = p_entity_id;

  -- Effective evidence = sum of receipt weights
  SELECT COALESCE(SUM(
    CASE WHEN submitter_established = TRUE
      THEN GREATEST(0.1, LEAST(1.0, COALESCE(submitter_score, 50) / 100.0))
      ELSE 0.1
    END
    * GREATEST(0.05, POWER(0.5, EXTRACT(EPOCH FROM (NOW() - created_at)) / 86400.0 / 90.0))
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
