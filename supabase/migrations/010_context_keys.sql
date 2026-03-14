-- ============================================================================
-- EMILIA Protocol — Migration 010: Context Keys
-- ============================================================================
-- Adds context JSONB column to receipts. Context makes trust contextual:
-- a merchant can be excellent for beauty products but weak for furniture.
--
-- Context key structure:
--   { task_type, category, geo, modality, value_band, risk_class }
--
-- All fields optional. Agents include what they know.
-- ============================================================================

ALTER TABLE receipts ADD COLUMN IF NOT EXISTS context JSONB DEFAULT NULL;

-- Update immutability trigger to protect context field
CREATE OR REPLACE FUNCTION enforce_receipt_immutability()
RETURNS trigger AS
$fn$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Receipts are append-only. DELETE is not permitted.';
    RETURN NULL;
  END IF;

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
      OR OLD.context::text IS DISTINCT FROM NEW.context::text
      OR OLD.submitter_score IS DISTINCT FROM NEW.submitter_score
      OR OLD.submitter_established IS DISTINCT FROM NEW.submitter_established
      OR OLD.previous_hash IS DISTINCT FROM NEW.previous_hash
    THEN
      RAISE EXCEPTION 'Receipt content is immutable. Only anchor metadata can be updated.';
    END IF;
    RETURN NEW;
  END IF;

  RETURN NEW;
END;
$fn$
LANGUAGE plpgsql;

-- Index for context-based queries (GIN index on JSONB)
CREATE INDEX IF NOT EXISTS idx_receipts_context ON receipts USING GIN (context) WHERE context IS NOT NULL;
