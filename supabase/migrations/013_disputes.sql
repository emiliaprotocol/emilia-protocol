-- ============================================================================
-- EMILIA Protocol — Migration 013: Dispute Lifecycle
-- ============================================================================
-- Adds the due-process layer. Any materially affected party can challenge
-- a receipt. Challenges follow a lifecycle:
--
--   submitted → challenged → under_review → upheld | reversed | superseded
--
-- Reversed receipts get graph_weight set to 0.0 (neutralized, not deleted).
-- Nothing is erased. Everything is append-only.
-- ============================================================================

-- Disputes table
CREATE TABLE IF NOT EXISTS disputes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  dispute_id TEXT NOT NULL UNIQUE,
  receipt_id TEXT NOT NULL REFERENCES receipts(receipt_id),
  entity_id UUID NOT NULL REFERENCES entities(id),
  
  -- Who filed the dispute
  filed_by UUID NOT NULL REFERENCES entities(id),
  filed_by_type TEXT NOT NULL CHECK (filed_by_type IN ('affected_entity', 'receipt_subject', 'third_party', 'human_operator')),
  
  -- Dispute details
  reason TEXT NOT NULL CHECK (reason IN (
    'fraudulent_receipt',
    'inaccurate_signals',
    'identity_dispute',
    'context_mismatch',
    'duplicate_transaction',
    'coerced_receipt',
    'other'
  )),
  description TEXT,
  evidence JSONB DEFAULT NULL,
  
  -- Lifecycle
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'under_review', 'upheld', 'reversed', 'superseded', 'dismissed')),
  
  -- Response from the receipt submitter
  response TEXT DEFAULT NULL,
  response_evidence JSONB DEFAULT NULL,
  responded_at TIMESTAMPTZ DEFAULT NULL,
  
  -- Resolution
  resolution TEXT DEFAULT NULL,
  resolution_rationale TEXT DEFAULT NULL,
  resolved_by TEXT DEFAULT NULL, -- 'auto', 'operator', 'community'
  resolved_at TIMESTAMPTZ DEFAULT NULL,
  
  -- If reversed, the original receipt's graph_weight is set to 0.0
  -- If superseded, a new receipt replaces the disputed one
  superseding_receipt_id TEXT DEFAULT NULL,
  
  -- Timestamps
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  
  -- Response window: 7 days from filing
  response_deadline TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '7 days')
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_disputes_receipt_id ON disputes(receipt_id);
CREATE INDEX IF NOT EXISTS idx_disputes_entity_id ON disputes(entity_id);
CREATE INDEX IF NOT EXISTS idx_disputes_filed_by ON disputes(filed_by);
CREATE INDEX IF NOT EXISTS idx_disputes_status ON disputes(status);

-- Add dispute_count to entities for quick access
ALTER TABLE entities ADD COLUMN IF NOT EXISTS dispute_count INTEGER DEFAULT 0;

-- Add dispute_status to receipts
ALTER TABLE receipts ADD COLUMN IF NOT EXISTS dispute_status TEXT DEFAULT NULL 
  CHECK (dispute_status IS NULL OR dispute_status IN ('challenged', 'under_review', 'upheld', 'reversed', 'superseded'));

-- Function to update entity dispute count
CREATE OR REPLACE FUNCTION update_dispute_count()
RETURNS trigger AS
$fn$
BEGIN
  IF TG_OP = 'INSERT' THEN
    UPDATE entities SET dispute_count = dispute_count + 1, updated_at = NOW()
    WHERE id = NEW.entity_id;
  END IF;
  RETURN NEW;
END;
$fn$
LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_update_dispute_count ON disputes;
CREATE TRIGGER trg_update_dispute_count
AFTER INSERT ON disputes
FOR EACH ROW EXECUTE FUNCTION update_dispute_count();

COMMENT ON TABLE disputes IS 
  'Due-process layer for EP. Any affected party can challenge a receipt. '
  'Reversed receipts are neutralized (graph_weight = 0.0), never deleted. '
  'Everything is append-only.';

-- Human reports table (not tied to specific receipts)
CREATE TABLE IF NOT EXISTS trust_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  report_id TEXT NOT NULL UNIQUE,
  entity_id UUID NOT NULL REFERENCES entities(id),
  report_type TEXT NOT NULL CHECK (report_type IN (
    'wrongly_downgraded', 'harmed_by_trusted_entity',
    'fraudulent_entity', 'inaccurate_profile', 'other'
  )),
  description TEXT NOT NULL,
  contact_email TEXT DEFAULT NULL,
  evidence JSONB DEFAULT NULL,
  status TEXT NOT NULL DEFAULT 'received' CHECK (status IN ('received', 'reviewing', 'actioned', 'dismissed')),
  resolution_notes TEXT DEFAULT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trust_reports_entity ON trust_reports(entity_id);
CREATE INDEX IF NOT EXISTS idx_trust_reports_status ON trust_reports(status);

COMMENT ON TABLE trust_reports IS
  'Human appeal layer. Anyone can report a trust issue — no EP entity or API key required. '
  'Reports are reviewed by operators and can trigger formal disputes.';
