-- ============================================================================
-- EMILIA Protocol — Migration 025: Trust-Graph Dispute Adjudication
-- ============================================================================
-- When a dispute is filed, high-confidence entities who have directly
-- transacted with the disputed entity are queried for a weighted vote.
-- Their implicit sentiment (inferred from shared receipt history) is
-- weighted by their own confidence score and aggregated into an adjudication
-- recommendation: uphold_dispute | dismiss_dispute | inconclusive
--
-- This is the mechanism that makes the ledger trustworthy under adversarial
-- conditions. You cannot manufacture a favorable adjudication without first
-- manufacturing real transaction history across multiple high-confidence
-- entities — which is precisely what Sybil resistance (migration 020) prevents.
--
-- The adjudication result is a RECOMMENDATION, not a final verdict.
-- Human operators retain resolution authority. The trust graph advises.
-- ============================================================================

-- Add adjudication columns to the disputes table
ALTER TABLE disputes
  ADD COLUMN IF NOT EXISTS adjudication_result         JSONB,
  ADD COLUMN IF NOT EXISTS adjudicated_at              TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS adjudication_triggered_by   TEXT;

-- ------------------------------------------------------------------
-- Column documentation
-- ------------------------------------------------------------------

COMMENT ON COLUMN disputes.adjudication_result IS
  'Trust-graph adjudication outcome. Shape: '
  '{ recommendation: "uphold_dispute"|"dismiss_dispute"|"inconclusive", '
  '  confidence: 0.0-1.0, '
  '  voucher_count: N, '
  '  participating_count: N, '
  '  weighted_vote: { uphold_fraction, weighted_uphold, weighted_dismiss, weighted_abstain }, '
  '  voucher_summary: [...] }. '
  'Set by lib/dispute-adjudication.js. Operator retains final resolution authority.';

COMMENT ON COLUMN disputes.adjudicated_at IS
  'When the trust-graph adjudication was last run for this dispute. '
  'May be run multiple times if new evidence arrives.';

COMMENT ON COLUMN disputes.adjudication_triggered_by IS
  'Who triggered adjudication: "cron" for automated, '
  'or the entity_id slug of the party who called POST /api/disputes/[id]/adjudicate.';

-- ------------------------------------------------------------------
-- Index: find disputes awaiting adjudication
-- Cron queries open disputes with no adjudication yet, ordered by age.
-- ------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_disputes_needs_adjudication
  ON disputes (created_at ASC)
  WHERE status IN ('open', 'under_review')
    AND adjudication_result IS NULL;

COMMENT ON INDEX idx_disputes_needs_adjudication IS
  'Used by the adjudication cron to find open disputes that have not yet '
  'been adjudicated by the trust graph. Ordered oldest-first so stale disputes '
  'are prioritized.';

-- ------------------------------------------------------------------
-- Index: find disputes with specific adjudication recommendations
-- Useful for operator dashboards filtering by graph verdict.
-- ------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_disputes_adjudication_recommendation
  ON disputes ((adjudication_result->>'recommendation'))
  WHERE adjudication_result IS NOT NULL;

COMMENT ON INDEX idx_disputes_adjudication_recommendation IS
  'Allows efficient filtering by adjudication recommendation '
  '(uphold_dispute, dismiss_dispute, inconclusive) for operator review queues.';

-- ------------------------------------------------------------------
-- Receipts index: counterparty lookup for voucher discovery
-- findVouchers() joins receipts by entity_id and submitted_by.
-- These indexes exist from migration 001 but we ensure the composite
-- is available for the bidirectional voucher query.
-- ------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_receipts_submitted_by_entity
  ON receipts (submitted_by, entity_id, created_at DESC);

COMMENT ON INDEX idx_receipts_submitted_by_entity IS
  'Bidirectional voucher lookup: find entities who transacted with a given entity '
  'in either direction. Used by dispute-adjudication.js findVouchers().';
