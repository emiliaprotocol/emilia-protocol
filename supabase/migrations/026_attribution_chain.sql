-- EMILIA Protocol — Migration 026: Attribution Chain
--
-- When an agent acts under delegation, the outcome propagates up the chain.
-- "Human A authorized Agent B to use Tool C. Outcome: X."
--   - Full attribution attaches to Agent B's behavioral record (handled by receipts table)
--   - A weak signal (0.15 weight) attaches to Human A's delegation judgment
--
-- This migration adds the columns needed to store the attribution chain on
-- receipts, and creates the principal_delegation_signals table for tracking
-- how well principals choose the agents they authorize.
--
-- Protocol note: Delegation judgment is a weak signal by design. A single bad
-- delegation should not punish a principal. A pattern of bad delegations should
-- be legible. The weight (0.15) encodes this asymmetry.

-- ---------------------------------------------------------------------------
-- 1. Extend receipts table with attribution metadata
-- ---------------------------------------------------------------------------

ALTER TABLE receipts
  ADD COLUMN IF NOT EXISTS attribution_chain JSONB,
  ADD COLUMN IF NOT EXISTS principal_id TEXT;

COMMENT ON COLUMN receipts.attribution_chain IS
  'Full attribution chain for this receipt. '
  'Array of { role, entity_id, weight } entries. '
  'Agent role: weight 1.0. Principal role: weight 0.15 (delegation judgment signal).';

COMMENT ON COLUMN receipts.principal_id IS
  'The principal (human/org) who authorized the agent that submitted this receipt. '
  'Populated only when a delegation_id is present in the receipt context. '
  'Links to principal_delegation_signals for judgment tracking.';

-- ---------------------------------------------------------------------------
-- 2. principal_delegation_signals: weak signals on principal delegation judgment
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS principal_delegation_signals (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id     TEXT NOT NULL,
  agent_entity_id  TEXT NOT NULL,
  receipt_id       TEXT NOT NULL,
  outcome_positive BOOLEAN NOT NULL,
  weight           NUMERIC NOT NULL DEFAULT 0.15,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Fast lookup by principal (primary query path for getDelegationJudgmentScore)
CREATE INDEX IF NOT EXISTS idx_pds_principal_id
  ON principal_delegation_signals (principal_id);

-- Lookup by agent (to answer: "who authorized this agent, and how did it go?")
CREATE INDEX IF NOT EXISTS idx_pds_agent_entity_id
  ON principal_delegation_signals (agent_entity_id);

-- Lookup by receipt (for reverse attribution audits)
CREATE INDEX IF NOT EXISTS idx_pds_receipt_id
  ON principal_delegation_signals (receipt_id);

-- Compound index for the judgment score query: all signals for a principal,
-- filtered by outcome, is the hot path for getDelegationJudgmentScore.
CREATE INDEX IF NOT EXISTS idx_pds_principal_outcome
  ON principal_delegation_signals (principal_id, outcome_positive);

COMMENT ON TABLE principal_delegation_signals IS
  'Weak signals on principal delegation judgment. '
  'Did the human authorize well-behaved agents? '
  'Each row records one delegation outcome at weight 0.15 — deliberately weak. '
  'A single bad delegation should not punish a principal. '
  'A pattern of bad delegations should be legible to the system. '
  'Trust must never be more powerful than appeal.';

COMMENT ON COLUMN principal_delegation_signals.outcome_positive IS
  'True if the delegated agent completed the task successfully (agent_behavior=completed '
  'or composite_score >= 70). False for abandoned, disputed, or low-composite outcomes.';

COMMENT ON COLUMN principal_delegation_signals.weight IS
  'Signal weight (default 0.15). Encodes the asymmetry: the agent bears full '
  'responsibility for its behavior; the principal bears only the judgment weight.';
