-- EP-IX Identity Continuity — Withdrawn State + State Machine Hardening
--
-- Adds the 'withdrawn' terminal state to continuity_claims and supporting
-- columns for the withdrawal record. Also adds dispute_id foreign key
-- for frozen_pending_dispute so the freeze can be lifted deterministically.

-- 1. Extend the status constraint to include 'withdrawn'.
--    Postgres does not support ALTER CONSTRAINT directly; we must drop and recreate.

ALTER TABLE continuity_claims
  DROP CONSTRAINT IF EXISTS continuity_claims_status_check;

ALTER TABLE continuity_claims
  ADD CONSTRAINT continuity_claims_status_check CHECK (status IN (
    'pending', 'under_challenge', 'approved_full', 'approved_partial',
    'rejected', 'frozen_pending_dispute', 'expired', 'withdrawn'
  ));

-- 2. Withdrawal metadata columns.
ALTER TABLE continuity_claims
  ADD COLUMN IF NOT EXISTS withdrawn_at   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS withdrawn_by   TEXT,         -- principal_id of the withdrawing party
  ADD COLUMN IF NOT EXISTS withdrawn_reason TEXT;

-- 3. dispute_id for frozen claims — links a freeze to the dispute that caused it,
--    so we can lift the freeze when that dispute resolves.
ALTER TABLE continuity_claims
  ADD COLUMN IF NOT EXISTS frozen_dispute_id TEXT;

COMMENT ON COLUMN continuity_claims.frozen_dispute_id IS
  'The dispute_id that triggered this claim being frozen. '
  'Set by freezeContinuityOnDispute(); cleared on unfreeze.';

COMMENT ON COLUMN continuity_claims.withdrawn_at IS
  'Timestamp when the claim was voluntarily withdrawn by its principal.';
