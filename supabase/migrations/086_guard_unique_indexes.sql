-- ============================================================================
-- EMILIA Protocol — Migration 086: GovGuard + FinGuard unique indexes
-- ============================================================================
--
-- Closes the TOCTOU window in the v1 trust-receipts API:
--
--   /api/v1/trust-receipts/{id}/consume       — at most one consume per receipt
--   /api/v1/signoffs/{id}/{approve,reject}    — at most one decision per signoff
--
-- Without these, two concurrent consumes (or two concurrent approvers) can
-- both pass the application-level "has it been done already?" check and
-- both insert audit events. The application code now also catches Postgres
-- SQLSTATE 23505 (unique_violation) and returns HTTP 409 instead of 500.
--
-- Also adds a btree index on after_state->>'signoff_id' for the
-- guard.signoff.requested events so /api/v1/signoffs/{id}/{approve,reject}
-- can filter at the SQL layer instead of scanning the whole partition.

-- ────────────────────────────────────────────────────────────────────────────
-- 1. At most one consume event per receipt
-- ────────────────────────────────────────────────────────────────────────────
CREATE UNIQUE INDEX IF NOT EXISTS guard_receipt_consume_once
  ON audit_events (target_id)
  WHERE event_type = 'guard.trust_receipt.consumed'
    AND target_type = 'trust_receipt';

COMMENT ON INDEX guard_receipt_consume_once IS
  'Enforces one-time consume on /api/v1/trust-receipts/{id}/consume. A second '
  'consume insert raises 23505; the application catches and returns 409.';

-- ────────────────────────────────────────────────────────────────────────────
-- 2. At most one decision per signoff_id
-- ────────────────────────────────────────────────────────────────────────────
CREATE UNIQUE INDEX IF NOT EXISTS guard_signoff_decided_once
  ON audit_events (((after_state ->> 'signoff_id')))
  WHERE event_type IN ('guard.signoff.approved', 'guard.signoff.rejected')
    AND target_type = 'trust_receipt';

COMMENT ON INDEX guard_signoff_decided_once IS
  'Enforces one-time decision per signoff_id on '
  '/api/v1/signoffs/{id}/{approve,reject}. Race winner records the audit '
  'event; loser sees 23505 and returns 409.';

-- ────────────────────────────────────────────────────────────────────────────
-- 3. Helper btree on signoff_id for the request-lookup fast path
-- ────────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS guard_signoff_requested_signoff_id
  ON audit_events (((after_state ->> 'signoff_id')))
  WHERE event_type = 'guard.signoff.requested'
    AND target_type = 'trust_receipt';

COMMENT ON INDEX guard_signoff_requested_signoff_id IS
  'Supports SELECT … WHERE event_type=''guard.signoff.requested'' AND '
  'after_state->>''signoff_id'' = $1 — used by lib/guard-signoff.js. '
  'Avoids a full scan over the requested-event partition at signoff '
  'approve/reject time.';

-- ────────────────────────────────────────────────────────────────────────────
-- 4. Helper btree on target_id for receipt-event timeline reads
-- ────────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS guard_audit_events_by_receipt
  ON audit_events (target_id, created_at)
  WHERE target_type = 'trust_receipt';

COMMENT ON INDEX guard_audit_events_by_receipt IS
  'Supports the GET /api/v1/trust-receipts/{id} and /evidence event-stream '
  'replay queries. Without this, every read pages through the full table.';
