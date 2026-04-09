-- 079_signoff_attestation_consumption_guard.sql
--
-- Defense-in-depth: partial unique index on signoff_attestations matching
-- the handshake_bindings consumption guard pattern (migration 065).
--
-- Context
-- -------
-- signoff_consumptions already has a UNIQUE constraint on signoff_id, which
-- enforces one-time-use at the insert level inside consume_signoff_atomic.
-- Under concurrent execution, two requests may both pass the JS-side
-- attestation status check before either reaches the RPC. The RPC's
-- INSERT INTO signoff_consumptions (step 2) resolves the race — only the
-- first succeeds; the second rolls back the entire transaction.
--
-- However, signoff_attestations has no DB-level guard preventing its status
-- column from being set to 'consumed' outside the RPC (e.g., a direct UPDATE,
-- a future migration, or an admin tooling path). Without a constraint on the
-- attestation row itself, the signoff_consumptions guard is the only line of
-- defense.
--
-- Fix
-- ---
-- A partial UNIQUE index on signoff_attestations(signoff_id) WHERE status = 'consumed'
-- prevents any code path from marking the same attestation consumed more than
-- once at the DB level, independently of the signoff_consumptions guard.
--
-- This mirrors migration 065 for handshake_bindings exactly:
--
--   065: idx_handshake_binding_consumed  ON handshake_bindings(handshake_id)    WHERE consumed_at IS NOT NULL
--   079: idx_signoff_attestation_consumed ON signoff_attestations(signoff_id)   WHERE status = 'consumed'
--
-- The existing forward-only status trigger (prevent_signoff_attestation_backward_status,
-- migration 049) already prevents 'consumed' from being unwound. This index
-- adds the symmetric guarantee: 'consumed' can only be written once.

CREATE UNIQUE INDEX IF NOT EXISTS idx_signoff_attestation_consumed
  ON signoff_attestations(signoff_id)
  WHERE status = 'consumed';

COMMENT ON INDEX idx_signoff_attestation_consumed IS
  'Partial unique index: enforces one-time-use consumption of signoff attestations '
  'at the DB level. A signoff_id may enter the consumed state exactly once. Any '
  'concurrent or subsequent attempt to set status = ''consumed'' for the same '
  'signoff_id will fail with a unique constraint violation. Mirrors the handshake '
  'binding consumption guard (migration 065).';
