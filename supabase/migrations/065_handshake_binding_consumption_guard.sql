-- 065_handshake_binding_consumption_guard.sql
--
-- Closes the TOCTOU double-consumption race in handshake_bindings.
--
-- Context
-- -------
-- The existing trigger (045_consumption_enforcement.sql) prevents consumed_at
-- from being *cleared* once set, but does not prevent two concurrent transactions
-- from both reading consumed_at IS NULL, both passing the application-layer guard,
-- and both executing the UPDATE that sets consumed_at.
--
-- The TLA+ spec formally proves HandshakeNeverConsumedTwice (T14), but that proof
-- covers the single-writer model. Under concurrent HTTP requests, the race window
-- between the SELECT ... WHERE consumed_at IS NULL and the UPDATE ... SET consumed_at
-- is real and exploitable.
--
-- Fix
-- ---
-- A partial UNIQUE index on (handshake_id) WHERE consumed_at IS NOT NULL causes
-- the second UPDATE to violate the constraint at the storage level, before it can
-- commit. Combined with the existing UNIQUE constraint on handshake_id itself
-- (one row per handshake), this means:
--
--   1. First consumer: reads consumed_at IS NULL, UPDATE succeeds, row now has
--      consumed_at = now(). The partial index gains one entry for this handshake_id.
--
--   2. Concurrent second consumer: also read consumed_at IS NULL (before first
--      commit was visible), attempts UPDATE. Postgres evaluates the partial index
--      and finds that handshake_id already has a row satisfying WHERE consumed_at
--      IS NOT NULL → unique violation → UPDATE aborted → transaction rolls back.
--
-- The verify_handshake_writes RPC (migration 060) already uses serializable
-- semantics for the binding consume step. This index adds defense-in-depth at
-- the constraint level regardless of transaction isolation mode.

CREATE UNIQUE INDEX IF NOT EXISTS idx_handshake_binding_consumed
  ON handshake_bindings(handshake_id)
  WHERE consumed_at IS NOT NULL;

COMMENT ON INDEX idx_handshake_binding_consumed IS
  'Partial unique index: enforces one-time-use consumption at the DB level. '
  'A handshake_id may appear in the consumed state (consumed_at IS NOT NULL) '
  'exactly once. Concurrent UPDATE attempts on the same row will fail with a '
  'unique constraint violation rather than succeeding silently.';
