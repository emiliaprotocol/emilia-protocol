-- Migration 123: guarded_receipt_consumptions
--
-- One-time consumption ledger for the /api/v1/guarded reference DEMAND route.
-- A verified EMILIA receipt authorizes ONE action, once. The route records the
-- receipt identifier the first time it passes verification; any later
-- presentation of the same receipt is a replay and is refused.
--
-- The UNIQUE constraint on (receipt_id, action) is the atomic replay primitive:
-- `INSERT ... ON CONFLICT DO NOTHING` inserts iff absent, so a second (possibly
-- concurrent, cross-pod) presentation loses the race and is rejected. This is
-- the same reserve→commit contract as packages/gate/store.js, made durable so a
-- receipt consumed on one instance can't be replayed on another.

CREATE TABLE IF NOT EXISTS guarded_receipt_consumptions (
  id BIGSERIAL PRIMARY KEY,
  -- Composite key of the consumption: receipt id scoped to the demanded action.
  consume_key TEXT NOT NULL,
  -- Lifecycle state: 'reserved' while the action is in flight, 'committed' once
  -- verification succeeded. A row in either state blocks replay.
  state TEXT NOT NULL DEFAULT 'reserved',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_guarded_receipt_consume_key UNIQUE (consume_key)
);

COMMENT ON TABLE guarded_receipt_consumptions IS
  'One-time consumption ledger for /api/v1/guarded — refuses receipt replay.';
COMMENT ON COLUMN guarded_receipt_consumptions.consume_key IS
  'sha256(action + ":" + receipt_id) — the replay-defense key.';
COMMENT ON COLUMN guarded_receipt_consumptions.state IS
  'reserved (in flight) or committed (action authorized). Either blocks replay.';
