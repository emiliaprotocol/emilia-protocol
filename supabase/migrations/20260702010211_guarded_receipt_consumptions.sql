-- Migration 123: guarded_receipt_consumptions
-- One-time consumption ledger for the /api/v1/guarded reference DEMAND route.
-- A verified EMILIA receipt authorizes ONE action, once. Durable so a receipt
-- consumed on one instance can't be replayed on another (cross-pod).
CREATE TABLE IF NOT EXISTS guarded_receipt_consumptions (
  id BIGSERIAL PRIMARY KEY,
  consume_key TEXT NOT NULL,
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
  'reserved (in flight) or committed (action authorized). Either blocks replay.';;
