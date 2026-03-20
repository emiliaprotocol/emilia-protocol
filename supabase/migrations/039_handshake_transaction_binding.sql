-- EP Handshake hardening: transaction binding + replay resistance
-- Audit findings 4, 5, 6

-- Add action binding fields to handshakes
ALTER TABLE handshakes
  ADD COLUMN IF NOT EXISTS action_type TEXT,
  ADD COLUMN IF NOT EXISTS resource_ref TEXT,
  ADD COLUMN IF NOT EXISTS intent_ref TEXT,
  ADD COLUMN IF NOT EXISTS policy_hash TEXT,
  ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

-- Add unique constraint on idempotency_key (NULL values are allowed)
CREATE UNIQUE INDEX IF NOT EXISTS uq_handshakes_idempotency_key
  ON handshakes (idempotency_key) WHERE idempotency_key IS NOT NULL;

-- Add unique constraint on binding nonce for replay resistance
ALTER TABLE handshake_bindings
  ADD CONSTRAINT uq_handshake_bindings_nonce UNIQUE (nonce);

-- Add consumed state columns to bindings
ALTER TABLE handshake_bindings
  ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS consumed_by TEXT,
  ADD COLUMN IF NOT EXISTS consumed_for TEXT;

-- Add policy/binding hash to results
ALTER TABLE handshake_results
  ADD COLUMN IF NOT EXISTS binding_hash TEXT,
  ADD COLUMN IF NOT EXISTS policy_hash TEXT,
  ADD COLUMN IF NOT EXISTS finalized_at TIMESTAMPTZ DEFAULT now();
