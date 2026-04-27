-- EP Handshake Consumptions — One-time authorization enforcement
-- Ensures each accepted handshake can only be consumed exactly once
-- by a downstream action.

CREATE TABLE IF NOT EXISTS handshake_consumptions (
  id BIGSERIAL PRIMARY KEY,
  handshake_id UUID NOT NULL REFERENCES handshakes(handshake_id),
  binding_hash TEXT NOT NULL,
  consumed_by_type TEXT NOT NULL,   -- e.g. 'commit_issue', 'trust_gate', 'action_execute'
  consumed_by_id TEXT NOT NULL,     -- ID of the consuming artifact (commit_id, gate_decision_id, etc.)
  consumed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_entity_ref TEXT,
  CONSTRAINT uq_handshake_consumption UNIQUE (handshake_id)
);

-- Optional: unique on binding_hash within scope
CREATE UNIQUE INDEX IF NOT EXISTS idx_handshake_consumptions_binding
  ON handshake_consumptions (binding_hash);

COMMENT ON TABLE handshake_consumptions IS 'One-time consumption records for handshake authorization artifacts';
COMMENT ON COLUMN handshake_consumptions.consumed_by_type IS 'Type of downstream action that consumed this handshake';
COMMENT ON COLUMN handshake_consumptions.consumed_by_id IS 'ID of the downstream artifact';
