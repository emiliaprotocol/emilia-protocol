-- Add consumed_by_action field per LOCK 100 B.1 specification
-- Records WHAT action the consumption was for (e.g., 'commit_issue', 'trust_gate')
-- Replay-safe: handshake_consumptions was historically created later (091) but is
-- referenced here and in 074. Create the canonical table now (IF NOT EXISTS, so 091
-- and any environment that already has it are unaffected) so a from-scratch replay
-- has it in dependency order.
CREATE TABLE IF NOT EXISTS handshake_consumptions (
  id BIGSERIAL PRIMARY KEY,
  handshake_id UUID NOT NULL REFERENCES handshakes(handshake_id),
  binding_hash TEXT NOT NULL,
  consumed_by_type TEXT NOT NULL,
  consumed_by_id TEXT NOT NULL,
  consumed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_entity_ref TEXT,
  CONSTRAINT uq_handshake_consumption UNIQUE (handshake_id)
);

ALTER TABLE handshake_consumptions
  ADD COLUMN IF NOT EXISTS consumed_by_action TEXT;
-- Optional composite unique: same binding can't be consumed for the same action twice.
CREATE UNIQUE INDEX IF NOT EXISTS idx_consumption_binding_action
  ON handshake_consumptions(binding_hash, consumed_by_action)
  WHERE consumed_by_action IS NOT NULL;

-- Add initiator_entity_ref to handshake_bindings for audit
-- Records WHO initiated the handshake (distinct from party_set_hash which covers all parties)
ALTER TABLE handshake_bindings
  ADD COLUMN IF NOT EXISTS initiator_entity_ref TEXT;
