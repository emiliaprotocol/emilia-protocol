-- Add consumed_by_action field per LOCK 100 B.1 specification
-- Records WHAT action the consumption was for (e.g., 'commit_issue', 'trust_gate')
ALTER TABLE handshake_consumptions
  ADD COLUMN IF NOT EXISTS consumed_by_action TEXT;

-- Add initiator_entity_ref to handshake_bindings for audit
-- Records WHO initiated the handshake (distinct from party_set_hash which covers all parties)
ALTER TABLE handshake_bindings
  ADD COLUMN IF NOT EXISTS initiator_entity_ref TEXT;

-- Optional composite unique: same binding can't be consumed for the same action type twice
-- (different from the existing handshake_id unique which prevents ANY reuse)
-- This is defense-in-depth alongside the existing unique(handshake_id)
CREATE UNIQUE INDEX IF NOT EXISTS idx_consumption_binding_action
  ON handshake_consumptions(binding_hash, consumed_by_action)
  WHERE consumed_by_action IS NOT NULL;
