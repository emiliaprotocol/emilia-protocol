-- EP Canonical Binding Material — party_set_hash, context_hash, binding_hash, binding_material_version
-- Critical Finding 5: Adds canonical binding material columns for cryptographic handshake integrity.

ALTER TABLE handshake_bindings
  ADD COLUMN IF NOT EXISTS party_set_hash TEXT,
  ADD COLUMN IF NOT EXISTS context_hash TEXT,
  ADD COLUMN IF NOT EXISTS binding_hash TEXT,
  ADD COLUMN IF NOT EXISTS binding_material_version INTEGER DEFAULT 1;

ALTER TABLE handshakes
  ADD COLUMN IF NOT EXISTS party_set_hash TEXT;

COMMENT ON COLUMN handshake_bindings.party_set_hash IS 'SHA-256 of sorted party role:entity_ref pairs';
COMMENT ON COLUMN handshake_bindings.context_hash IS 'SHA-256 of action context (action_type, resource_ref, policy_id, etc.)';
COMMENT ON COLUMN handshake_bindings.binding_hash IS 'SHA-256 of full canonical binding material';
COMMENT ON COLUMN handshake_bindings.binding_material_version IS 'Version of the binding material schema';

CREATE INDEX IF NOT EXISTS idx_handshake_bindings_binding_hash
  ON handshake_bindings (binding_hash);
