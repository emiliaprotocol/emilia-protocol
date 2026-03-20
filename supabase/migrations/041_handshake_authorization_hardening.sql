-- EP Handshake Authorization Hardening
-- Adds remaining columns, constraints, and indexes from audit findings
-- for authorization-layer support.

-- ============================================================================
-- 1. Action hash + policy hash on handshake_bindings
--    Per-binding action verification (distinct from handshakes-level hashes)
-- ============================================================================

ALTER TABLE handshake_bindings
  ADD COLUMN IF NOT EXISTS action_hash TEXT,
  ADD COLUMN IF NOT EXISTS policy_hash TEXT;

COMMENT ON COLUMN handshake_bindings.action_hash IS 'SHA-256 of the bound action — verifies the binding targets the intended action';
COMMENT ON COLUMN handshake_bindings.policy_hash IS 'SHA-256 of the policy snapshot at binding time — detects policy drift between binding and consumption';

-- ============================================================================
-- 2. Actor tracking on handshake_events
--    actor_entity_ref provides a stable entity reference (vs actor_id which
--    may be an opaque session/token id). detail captures structured context.
-- ============================================================================

ALTER TABLE handshake_events
  ADD COLUMN IF NOT EXISTS actor_entity_ref TEXT,
  ADD COLUMN IF NOT EXISTS detail JSONB DEFAULT '{}';

COMMENT ON COLUMN handshake_events.actor_entity_ref IS 'Stable entity reference of the actor that triggered the event';
COMMENT ON COLUMN handshake_events.detail IS 'Structured detail payload for authorization-relevant context';

-- ============================================================================
-- 3. Composite index for party-membership authorization checks
--    Queries of the form "is entity X a party to handshake Y?" need
--    entity_ref leading for fast lookups across handshakes.
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_handshake_parties_entity_lookup
  ON handshake_parties (entity_ref, handshake_id);

-- ============================================================================
-- 4. Index for handshake_events by handshake_id + created_at
--    NOTE: migration 037 already created idx_handshake_events_handshake_created
--    with the same column pair. We skip this to avoid a redundant index.
-- ============================================================================

-- (already covered by idx_handshake_events_handshake_created from 037)

-- ============================================================================
-- 5. Unique active presentation guard
--    Prevents duplicate active presentations for the same
--    handshake + party role + presentation type combination.
-- ============================================================================

CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_active_presentation
  ON handshake_presentations (handshake_id, party_role, presentation_type);
