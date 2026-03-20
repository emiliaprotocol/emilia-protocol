-- ============================================================================
-- Make handshake_events append-only (match protocol_events enforcement)
--
-- Once an event is written, it can NEVER be updated or deleted.
-- This is a database-level guarantee, not application convention.
-- ============================================================================

-- Add columns used by lightweight event emission (actor_entity_ref, detail)
-- that were not in the original 037 schema.
ALTER TABLE handshake_events
  ADD COLUMN IF NOT EXISTS actor_entity_ref TEXT,
  ADD COLUMN IF NOT EXISTS detail JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Relax the event_type CHECK constraint to accept the lightweight event types
-- used by the application code (initiated, presentation_added, status_changed,
-- verified, rejected, expired, revoked) in addition to the original formal types.
ALTER TABLE handshake_events DROP CONSTRAINT IF EXISTS handshake_events_event_type_check;
ALTER TABLE handshake_events ADD CONSTRAINT handshake_events_event_type_check
  CHECK (event_type IN (
    -- Original formal types
    'handshake_created',
    'handshake_presented',
    'handshake_verification_started',
    'handshake_verified',
    'handshake_rejected',
    'handshake_expired',
    'handshake_cancelled',
    'handshake_revoked',
    -- Lightweight event types used by handlers
    'initiated',
    'presentation_added',
    'status_changed',
    'verified',
    'rejected',
    'expired',
    'revoked'
  ));

-- Prevent mutations on handshake_events
CREATE OR REPLACE FUNCTION prevent_handshake_event_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'EVENT_IMMUTABILITY_VIOLATION: handshake_events is append-only. Cannot % event %',
    TG_OP, COALESCE(OLD.event_id::text, 'unknown');
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_handshake_events_no_update
  BEFORE UPDATE ON handshake_events
  FOR EACH ROW EXECUTE FUNCTION prevent_handshake_event_mutation();

CREATE TRIGGER enforce_handshake_events_no_delete
  BEFORE DELETE ON handshake_events
  FOR EACH ROW EXECUTE FUNCTION prevent_handshake_event_mutation();

COMMENT ON TABLE handshake_events IS 'Append-only event store for handshake lifecycle. Once written, events can NEVER be updated or deleted. This is enforced at the database level by triggers.';
