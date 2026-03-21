-- ============================================================================
-- Signoff Events — Append-only audit log for signoff lifecycle
--
-- Follows the handshake_events pattern (037 + 046) as a dedicated event
-- table for the signoff subsystem. Signoff events reference both the
-- handshake_id and the specific signoff entity (challenge/attestation)
-- so that audit queries can reconstruct the full timeline.
-- ============================================================================

-- ============================================================================
-- 1. Create the signoff_events table
-- ============================================================================

CREATE TABLE IF NOT EXISTS signoff_events (
  event_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  handshake_id      UUID NOT NULL REFERENCES handshake_bindings(id),
  event_type        TEXT NOT NULL CHECK (event_type IN (
                      -- Challenge lifecycle
                      'challenge_issued',
                      'challenge_viewed',
                      'challenge_expired',
                      'challenge_revoked',
                      -- Attestation lifecycle
                      'signoff_approved',
                      'signoff_denied',
                      'signoff_expired',
                      'signoff_revoked',
                      -- Consumption
                      'signoff_consumed'
                    )),
  challenge_id      UUID REFERENCES signoff_challenges(challenge_id),
  signoff_id        UUID REFERENCES signoff_attestations(signoff_id),
  actor_entity_ref  TEXT,
  binding_hash      TEXT,
  detail            JSONB NOT NULL DEFAULT '{}'::jsonb,
  idempotency_key   TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- 2. Indexes
-- ============================================================================

-- Chronological lookup per handshake (join with handshake_events for full timeline)
CREATE INDEX idx_signoff_events_handshake_created
  ON signoff_events(handshake_id, created_at);

-- Filter by event type across all signoffs
CREATE INDEX idx_signoff_events_type
  ON signoff_events(event_type);

-- Lookup by challenge
CREATE INDEX idx_signoff_events_challenge
  ON signoff_events(challenge_id);

-- Lookup by attestation
CREATE INDEX idx_signoff_events_signoff
  ON signoff_events(signoff_id);

-- Idempotency guard: only one row per non-null idempotency_key
CREATE UNIQUE INDEX idx_signoff_events_idempotency
  ON signoff_events(idempotency_key)
  WHERE idempotency_key IS NOT NULL;

-- ============================================================================
-- 3. Append-only enforcement
--    (match pattern from 046_handshake_events_immutable.sql)
-- ============================================================================

CREATE OR REPLACE FUNCTION prevent_signoff_event_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'EVENT_IMMUTABILITY_VIOLATION: signoff_events is append-only. Cannot % event %',
    TG_OP, COALESCE(OLD.event_id::text, 'unknown');
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_signoff_events_no_update
  BEFORE UPDATE ON signoff_events
  FOR EACH ROW EXECUTE FUNCTION prevent_signoff_event_mutation();

CREATE TRIGGER enforce_signoff_events_no_delete
  BEFORE DELETE ON signoff_events
  FOR EACH ROW EXECUTE FUNCTION prevent_signoff_event_mutation();

COMMENT ON TABLE signoff_events IS 'Append-only event store for signoff lifecycle. Once written, events can NEVER be updated or deleted. This is enforced at the database level by triggers. Join with handshake_events on handshake_id for the complete handshake + signoff timeline.';

-- ============================================================================
-- Summary
-- ============================================================================
-- Table:
--   signoff_events — append-only audit log for challenge/attestation/consumption
--
-- Event types:
--   challenge_issued, challenge_viewed, challenge_expired, challenge_revoked
--   signoff_approved, signoff_denied, signoff_expired, signoff_revoked
--   signoff_consumed
--
-- Indexes:
--   idx_signoff_events_handshake_created — chronological per handshake
--   idx_signoff_events_type             — filter by event type
--   idx_signoff_events_challenge        — lookup by challenge
--   idx_signoff_events_signoff          — lookup by attestation
--   idx_signoff_events_idempotency      — dedup guard
--
-- Triggers:
--   enforce_signoff_events_no_update    — prevent mutation
--   enforce_signoff_events_no_delete    — prevent deletion
