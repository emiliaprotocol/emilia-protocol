-- EP Handshake Events — Immutable audit log for handshake lifecycle transitions.
-- Every state change or significant action on a handshake is recorded here,
-- enabling full replay, debugging, and compliance auditing.

-- ============================================================================
-- 1. Create the handshake_events table
-- ============================================================================

CREATE TABLE IF NOT EXISTS handshake_events (
  event_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  handshake_id     UUID NOT NULL REFERENCES handshakes(handshake_id) ON DELETE CASCADE,
  event_type       TEXT NOT NULL CHECK (event_type IN (
                     'handshake_created',
                     'handshake_presented',
                     'handshake_verification_started',
                     'handshake_verified',
                     'handshake_rejected',
                     'handshake_expired',
                     'handshake_cancelled',
                     'handshake_revoked'
                   )),
  event_payload    JSONB NOT NULL DEFAULT '{}'::jsonb,
  actor_id         TEXT,
  idempotency_key  TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- 2. Indexes
-- ============================================================================

-- Chronological lookup per handshake (the most common query pattern)
CREATE INDEX idx_handshake_events_handshake_created
  ON handshake_events (handshake_id, created_at);

-- Filter by event type across all handshakes
CREATE INDEX idx_handshake_events_type
  ON handshake_events (event_type);

-- Idempotency guard: only one row per non-null idempotency_key
CREATE UNIQUE INDEX idx_handshake_events_idempotency
  ON handshake_events (idempotency_key)
  WHERE idempotency_key IS NOT NULL;

-- ============================================================================
-- 3. Add idempotency_key to handshakes table
-- ============================================================================

ALTER TABLE handshakes
  ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_handshakes_idempotency
  ON handshakes (idempotency_key)
  WHERE idempotency_key IS NOT NULL;
