-- Fix handshake_events check constraint to match actual event types used in code.
-- The code uses short names (initiated, presentation_added, verified, etc.)
-- while the original constraint used prefixed names (handshake_created, etc.).
-- Allow both to avoid breaking existing records.

ALTER TABLE handshake_events DROP CONSTRAINT IF EXISTS handshake_events_event_type_check;

ALTER TABLE handshake_events ADD CONSTRAINT handshake_events_event_type_check
  CHECK (event_type = ANY (ARRAY[
    -- Original prefixed names (existing records use these)
    'handshake_created',
    'handshake_presented',
    'handshake_verification_started',
    'handshake_verified',
    'handshake_rejected',
    'handshake_expired',
    'handshake_cancelled',
    'handshake_revoked',
    -- Short names used by application code
    'initiated',
    'presentation_added',
    'status_changed',
    'verified',
    'rejected',
    'expired',
    'revoked'
  ]));
