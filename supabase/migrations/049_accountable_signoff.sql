-- ============================================================================
-- Accountable Signoff — Human-in-the-loop approval for high-stakes actions
--
-- Extends EP Handshake with cryptographically bound challenge/response
-- signoff. Each signoff is tied to a handshake binding via binding_hash,
-- ensuring the human approving an action sees the exact same binding
-- material that the protocol will consume.
--
-- Tables:
--   signoff_challenges    — Issued challenges awaiting human response
--   signoff_attestations  — Signed approvals from authenticated humans
--   signoff_consumptions  — One-time consumption proof (insert-or-fail)
-- ============================================================================

-- ============================================================================
-- 1. signoff_challenges
-- ============================================================================

CREATE TABLE IF NOT EXISTS signoff_challenges (
  challenge_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  handshake_id          UUID NOT NULL REFERENCES handshake_bindings(id),
  binding_hash          TEXT NOT NULL,
  accountable_actor_ref TEXT NOT NULL,
  signoff_policy_id     TEXT,
  signoff_policy_hash   TEXT,
  required_assurance    TEXT NOT NULL DEFAULT 'substantial',
  allowed_methods       TEXT[] NOT NULL DEFAULT '{passkey,secure_app,platform_authenticator}',
  issued_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at            TIMESTAMPTZ NOT NULL,
  status                TEXT NOT NULL DEFAULT 'challenge_issued'
                          CHECK (status IN (
                            'challenge_issued',
                            'challenge_viewed',
                            'approved',
                            'denied',
                            'expired',
                            'revoked',
                            'consumed'
                          )),
  metadata              JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_signoff_challenges_handshake
  ON signoff_challenges(handshake_id);

CREATE INDEX idx_signoff_challenges_actor
  ON signoff_challenges(accountable_actor_ref);

COMMENT ON TABLE signoff_challenges IS 'Challenge tokens issued for accountable signoff. Each challenge binds a human actor to a specific handshake binding via binding_hash.';

-- ============================================================================
-- 2. signoff_attestations
-- ============================================================================

CREATE TABLE IF NOT EXISTS signoff_attestations (
  signoff_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  challenge_id      UUID NOT NULL REFERENCES signoff_challenges(challenge_id),
  handshake_id      UUID NOT NULL REFERENCES handshake_bindings(id),
  binding_hash      TEXT NOT NULL,
  human_entity_ref  TEXT NOT NULL,
  auth_method       TEXT NOT NULL,
  assurance_level   TEXT NOT NULL,
  channel           TEXT NOT NULL,
  approved_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at        TIMESTAMPTZ NOT NULL,
  attestation_hash  TEXT NOT NULL,
  status            TEXT NOT NULL DEFAULT 'approved'
                      CHECK (status IN (
                        'approved',
                        'expired',
                        'revoked',
                        'consumed'
                      )),
  metadata          JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_signoff_attestations_challenge
  ON signoff_attestations(challenge_id);

CREATE INDEX idx_signoff_attestations_handshake
  ON signoff_attestations(handshake_id);

COMMENT ON TABLE signoff_attestations IS 'Signed attestations from authenticated humans approving a signoff challenge. Each attestation carries the binding_hash and attestation_hash for cryptographic verification.';

-- ============================================================================
-- 3. signoff_consumptions
-- ============================================================================

CREATE TABLE IF NOT EXISTS signoff_consumptions (
  signoff_consumption_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  signoff_id             UUID NOT NULL UNIQUE REFERENCES signoff_attestations(signoff_id),
  binding_hash           TEXT NOT NULL,
  execution_ref          TEXT NOT NULL,
  consumed_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE signoff_consumptions IS 'One-time consumption proof for signoff attestations. The UNIQUE constraint on signoff_id enforces atomic insert-or-fail semantics.';

-- ============================================================================
-- 4. Append-only enforcement on signoff_challenges
--    (match pattern from 046_handshake_events_immutable.sql)
-- ============================================================================

-- Status progression order for challenges
-- challenge_issued -> challenge_viewed -> approved|denied|expired|revoked -> consumed
-- Forward-only transitions; backward transitions are rejected.

CREATE OR REPLACE FUNCTION prevent_signoff_challenge_backward_status()
RETURNS TRIGGER AS $$
DECLARE
  old_rank INTEGER;
  new_rank INTEGER;
BEGIN
  -- Assign ordinal ranks to statuses
  old_rank := CASE OLD.status
    WHEN 'challenge_issued' THEN 0
    WHEN 'challenge_viewed' THEN 1
    WHEN 'approved'         THEN 2
    WHEN 'denied'           THEN 2
    WHEN 'expired'          THEN 2
    WHEN 'revoked'          THEN 2
    WHEN 'consumed'         THEN 3
  END;
  new_rank := CASE NEW.status
    WHEN 'challenge_issued' THEN 0
    WHEN 'challenge_viewed' THEN 1
    WHEN 'approved'         THEN 2
    WHEN 'denied'           THEN 2
    WHEN 'expired'          THEN 2
    WHEN 'revoked'          THEN 2
    WHEN 'consumed'         THEN 3
  END;

  IF new_rank < old_rank THEN
    RAISE EXCEPTION 'SIGNOFF_STATUS_REGRESSION: Cannot move signoff_challenge % from % to %',
      OLD.challenge_id, OLD.status, NEW.status;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_signoff_challenge_status_forward
  BEFORE UPDATE ON signoff_challenges
  FOR EACH ROW EXECUTE FUNCTION prevent_signoff_challenge_backward_status();

CREATE OR REPLACE FUNCTION prevent_signoff_challenge_delete()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'SIGNOFF_IMMUTABILITY_VIOLATION: signoff_challenges is append-only. Cannot DELETE challenge %',
    OLD.challenge_id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_signoff_challenges_no_delete
  BEFORE DELETE ON signoff_challenges
  FOR EACH ROW EXECUTE FUNCTION prevent_signoff_challenge_delete();

-- ============================================================================
-- 5. Append-only enforcement on signoff_attestations
--    (match pattern from 046_handshake_events_immutable.sql)
-- ============================================================================

CREATE OR REPLACE FUNCTION prevent_signoff_attestation_backward_status()
RETURNS TRIGGER AS $$
DECLARE
  old_rank INTEGER;
  new_rank INTEGER;
BEGIN
  old_rank := CASE OLD.status
    WHEN 'approved' THEN 0
    WHEN 'expired'  THEN 1
    WHEN 'revoked'  THEN 1
    WHEN 'consumed' THEN 2
  END;
  new_rank := CASE NEW.status
    WHEN 'approved' THEN 0
    WHEN 'expired'  THEN 1
    WHEN 'revoked'  THEN 1
    WHEN 'consumed' THEN 2
  END;

  IF new_rank < old_rank THEN
    RAISE EXCEPTION 'SIGNOFF_STATUS_REGRESSION: Cannot move signoff_attestation % from % to %',
      OLD.signoff_id, OLD.status, NEW.status;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_signoff_attestation_status_forward
  BEFORE UPDATE ON signoff_attestations
  FOR EACH ROW EXECUTE FUNCTION prevent_signoff_attestation_backward_status();

CREATE OR REPLACE FUNCTION prevent_signoff_attestation_delete()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'SIGNOFF_IMMUTABILITY_VIOLATION: signoff_attestations is append-only. Cannot DELETE attestation %',
    OLD.signoff_id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_signoff_attestations_no_delete
  BEFORE DELETE ON signoff_attestations
  FOR EACH ROW EXECUTE FUNCTION prevent_signoff_attestation_delete();

-- ============================================================================
-- 6. Consumption reversal prevention on signoff_consumptions
--    (match pattern from 045_consumption_enforcement.sql)
-- ============================================================================

CREATE OR REPLACE FUNCTION prevent_signoff_consumption_reversal()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS NULL THEN
    RAISE EXCEPTION 'SIGNOFF_CONSUMPTION_IRREVERSIBLE: Cannot clear consumed_at once set on signoff_consumption %',
      OLD.signoff_consumption_id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_signoff_consumption_irreversible
  BEFORE UPDATE ON signoff_consumptions
  FOR EACH ROW
  EXECUTE FUNCTION prevent_signoff_consumption_reversal();

-- ============================================================================
-- Summary
-- ============================================================================
-- Tables:
--   signoff_challenges    — challenge tokens bound to handshake bindings
--   signoff_attestations  — human-signed approvals with attestation_hash
--   signoff_consumptions  — one-time consumption (UNIQUE on signoff_id)
--
-- Indexes:
--   idx_signoff_challenges_handshake   — lookup by handshake_id
--   idx_signoff_challenges_actor       — lookup by accountable_actor_ref
--   idx_signoff_attestations_challenge — lookup by challenge_id
--   idx_signoff_attestations_handshake — lookup by handshake_id
--
-- Triggers:
--   enforce_signoff_challenge_status_forward     — no backward status transitions
--   enforce_signoff_challenges_no_delete         — append-only
--   enforce_signoff_attestation_status_forward   — no backward status transitions
--   enforce_signoff_attestations_no_delete       — append-only
--   enforce_signoff_consumption_irreversible     — consumed_at is permanent
