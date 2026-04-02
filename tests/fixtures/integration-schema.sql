-- =============================================================================
-- EMILIA Protocol — Integration Test Schema
-- Minimal self-contained schema for critical DB constraint tests.
-- Uses plain Postgres (no pgvector, no Supabase auth).
-- Tests: append-only receipts, consumption irreversibility, signoff consume-once,
--        forward-only signoff status transitions.
-- =============================================================================

-- ── Receipts (append-only ledger) ────────────────────────────────────────────

CREATE TABLE receipts (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id         TEXT NOT NULL,
  submitted_by      TEXT NOT NULL,
  composite_score   FLOAT NOT NULL CHECK (composite_score BETWEEN 0 AND 100),
  receipt_hash      TEXT NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Hard gate: receipts are immutable — no updates, no deletes.
CREATE OR REPLACE FUNCTION prevent_receipt_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'RECEIPT_IMMUTABLE: receipts are append-only. id=%', OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_receipt_immutable_update
  BEFORE UPDATE ON receipts
  FOR EACH ROW EXECUTE FUNCTION prevent_receipt_mutation();

CREATE TRIGGER enforce_receipt_immutable_delete
  BEFORE DELETE ON receipts
  FOR EACH ROW EXECUTE FUNCTION prevent_receipt_mutation();

-- ── Entities (minimal — needed as FK target) ──────────────────────────────────

CREATE TABLE entities (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id  TEXT UNIQUE NOT NULL,
  status     TEXT NOT NULL DEFAULT 'active'
);

-- ── Handshakes ────────────────────────────────────────────────────────────────

CREATE TABLE handshakes (
  handshake_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nonce        TEXT NOT NULL UNIQUE,
  status       TEXT NOT NULL DEFAULT 'initiated'
                 CHECK (status IN ('initiated', 'presented', 'verified', 'consumed', 'revoked', 'expired')),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE handshake_bindings (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  handshake_id  UUID NOT NULL REFERENCES handshakes(handshake_id) UNIQUE,
  payload_hash  TEXT NOT NULL,
  nonce         TEXT NOT NULL,
  expires_at    TIMESTAMPTZ NOT NULL,
  consumed_at   TIMESTAMPTZ,
  bound_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Hard gate: once consumed_at is set it can never be cleared.
-- Mirrors migration 045_consumption_enforcement.sql.
CREATE OR REPLACE FUNCTION prevent_consumption_reversal()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS NULL THEN
    RAISE EXCEPTION 'CONSUMPTION_IRREVERSIBLE: Cannot clear consumed_at once set on binding %', OLD.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_consumption_irreversible
  BEFORE UPDATE ON handshake_bindings
  FOR EACH ROW EXECUTE FUNCTION prevent_consumption_reversal();

-- ── Accountable Signoff ───────────────────────────────────────────────────────

CREATE TABLE signoff_challenges (
  challenge_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  handshake_id UUID NOT NULL REFERENCES handshake_bindings(id),
  binding_hash TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'challenge_issued'
                 CHECK (status IN (
                   'challenge_issued', 'challenge_viewed', 'approved',
                   'denied', 'expired', 'revoked', 'consumed'
                 )),
  expires_at   TIMESTAMPTZ NOT NULL,
  issued_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Forward-only status transitions. Mirrors migration 049_accountable_signoff.sql.
CREATE OR REPLACE FUNCTION prevent_signoff_challenge_backward_status()
RETURNS TRIGGER AS $$
DECLARE
  old_rank INTEGER;
  new_rank INTEGER;
BEGIN
  old_rank := CASE OLD.status
    WHEN 'challenge_issued' THEN 0
    WHEN 'challenge_viewed' THEN 1
    WHEN 'approved'         THEN 2
    WHEN 'denied'           THEN 2
    WHEN 'expired'          THEN 2
    WHEN 'revoked'          THEN 2
    WHEN 'consumed'         THEN 3
    ELSE 99
  END;
  new_rank := CASE NEW.status
    WHEN 'challenge_issued' THEN 0
    WHEN 'challenge_viewed' THEN 1
    WHEN 'approved'         THEN 2
    WHEN 'denied'           THEN 2
    WHEN 'expired'          THEN 2
    WHEN 'revoked'          THEN 2
    WHEN 'consumed'         THEN 3
    ELSE 99
  END;
  IF new_rank < old_rank THEN
    RAISE EXCEPTION 'SIGNOFF_BACKWARD_TRANSITION: Cannot move challenge % from % (rank %) to % (rank %)',
      OLD.challenge_id, OLD.status, old_rank, NEW.status, new_rank;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_signoff_challenge_forward_only
  BEFORE UPDATE ON signoff_challenges
  FOR EACH ROW EXECUTE FUNCTION prevent_signoff_challenge_backward_status();

CREATE TABLE signoff_attestations (
  signoff_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  challenge_id  UUID NOT NULL REFERENCES signoff_challenges(challenge_id),
  handshake_id  UUID NOT NULL REFERENCES handshake_bindings(id),
  binding_hash  TEXT NOT NULL,
  auth_method   TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'approved'
                  CHECK (status IN ('approved', 'expired', 'revoked', 'consumed')),
  approved_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ NOT NULL DEFAULT now() + interval '1 hour'
);

-- One-time consumption proof: UNIQUE on signoff_id enforces insert-or-fail.
-- Mirrors migration 049_accountable_signoff.sql.
CREATE TABLE signoff_consumptions (
  signoff_consumption_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  signoff_id             UUID NOT NULL UNIQUE REFERENCES signoff_attestations(signoff_id),
  binding_hash           TEXT NOT NULL,
  execution_ref          TEXT NOT NULL,
  consumed_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Fraud flags (for sybil partial-failure logging) ──────────────────────────

CREATE TABLE fraud_flags (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id  TEXT NOT NULL,
  reason     TEXT NOT NULL,
  metadata   JSONB DEFAULT '{}'::jsonb,
  flagged_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
