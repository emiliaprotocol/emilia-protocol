-- 094_entity_signing_key_history.sql
-- PIP-006 Federation — key rotation safety. Retired Ed25519 signing keys,
-- advertised as historical_keys in /.well-known/ep-keys.json so pre-rotation
-- receipts remain verifiable. Service-role-only (RLS on, no policy).

CREATE TABLE IF NOT EXISTS entity_signing_key_history (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  entity_id     TEXT NOT NULL,
  public_key    TEXT NOT NULL,
  algorithm     TEXT NOT NULL DEFAULT 'Ed25519',
  activated_at  TIMESTAMPTZ,
  retired_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  retire_reason TEXT NOT NULL DEFAULT 'rotation'
    CHECK (retire_reason IN ('rotation', 'compromise')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_entity_signing_key_history_entity
  ON entity_signing_key_history (entity_id, retired_at DESC);

COMMENT ON TABLE entity_signing_key_history IS
  'PIP-006: retired Ed25519 signing keys, advertised as historical_keys in /.well-known/ep-keys.json so pre-rotation receipts remain verifiable.';

ALTER TABLE entity_signing_key_history ENABLE ROW LEVEL SECURITY;;
