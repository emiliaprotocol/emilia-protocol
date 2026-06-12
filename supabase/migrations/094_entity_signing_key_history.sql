-- 094_entity_signing_key_history.sql
--
-- PIP-006 Federation — key rotation safety.
--
-- When an operator rotates the Ed25519 signing key it uses to issue
-- EP-RECEIPT-v1 documents, receipts signed under the OLD key must remain
-- verifiable by relying parties (PIP-006 §"Security considerations" → Key
-- rotation). To make that possible without contacting the issuer, the operator
-- advertises retired keys in /.well-known/ep-keys.json under `historical_keys`.
--
-- This table is the source of truth for those retired keys. It is distinct from
-- 064_key_rotation.sql, which rotates `api_keys` (bearer access tokens) — those
-- are NOT signing keys and are never advertised for verification.
--
-- The table is empty until the first signing-key rotation occurs; the discovery
-- endpoint reads from it, so the `historical_keys` surface is real and wired,
-- not a placeholder.

CREATE TABLE IF NOT EXISTS entity_signing_key_history (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  entity_id     TEXT NOT NULL,
  -- The retired key, stored exactly as advertised: base64url SPKI DER, Ed25519.
  public_key    TEXT NOT NULL,
  algorithm     TEXT NOT NULL DEFAULT 'Ed25519',
  -- When this key became the entity's active signing key, and when it retired.
  activated_at  TIMESTAMPTZ,
  retired_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Why it retired: 'rotation' (planned) vs 'compromise' (emergency). A key
  -- retired for compromise stays advertised so old receipts verify, but a
  -- relying party MAY choose to distrust receipts signed near the compromise.
  retire_reason TEXT NOT NULL DEFAULT 'rotation'
    CHECK (retire_reason IN ('rotation', 'compromise')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Discovery reads all retired keys for an entity, newest first.
CREATE INDEX IF NOT EXISTS idx_entity_signing_key_history_entity
  ON entity_signing_key_history (entity_id, retired_at DESC);

COMMENT ON TABLE entity_signing_key_history IS
  'PIP-006: retired Ed25519 signing keys, advertised as historical_keys in /.well-known/ep-keys.json so pre-rotation receipts remain verifiable.';

-- Service-role-only table: enable RLS with no policy so anon/authenticated are
-- denied by default. The app reaches this exclusively via getGuardedClient()
-- (service role), which bypasses RLS.
ALTER TABLE entity_signing_key_history ENABLE ROW LEVEL SECURITY;
