-- EMILIA Protocol — Migration 029: EP Commit (Signed Pre-Action Authorization)
--
-- An EP Commit is a signed authorization token proving that a machine action was
-- evaluated under policy BEFORE the action proceeded. It is the pre-action
-- counterpart to a receipt (post-action record).
--
-- State machine:
--   active → fulfilled   (action completed successfully)
--   active → revoked     (policy change, abuse discovered, manual revocation)
--   active → expired     (automatic when current_time > expires_at)
--
-- Terminal states (fulfilled, revoked, expired) allow NO further transitions.
-- A fulfilled commit's RECEIPT can be disputed, but the commit status itself
-- stays fulfilled — the commit proved evaluation happened.
--
-- EP does not enforce, hold, or settle monetary value. max_value_usd is advisory
-- only and informs policy evaluation.

CREATE TABLE IF NOT EXISTS commits (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  commit_id               TEXT NOT NULL UNIQUE,
  entity_id               TEXT NOT NULL,
  principal_id            TEXT,
  counterparty_entity_id  TEXT,
  delegation_id           TEXT,
  action_type             TEXT NOT NULL
                            CHECK (action_type IN ('install', 'connect', 'delegate', 'transact')),
  decision                TEXT NOT NULL
                            CHECK (decision IN ('allow', 'review', 'deny')),
  scope                   JSONB,
  max_value_usd           NUMERIC,
  context                 JSONB,
  policy_snapshot         JSONB,
  nonce                   TEXT NOT NULL UNIQUE,
  signature               TEXT NOT NULL,
  public_key              TEXT NOT NULL,
  expires_at              TIMESTAMPTZ NOT NULL,
  status                  TEXT NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'revoked', 'expired', 'fulfilled')),
  receipt_id              TEXT,
  revoked_reason          TEXT,
  revoked_at              TIMESTAMPTZ,
  fulfilled_at            TIMESTAMPTZ,
  evaluation_result       JSONB,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Primary lookup by commit_id
CREATE INDEX IF NOT EXISTS idx_commits_commit_id ON commits (commit_id);

-- Entity-scoped queries
CREATE INDEX IF NOT EXISTS idx_commits_entity_id ON commits (entity_id);

-- Status filtering (active commits for expiry checks)
CREATE INDEX IF NOT EXISTS idx_commits_status ON commits (status)
  WHERE status = 'active';

-- Expiry-based cleanup/auto-expire
CREATE INDEX IF NOT EXISTS idx_commits_expires_at ON commits (expires_at)
  WHERE status = 'active';

-- Nonce uniqueness is enforced by the UNIQUE constraint above;
-- this index supports replay detection queries.

COMMENT ON TABLE commits IS
  'EP Commit: signed pre-action authorization tokens. '
  'Proves a machine action was evaluated under policy before proceeding. '
  'State machine: active → fulfilled | revoked | expired (terminal, no inter-terminal transitions). '
  'A fulfilled commit''s receipt can be disputed, but the commit itself stays fulfilled. '
  'max_value_usd is advisory only — EP does not enforce, hold, or settle monetary value. '
  'Trust must never be more powerful than appeal.';

COMMENT ON COLUMN commits.decision IS
  'Canonical EP trust decision vocabulary: allow, review, deny.';

COMMENT ON COLUMN commits.action_type IS
  'What the commit authorizes: install, connect, delegate, or transact.';

COMMENT ON COLUMN commits.status IS
  'Lifecycle: active → fulfilled | revoked | expired. Terminal states are immutable.';

COMMENT ON COLUMN commits.max_value_usd IS
  'Advisory only. Informs policy evaluation. EP does not enforce, hold, or settle monetary value.';

COMMENT ON COLUMN commits.nonce IS
  'Cryptographic nonce (32 bytes hex) for replay protection. Globally unique.';
