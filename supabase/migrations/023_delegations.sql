-- EMILIA Protocol — Migration 023: Delegation System
-- Creates the delegations table for principal-to-agent authorization records.
-- Delegations are verifiable by any party. Expired/revoked delegations are immediately invalid.

CREATE TABLE IF NOT EXISTS delegations (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  delegation_id     TEXT NOT NULL UNIQUE,
  principal_id      TEXT NOT NULL,
  agent_entity_id   TEXT NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
  scope             TEXT[] NOT NULL,
  max_value_usd     NUMERIC,
  expires_at        TIMESTAMPTZ NOT NULL,
  constraints       JSONB,
  status            TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active', 'expired', 'revoked')),
  revoked_at        TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for fast lookup by delegation_id
CREATE INDEX IF NOT EXISTS idx_delegations_delegation_id ON delegations (delegation_id);

-- Index for principal lookups
CREATE INDEX IF NOT EXISTS idx_delegations_principal_id ON delegations (principal_id);

-- Index for agent entity lookups
CREATE INDEX IF NOT EXISTS idx_delegations_agent_entity_id ON delegations (agent_entity_id);

-- Index for expiry (for cleanup cron)
CREATE INDEX IF NOT EXISTS idx_delegations_expires_at ON delegations (expires_at)
  WHERE status = 'active';

-- Auto-expire: mark delegations as expired when queried past their expiry
-- (Application-level expiry check; this index supports the query)

COMMENT ON TABLE delegations IS
  'Principal-to-agent authorization records. '
  'A delegation allows an agent to act on behalf of a human/org within defined scope. '
  'Protocol guarantee: any party may verify a delegation. '
  'Trust must never be more powerful than appeal.';
