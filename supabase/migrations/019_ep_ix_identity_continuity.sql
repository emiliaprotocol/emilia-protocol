-- ============================================================================
-- EMILIA Protocol — Migration 019: EP-IX Identity Continuity
-- Principals, identity bindings, continuity claims, challenges, decisions
-- ============================================================================

-- Principals — the enduring actor behind one or more entities
CREATE TABLE IF NOT EXISTS principals (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id        TEXT UNIQUE NOT NULL,
  principal_type      TEXT NOT NULL CHECK (principal_type IN (
    'human', 'organization', 'merchant', 'seller', 'software_publisher',
    'ai_operator', 'service_provider', 'marketplace_operator'
  )),
  display_name        TEXT NOT NULL,
  status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'archived')),
  bootstrap_verified  BOOLEAN NOT NULL DEFAULT FALSE,
  metadata            JSONB DEFAULT '{}',
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Link entities to principals (nullable — legacy entities have no principal yet)
ALTER TABLE entities ADD COLUMN IF NOT EXISTS principal_id UUID REFERENCES principals(id);
ALTER TABLE entities ADD COLUMN IF NOT EXISTS principal_linked_at TIMESTAMPTZ;

-- Identity bindings — prove a principal controls a real-world surface
CREATE TABLE IF NOT EXISTS identity_bindings (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  binding_id          TEXT UNIQUE NOT NULL,
  principal_id        UUID NOT NULL REFERENCES principals(id),
  binding_type        TEXT NOT NULL CHECK (binding_type IN (
    'domain_control', 'github_org', 'npm_publisher', 'chrome_store',
    'shopify_store', 'mcp_server', 'marketplace_account',
    'key_control', 'enterprise_oidc', 'verified_email', 'passkey'
  )),
  binding_target      TEXT NOT NULL,
  proof_type          TEXT,
  proof_payload       JSONB DEFAULT '{}',
  provenance          TEXT NOT NULL DEFAULT 'self_attested' CHECK (provenance IN (
    'self_attested', 'identified_signed', 'bilateral_confirmed',
    'host_verified', 'adjudicated_verified'
  )),
  status              TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
    'pending', 'verified', 'expired', 'revoked', 'challenged'
  )),
  verified_at         TIMESTAMPTZ,
  expires_at          TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Continuity claims — assert entity succession under the same principal
CREATE TABLE IF NOT EXISTS continuity_claims (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  continuity_id       TEXT UNIQUE NOT NULL,
  principal_id        UUID NOT NULL REFERENCES principals(id),
  old_entity_id       TEXT NOT NULL,
  new_entity_id       TEXT NOT NULL,
  reason              TEXT NOT NULL CHECK (reason IN (
    'key_rotation', 'infrastructure_migration', 'host_migration',
    'entity_rename', 'domain_change', 'publisher_transition',
    'merger_or_acquisition', 'recovery_after_compromise', 'fission'
  )),
  continuity_mode     TEXT NOT NULL DEFAULT 'linear' CHECK (continuity_mode IN ('linear', 'fission', 'merger')),
  proofs              JSONB DEFAULT '[]',
  status              TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
    'pending', 'under_challenge', 'approved_full', 'approved_partial',
    'rejected', 'frozen_pending_dispute', 'expired'
  )),
  transfer_policy     TEXT CHECK (transfer_policy IN ('full', 'partial', 'none', 'rejected_laundering')),
  transfer_budget     NUMERIC(3,2) DEFAULT 1.0,
  challenge_deadline  TIMESTAMPTZ,
  expires_at          TIMESTAMPTZ,
  frozen_due_to       TEXT,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Continuity challenges — dispute a continuity claim
CREATE TABLE IF NOT EXISTS continuity_challenges (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  challenge_id        TEXT UNIQUE NOT NULL,
  continuity_id       TEXT NOT NULL REFERENCES continuity_claims(continuity_id),
  challenger_type     TEXT NOT NULL CHECK (challenger_type IN (
    'old_entity_controller', 'principal_owner', 'bound_host',
    'dispute_counterparty', 'operator', 'enterprise_admin'
  )),
  challenger_id       TEXT,
  reason              TEXT NOT NULL,
  evidence            JSONB DEFAULT '{}',
  status              TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'reviewed', 'upheld', 'dismissed')),
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Continuity decisions — record outcome of continuity claim
CREATE TABLE IF NOT EXISTS continuity_decisions (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  continuity_id       TEXT NOT NULL REFERENCES continuity_claims(continuity_id),
  decision            TEXT NOT NULL CHECK (decision IN (
    'approved_full', 'approved_partial', 'rejected', 'rejected_laundering'
  )),
  transfer_policy     TEXT NOT NULL,
  allocation_rule     JSONB,
  reasoning           JSONB DEFAULT '[]',
  decided_by          TEXT NOT NULL,
  decided_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Audit events — append-only log of all trust-changing actions
CREATE TABLE IF NOT EXISTS audit_events (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type          TEXT NOT NULL,
  actor_id            TEXT NOT NULL,
  actor_type          TEXT NOT NULL CHECK (actor_type IN (
    'entity', 'principal', 'operator', 'system', 'human'
  )),
  target_type         TEXT NOT NULL,
  target_id           TEXT NOT NULL,
  action              TEXT NOT NULL,
  before_state        JSONB,
  after_state         JSONB,
  metadata            JSONB DEFAULT '{}',
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_principals_type ON principals(principal_type);
CREATE INDEX IF NOT EXISTS idx_bindings_principal ON identity_bindings(principal_id);
CREATE INDEX IF NOT EXISTS idx_bindings_type ON identity_bindings(binding_type);
CREATE INDEX IF NOT EXISTS idx_continuity_principal ON continuity_claims(principal_id);
CREATE INDEX IF NOT EXISTS idx_continuity_status ON continuity_claims(status);
CREATE INDEX IF NOT EXISTS idx_continuity_old_entity ON continuity_claims(old_entity_id);
CREATE INDEX IF NOT EXISTS idx_continuity_new_entity ON continuity_claims(new_entity_id);
CREATE INDEX IF NOT EXISTS idx_challenges_continuity ON continuity_challenges(continuity_id);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_events(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(created_at);
