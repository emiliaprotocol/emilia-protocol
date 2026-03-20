-- EP Handshake Policies — Defines verification policy templates for handshakes.
-- Allows handshakes to reference a structured, versioned policy definition
-- rather than an opaque text identifier.

-- ============================================================================
-- 1. Create the handshake_policies table
-- ============================================================================

CREATE TABLE IF NOT EXISTS handshake_policies (
  policy_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_key      TEXT NOT NULL,
  version         INTEGER NOT NULL DEFAULT 1,
  name            TEXT NOT NULL,
  mode            TEXT NOT NULL CHECK (mode IN ('one_sided', 'mutual', 'basic', 'selective', 'delegated')),
  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'deprecated')),
  rules           JSONB NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (policy_key, version)
);

-- ============================================================================
-- 2. Indexes
-- ============================================================================

CREATE INDEX idx_handshake_policies_key_status
  ON handshake_policies (policy_key, status);

-- ============================================================================
-- 3. Alter handshakes table to reference handshake_policies
-- ============================================================================
-- The existing handshakes.policy_id column is TEXT NOT NULL.
-- We need to:
--   a) Add a new UUID column for the FK relationship.
--   b) Keep the original text column as policy_id_legacy for backwards compat.

ALTER TABLE handshakes
  RENAME COLUMN policy_id TO policy_id_legacy;

ALTER TABLE handshakes
  ADD COLUMN policy_id UUID REFERENCES handshake_policies(policy_id);

-- ============================================================================
-- 4. Seed initial policies
-- ============================================================================

INSERT INTO handshake_policies (policy_key, version, name, mode, rules)
VALUES
  (
    'authorized_signer_basic_v1',
    1,
    'Authorized Signer Basic',
    'one_sided',
    '{
      "required_parties": {
        "initiator": {
          "required_claims": ["authorized_signer"],
          "minimum_assurance": "medium"
        }
      },
      "binding": {
        "payload_hash_required": true,
        "nonce_required": true,
        "expiry_minutes": 30
      },
      "storage": {
        "store_raw_payload": false,
        "store_normalized_claims": true
      }
    }'::jsonb
  ),
  (
    'mutual_counterparty_high_value_v1',
    1,
    'Mutual Counterparty High Value',
    'mutual',
    '{
      "required_parties": {
        "initiator": {
          "required_claims": ["legal_entity", "authorized_signer"],
          "minimum_assurance": "high"
        },
        "responder": {
          "required_claims": ["legal_name", "sanctions_screened"],
          "minimum_assurance": "substantial"
        }
      },
      "binding": {
        "payload_hash_required": true,
        "nonce_required": true,
        "expiry_minutes": 10
      },
      "storage": {
        "store_raw_payload": false,
        "store_normalized_claims": true
      }
    }'::jsonb
  );
