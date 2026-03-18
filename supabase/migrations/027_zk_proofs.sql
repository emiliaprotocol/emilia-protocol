-- EMILIA Protocol — Sprint 5A: Zero-Knowledge Proof Layer
--
-- ZK-lite trust proofs: an entity can prove it meets a trust threshold
-- without revealing receipt contents, counterparty identities, or
-- transaction details. This enables participation from healthcare, legal,
-- and financial industry actors who cannot expose transaction history.
--
-- Privacy model:
--   REVEALED:  claim type, threshold, domain, receipt count, commitment root,
--              on-chain anchor block, generated/expires timestamps
--   HIDDEN:    receipt contents, counterparty IDs, transaction amounts,
--              transaction dates, behavioral outcome details
--
-- Proof lifecycle:
--   generated → valid (re-verified at each GET) → expired (after 30 days)
--               or invalid (if entity score drops below threshold)
--
-- @license Apache-2.0

CREATE TABLE IF NOT EXISTS zk_proofs (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Human-readable proof identifier, shared publicly by the proving entity.
  -- Format: 'ep_zkp_' + 32 hex chars. The verifier only needs this ID.
  proof_id         TEXT        NOT NULL UNIQUE,

  -- The entity making the claim. Foreign-key semantics enforced at
  -- application level (entities table may use TEXT entity_id, not UUID).
  entity_id        TEXT        NOT NULL,

  -- Claim type:
  --   'score_above'        — global behavioral score > threshold (0.0–1.0)
  --   'receipt_count_above' — total receipts > threshold (integer)
  --   'domain_score_above' — domain behavioral score > threshold (0.0–1.0)
  claim_type       TEXT        NOT NULL CHECK (
    claim_type IN ('score_above', 'receipt_count_above', 'domain_score_above')
  ),

  -- Numeric threshold. Normalized [0, 1] for score claims, integer for count.
  claim_threshold  NUMERIC     NOT NULL,

  -- Domain for domain_score_above claims. NULL for global score claims.
  claim_domain     TEXT        CHECK (
    claim_domain IS NULL OR claim_domain IN (
      'financial', 'code_execution', 'communication', 'delegation',
      'infrastructure', 'content_creation', 'data_access'
    )
  ),

  -- Merkle root of HMAC-SHA256 commitments over receipt {id, entity_id, created_at}.
  -- The root is the publicly verifiable anchor of the commitment set.
  -- Receipt contents are NOT included in commitments — this is the core
  -- ZK-lite privacy guarantee.
  commitment_root  TEXT        NOT NULL,

  -- Number of receipts that form the commitment set for this proof.
  -- Revealed so the verifier can assess the depth of evidence.
  receipt_count    INTEGER     NOT NULL CHECK (receipt_count > 0),

  -- Public HMAC nonce. Included in the proof so commitment recomputation
  -- is possible by the entity (for internal auditing). Not a secret — the
  -- hiding property comes from commitment input selection, not key secrecy.
  salt             TEXT        NOT NULL,

  -- Base L2 transaction hash that anchors the commitment_root on-chain.
  -- NULL if no blockchain anchor was available at proof generation time.
  anchor_block     TEXT,

  generated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- Proofs expire after 30 days. Expired proofs are retained for audit
  -- purposes but return valid=false on verification.
  expires_at       TIMESTAMPTZ NOT NULL,

  -- Timestamp of the most recent successful or failed verification call.
  last_verified_at TIMESTAMPTZ,

  -- Whether the proof is currently valid. Set to false on expiry or when
  -- the entity's current score drops below the claimed threshold.
  is_valid         BOOLEAN     NOT NULL DEFAULT true
);

-- Lookup by entity (list all proofs for an entity)
CREATE INDEX IF NOT EXISTS idx_zk_proofs_entity_id
  ON zk_proofs (entity_id);

-- Lookup by proof_id (primary verification path)
CREATE INDEX IF NOT EXISTS idx_zk_proofs_proof_id
  ON zk_proofs (proof_id);

-- Expiry sweep: find proofs that should be invalidated (background job)
CREATE INDEX IF NOT EXISTS idx_zk_proofs_expires_at
  ON zk_proofs (expires_at) WHERE is_valid = true;

COMMENT ON TABLE zk_proofs IS
  'Zero-knowledge trust proofs (ZK-lite). Entities prove a trust threshold '
  'claim without revealing receipt contents, counterparty identities, or '
  'transaction details. Core privacy primitive for healthcare, legal, and '
  'financial industry participation.';

COMMENT ON COLUMN zk_proofs.commitment_root IS
  'Merkle root of HMAC-SHA256(salt, receipt_id|entity_id|created_at) for each '
  'qualifying receipt. Counterparty fields are excluded from commitment input '
  'to preserve the ZK-lite privacy guarantee.';

COMMENT ON COLUMN zk_proofs.salt IS
  'Public HMAC nonce. Included in proof. Hiding comes from commitment input '
  'selection (no counterparty, no amounts), not from key secrecy.';

COMMENT ON COLUMN zk_proofs.is_valid IS
  'Set to false on expiry or when live re-evaluation finds the entity no '
  'longer meets the claimed threshold. False does not mean fraud — only that '
  'the claim is no longer current.';
