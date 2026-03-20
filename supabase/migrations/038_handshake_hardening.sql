-- EP Handshake hardening: claims persistence + presentation actor tracking
-- Audit findings 2, 3

-- Add claims columns to handshake_presentations
ALTER TABLE handshake_presentations
  ADD COLUMN IF NOT EXISTS raw_claims JSONB,
  ADD COLUMN IF NOT EXISTS normalized_claims JSONB,
  ADD COLUMN IF NOT EXISTS canonical_claims_hash TEXT,
  ADD COLUMN IF NOT EXISTS actor_entity_ref TEXT,
  ADD COLUMN IF NOT EXISTS authority_id TEXT,
  ADD COLUMN IF NOT EXISTS issuer_status TEXT;
