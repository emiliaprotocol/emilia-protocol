-- Authority Registry — Trusted signers for EP Commits and protocol operations
CREATE TABLE IF NOT EXISTS authorities (
  authority_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  algorithm TEXT NOT NULL DEFAULT 'Ed25519',
  role TEXT NOT NULL CHECK (role IN ('system', 'operator', 'delegated_agent', 'machine_service')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'retired')),
  valid_from TIMESTAMPTZ NOT NULL DEFAULT now(),
  valid_to TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  metadata_json JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_authorities_key_id ON authorities (key_id);
CREATE INDEX idx_authorities_status ON authorities (status, valid_from, valid_to);

COMMENT ON TABLE authorities IS 'Authority registry for protocol signers. Verification resolves key_id here, not from embedded commit data.';
