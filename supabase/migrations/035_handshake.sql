-- EP Handshake — Transaction-bound identity verification extension
-- An EP Extension (not core). Optional but powerful.

CREATE TABLE IF NOT EXISTS handshakes (
  handshake_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  mode TEXT NOT NULL CHECK (mode IN ('basic', 'mutual', 'selective', 'delegated')),
  policy_id TEXT NOT NULL,
  policy_version TEXT,
  interaction_id TEXT,
  status TEXT NOT NULL DEFAULT 'initiated' CHECK (status IN ('initiated', 'pending_verification', 'verified', 'rejected', 'expired', 'revoked')),
  initiated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  verified_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  commit_ref TEXT,
  decision_ref TEXT,
  metadata_json JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS handshake_parties (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  handshake_id UUID NOT NULL REFERENCES handshakes(handshake_id),
  party_role TEXT NOT NULL CHECK (party_role IN ('initiator', 'responder', 'verifier', 'delegate')),
  entity_ref TEXT NOT NULL,
  assurance_level TEXT CHECK (assurance_level IN ('low', 'substantial', 'high')),
  verified_status TEXT DEFAULT 'pending' CHECK (verified_status IN ('pending', 'verified', 'rejected', 'expired')),
  verified_at TIMESTAMPTZ,
  delegation_chain JSONB
);

CREATE TABLE IF NOT EXISTS handshake_presentations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  handshake_id UUID NOT NULL REFERENCES handshakes(handshake_id),
  party_role TEXT NOT NULL,
  presentation_type TEXT NOT NULL,
  issuer_ref TEXT,
  presentation_hash TEXT NOT NULL,
  disclosure_mode TEXT DEFAULT 'full' CHECK (disclosure_mode IN ('full', 'selective', 'commitment')),
  verified BOOLEAN DEFAULT false,
  verified_at TIMESTAMPTZ,
  revocation_checked BOOLEAN DEFAULT false,
  revocation_status TEXT
);

CREATE TABLE IF NOT EXISTS handshake_bindings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  handshake_id UUID NOT NULL REFERENCES handshakes(handshake_id) UNIQUE,
  payload_hash TEXT NOT NULL,
  nonce TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  session_ref TEXT,
  bound_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS handshake_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  handshake_id UUID NOT NULL REFERENCES handshakes(handshake_id) UNIQUE,
  policy_version TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('accepted', 'rejected', 'partial', 'expired')),
  reason_codes TEXT[] DEFAULT '{}',
  assurance_achieved TEXT,
  decision_ref TEXT,
  evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes
CREATE INDEX idx_handshakes_status ON handshakes (status, created_at);
CREATE INDEX idx_handshakes_interaction ON handshakes (interaction_id);
CREATE INDEX idx_handshake_parties_entity ON handshake_parties (entity_ref);
CREATE INDEX idx_handshake_parties_handshake ON handshake_parties (handshake_id);
CREATE INDEX idx_handshake_presentations_handshake ON handshake_presentations (handshake_id);
