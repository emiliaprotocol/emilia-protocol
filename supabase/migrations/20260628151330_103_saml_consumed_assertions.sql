CREATE TABLE IF NOT EXISTS saml_consumed_assertions (
  replay_key  TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL,
  consumed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_saml_consumed_expiry
  ON saml_consumed_assertions (expires_at);

COMMENT ON TABLE saml_consumed_assertions IS
  'T4-B: one row per consumed SAML Response (replay_key = sha256 of the validated SAMLResponse b64). A duplicate insert at the ACS means replay and is rejected. Pruned by expires_at.';;
