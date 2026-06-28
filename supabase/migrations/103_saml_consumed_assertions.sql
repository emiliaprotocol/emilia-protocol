-- 103_saml_consumed_assertions.sql
--
-- T4-B SAML assertion replay protection.
--
-- node-saml validates the assertion signature and the Conditions/NotOnOrAfter
-- window, and its built-in InResponseTo cache covers SP-initiated flows. But EP
-- also accepts unsolicited IdP-initiated responses (common in gov SSO), which
-- carry no InResponseTo to deduplicate on. A SAML Response captured off the wire
-- could therefore be replayed at the ACS while still inside its validity window.
--
-- The ACS records a per-response replay key (sha256 of the validated
-- SAMLResponse) on first consume. A second presentation of the same response
-- collides on the primary key and is rejected as a replay. Rows expire with the
-- assertion window and are pruned opportunistically.

CREATE TABLE IF NOT EXISTS saml_consumed_assertions (
  replay_key  TEXT PRIMARY KEY,            -- sha256(validated SAMLResponse, hex)
  tenant_id   TEXT NOT NULL,
  consumed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_saml_consumed_expiry
  ON saml_consumed_assertions (expires_at);

COMMENT ON TABLE saml_consumed_assertions IS
  'T4-B: one row per consumed SAML Response (replay_key = sha256 of the validated SAMLResponse b64). A duplicate insert at the ACS means replay and is rejected. Pruned by expires_at.';
