ALTER TABLE sso_connections
  ADD COLUMN IF NOT EXISTS saml_want_response_signed BOOLEAN;

COMMENT ON COLUMN sso_connections.saml_want_response_signed IS
  'NULL/true means the ACS requires a signed SAML Response envelope (secure default). false means opt out (e.g. IdP-initiated flows that sign only the assertion).';;
