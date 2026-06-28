-- 106_saml_response_signed_optout.sql
--
-- SAML response-envelope signing is now REQUIRED by default (the ACS passes
-- wantAuthnResponseSigned: true unless this column is explicitly set false).
-- Assertions are always signed (wantAssertionsSigned); requiring the response
-- envelope too closes the assertion-wrapping class. A tenant whose IdP sends
-- IdP-initiated responses with an unsigned envelope can opt OUT per-connection.

ALTER TABLE sso_connections
  ADD COLUMN IF NOT EXISTS saml_want_response_signed BOOLEAN;

COMMENT ON COLUMN sso_connections.saml_want_response_signed IS
  'NULL/true → ACS requires a signed SAML Response envelope (secure default). false → opt out (e.g. IdP-initiated flows that sign only the assertion).';
