-- 096_sso_connections.sql
--
-- Enterprise SSO connections (SAML 2.0 / OIDC), one per tenant per protocol.
--
-- A customer configures their IdP here (entry point + signing cert for SAML, or
-- issuer + client credentials for OIDC). The SSO routes read this to drive
-- AuthnRequest/authorize redirects and to validate the signed Response / ID
-- token. Rows are written only via the service-role client (getGuardedClient);
-- the SAML idp_cert is public key material, and oidc_client_secret lives in a
-- service-role-only column (same posture as entities.private_key_encrypted).

CREATE TABLE IF NOT EXISTS sso_connections (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     TEXT NOT NULL,
  protocol      TEXT NOT NULL CHECK (protocol IN ('saml', 'oidc')),
  enabled       BOOLEAN NOT NULL DEFAULT true,

  -- SAML SP <- IdP
  saml_idp_entry_point TEXT,        -- IdP SSO redirect URL
  saml_idp_cert        TEXT,        -- IdP signing certificate (PEM body)
  saml_audience        TEXT,        -- expected audience (defaults to SP entityID)

  -- OIDC RP <- provider
  oidc_issuer          TEXT,        -- e.g. https://acme.okta.com
  oidc_client_id       TEXT,
  oidc_client_secret   TEXT,        -- service-role-only column
  oidc_redirect_uri    TEXT,

  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, protocol)
);
CREATE INDEX IF NOT EXISTS idx_sso_connections_tenant ON sso_connections (tenant_id);

COMMENT ON TABLE sso_connections IS
  'Per-tenant enterprise SSO config (SAML 2.0 / OIDC). Drives lib/sso. Service-role write only.';
