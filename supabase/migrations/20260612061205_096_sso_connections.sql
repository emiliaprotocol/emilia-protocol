-- 096_sso_connections.sql
-- Enterprise SSO connections (SAML 2.0 / OIDC), one per tenant per protocol.
-- Service-role write only; holds the OIDC client secret (RLS on, no policy).

CREATE TABLE IF NOT EXISTS sso_connections (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     TEXT NOT NULL,
  protocol      TEXT NOT NULL CHECK (protocol IN ('saml', 'oidc')),
  enabled       BOOLEAN NOT NULL DEFAULT true,
  saml_idp_entry_point TEXT,
  saml_idp_cert        TEXT,
  saml_audience        TEXT,
  oidc_issuer          TEXT,
  oidc_client_id       TEXT,
  oidc_client_secret   TEXT,
  oidc_redirect_uri    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, protocol)
);
CREATE INDEX IF NOT EXISTS idx_sso_connections_tenant ON sso_connections (tenant_id);

COMMENT ON TABLE sso_connections IS
  'Per-tenant enterprise SSO config (SAML 2.0 / OIDC). Drives lib/sso. Service-role write only.';

ALTER TABLE sso_connections ENABLE ROW LEVEL SECURITY;;
