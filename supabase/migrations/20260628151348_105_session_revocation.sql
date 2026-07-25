CREATE TABLE IF NOT EXISTS revoked_sessions (
  jti         TEXT PRIMARY KEY,
  subject     TEXT,
  tenant      TEXT,
  revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revoked_sessions_expiry
  ON revoked_sessions (expires_at);

CREATE TABLE IF NOT EXISTS session_cutoffs (
  subject     TEXT NOT NULL,
  tenant      TEXT NOT NULL DEFAULT '',
  not_before  TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (subject, tenant)
);

COMMENT ON TABLE revoked_sessions IS
  'Single-session revocation by JWT jti (logout / stolen token). verifySession rejects a listed jti. Pruned by expires_at.';
COMMENT ON TABLE session_cutoffs IS
  'Subject-wide session cutoff (logout-all-devices / incident kill). verifySession rejects any token with iat < not_before for (subject, tenant).';;
