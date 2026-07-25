-- 105_session_revocation.sql
--
-- Server-side SSO session revocation. EP sessions are stateless HS256 JWTs; on
-- their own, logout can only clear the cookie and a stolen token stays valid
-- until exp. These tables make revocation real:
--
--   revoked_sessions  — single-session kill by jti (logout, stolen token). The
--                       jti is minted into every session (lib/sso/session.js).
--   session_cutoffs   — subject-wide "logout all devices" / incident kill: a
--                       not_before timestamp; verifySession rejects any token
--                       whose iat predates it.
--
-- verifySession() consults both (fail-open if unavailable — signature + expiry
-- remain the primary gate). Rows in revoked_sessions expire with the token.

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
  'Subject-wide session cutoff (logout-all-devices / incident kill). verifySession rejects any token with iat < not_before for (subject, tenant).';
