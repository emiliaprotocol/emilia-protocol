-- 104_revoked_commit_keys.sql
--
-- T6 emergency commit-key revocation.
--
-- Commit signing keys are configured via env (EP_COMMIT_SIGNING_KEY +
-- EP_COMMIT_SIGNING_KEYS), so there is no runtime "rotate the env" operation.
-- The emergency response to a leaked/compromised signing key is therefore
-- REVOCATION BY kid: a kid recorded here is treated as compromised, and
-- verifyCommit() rejects every commit bearing it (reason: kid_revoked) regardless
-- of an otherwise-valid signature. Legitimate authorizations are re-issued under
-- a fresh kid (rotate EP_COMMIT_SIGNING_KEY, publish the new public key in
-- EP_COMMIT_SIGNING_KEYS), after which the old kid is revoked here.
--
-- Populated only by the operator-authenticated POST /api/commit-keys/revoke.

CREATE TABLE IF NOT EXISTS revoked_commit_keys (
  kid         TEXT PRIMARY KEY,
  revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  reason      TEXT,
  revoked_by  TEXT
);

COMMENT ON TABLE revoked_commit_keys IS
  'T6: a kid here is treated as compromised — verifyCommit rejects every commit signed by it (kid_revoked). Written only by POST /api/commit-keys/revoke (operator auth).';
