CREATE TABLE IF NOT EXISTS revoked_commit_keys (
  kid         TEXT PRIMARY KEY,
  revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  reason      TEXT,
  revoked_by  TEXT
);

COMMENT ON TABLE revoked_commit_keys IS
  'T6: a kid here is treated as compromised - verifyCommit rejects every commit signed by it (kid_revoked). Written only by POST /api/commit-keys/revoke (operator auth).';;
