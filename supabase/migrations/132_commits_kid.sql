-- 132_commits_kid.sql
-- Additive: add the signing-key id (`kid`) column the commit issuer writes.
--
-- lib/commit.js issueCommit() inserts `kid` into `commits` and verifyCommit()
-- reads `commit.kid` to resolve the verification key, but the column was never
-- created (029_commits.sql / 120 reconcile omit it). In production this makes
-- every issueCommit() fail with "Could not find the 'kid' column of 'commits' in
-- the schema cache" (COMMIT_STORAGE_FAILED), so the commits table stays empty.
--
-- Nullable with a default matching the verifier's fallback, so existing rows
-- (none in prod today) and callers that omit a custody kid keep working.
ALTER TABLE commits
  ADD COLUMN IF NOT EXISTS kid TEXT NOT NULL DEFAULT 'ep-signing-key-1';

-- Lookups that resolve a verification key by kid.
CREATE INDEX IF NOT EXISTS idx_commits_kid ON commits (kid);
