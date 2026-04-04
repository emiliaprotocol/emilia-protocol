-- EP Handshake — Policy Version Pinning
--
-- A handshake pins the *exact* policy version at initiation time.
-- Verification must compare against the pinned version, not just the hash.
-- This closes a silent-upgrade window where a policy is replaced with a new
-- version that has an identical hash but different semantics.
--
-- The policy_version column that already exists stores the TEXT key
-- (e.g. "authorized_signer_basic_v1"). We add policy_version_number INTEGER
-- to pin the numeric version from handshake_policies.version.

ALTER TABLE handshakes
  ADD COLUMN IF NOT EXISTS policy_version_number INTEGER;

COMMENT ON COLUMN handshakes.policy_version_number IS
  'The integer version from handshake_policies.version pinned at initiation. '
  'Verification fails if the fetched policy version does not match this value.';
