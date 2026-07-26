ALTER TABLE signoff_challenges
  ADD COLUMN IF NOT EXISTS quorum_policy JSONB;

COMMENT ON COLUMN signoff_challenges.quorum_policy IS
  'EP-QUORUM-v1 policy {mode:ordered|threshold, required, approvers:[{role,approver}], distinct_humans, window_sec}. NULL = single-signoff (unchanged). Enforced by lib/signoff/quorum-session.js: canAccept() at attest, quorumGate() at consume.';;
