-- 094_signoff_quorum_policy.sql
-- Multi-party (M-of-N / ordered) signoff: a challenge MAY require a QUORUM.
--
-- Additive + nullable by design: a NULL quorum_policy means single-signoff —
-- the existing behavior is completely unchanged. The quorum itself reuses the
-- existing one-challenge-many-attestations model (signoff_attestations
-- references signoff_challenges(challenge_id)); this only attaches the policy.
--
-- Enforcement lives in lib/signoff/quorum-session.js, composed at two points
-- (see docs/MULTI-PARTY-DEPLOYMENT.md):
--   • attest  → canAccept()  rejects a bad/duplicate/out-of-order signer before
--                            their attestation is written into the trail.
--   • consume → quorumGate()  blocks consumption until the trail is a satisfied
--                            quorum (the same fail-closed predicate JS/Python/Go
--                            agree on in conformance).

ALTER TABLE signoff_challenges
  ADD COLUMN IF NOT EXISTS quorum_policy JSONB;

COMMENT ON COLUMN signoff_challenges.quorum_policy IS
  'EP-QUORUM-v1 policy {mode:ordered|threshold, required, approvers:[{role,approver}], distinct_humans, window_sec}. NULL = single-signoff (unchanged). Enforced by lib/signoff/quorum-session.js: canAccept() at attest, quorumGate() at consume.';
