-- 107_org_bound_webauthn_execution.sql
-- Close the red-team chain where global approver credentials could be used
-- against an org-bound receipt. New Class-A credentials and WebAuthn
-- challenges are tenant/org-scoped; existing NULL rows are intentionally not
-- usable by the tightened routes until explicitly backfilled/re-enrolled.

ALTER TABLE approver_credentials
  ADD COLUMN IF NOT EXISTS organization_id TEXT;

ALTER TABLE webauthn_challenges
  ADD COLUMN IF NOT EXISTS organization_id TEXT;

CREATE INDEX IF NOT EXISTS idx_approver_credentials_org_approver
  ON approver_credentials (organization_id, approver_id)
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_approver_credentials_org_credential
  ON approver_credentials (organization_id, credential_id)
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_org_signoff
  ON webauthn_challenges (organization_id, signoff_id, approver_id, challenge, created_at DESC)
  WHERE consumed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_org_registration
  ON webauthn_challenges (organization_id, approver_id, created_at DESC)
  WHERE kind = 'registration' AND consumed_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS guard_receipt_execution_once
  ON audit_events (target_id)
  WHERE event_type = 'guard.trust_receipt.executed'
    AND target_type = 'trust_receipt';
