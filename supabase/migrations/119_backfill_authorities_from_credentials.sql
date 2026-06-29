-- 119_backfill_authorities_from_credentials.sql
--
-- Backfill the authorities registry (created in 118) from the source of truth
-- for human-approver permission: active approver_credentials. Principle —
-- credentials prove control; this seeds the matching authority (permission)
-- so the already-fail-closed guard gate (lib/guard-authority.js) resolves
-- legitimate approvers instead of denying everyone.
--
-- Dry-run before applying (2026-06-29): 5 active credentials → 5 authority rows
-- (2 org-scoped + resolvable, 3 null-org + inert); all Class-A e2e/realdevice
-- test identities (no real customers yet). Resolver miss-analysis: the only
-- approvers NOT covered were `poc` / `poc-rogue-approver-*` — stale red-team/POC
-- fixtures that are SUPPOSED to be denied. No legitimate approver locked out.
--
-- Idempotent (ON CONFLICT (key_id) DO NOTHING). role is set to 'approver' but is
-- not load-bearing: every guard.signoff.approved event carries role=null, so the
-- resolver skips the role check. assurance_class mirrors the credential key_class.

INSERT INTO authorities (
  key_id, public_key, algorithm, role, status,
  valid_from, valid_to, revoked_at,
  organization_id, subject_type, subject_ref, assurance_class, metadata_json
)
SELECT
  credential_id, public_key_spki, 'ES256', 'approver', 'active',
  valid_from, valid_to, revoked_at,
  organization_id, 'human_approver', approver_id, key_class,
  jsonb_build_object('backfilled_from', 'approver_credentials', 'approver_name', approver_name,
                     'reconciliation', 'authorities 033/102 (mig 118/119)')
FROM approver_credentials
WHERE revoked_at IS NULL
ON CONFLICT (key_id) DO NOTHING;
