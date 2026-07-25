-- 102_authority_registry_subjects.sql
--
-- #5 Authority registry. Extend the registry from 033 into the unified
-- PERMISSION registry. The principle: credentials prove control (a passkey in
-- approver_credentials proves possession of a key); AUTHORITIES prove
-- permission — this subject was authorized for this org, in this role, during
-- this window, at this assurance class, and was not revoked. A person can hold
-- a valid credential and no longer be authorized; only the registry answers that.
--
-- New columns are nullable so existing protocol-signer rows are unaffected.
-- The guard signoff path resolves: (organization_id, approver_id, role, at) ->
-- authority record -> assurance_class + validity/revocation/org-scope checks.

ALTER TABLE authorities
  ADD COLUMN IF NOT EXISTS organization_id TEXT,
  ADD COLUMN IF NOT EXISTS subject_type     TEXT,  -- protocol_signer | human_approver | system | issuer
  ADD COLUMN IF NOT EXISTS subject_ref      TEXT,  -- approver_id / entity_id / key_id
  ADD COLUMN IF NOT EXISTS assurance_class  TEXT;  -- e.g. 'A' (approver-held device key), 'C' (platform)

-- The original role CHECK (033) only allowed protocol-signer roles
-- (system/operator/delegated_agent/machine_service). Human approvers need
-- approver/controller/supervisor/etc. Relax to any non-empty role; the resolver
-- enforces the specific role required per action.
ALTER TABLE authorities DROP CONSTRAINT IF EXISTS authorities_role_check;

CREATE INDEX IF NOT EXISTS idx_authorities_subject
  ON authorities (subject_type, subject_ref, organization_id, status);

COMMENT ON COLUMN authorities.subject_type IS
  'protocol_signer | human_approver | system | issuer. Credentials prove control; authorities prove permission.';
COMMENT ON COLUMN authorities.assurance_class IS
  'Highest assurance this subject is authorized at (e.g. A = approver-held device key). Gates Class-A actions.';
