ALTER TABLE scim_provisioning_tokens ADD COLUMN IF NOT EXISTS organization_id TEXT;
COMMENT ON COLUMN scim_provisioning_tokens.organization_id IS
  'Protocol organization this SCIM tenant provisions into. Used to scope approver-credential revocation on deprovision. NULL falls back to tenant_id.';;
