-- 109_scim_token_organization.sql
--
-- #6 Confirmed SCIM tenant -> protocol org mapping.
--
-- A SCIM tenant_id is NOT the same namespace as a protocol organization_id, so
-- scoping approver-credential revocation by tenant_id was an implicit assumption.
-- This column makes the mapping EXPLICIT: each SCIM provisioning token records
-- the protocol organization its directory provisions into. requireScimAuth
-- surfaces it and SCIM deprovision revokes only credentials in that org.
--
-- INVARIANT (EP Cloud onboarding must guarantee): a tenant's approver
-- credentials are enrolled under this same organization_id — i.e. the EP API-key
-- entity used to enroll that tenant's approvers has entities.organization_id ==
-- this value. Then deprovision revokes exactly that tenant's credentials.
--
-- Nullable: when unset, revoke falls back to tenant_id (prior behavior). No SCIM
-- tenants exist yet, so this is forward-looking and changes nothing today.

ALTER TABLE scim_provisioning_tokens ADD COLUMN IF NOT EXISTS organization_id TEXT;

COMMENT ON COLUMN scim_provisioning_tokens.organization_id IS
  'Protocol organization this SCIM tenant provisions into. Used to scope approver-credential revocation on deprovision. NULL falls back to tenant_id.';
