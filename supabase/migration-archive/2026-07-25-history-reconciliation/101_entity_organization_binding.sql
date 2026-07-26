-- 101_entity_organization_binding.sql
--
-- Tenant/org IDOR hardening. The v1 API authenticates a protocol entity
-- (api_keys -> resolve_authenticated_actor -> entities row) but historically
-- took organization_id from the request body, so an authenticated caller could
-- scope receipts to ANY org. Bind each entity to its authoritative organization
-- here; resolve_authenticated_actor returns the full entities row, so this
-- column surfaces on auth.entity.organization_id with no RPC change.
--
-- Rollout: this column is nullable so existing entities keep working
-- (the API falls back to the body value, logged, while unbound). After
-- backfilling organization_id for every entity, flip the API call sites to
-- requireBound=true (lib/tenant-binding.js) so an unbound entity fails closed.

ALTER TABLE entities ADD COLUMN IF NOT EXISTS organization_id TEXT;

COMMENT ON COLUMN entities.organization_id IS
  'Authoritative organization/tenant for this entity. When set, the v1 API binds receipts to this value and rejects a mismatched body.organization_id (403 organization_mismatch). Backfill all entities, then make the API fail-closed for unbound entities.';

CREATE INDEX IF NOT EXISTS idx_entities_organization ON entities(organization_id);
