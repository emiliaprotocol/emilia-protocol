ALTER TABLE entities ADD COLUMN IF NOT EXISTS organization_id TEXT;
CREATE INDEX IF NOT EXISTS idx_entities_organization ON entities(organization_id);
COMMENT ON COLUMN entities.organization_id IS
  'Authoritative organization/tenant for this entity. When set, the v1 API binds receipts to this value and rejects a mismatched body.organization_id (403 organization_mismatch).';;
