ALTER TABLE api_keys
  ADD COLUMN IF NOT EXISTS revocation_reason TEXT DEFAULT NULL;

COMMENT ON COLUMN api_keys.revocation_reason IS
  'Optional operator/audit reason recorded when a key is revoked (e.g. post-113 dormant surface reduction, rotation, compromise).';;
