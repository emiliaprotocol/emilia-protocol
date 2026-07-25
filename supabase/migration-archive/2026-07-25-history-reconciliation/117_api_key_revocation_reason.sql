-- 117_api_key_revocation_reason.sql
--
-- Add an auditable reason to api_keys revocations. Nullable + additive; existing
-- rows and the rotate_api_key_atomic / admin_*_key_rotation paths are unaffected
-- (reason stays NULL unless explicitly set). Used by the post-113 dormant-key
-- surface-reduction cleanup and future operator revocations.

ALTER TABLE api_keys
  ADD COLUMN IF NOT EXISTS revocation_reason TEXT DEFAULT NULL;

COMMENT ON COLUMN api_keys.revocation_reason IS
  'Optional operator/audit reason recorded when a key is revoked (e.g. post-113 dormant surface reduction, rotation, compromise).';
