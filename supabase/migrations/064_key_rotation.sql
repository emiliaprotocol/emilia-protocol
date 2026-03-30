-- 064_key_rotation.sql
-- Adds invalidated_at column to api_keys for key rotation audit trail.
-- Note: the rotation endpoint uses revoked_at (already exists) to invalidate
-- old keys, since resolve_authenticated_actor RPC already checks
-- revoked_at IS NULL. invalidated_at is kept as an additional audit marker
-- to distinguish rotation-based revocations from manual revocations.

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS invalidated_at TIMESTAMPTZ;
