-- Migration 028: Remove deprecated api_key_hash column from entities table.
--
-- The api_keys table is the sole source of truth for API-key authentication
-- (see lib/supabase.js). The api_key_hash column on entities was a legacy
-- shortcut that duplicated auth data; it is no longer written by the
-- registration flow and can be safely dropped.

DROP INDEX IF EXISTS idx_entities_api_key_hash;

ALTER TABLE entities DROP COLUMN IF EXISTS api_key_hash;

COMMENT ON TABLE entities IS
  'Auth is handled exclusively via the api_keys table. '
  'The former api_key_hash column was removed in migration 028.';
