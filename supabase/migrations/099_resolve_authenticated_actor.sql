-- 099_resolve_authenticated_actor.sql
--
-- Captures the resolve_authenticated_actor() auth RPC into the migration set.
-- This function is called by lib/supabase.js authenticateRequest() and is
-- required for EVERY authenticated API request, but it had no creating migration
-- — it existed only out-of-band on deployed databases, so a from-scratch replay
-- produced a DB where no authenticated call worked. Definition captured verbatim
-- from the production database (pg_get_functiondef) on 2026-06-20.
--
-- CREATE OR REPLACE is idempotent: a no-op (identical redefinition) on databases
-- that already have it; the missing definition on fresh replays / CI / DR.

CREATE OR REPLACE FUNCTION public.resolve_authenticated_actor(p_key_hash text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_key_record RECORD;
  v_entity RECORD;
  v_active_count INT;
  v_revoked_count INT;
BEGIN
  -- Count active vs revoked keys for this hash
  SELECT
    COUNT(*) FILTER (WHERE revoked_at IS NULL) AS active,
    COUNT(*) FILTER (WHERE revoked_at IS NOT NULL) AS revoked
  INTO v_active_count, v_revoked_count
  FROM api_keys
  WHERE key_hash = p_key_hash;

  -- No rows at all
  IF v_active_count = 0 AND v_revoked_count = 0 THEN
    RETURN jsonb_build_object('error', 'auth_failed', 'reason', 'key_not_found');
  END IF;

  -- All revoked
  IF v_active_count = 0 AND v_revoked_count > 0 THEN
    RETURN jsonb_build_object('error', 'auth_failed', 'reason', 'key_revoked');
  END IF;

  -- Get first active key record
  SELECT entity_id, permissions
  INTO v_key_record
  FROM api_keys
  WHERE key_hash = p_key_hash AND revoked_at IS NULL
  LIMIT 1;

  -- Update last_used_at (fire-and-forget within same transaction)
  UPDATE api_keys SET last_used_at = now() WHERE key_hash = p_key_hash AND revoked_at IS NULL;

  -- Validate entity_id
  IF v_key_record.entity_id IS NULL THEN
    RETURN jsonb_build_object('error', 'malformed_key_record', 'reason', 'missing_entity_id');
  END IF;

  -- Fetch entity
  SELECT *
  INTO v_entity
  FROM entities
  WHERE id = v_key_record.entity_id;

  -- Entity not found or inactive
  IF v_entity IS NULL OR v_entity.status != 'active' THEN
    RETURN jsonb_build_object('error', 'auth_failed', 'reason', 'entity_inactive');
  END IF;

  -- Success: return entity as JSON + permissions
  RETURN jsonb_build_object(
    'entity', row_to_json(v_entity)::JSONB,
    'permissions', COALESCE(v_key_record.permissions, '[]'::JSONB)
  );
END;
$function$;
