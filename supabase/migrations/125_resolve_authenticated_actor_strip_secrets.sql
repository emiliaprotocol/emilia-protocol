-- 125_resolve_authenticated_actor_strip_secrets.sql
--
-- Security hardening (least-disclosure at the auth root).
--
-- resolve_authenticated_actor() (migration 099) returned `row_to_json(v_entity)`
-- from `SELECT * FROM entities`, so the auth context handed to EVERY
-- authenticated request (auth.entity in lib/supabase.js authenticateRequest())
-- carried `private_key_encrypted` — the Ed25519 private key material sealed at
-- rest (added in migration 078). No route reads that column off auth.entity, and
-- responses go through authEntityId()/scalar projections, so it is not currently
-- serialized to a client — but shipping sealed private-key material into every
-- request's in-memory auth object, and into telemetry logs (protocol-write.js
-- logs command.actor), is a latent exposure whose only backstop is name-pattern
-- log redaction. One rename or one non-redacting sink turns it into a breach; the
-- v1 bearer path was bitten by this exact class once.
--
-- Fix at the source: the RPC MUST NOT return key material. We strip the sensitive
-- keys from the returned JSON with jsonb `-`, preserving EVERY other column, so no
-- downstream consumer can break (they never read the stripped keys). This is the
-- decisive control — it removes the material from the auth boundary entirely
-- rather than relying on each consumer to avoid leaking it.
--
--   - private_key_encrypted : the live sensitive column (migration 078).
--   - api_key_hash          : dropped in migration 028; stripped here defensively
--                             so a future re-add cannot silently re-leak.
--
-- CREATE OR REPLACE is idempotent. Only the final projection changed vs 099.

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

  -- Success: return entity as JSON MINUS key material + permissions.
  -- Least-disclosure: strip sealed private key (and the historically-dropped
  -- api_key_hash) so no auth-context consumer ever holds secret material.
  RETURN jsonb_build_object(
    'entity', (row_to_json(v_entity)::jsonb) - 'private_key_encrypted' - 'api_key_hash',
    'permissions', COALESCE(v_key_record.permissions, '[]'::JSONB)
  );
END;
$function$;
