-- SPDX-License-Identifier: Apache-2.0
-- Explicit authentication-strength contract for bearer credentials.
--
-- A bearer API key is password-strength unless a trusted provisioning path
-- records a stronger, verified ceremony. The application never accepts this
-- value from a request body or entity metadata.

ALTER TABLE public.api_keys
  ADD COLUMN IF NOT EXISTS auth_strength TEXT NOT NULL DEFAULT 'password';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'public.api_keys'::regclass
      AND conname = 'api_keys_auth_strength_check'
  ) THEN
    ALTER TABLE public.api_keys
      ADD CONSTRAINT api_keys_auth_strength_check
      CHECK (auth_strength IN ('password', 'mfa', 'phishing_resistant_mfa', 'service_account'));
  END IF;
END $$;

COMMENT ON COLUMN public.api_keys.auth_strength IS
  'Server-derived authentication strength. Defaults to password; never sourced from request-body claims.';

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
  SELECT
    COUNT(*) FILTER (WHERE revoked_at IS NULL) AS active,
    COUNT(*) FILTER (WHERE revoked_at IS NOT NULL) AS revoked
  INTO v_active_count, v_revoked_count
  FROM api_keys
  WHERE key_hash = p_key_hash;

  IF v_active_count = 0 AND v_revoked_count = 0 THEN
    RETURN jsonb_build_object('error', 'auth_failed', 'reason', 'key_not_found');
  END IF;

  IF v_active_count = 0 AND v_revoked_count > 0 THEN
    RETURN jsonb_build_object('error', 'auth_failed', 'reason', 'key_revoked');
  END IF;

  SELECT entity_id, permissions, auth_strength
  INTO v_key_record
  FROM api_keys
  WHERE key_hash = p_key_hash AND revoked_at IS NULL
  LIMIT 1;

  UPDATE api_keys SET last_used_at = now() WHERE key_hash = p_key_hash AND revoked_at IS NULL;

  IF v_key_record.entity_id IS NULL THEN
    RETURN jsonb_build_object('error', 'malformed_key_record', 'reason', 'missing_entity_id');
  END IF;

  SELECT *
  INTO v_entity
  FROM entities
  WHERE id = v_key_record.entity_id;

  IF v_entity IS NULL OR v_entity.status != 'active' THEN
    RETURN jsonb_build_object('error', 'auth_failed', 'reason', 'entity_inactive');
  END IF;

  RETURN jsonb_build_object(
    'entity', (row_to_json(v_entity)::jsonb) - 'private_key_encrypted' - 'api_key_hash',
    'permissions', COALESCE(v_key_record.permissions, '[]'::JSONB),
    'auth_strength', COALESCE(v_key_record.auth_strength, 'password')
  );
END;
$function$;
