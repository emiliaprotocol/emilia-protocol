-- Preserve the least-privilege scope of a key across atomic rotation.
-- The historical function inserted a replacement without permissions, which
-- invoked the schema default ["read", "write"] and could broaden a restricted
-- key during rotation.

CREATE OR REPLACE FUNCTION public.rotate_api_key_atomic(
  p_entity_id UUID,
  p_old_key_hash TEXT,
  p_new_key_hash TEXT,
  p_new_key_prefix TEXT,
  p_label TEXT DEFAULT 'Rotated key'
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_entity_id UUID;
  v_old_key_id UUID;
  v_permissions JSONB;
BEGIN
  SELECT id INTO v_entity_id
  FROM entities
  WHERE id = p_entity_id
  FOR UPDATE;

  IF v_entity_id IS NULL THEN
    RETURN jsonb_build_object('error', 'entity_not_found');
  END IF;

  SELECT id, COALESCE(permissions, '[]'::jsonb)
  INTO v_old_key_id, v_permissions
  FROM api_keys
  WHERE entity_id = p_entity_id
    AND key_hash = p_old_key_hash
    AND revoked_at IS NULL
  FOR UPDATE;

  IF v_old_key_id IS NULL THEN
    RETURN jsonb_build_object('error', 'old_key_not_active');
  END IF;

  UPDATE api_keys
  SET revoked_at = v_now,
      invalidated_at = COALESCE(invalidated_at, v_now)
  WHERE entity_id = p_entity_id
    AND revoked_at IS NULL;

  INSERT INTO api_keys (
    entity_id, key_hash, key_prefix, label, permissions
  ) VALUES (
    p_entity_id,
    p_new_key_hash,
    p_new_key_prefix,
    COALESCE(NULLIF(p_label, ''), 'Rotated key'),
    v_permissions
  );

  RETURN jsonb_build_object(
    'rotated_at', v_now,
    'old_key_invalidated', true
  );
END;
$function$;

REVOKE EXECUTE ON FUNCTION public.rotate_api_key_atomic(UUID, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.rotate_api_key_atomic(UUID, TEXT, TEXT, TEXT, TEXT) TO service_role;
