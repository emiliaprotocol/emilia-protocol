CREATE OR REPLACE FUNCTION public.admin_begin_key_rotation(
  p_entity_id      UUID,
  p_new_key_hash   TEXT,
  p_new_key_prefix TEXT,
  p_label          TEXT DEFAULT 'Rotated key (dual-accept)'
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
DECLARE
  v_entity_id UUID;
  v_new_id    UUID;
BEGIN
  SELECT id INTO v_entity_id FROM entities WHERE id = p_entity_id FOR UPDATE;
  IF v_entity_id IS NULL THEN
    RETURN jsonb_build_object('error', 'entity_not_found');
  END IF;

  INSERT INTO api_keys (entity_id, key_hash, key_prefix, label)
  VALUES (p_entity_id, p_new_key_hash, p_new_key_prefix, COALESCE(NULLIF(p_label, ''), 'Rotated key (dual-accept)'))
  RETURNING id INTO v_new_id;

  RETURN jsonb_build_object(
    'new_key_id', v_new_id,
    'dual_accept', true,
    'note', 'old keys remain active until admin_complete_key_rotation'
  );
END;
$function$;

CREATE OR REPLACE FUNCTION public.admin_complete_key_rotation(
  p_entity_id    UUID,
  p_keep_key_id  UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
DECLARE
  v_keep   UUID;
  v_now    TIMESTAMPTZ := now();
  v_count  INT;
BEGIN
  SELECT id INTO v_keep FROM api_keys
  WHERE id = p_keep_key_id AND entity_id = p_entity_id AND revoked_at IS NULL
  FOR UPDATE;
  IF v_keep IS NULL THEN
    RETURN jsonb_build_object('error', 'keep_key_not_active_for_entity');
  END IF;

  UPDATE api_keys
  SET revoked_at = v_now, invalidated_at = COALESCE(invalidated_at, v_now)
  WHERE entity_id = p_entity_id AND revoked_at IS NULL AND id <> p_keep_key_id;
  GET DIAGNOSTICS v_count = ROW_COUNT;

  RETURN jsonb_build_object('kept_key_id', p_keep_key_id, 'revoked_count', v_count, 'completed_at', v_now);
END;
$function$;

REVOKE EXECUTE ON FUNCTION public.admin_begin_key_rotation(UUID, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.admin_complete_key_rotation(UUID, UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_begin_key_rotation(UUID, TEXT, TEXT, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.admin_complete_key_rotation(UUID, UUID) TO service_role;;
