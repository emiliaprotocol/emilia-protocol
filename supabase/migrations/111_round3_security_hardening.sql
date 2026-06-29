-- 111_round3_security_hardening.sql
--
-- Closes two production hardening gaps:
--   1. API-key rotation must be atomic and entity-locked.
--   2. Registration should reject normalized display-name impersonation clones.

-- Normalized display-name collision key. Existing rows are backfilled only when
-- their normalized key is unique; duplicate historical names stay NULL so this
-- migration cannot fail on legacy data. New registrations write display_name_key
-- and are protected by the partial unique index.
ALTER TABLE entities
  ADD COLUMN IF NOT EXISTS display_name_key TEXT DEFAULT NULL;

COMMENT ON COLUMN entities.display_name_key IS
  'Normalized display_name collision key used to block case/spacing/punctuation impersonation clones at registration.';

WITH normalized AS (
  SELECT
    id,
    NULLIF(lower(regexp_replace(display_name, '[^[:alnum:]]+', '', 'g')), '') AS key
  FROM entities
  WHERE display_name_key IS NULL
),
ranked AS (
  SELECT
    id,
    key,
    COUNT(*) OVER (PARTITION BY key) AS key_count
  FROM normalized
  WHERE key IS NOT NULL
)
UPDATE entities e
SET display_name_key = r.key
FROM ranked r
WHERE e.id = r.id
  AND r.key_count = 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_entities_display_name_key_unique
  ON entities(display_name_key)
  WHERE display_name_key IS NOT NULL;

-- Atomic bearer API-key rotation. This function locks the entity row, locks the
-- currently-authenticated key, revokes all active keys for that entity, and
-- inserts exactly one replacement key in one transaction.
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
BEGIN
  SELECT id
  INTO v_entity_id
  FROM entities
  WHERE id = p_entity_id
  FOR UPDATE;

  IF v_entity_id IS NULL THEN
    RETURN jsonb_build_object('error', 'entity_not_found');
  END IF;

  SELECT id
  INTO v_old_key_id
  FROM api_keys
  WHERE entity_id = p_entity_id
    AND key_hash = p_old_key_hash
    AND revoked_at IS NULL
  FOR UPDATE;

  IF v_old_key_id IS NULL THEN
    RETURN jsonb_build_object('error', 'old_key_not_active');
  END IF;

  -- Collapse concurrent rotations: after this transaction commits, the entity
  -- has exactly one active bearer key, the replacement inserted below.
  UPDATE api_keys
  SET revoked_at = v_now,
      invalidated_at = COALESCE(invalidated_at, v_now)
  WHERE entity_id = p_entity_id
    AND revoked_at IS NULL;

  INSERT INTO api_keys (
    entity_id,
    key_hash,
    key_prefix,
    label
  ) VALUES (
    p_entity_id,
    p_new_key_hash,
    p_new_key_prefix,
    COALESCE(NULLIF(p_label, ''), 'Rotated key')
  );

  RETURN jsonb_build_object(
    'rotated_at', v_now,
    'old_key_invalidated', true
  );
END;
$function$;

-- SECURITY DEFINER + default PUBLIC execute would let anon/authenticated call
-- this key-mutating RPC directly via PostgREST. Revoke first, then grant only to
-- the service role the server uses.
REVOKE EXECUTE ON FUNCTION public.rotate_api_key_atomic(UUID, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.rotate_api_key_atomic(UUID, TEXT, TEXT, TEXT, TEXT) TO service_role;
