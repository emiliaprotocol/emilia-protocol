-- 080_consume_handshake_binding_hash_guard.sql
--
-- Audit-fix (C1): consume_handshake_atomic must verify the caller-supplied
-- p_binding_hash against the authoritative stored binding hash BEFORE
-- inserting the consumption record. The previous version (migration 074)
-- stored the caller's value verbatim, producing an attacker-controlled
-- audit trail in handshake_consumptions.binding_hash.
--
-- Attack closed: a caller in 'verified' state could consume a handshake with
-- ANY binding_hash value, populating handshake_consumptions with a forged or
-- mismatched hash. Downstream systems that re-check "the consumption's
-- binding_hash matches the action I'm about to perform" (LOCK 100 B.1) were
-- defeated.
--
-- Fix: SELECT the real binding_hash under FOR UPDATE (already held by the
-- handshakes-row lock but made explicit for clarity), compare, raise on
-- mismatch, and INSERT the server-truth value (not the caller's).

CREATE OR REPLACE FUNCTION consume_handshake_atomic(
  p_handshake_id   UUID,
  p_binding_hash   TEXT,
  p_consumed_by_type TEXT,
  p_consumed_by_id   TEXT,
  p_actor_entity_ref TEXT,
  p_consumed_by_action TEXT DEFAULT NULL
)
RETURNS SETOF handshake_consumptions
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_status TEXT;
  v_real_binding_hash TEXT;
  v_consumption handshake_consumptions;
BEGIN
  -- Lock the handshake row to prevent concurrent revocation between
  -- the status check and the consumption insert.
  SELECT status INTO v_status
  FROM handshakes
  WHERE handshake_id = p_handshake_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'HANDSHAKE_NOT_FOUND'
      USING ERRCODE = 'P0002',
            DETAIL  = 'handshake_id: ' || p_handshake_id::text;
  END IF;

  IF v_status != 'verified' THEN
    RAISE EXCEPTION 'INVALID_STATE_FOR_CONSUMPTION'
      USING ERRCODE = 'P0001',
            DETAIL  = 'current status: ' || v_status;
  END IF;

  -- Audit-fix (C1): fetch the authoritative binding_hash and verify against
  -- the caller's input. FOR UPDATE is redundant given the handshakes-row
  -- lock above (binding_hash is immutable post-bind), but makes the lock
  -- intent explicit in the hot path.
  SELECT binding_hash INTO v_real_binding_hash
  FROM handshake_bindings
  WHERE handshake_id = p_handshake_id
  FOR UPDATE;

  IF v_real_binding_hash IS NULL THEN
    RAISE EXCEPTION 'BINDING_NOT_FOUND'
      USING ERRCODE = 'P0002',
            DETAIL  = 'handshake_id: ' || p_handshake_id::text;
  END IF;

  IF v_real_binding_hash IS DISTINCT FROM p_binding_hash THEN
    RAISE EXCEPTION 'BINDING_HASH_MISMATCH'
      USING ERRCODE = 'P0003',
            DETAIL  = format('expected server truth (length %s), got caller value (length %s)',
                             length(v_real_binding_hash),
                             length(coalesce(p_binding_hash, '')));
  END IF;

  -- Unique constraint on handshake_id prevents double-consumption.
  -- Note: we insert v_real_binding_hash (server truth), not p_binding_hash.
  -- Even though we've verified equality, future-proof against a race where
  -- the caller-supplied value diverges from storage.
  INSERT INTO handshake_consumptions (
    handshake_id,
    binding_hash,
    consumed_by_type,
    consumed_by_id,
    actor_entity_ref,
    consumed_by_action
  ) VALUES (
    p_handshake_id,
    v_real_binding_hash,
    p_consumed_by_type,
    p_consumed_by_id,
    p_actor_entity_ref,
    p_consumed_by_action
  )
  RETURNING * INTO v_consumption;

  RETURN NEXT v_consumption;
END;
$$;

COMMENT ON FUNCTION consume_handshake_atomic IS
  'Atomically verify handshake status, binding_hash integrity, and insert '
  'consumption record under FOR UPDATE lock. Raises P0001 INVALID_STATE_FOR_CONSUMPTION, '
  'P0002 HANDSHAKE_NOT_FOUND / BINDING_NOT_FOUND, or P0003 BINDING_HASH_MISMATCH.';
