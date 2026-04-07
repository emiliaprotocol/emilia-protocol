-- Migration 074: Atomic handshake consumption RPC
--
-- Closes TOCTOU race in consumeHandshake() where a two-step
-- SELECT status + INSERT could consume a handshake that was
-- revoked between the check and the write.
--
-- This RPC performs both operations under a FOR UPDATE row lock,
-- guaranteeing that the status check and consumption insert are
-- serialized against concurrent revocations.

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

  -- Unique constraint on handshake_id prevents double-consumption.
  INSERT INTO handshake_consumptions (
    handshake_id,
    binding_hash,
    consumed_by_type,
    consumed_by_id,
    actor_entity_ref,
    consumed_by_action
  ) VALUES (
    p_handshake_id,
    p_binding_hash,
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
  'Atomically verify handshake status and insert consumption record under FOR UPDATE lock. '
  'Prevents TOCTOU race between status check and consumption insert. '
  'Raises P0001 (INVALID_STATE_FOR_CONSUMPTION) or P0002 (HANDSHAKE_NOT_FOUND) on failure.';
