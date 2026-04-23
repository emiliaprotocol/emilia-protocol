-- 081_verify_handshake_status_precheck.sql
--
-- Audit-fix (H3): verify_handshake_writes must re-check the handshake's status
-- under FOR UPDATE before mutating it. The previous implementation (migration
-- 060) performed a bare `UPDATE handshakes SET status = p_new_status WHERE
-- handshake_id = p_handshake_id` with no pre-condition on the current state.
--
-- Attack closed:
--   1. JS layer reads handshake.status = 'initiated' from a replica.
--   2. A concurrent revoke_handshake transitions the row to 'revoked' on the
--      primary.
--   3. The JS layer calls verify_handshake_writes with p_new_status = 'verified'.
--   4. Old RPC: resurrects the revoked handshake to 'verified'. Defeats
--      CTO-plan Invariant 10 (finalized immutability).
--
-- Fix: SELECT status FOR UPDATE inside the RPC; only accept valid source
-- states (initiated, pending_verification) for transitions into verified /
-- rejected / pending_verification. Explicitly reject a transition out of
-- revoked or expired.

CREATE OR REPLACE FUNCTION verify_handshake_writes(
  p_handshake_id UUID,
  p_outcome TEXT,
  p_reason_codes JSONB,
  p_assurance_achieved TEXT,
  p_policy_version TEXT,
  p_binding_hash TEXT,
  p_policy_hash TEXT,
  p_new_status TEXT,
  p_actor_id TEXT,
  p_actor_entity_ref TEXT,
  p_event_type TEXT,
  p_event_detail JSONB,
  p_party_updates JSONB,
  p_consume_binding BOOLEAN DEFAULT FALSE
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_party JSONB;
  v_current_status TEXT;
BEGIN
  -- Audit-fix (H3): acquire row lock and validate current state.
  SELECT status INTO v_current_status
  FROM handshakes
  WHERE handshake_id = p_handshake_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'HANDSHAKE_NOT_FOUND'
      USING ERRCODE = 'P0002',
            DETAIL  = 'handshake_id: ' || p_handshake_id::text;
  END IF;

  -- Valid source states for a verify-write transition:
  --   initiated, pending_verification   → verified, rejected, pending_verification
  -- Invalid:
  --   verified, rejected, revoked, expired (finalized or terminal)
  IF v_current_status NOT IN ('initiated', 'pending_verification') THEN
    RAISE EXCEPTION 'INVALID_STATE_TRANSITION'
      USING ERRCODE = 'P0004',
            DETAIL  = format('cannot transition from %s to %s (handshake_id: %s)',
                             v_current_status, p_new_status, p_handshake_id::text);
  END IF;

  -- 1. Insert verification result
  INSERT INTO handshake_results (
    handshake_id, policy_version, outcome, reason_codes,
    assurance_achieved, binding_hash, policy_hash,
    finalized_at, evaluated_at
  ) VALUES (
    p_handshake_id, p_policy_version, p_outcome, p_reason_codes,
    p_assurance_achieved, p_binding_hash, p_policy_hash,
    v_now, v_now
  );

  -- 2. Insert handshake event
  INSERT INTO handshake_events (
    handshake_id, event_type, event_payload, actor_id,
    actor_entity_ref, detail, created_at
  ) VALUES (
    p_handshake_id, p_event_type, '{}'::JSONB, p_actor_id,
    p_actor_entity_ref, p_event_detail, v_now
  );

  -- 3. Update handshake status (row already locked above).
  UPDATE handshakes
  SET status = p_new_status,
      verified_at = CASE WHEN p_new_status = 'verified' THEN v_now ELSE verified_at END
  WHERE handshake_id = p_handshake_id;

  -- 4. Update party verified_status
  IF p_party_updates IS NOT NULL THEN
    FOR v_party IN SELECT * FROM jsonb_array_elements(p_party_updates)
    LOOP
      UPDATE handshake_parties
      SET verified_status = v_party->>'verified_status',
          verified_at = CASE WHEN v_party->>'verified_status' = 'verified' THEN v_now ELSE verified_at END
      WHERE id = (v_party->>'id')::UUID;
    END LOOP;
  END IF;

  -- 5. Consume binding (one-time-use enforcement)
  IF p_consume_binding THEN
    UPDATE handshake_bindings
    SET consumed_at = v_now,
        consumed_by = p_actor_entity_ref,
        consumed_for = 'handshake_verified:' || p_handshake_id::TEXT
    WHERE handshake_id = p_handshake_id AND consumed_at IS NULL;
  END IF;

  -- 6. Protocol event
  INSERT INTO protocol_events (
    aggregate_type, aggregate_id, command_type,
    payload_json, payload_hash, actor_authority_id,
    created_at
  ) VALUES (
    'handshake', p_handshake_id::TEXT, 'verify_handshake',
    p_event_detail, '', p_actor_id,
    v_now
  );

  RETURN jsonb_build_object('ok', TRUE);
END;
$$;

COMMENT ON FUNCTION verify_handshake_writes IS
  'Atomically finalize handshake verification. Acquires FOR UPDATE lock on the '
  'handshake row, validates the current status (initiated | pending_verification), '
  'and raises P0004 INVALID_STATE_TRANSITION if the handshake is already finalized '
  'or terminal (verified | rejected | revoked | expired). Closes the TOCTOU race '
  'where a replica read + concurrent revoke could resurrect a revoked handshake.';
