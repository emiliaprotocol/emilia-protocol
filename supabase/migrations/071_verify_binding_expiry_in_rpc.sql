-- EP Handshake — Move binding expiry check into verify_handshake_writes RPC
--
-- Problem: bind.js:25 checks `new Date(binding.expires_at) < new Date()`
-- using the JS process clock. In a multi-node deployment with clock skew,
-- one node may accept while another rejects the same binding.
--
-- Fix: Check expiry inside the RPC using Postgres `now()` (the authoritative
-- clock). Return {ok: false, binding_expired: true} if the binding has expired.
-- This is checked under the FOR UPDATE lock, so it's atomic with consumption.

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
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_party JSONB;
  v_consumed_at TIMESTAMPTZ;
  v_expires_at TIMESTAMPTZ;
BEGIN
  -- 0. Lock the binding row for the duration of this transaction.
  --    Serializes concurrent verify calls for the same handshake.
  --    Checks BOTH consumption AND expiry under the lock using the DB clock
  --    (eliminates JS clock-skew inconsistency across nodes).
  IF p_consume_binding THEN
    SELECT consumed_at, expires_at
      INTO v_consumed_at, v_expires_at
      FROM handshake_bindings
     WHERE handshake_id = p_handshake_id
       FOR UPDATE;

    IF v_consumed_at IS NOT NULL THEN
      RETURN jsonb_build_object('ok', FALSE, 'already_consumed', TRUE, 'consumed_at', v_consumed_at);
    END IF;

    IF v_expires_at IS NOT NULL AND v_expires_at < v_now THEN
      RETURN jsonb_build_object('ok', FALSE, 'binding_expired', TRUE, 'expires_at', v_expires_at, 'server_now', v_now);
    END IF;
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

  -- 3. Update handshake status
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

  -- 5. Consume binding (now under lock — safe from race and clock skew)
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
