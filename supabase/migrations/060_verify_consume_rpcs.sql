-- Batch write RPCs for handshake verify and signoff consume hot paths.
-- These reduce serial DB roundtrips without changing semantics.

-- ============================================================================
-- 1. verify_handshake_writes — batches all write operations after verification
-- ============================================================================
-- Called after JS-side verification logic completes.
-- Writes result, event, status update, party updates, and binding consume
-- in a single atomic transaction.

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
  p_party_updates JSONB,         -- [{id, verified_status, verified_at?}]
  p_consume_binding BOOLEAN DEFAULT FALSE
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_party JSONB;
BEGIN
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


-- ============================================================================
-- 2. consume_signoff_atomic — batches signoff consumption writes
-- ============================================================================
-- Replaces 3 serial writes (event + consumption + status update)
-- with a single atomic transaction.

CREATE OR REPLACE FUNCTION consume_signoff_atomic(
  p_signoff_id TEXT,
  p_binding_hash TEXT,
  p_execution_ref TEXT,
  p_handshake_id TEXT,
  p_challenge_id TEXT,
  p_human_entity_ref TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_consumption_id UUID;
BEGIN
  -- 1. Insert signoff event (event-first ordering)
  INSERT INTO signoff_events (
    handshake_id, challenge_id, signoff_id,
    event_type, detail, actor_entity_ref, created_at
  ) VALUES (
    p_handshake_id::UUID, p_challenge_id::UUID, p_signoff_id,
    'consumed',
    jsonb_build_object('execution_ref', p_execution_ref, 'human_entity_ref', p_human_entity_ref),
    p_human_entity_ref, v_now
  );

  -- 2. Atomic insert into signoff_consumptions (unique constraint enforces one-time-use)
  INSERT INTO signoff_consumptions (
    signoff_id, binding_hash, execution_ref,
    consumed_at, created_at
  ) VALUES (
    p_signoff_id, p_binding_hash, p_execution_ref,
    v_now, v_now
  )
  RETURNING id INTO v_consumption_id;

  -- 3. Update attestation status
  UPDATE signoff_attestations
  SET status = 'consumed', consumed_at = v_now
  WHERE signoff_id = p_signoff_id;

  -- 4. Protocol event
  INSERT INTO protocol_events (
    aggregate_type, aggregate_id, command_type,
    payload_json, payload_hash, actor_authority_id,
    created_at
  ) VALUES (
    'signoff', p_signoff_id, 'consume_signoff',
    jsonb_build_object('execution_ref', p_execution_ref, 'binding_hash', p_binding_hash),
    '', p_human_entity_ref,
    v_now
  );

  RETURN jsonb_build_object('consumption_id', v_consumption_id, 'consumed_at', v_now);
END;
$$;


-- ============================================================================
-- 3. create_test_fixtures — bulk fixture creator for load tests
-- ============================================================================

CREATE OR REPLACE FUNCTION create_test_fixtures(
  p_count INT,
  p_initiator_ref TEXT,
  p_responder_ref TEXT,
  p_policy_id UUID,
  p_status TEXT DEFAULT 'initiated'
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_ids UUID[];
  v_id UUID;
  v_now TIMESTAMPTZ := now();
  i INT;
BEGIN
  FOR i IN 1..p_count LOOP
    INSERT INTO handshakes (
      mode, policy_id, policy_id_legacy, status, metadata_json,
      initiated_at, created_at
    ) VALUES (
      'mutual', p_policy_id, p_policy_id::TEXT, p_status, '{}'::JSONB,
      v_now, v_now
    )
    RETURNING handshake_id INTO v_id;

    INSERT INTO handshake_parties (handshake_id, party_role, entity_ref, verified_status)
    VALUES (v_id, 'initiator', p_initiator_ref, 'pending'),
           (v_id, 'responder', p_responder_ref, 'pending');

    INSERT INTO handshake_bindings (
      handshake_id, payload_hash, nonce, expires_at, bound_at,
      binding_material_version, initiator_entity_ref
    ) VALUES (
      v_id, encode(gen_random_bytes(32), 'hex'), encode(gen_random_bytes(32), 'hex'),
      v_now + INTERVAL '1 hour', v_now, 1, p_initiator_ref
    );

    INSERT INTO handshake_events (
      handshake_id, event_type, event_payload, created_at
    ) VALUES (v_id, 'handshake_created', '{}'::JSONB, v_now);

    v_ids := array_append(v_ids, v_id);
  END LOOP;

  RETURN to_jsonb(v_ids);
END;
$$;
