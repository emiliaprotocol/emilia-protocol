-- 083_verify_handshake_restore_071_guards.sql
--
-- Audit-fix (regression introduced in 081): migration 081 added the
-- H3 FOR UPDATE status-precheck but accidentally dropped the
-- binding-consumed and binding-expired short-circuits that migration 071
-- had previously added. Re-composing 071 + 081 in a single atomic function.
--
-- The bug: two concurrent verifies racing the JS-side HARD GATE (verify.js:94)
-- both see consumed_at = null, both reach verify_handshake_writes, and under
-- 081 (without the 071 gates) both pass the status check (initiated) and both
-- INSERT into handshake_results — producing two "accepted" results with the
-- same binding_hash. Violates CTO-Plan Invariant 7 (no_duplicate_accepted_results).
--
-- Also re-adds the DB-clock expiry recheck (071) that closes clock-skew
-- expiry bypass where the JS node's clock is behind the DB clock.
--
-- Compose order matters: status check (081) MUST run FIRST so that a
-- revoked/verified handshake fails fast before any binding read. Then the
-- binding-consumed + expiry guards (071) run under FOR UPDATE.

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
  v_consumed_at TIMESTAMPTZ;
  v_expires_at TIMESTAMPTZ;
BEGIN
  -- Step 1 (from 081): status precheck under row lock.
  -- Closes race where a revoked handshake could be resurrected to verified.
  SELECT status INTO v_current_status
  FROM handshakes
  WHERE handshake_id = p_handshake_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'HANDSHAKE_NOT_FOUND'
      USING ERRCODE = 'P0002',
            DETAIL  = 'handshake_id: ' || p_handshake_id::text;
  END IF;

  IF v_current_status NOT IN ('initiated', 'pending_verification') THEN
    RAISE EXCEPTION 'INVALID_STATE_TRANSITION'
      USING ERRCODE = 'P0004',
            DETAIL  = format('cannot transition from %s to %s (handshake_id: %s)',
                             v_current_status, p_new_status, p_handshake_id::text);
  END IF;

  -- Step 2 (from 071, RESTORED): binding consumption + expiry under row lock.
  -- Serializes concurrent verify calls for the same handshake and prevents
  -- two concurrent verifies from each inserting an 'accepted' result.
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

  -- Step 3: write path (unchanged from 081, 060).
  INSERT INTO handshake_results (
    handshake_id, policy_version, outcome, reason_codes,
    assurance_achieved, binding_hash, policy_hash,
    finalized_at, evaluated_at
  ) VALUES (
    p_handshake_id, p_policy_version, p_outcome, p_reason_codes,
    p_assurance_achieved, p_binding_hash, p_policy_hash,
    v_now, v_now
  );

  INSERT INTO handshake_events (
    handshake_id, event_type, event_payload, actor_id,
    actor_entity_ref, detail, created_at
  ) VALUES (
    p_handshake_id, p_event_type, '{}'::JSONB, p_actor_id,
    p_actor_entity_ref, p_event_detail, v_now
  );

  UPDATE handshakes
  SET status = p_new_status,
      verified_at = CASE WHEN p_new_status = 'verified' THEN v_now ELSE verified_at END
  WHERE handshake_id = p_handshake_id;

  IF p_party_updates IS NOT NULL THEN
    FOR v_party IN SELECT * FROM jsonb_array_elements(p_party_updates)
    LOOP
      UPDATE handshake_parties
      SET verified_status = v_party->>'verified_status',
          verified_at = CASE WHEN v_party->>'verified_status' = 'verified' THEN v_now ELSE verified_at END
      WHERE id = (v_party->>'id')::UUID;
    END LOOP;
  END IF;

  IF p_consume_binding THEN
    UPDATE handshake_bindings
    SET consumed_at = v_now,
        consumed_by = p_actor_entity_ref,
        consumed_for = 'handshake_verified:' || p_handshake_id::TEXT
    WHERE handshake_id = p_handshake_id AND consumed_at IS NULL;
  END IF;

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
  'Atomic finalize. Composes migration 071 (binding consumption + expiry guards under FOR UPDATE) '
  'with migration 081 (status precheck under FOR UPDATE) in one function. Migration 083 restored '
  'the 071 guards that 081 accidentally dropped.';
