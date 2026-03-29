-- Batch write RPC for handshake present hot path.
-- Reduces 3-4 serial DB writes to a single atomic transaction.
-- Mirrors the pattern established in 060_verify_consume_rpcs.sql.

-- ============================================================================
-- present_handshake_writes — batches presentation insert + events + status update
-- ============================================================================
-- Called after JS-side validation (auth, handshake fetch, party fetch, authority
-- resolution, claims normalization) completes. Only the write portion is batched.

CREATE OR REPLACE FUNCTION present_handshake_writes(
  p_handshake_id UUID,
  p_party_role TEXT,
  p_presentation_type TEXT,
  p_issuer_ref TEXT,
  p_presentation_hash TEXT,
  p_disclosure_mode TEXT,
  p_raw_claims JSONB,
  p_normalized_claims JSONB,
  p_canonical_claims_hash TEXT,
  p_actor_entity_ref TEXT,
  p_authority_id TEXT,
  p_issuer_status TEXT,
  p_verified BOOLEAN,
  p_revocation_checked BOOLEAN,
  p_revocation_status TEXT,
  p_current_hs_status TEXT,       -- current handshake status (for conditional transition)
  p_actor_id TEXT,                -- actor ref for events + protocol_events
  p_issuer_trusted BOOLEAN,       -- for event detail
  p_event_detail JSONB            -- presentation_added event detail
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_presentation_id UUID;
  v_verified_at TIMESTAMPTZ;
BEGIN
  -- Compute verified_at
  IF p_verified THEN
    v_verified_at := v_now;
  ELSE
    v_verified_at := NULL;
  END IF;

  -- 1. Insert presentation record
  INSERT INTO handshake_presentations (
    handshake_id, party_role, presentation_type,
    issuer_ref, presentation_hash, disclosure_mode,
    raw_claims, normalized_claims, canonical_claims_hash,
    actor_entity_ref, authority_id, issuer_status,
    verified, verified_at,
    revocation_checked, revocation_status
  ) VALUES (
    p_handshake_id, p_party_role, p_presentation_type,
    p_issuer_ref, p_presentation_hash, p_disclosure_mode,
    p_raw_claims, p_normalized_claims, p_canonical_claims_hash,
    p_actor_entity_ref, p_authority_id, p_issuer_status,
    p_verified, v_verified_at,
    p_revocation_checked, p_revocation_status
  )
  RETURNING id INTO v_presentation_id;

  -- 2. Insert handshake event: presentation_added
  INSERT INTO handshake_events (
    handshake_id, event_type, event_payload,
    actor_entity_ref, detail, created_at
  ) VALUES (
    p_handshake_id, 'presentation_added', '{}'::JSONB,
    p_actor_id, p_event_detail, v_now
  );

  -- 3. Conditional status transition: initiated -> pending_verification
  IF p_current_hs_status = 'initiated' THEN
    -- Record status_changed event BEFORE the actual status change (event-first ordering)
    INSERT INTO handshake_events (
      handshake_id, event_type, event_payload,
      actor_entity_ref, detail, created_at
    ) VALUES (
      p_handshake_id, 'status_changed', '{}'::JSONB,
      p_actor_id,
      jsonb_build_object('from', 'initiated', 'to', 'pending_verification', 'trigger', 'presentation_added'),
      v_now
    );

    UPDATE handshakes
    SET status = 'pending_verification'
    WHERE handshake_id = p_handshake_id
      AND status = 'initiated';
  END IF;

  -- 4. Protocol event (skip protocolWrite's append)
  INSERT INTO protocol_events (
    aggregate_type, aggregate_id, command_type,
    payload_json, payload_hash, actor_authority_id,
    created_at
  ) VALUES (
    'handshake', p_handshake_id::TEXT, 'add_presentation',
    p_event_detail, '', p_actor_id,
    v_now
  );

  -- Return the stored presentation for the handler response
  RETURN jsonb_build_object(
    'id', v_presentation_id,
    'handshake_id', p_handshake_id,
    'party_role', p_party_role,
    'presentation_type', p_presentation_type,
    'issuer_ref', p_issuer_ref,
    'presentation_hash', p_presentation_hash,
    'disclosure_mode', p_disclosure_mode,
    'verified', p_verified,
    'verified_at', v_verified_at,
    'revocation_checked', p_revocation_checked,
    'revocation_status', p_revocation_status,
    'issuer_status', p_issuer_status,
    'authority_id', p_authority_id,
    'actor_entity_ref', p_actor_entity_ref,
    'canonical_claims_hash', p_canonical_claims_hash
  );
END;
$$;
