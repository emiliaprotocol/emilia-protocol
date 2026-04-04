-- EP Handshake — Close issuer authority TOCTOU in present_handshake_writes
--
-- Problem: The JS layer resolves the issuer authority (checking status, validity,
-- revocation), then passes the result to the RPC. Between the JS check and the
-- RPC write, the authority can be revoked. The presentation is then recorded as
-- verified even though the authority is now revoked.
--
-- Fix: If p_issuer_ref is provided and p_verified is TRUE, the RPC re-checks
-- the authority status using SELECT ... FOR UPDATE (locks the authority row for
-- the duration of the transaction). If the authority is no longer valid, the RPC
-- overrides p_verified to FALSE and sets issuer_status to 'authority_revoked_at_write'.

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
  p_current_hs_status TEXT,
  p_actor_id TEXT,
  p_issuer_trusted BOOLEAN,
  p_event_detail JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_presentation_id UUID;
  v_verified_at TIMESTAMPTZ;
  v_verified BOOLEAN := p_verified;
  v_issuer_status TEXT := p_issuer_status;
  v_authority_status TEXT;
  v_authority_valid_to TIMESTAMPTZ;
  v_authority_revoked_at TIMESTAMPTZ;
BEGIN
  -- 0. Re-check issuer authority under lock if we're about to record verified=true.
  --    This closes the TOCTOU between JS-side authority resolution and DB write.
  IF v_verified AND p_issuer_ref IS NOT NULL AND p_authority_id IS NOT NULL THEN
    SELECT status, valid_to, revoked_at
      INTO v_authority_status, v_authority_valid_to, v_authority_revoked_at
      FROM authorities
     WHERE key_id = p_authority_id
       FOR UPDATE;

    -- Authority revoked between JS check and RPC call
    IF v_authority_status IS NOT NULL AND v_authority_status != 'active' THEN
      v_verified := FALSE;
      v_issuer_status := 'authority_revoked_at_write';
    END IF;

    -- Authority expired between JS check and RPC call
    IF v_authority_valid_to IS NOT NULL AND v_authority_valid_to < v_now THEN
      v_verified := FALSE;
      v_issuer_status := 'authority_expired_at_write';
    END IF;
  END IF;

  -- Compute verified_at
  IF v_verified THEN
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
    p_actor_entity_ref, p_authority_id, v_issuer_status,
    v_verified, v_verified_at,
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

  -- 4. Protocol event
  INSERT INTO protocol_events (
    aggregate_type, aggregate_id, command_type,
    payload_json, payload_hash, actor_authority_id,
    created_at
  ) VALUES (
    'handshake', p_handshake_id::TEXT, 'add_presentation',
    p_event_detail, '', p_actor_id,
    v_now
  );

  RETURN jsonb_build_object(
    'id', v_presentation_id,
    'handshake_id', p_handshake_id,
    'party_role', p_party_role,
    'presentation_type', p_presentation_type,
    'issuer_ref', p_issuer_ref,
    'presentation_hash', p_presentation_hash,
    'disclosure_mode', p_disclosure_mode,
    'verified', v_verified,
    'verified_at', v_verified_at,
    'revocation_checked', p_revocation_checked,
    'revocation_status', p_revocation_status,
    'issuer_status', v_issuer_status,
    'authority_id', p_authority_id,
    'actor_entity_ref', p_actor_entity_ref,
    'canonical_claims_hash', p_canonical_claims_hash
  );
END;
$$;
