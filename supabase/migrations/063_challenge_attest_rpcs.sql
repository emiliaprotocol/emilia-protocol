-- Batch write RPCs for signoff challenge issuance and attestation approval.
-- These reduce serial DB roundtrips without changing semantics.
-- Event-first ordering is preserved: event INSERT precedes state INSERT/UPDATE.

-- ============================================================================
-- 1. issue_challenge_atomic — batches event + challenge insert
-- ============================================================================
-- Called after JS-side validation (handshake status, binding_hash match).
-- Writes signoff_event then signoff_challenge in a single transaction.

CREATE OR REPLACE FUNCTION issue_challenge_atomic(
  p_challenge_id UUID,
  p_handshake_id UUID,
  p_binding_hash TEXT,
  p_accountable_actor_ref TEXT,
  p_signoff_policy_id TEXT,
  p_signoff_policy_hash TEXT,
  p_required_assurance TEXT,
  p_allowed_methods TEXT[],
  p_expires_at TIMESTAMPTZ,
  p_metadata_json JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_event_id UUID := gen_random_uuid();
  v_challenge JSONB;
BEGIN
  -- 1. Event-first: insert signoff event
  INSERT INTO signoff_events (
    event_id, handshake_id, challenge_id, signoff_id,
    event_type, actor_entity_ref, detail, created_at
  ) VALUES (
    v_event_id, p_handshake_id, p_challenge_id, NULL,
    'challenge_issued', p_accountable_actor_ref,
    jsonb_build_object(
      'accountable_actor_ref', p_accountable_actor_ref,
      'signoff_policy_id', p_signoff_policy_id,
      'required_assurance', p_required_assurance,
      'allowed_methods', to_jsonb(p_allowed_methods),
      'expires_at', p_expires_at
    ),
    v_now
  );

  -- 2. Insert challenge record
  INSERT INTO signoff_challenges (
    challenge_id, handshake_id, binding_hash,
    accountable_actor_ref, signoff_policy_id, signoff_policy_hash,
    required_assurance, allowed_methods,
    status, expires_at, metadata, issued_at
  ) VALUES (
    p_challenge_id, p_handshake_id, p_binding_hash,
    p_accountable_actor_ref, p_signoff_policy_id, p_signoff_policy_hash,
    p_required_assurance, p_allowed_methods,
    'challenge_issued', p_expires_at, p_metadata_json, v_now
  );

  -- Return the inserted challenge as JSONB
  SELECT to_jsonb(c.*) INTO v_challenge
  FROM signoff_challenges c
  WHERE c.challenge_id = p_challenge_id;

  RETURN v_challenge;
END;
$$;

COMMENT ON FUNCTION issue_challenge_atomic IS 'Atomic challenge issuance: inserts signoff event then challenge record in one transaction. Event-first ordering preserved.';

-- ============================================================================
-- 2. approve_attestation_atomic — batches event + attestation + challenge update
-- ============================================================================
-- Called after JS-side validation (challenge status, actor ownership,
-- assurance level, allowed methods).
-- Writes signoff_event, signoff_attestation, then updates challenge status
-- in a single transaction.

CREATE OR REPLACE FUNCTION approve_attestation_atomic(
  p_signoff_id UUID,
  p_challenge_id UUID,
  p_handshake_id UUID,
  p_binding_hash TEXT,
  p_human_entity_ref TEXT,
  p_auth_method TEXT,
  p_assurance_level TEXT,
  p_channel TEXT,
  p_expires_at TIMESTAMPTZ,
  p_attestation_hash TEXT,
  p_metadata_json JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_event_id UUID := gen_random_uuid();
  v_attestation JSONB;
BEGIN
  -- 1. Event-first: insert signoff event
  INSERT INTO signoff_events (
    event_id, handshake_id, challenge_id, signoff_id,
    event_type, actor_entity_ref, detail, created_at
  ) VALUES (
    v_event_id, p_handshake_id, p_challenge_id, p_signoff_id,
    'signoff_approved', p_human_entity_ref,
    jsonb_build_object(
      'human_entity_ref', p_human_entity_ref,
      'auth_method', p_auth_method,
      'assurance_level', p_assurance_level,
      'channel', p_channel
    ),
    v_now
  );

  -- 2. Insert attestation record
  INSERT INTO signoff_attestations (
    signoff_id, challenge_id, handshake_id, binding_hash,
    human_entity_ref, auth_method, assurance_level,
    channel, status, expires_at,
    attestation_hash, metadata, approved_at
  ) VALUES (
    p_signoff_id, p_challenge_id, p_handshake_id, p_binding_hash,
    p_human_entity_ref, p_auth_method, p_assurance_level,
    p_channel, 'approved', p_expires_at,
    p_attestation_hash, p_metadata_json, v_now
  );

  -- 3. Update challenge status to approved
  UPDATE signoff_challenges
  SET status = 'approved',
      metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('approved_at', v_now)
  WHERE challenge_id = p_challenge_id;

  -- Return the inserted attestation as JSONB
  SELECT to_jsonb(a.*) INTO v_attestation
  FROM signoff_attestations a
  WHERE a.signoff_id = p_signoff_id;

  RETURN v_attestation;
END;
$$;

COMMENT ON FUNCTION approve_attestation_atomic IS 'Atomic attestation approval: inserts signoff event, attestation record, and updates challenge status in one transaction. Event-first ordering preserved.';
