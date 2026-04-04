-- EP Handshake — Fold policy_version_number into create_handshake_atomic RPC
--
-- Problem: policy_version_number was set via a separate UPDATE after the RPC
-- completed. If the UPDATE failed (connection drop, timeout), the pin was
-- silently lost and verification would skip the version check.
--
-- Fix: Add p_policy_version_number as an RPC parameter and write it atomically
-- with the handshake row inside the same transaction.

CREATE OR REPLACE FUNCTION create_handshake_atomic(
  p_mode TEXT,
  p_policy_id UUID,
  p_policy_id_legacy TEXT,
  p_policy_version TEXT DEFAULT NULL,
  p_policy_version_number INTEGER DEFAULT NULL,
  p_interaction_id TEXT DEFAULT NULL,
  p_action_type TEXT DEFAULT NULL,
  p_resource_ref TEXT DEFAULT NULL,
  p_intent_ref TEXT DEFAULT NULL,
  p_action_hash TEXT DEFAULT NULL,
  p_policy_hash TEXT DEFAULT NULL,
  p_idempotency_key TEXT DEFAULT NULL,
  p_party_set_hash TEXT DEFAULT NULL,
  p_metadata_json JSONB DEFAULT '{}'::JSONB,
  p_parties JSONB DEFAULT '[]'::JSONB,
  p_binding JSONB DEFAULT '{}'::JSONB,
  p_event_actor_id TEXT DEFAULT NULL,
  p_event_actor_entity_ref TEXT DEFAULT NULL,
  p_event_detail JSONB DEFAULT '{}'::JSONB,
  p_protocol_event_payload JSONB DEFAULT '{}'::JSONB,
  p_protocol_event_payload_hash TEXT DEFAULT NULL,
  p_protocol_event_idempotency_key TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_handshake_id UUID;
  v_now TIMESTAMPTZ := now();
  v_party JSONB;
  v_binding_expires TIMESTAMPTZ;
BEGIN
  -- 1. Insert handshake row (includes policy_version_number atomically)
  INSERT INTO handshakes (
    mode, policy_id, policy_id_legacy, policy_version, policy_version_number,
    interaction_id, action_type, resource_ref, intent_ref,
    action_hash, policy_hash, idempotency_key,
    status, metadata_json, initiated_at, created_at
  ) VALUES (
    p_mode, p_policy_id, p_policy_id_legacy, p_policy_version, p_policy_version_number,
    p_interaction_id, p_action_type, p_resource_ref, p_intent_ref,
    p_action_hash, p_policy_hash, p_idempotency_key,
    'initiated', p_metadata_json, v_now, v_now
  )
  RETURNING handshake_id INTO v_handshake_id;

  -- 2. Insert parties
  FOR v_party IN SELECT * FROM jsonb_array_elements(p_parties)
  LOOP
    INSERT INTO handshake_parties (
      handshake_id, party_role, entity_ref, assurance_level, delegation_chain, verified_status
    ) VALUES (
      v_handshake_id,
      v_party->>'party_role',
      v_party->>'entity_ref',
      v_party->>'assurance_level',
      CASE WHEN v_party->'delegation_chain' IS NOT NULL AND v_party->>'delegation_chain' != 'null'
           THEN v_party->'delegation_chain' ELSE NULL END,
      'pending'
    );
  END LOOP;

  -- 3. Insert binding
  v_binding_expires := COALESCE(
    (p_binding->>'expires_at')::TIMESTAMPTZ,
    v_now + INTERVAL '30 minutes'
  );

  INSERT INTO handshake_bindings (
    handshake_id, payload_hash, nonce, expires_at, bound_at,
    party_set_hash, context_hash, binding_hash,
    binding_material_version, initiator_entity_ref
  ) VALUES (
    v_handshake_id,
    p_binding->>'payload_hash',
    p_binding->>'nonce',
    v_binding_expires,
    v_now,
    p_binding->>'party_set_hash',
    p_binding->>'context_hash',
    p_binding->>'binding_hash',
    COALESCE((p_binding->>'binding_material_version')::INTEGER, 1),
    p_binding->>'initiator_entity_ref'
  );

  -- 4. Insert handshake event
  INSERT INTO handshake_events (
    handshake_id, event_type, event_payload,
    actor_id, actor_entity_ref, detail, created_at
  ) VALUES (
    v_handshake_id, 'handshake_created', '{}'::JSONB,
    p_event_actor_id, p_event_actor_entity_ref,
    p_event_detail, v_now
  );

  -- 5. Insert protocol event
  INSERT INTO protocol_events (
    aggregate_type, aggregate_id, command_type,
    payload_json, payload_hash, actor_authority_id,
    idempotency_key, created_at
  ) VALUES (
    'handshake', v_handshake_id::TEXT, 'initiate_handshake',
    p_protocol_event_payload, COALESCE(p_protocol_event_payload_hash, ''),
    p_event_actor_id,
    p_protocol_event_idempotency_key,
    v_now
  );

  RETURN jsonb_build_object('handshake_id', v_handshake_id);
END;
$$;
