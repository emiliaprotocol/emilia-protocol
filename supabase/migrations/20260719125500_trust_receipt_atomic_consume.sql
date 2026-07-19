-- Atomic generic Trust Receipt consumption.
--
-- Application code verifies signatures and quorum semantics first. This
-- function then locks the immutable creation evidence plus every credential
-- and authority relied upon, rechecks their current registry state, and
-- appends the one-time consume event in the same transaction. It deliberately
-- rejects policy_rollout, whose consume must stay atomic with rollout state.

CREATE OR REPLACE FUNCTION public.consume_trust_receipt_authorized(
  p_receipt_id TEXT,
  p_action_hash TEXT,
  p_actor_id TEXT,
  p_organization_id TEXT,
  p_executing_system TEXT,
  p_execution_reference_id TEXT,
  p_registry_bindings JSONB,
  p_authority_facts JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_created JSONB;
  v_created_count BIGINT;
  v_consumed_count BIGINT;
  v_binding_count BIGINT;
  v_valid_binding_count BIGINT;
  v_required_count INTEGER := 1;
  v_required_assurance TEXT := 'C';
  v_signoff_required BOOLEAN := false;
  v_has_quorum BOOLEAN := false;
  v_expires_at TIMESTAMPTZ;
  v_consumed_at TIMESTAMPTZ := pg_catalog.now();
BEGIN
  IF p_receipt_id IS NULL OR p_receipt_id !~ '^tr_[a-f0-9]{32}$'
     OR p_action_hash IS NULL OR p_action_hash !~ '^[a-f0-9]{64}$'
     OR p_actor_id IS NULL OR btrim(p_actor_id) = ''
     OR p_organization_id IS NULL OR btrim(p_organization_id) = ''
     OR p_executing_system IS NULL OR btrim(p_executing_system) = ''
     OR jsonb_typeof(p_registry_bindings) IS DISTINCT FROM 'array'
     OR jsonb_typeof(COALESCE(p_authority_facts, 'null'::jsonb))
          NOT IN ('object', 'null')
  THEN
    RAISE EXCEPTION 'invalid_trust_receipt_consume'
      USING ERRCODE = '22023';
  END IF;

  SELECT count(*)
  INTO v_created_count
  FROM public.audit_events ae
  WHERE ae.target_type = 'trust_receipt'
    AND ae.target_id = p_receipt_id
    AND ae.event_type = 'guard.trust_receipt.created';

  IF v_created_count <> 1 THEN
    RAISE EXCEPTION 'trust_receipt_unavailable'
      USING ERRCODE = '28000';
  END IF;

  SELECT ae.after_state
  INTO v_created
  FROM public.audit_events ae
  WHERE ae.target_type = 'trust_receipt'
    AND ae.target_id = p_receipt_id
    AND ae.event_type = 'guard.trust_receipt.created'
  FOR UPDATE;

  IF v_created ->> 'organization_id' IS DISTINCT FROM p_organization_id
     OR v_created ->> 'action_hash' IS DISTINCT FROM p_action_hash
     OR v_created ->> 'action_type' IS NULL
     OR v_created ->> 'action_type' = 'policy_rollout'
     OR (
       v_created ? 'required_assurance'
       AND v_created ->> 'required_assurance' NOT IN ('A', 'B', 'C')
     )
     OR (
       v_created ? 'signoff_required'
       AND jsonb_typeof(v_created -> 'signoff_required') <> 'boolean'
     )
     OR (
       v_created ? 'quorum_policy'
       AND jsonb_typeof(v_created -> 'quorum_policy') NOT IN ('object', 'null')
     )
     OR NOT pg_catalog.pg_input_is_valid(v_created ->> 'expires_at', 'timestamptz')
  THEN
    RAISE EXCEPTION 'trust_receipt_consume_mismatch'
      USING ERRCODE = '28000';
  END IF;

  v_expires_at := (v_created ->> 'expires_at')::timestamptz;
  IF v_expires_at <= v_consumed_at THEN
    RAISE EXCEPTION 'trust_receipt_expired'
      USING ERRCODE = '28000';
  END IF;

  v_signoff_required :=
    COALESCE((v_created ->> 'signoff_required')::boolean, false);
  v_required_assurance :=
    COALESCE(v_created ->> 'required_assurance', 'C');
  v_has_quorum :=
    jsonb_typeof(v_created -> 'quorum_policy') = 'object';

  SELECT count(*)
  INTO v_consumed_count
  FROM public.audit_events ae
  WHERE ae.target_type = 'trust_receipt'
    AND ae.target_id = p_receipt_id
    AND ae.event_type = 'guard.trust_receipt.consumed';
  IF v_consumed_count <> 0 THEN
    RAISE EXCEPTION 'trust_receipt_already_consumed'
      USING ERRCODE = '23505';
  END IF;

  IF v_has_quorum THEN
    IF NOT pg_catalog.pg_input_is_valid(
      v_created #>> '{quorum_policy,required}',
      'integer'
    ) THEN
      RAISE EXCEPTION 'trust_receipt_registry_facts_invalid'
        USING ERRCODE = '28000';
    END IF;
    v_required_count := (v_created #>> '{quorum_policy,required}')::integer;
    IF v_required_count < 1 THEN
      RAISE EXCEPTION 'trust_receipt_registry_facts_invalid'
        USING ERRCODE = '28000';
    END IF;
    -- The quorum verifier admits only Class-A members; keep the same
    -- requirement inside the transaction that consumes the receipt.
    v_required_assurance := 'A';
  END IF;

  SELECT count(*)
  INTO v_binding_count
  FROM pg_catalog.jsonb_array_elements(p_registry_bindings) binding;

  IF (
       v_signoff_required
       OR v_has_quorum
     )
     AND v_binding_count < v_required_count
  THEN
    RAISE EXCEPTION 'trust_receipt_registry_facts_invalid'
      USING ERRCODE = '28000';
  END IF;

  IF NOT v_signoff_required
     AND NOT v_has_quorum
     AND v_binding_count <> 0
  THEN
    RAISE EXCEPTION 'trust_receipt_registry_facts_invalid'
      USING ERRCODE = '28000';
  END IF;

  -- A binding is the exact tuple the application verified. Keeping the
  -- expected approver, role, authority and credential together prevents an
  -- authority-row reassignment from becoming a valid consume in the gap
  -- between application verification and this transaction.
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements(p_registry_bindings) binding
    WHERE jsonb_typeof(binding) <> 'object'
       OR binding ->> 'authority_id' IS NULL
       OR binding ->> 'approver_id' IS NULL
       OR (
         binding ? 'required_assurance'
         AND binding ->> 'required_assurance' NOT IN ('A', 'B', 'C')
       )
  ) OR v_binding_count <> (
    SELECT count(DISTINCT binding ->> 'authority_id')
    FROM pg_catalog.jsonb_array_elements(p_registry_bindings) binding
  ) OR v_binding_count <> (
    SELECT count(DISTINCT binding ->> 'approver_id')
    FROM pg_catalog.jsonb_array_elements(p_registry_bindings) binding
  ) THEN
    RAISE EXCEPTION 'trust_receipt_registry_facts_invalid'
      USING ERRCODE = '28000';
  END IF;

  PERFORM 1
  FROM public.approver_credentials ac
  JOIN pg_catalog.jsonb_array_elements(p_registry_bindings) binding
    ON ac.credential_id = binding ->> 'credential_id'
  WHERE binding ->> 'credential_id' IS NOT NULL
  ORDER BY ac.credential_id
  FOR UPDATE OF ac;

  PERFORM 1
  FROM public.authorities a
  JOIN pg_catalog.jsonb_array_elements(p_registry_bindings) binding
    ON a.authority_id::text = binding ->> 'authority_id'
  ORDER BY a.authority_id
  FOR UPDATE;

  SELECT count(*)
  INTO v_valid_binding_count
  FROM pg_catalog.jsonb_array_elements(p_registry_bindings) binding
  JOIN public.authorities a
    ON a.authority_id::text = binding ->> 'authority_id'
  LEFT JOIN public.approver_credentials ac
    ON ac.credential_id = binding ->> 'credential_id'
   AND ac.organization_id = p_organization_id
   AND ac.approver_id = binding ->> 'approver_id'
  WHERE a.organization_id = p_organization_id
    AND a.subject_type = 'human_approver'
    AND a.subject_ref = binding ->> 'approver_id'
    AND (
      binding ->> 'role' IS NULL
      OR a.role = binding ->> 'role'
    )
    AND a.status = 'active'
    AND a.revoked_at IS NULL
    AND a.valid_from <= v_consumed_at
    AND (a.valid_to IS NULL OR a.valid_to > v_consumed_at)
    AND (
      a.action_scopes IS NULL
      OR (v_created ->> 'action_type') = ANY (a.action_scopes)
    )
    AND CASE a.assurance_class
          WHEN 'A' THEN 3
          WHEN 'B' THEN 2
          WHEN 'C' THEN 1
          ELSE 0
        END >= CASE v_required_assurance
          WHEN 'A' THEN 3
          WHEN 'B' THEN 2
          ELSE 1
        END
    AND (
      v_required_assurance <> 'A'
      OR (
        binding ->> 'credential_id' IS NOT NULL
        AND ac.key_class = 'A'
        AND ac.revoked_at IS NULL
        AND ac.valid_from <= v_consumed_at
        AND (ac.valid_to IS NULL OR ac.valid_to > v_consumed_at)
      )
    );

  IF v_valid_binding_count <> v_binding_count THEN
    RAISE EXCEPTION 'trust_receipt_registry_facts_invalid'
      USING ERRCODE = '28000';
  END IF;

  INSERT INTO public.audit_events (
    event_type,
    actor_id,
    actor_type,
    target_type,
    target_id,
    action,
    before_state,
    after_state
  )
  VALUES (
    'guard.trust_receipt.consumed',
    p_actor_id,
    'system',
    'trust_receipt',
    p_receipt_id,
    'consume',
    pg_catalog.jsonb_build_object('receipt_status', 'pending_consume'),
    pg_catalog.jsonb_build_object(
      'receipt_status', 'consumed',
      'consumed_at', v_consumed_at,
      'consumed_by_system', p_executing_system,
      'execution_reference_id', p_execution_reference_id,
      'action_hash', p_action_hash,
      'authority', p_authority_facts
    )
  );

  RETURN pg_catalog.jsonb_build_object(
    'receipt_id', p_receipt_id,
    'consumed_at', v_consumed_at,
    'consumed_by_system', p_executing_system,
    'execution_reference_id', p_execution_reference_id
  );
END;
$$;

REVOKE ALL ON FUNCTION public.consume_trust_receipt_authorized(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, JSONB
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_trust_receipt_authorized(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, JSONB
) TO service_role;
