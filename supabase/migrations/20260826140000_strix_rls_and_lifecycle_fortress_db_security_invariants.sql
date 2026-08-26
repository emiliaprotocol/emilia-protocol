-- STRIX database closure: make the intended service-only posture real and
-- serialize receipt/signoff terminal transitions at their durable roots.

-- BEGIN STRIX-RLS-CLOSURE
ALTER TABLE public.alert_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.continuity_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.continuity_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.continuity_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ep_gate_control_domain_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ep_gate_control_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.eye_advisories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.eye_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.eye_suppressions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.guarded_receipt_consumptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.handshake_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.handshake_consumptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.handshake_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.handshake_parties ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.handshake_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.handshake_presentations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.handshake_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.merkle_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.principal_delegation_signals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.protocol_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.signoff_approval_velocity ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.signoff_consumptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.signoff_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_control_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.trust_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zk_proofs ENABLE ROW LEVEL SECURITY;

-- These tables are all reached through service/RPC paths. FORCE closes the
-- accidental table-owner bypass while the service_role policy below preserves
-- the intended Supabase service path.
ALTER TABLE public.alert_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.alert_rules FORCE ROW LEVEL SECURITY;
ALTER TABLE public.continuity_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE public.continuity_claims FORCE ROW LEVEL SECURITY;
ALTER TABLE public.continuity_decisions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.delegations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ep_gate_control_domain_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ep_gate_control_domains FORCE ROW LEVEL SECURITY;
ALTER TABLE public.eye_advisories FORCE ROW LEVEL SECURITY;
ALTER TABLE public.eye_observations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.eye_suppressions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.guarded_receipt_consumptions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.handshake_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE public.handshake_consumptions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.handshake_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.handshake_parties FORCE ROW LEVEL SECURITY;
ALTER TABLE public.handshake_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE public.handshake_presentations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.handshake_results FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE public.merkle_batches FORCE ROW LEVEL SECURITY;
ALTER TABLE public.principal_delegation_signals FORCE ROW LEVEL SECURITY;
ALTER TABLE public.principals FORCE ROW LEVEL SECURITY;
ALTER TABLE public.protocol_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.signoff_approval_velocity FORCE ROW LEVEL SECURITY;
ALTER TABLE public.signoff_consumptions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.signoff_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_control_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_environments FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_members FORCE ROW LEVEL SECURITY;
ALTER TABLE public.trust_reports FORCE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_deliveries FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zk_proofs FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.alert_events FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.alert_rules FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.continuity_challenges FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.continuity_claims FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.continuity_decisions FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.delegations FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.ep_gate_control_domain_events FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.ep_gate_control_domains FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.eye_advisories FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.eye_observations FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.eye_suppressions FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.guarded_receipt_consumptions FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.handshake_bindings FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.handshake_consumptions FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.handshake_events FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.handshake_parties FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.handshake_policies FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.handshake_presentations FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.handshake_results FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.identity_bindings FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.merkle_batches FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.principal_delegation_signals FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.principals FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.protocol_events FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.signoff_approval_velocity FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.signoff_consumptions FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.signoff_events FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.tenant_control_events FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.tenant_environments FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.tenant_members FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.trust_reports FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.webhook_deliveries FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.zk_proofs FROM PUBLIC, anon, authenticated;

DO $strix_rls$
DECLARE
  table_name TEXT;
  service_tables CONSTANT TEXT[] := ARRAY[
    'alert_events', 'alert_rules', 'continuity_challenges', 'continuity_claims',
    'continuity_decisions', 'delegations', 'ep_gate_control_domain_events',
    'ep_gate_control_domains', 'eye_advisories', 'eye_observations',
    'eye_suppressions', 'guarded_receipt_consumptions', 'handshake_bindings',
    'handshake_consumptions', 'handshake_events', 'handshake_parties',
    'handshake_policies', 'handshake_presentations', 'handshake_results',
    'identity_bindings', 'merkle_batches', 'principal_delegation_signals',
    'principals', 'protocol_events', 'signoff_approval_velocity',
    'signoff_consumptions', 'signoff_events', 'tenant_control_events',
    'tenant_environments', 'tenant_members', 'trust_reports',
    'webhook_deliveries', 'zk_proofs'
  ];
BEGIN
  FOREACH table_name IN ARRAY service_tables LOOP
    EXECUTE pg_catalog.format(
      'DROP POLICY IF EXISTS service_role_bypass ON public.%I', table_name
    );
    EXECUTE pg_catalog.format(
      'CREATE POLICY service_role_bypass ON public.%I TO service_role USING (true) WITH CHECK (true)',
      table_name
    );
  END LOOP;
END;
$strix_rls$;
-- END STRIX-RLS-CLOSURE

-- BEGIN STRIX-SAML-SIGNING-CLOSURE
-- Response-envelope signing is now a service-wide ACS invariant. Normalize the
-- legacy per-tenant compatibility field so stored configuration cannot imply
-- an assertion-only mode that the authentication path no longer accepts.
UPDATE public.sso_connections
SET saml_want_response_signed = true
WHERE saml_want_response_signed IS DISTINCT FROM true;

ALTER TABLE public.sso_connections
  ALTER COLUMN saml_want_response_signed SET DEFAULT true;
ALTER TABLE public.sso_connections
  ALTER COLUMN saml_want_response_signed SET NOT NULL;

COMMENT ON COLUMN public.sso_connections.saml_want_response_signed IS
  'Legacy compatibility field pinned true. The ACS requires a signed SAML Response envelope regardless of this tenant field.';
-- END STRIX-SAML-SIGNING-CLOSURE

-- BEGIN STRIX-TRANSACTIONAL-CLOSURE
-- Match only a rejection attached to a creator-issued request for this exact
-- action. A loose event with a leaked receipt id is not authority evidence.
CREATE OR REPLACE FUNCTION public.guard_receipt_has_bound_rejection(
  p_receipt_id TEXT,
  p_creator_actor_id TEXT,
  p_action_hash TEXT
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SET search_path = ''
AS $guard_receipt_has_bound_rejection$
  SELECT EXISTS (
    SELECT 1
    FROM public.audit_events AS request_event
    JOIN public.audit_events AS rejection_event
      ON rejection_event.target_type = 'trust_receipt'
     AND rejection_event.target_id = request_event.target_id
     AND rejection_event.event_type = 'guard.signoff.rejected'
     AND rejection_event.after_state ->> 'signoff_id'
           = request_event.after_state ->> 'signoff_id'
    WHERE request_event.target_type = 'trust_receipt'
      AND request_event.target_id = p_receipt_id
      AND request_event.event_type = 'guard.signoff.requested'
      AND request_event.actor_id = p_creator_actor_id
      AND request_event.after_state ->> 'signoff_id' IS NOT NULL
      AND rejection_event.after_state ->> 'approved_action_hash' = p_action_hash
      AND (
        COALESCE(
          request_event.after_state ->> 'approver_id',
          request_event.after_state #>> '{quorum,approver_id}'
        ) IS NULL
        OR COALESCE(
          rejection_event.after_state ->> 'approver_id',
          rejection_event.actor_id
        ) = COALESCE(
          request_event.after_state ->> 'approver_id',
          request_event.after_state #>> '{quorum,approver_id}'
        )
      )
  );
$guard_receipt_has_bound_rejection$;

REVOKE ALL ON FUNCTION public.guard_receipt_has_bound_rejection(
  TEXT, TEXT, TEXT
) FROM PUBLIC, anon, authenticated, service_role;

-- The immutable creation event is the per-receipt mutex shared by decision
-- insertion and consume. Whichever terminal transition obtains this row lock
-- first commits; the loser rechecks durable state and fails closed.
CREATE OR REPLACE FUNCTION public.serialize_guard_receipt_lifecycle_event()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $serialize_guard_receipt_lifecycle_event$
DECLARE
  v_creator_actor_id TEXT;
  v_action_hash TEXT;
  v_expires_at_text TEXT;
  v_signoff_required BOOLEAN;
BEGIN
  IF NEW.target_type IS DISTINCT FROM 'trust_receipt'
     OR NEW.event_type NOT IN (
       'guard.signoff.approved',
       'guard.signoff.rejected',
       'guard.trust_receipt.consumed'
     ) THEN
    RETURN NEW;
  END IF;

  SELECT
    created_event.actor_id,
    created_event.after_state ->> 'action_hash',
    created_event.after_state ->> 'expires_at',
    created_event.after_state @> '{"signoff_required": true}'::JSONB
      OR pg_catalog.jsonb_typeof(created_event.after_state -> 'quorum_policy') = 'object'
  INTO
    v_creator_actor_id,
    v_action_hash,
    v_expires_at_text,
    v_signoff_required
  FROM public.audit_events AS created_event
  WHERE created_event.target_type = 'trust_receipt'
    AND created_event.target_id = NEW.target_id
    AND created_event.event_type = 'guard.trust_receipt.created'
  FOR UPDATE OF created_event;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'trust_receipt_unavailable'
      USING ERRCODE = '28000';
  END IF;

  IF NEW.event_type IN ('guard.signoff.approved', 'guard.signoff.rejected') THEN
    IF EXISTS (
      SELECT 1
      FROM public.audit_events AS consumed_event
      WHERE consumed_event.target_type = 'trust_receipt'
        AND consumed_event.target_id = NEW.target_id
        AND consumed_event.event_type = 'guard.trust_receipt.consumed'
    ) THEN
      RAISE EXCEPTION 'trust_receipt_already_consumed'
        USING ERRCODE = '23505';
    END IF;
    RETURN NEW;
  END IF;

  IF NOT pg_catalog.pg_input_is_valid(v_expires_at_text, 'timestamptz') THEN
    RAISE EXCEPTION 'trust_receipt_consume_mismatch'
      USING ERRCODE = '28000';
  END IF;
  IF v_expires_at_text::TIMESTAMPTZ <= pg_catalog.clock_timestamp() THEN
    RAISE EXCEPTION 'trust_receipt_expired'
      USING ERRCODE = '28000';
  END IF;

  IF v_signoff_required
     AND public.guard_receipt_has_bound_rejection(
       NEW.target_id,
       v_creator_actor_id,
       v_action_hash
     ) THEN
    RAISE EXCEPTION 'trust_receipt_signoff_rejected'
      USING ERRCODE = '28000';
  END IF;

  RETURN NEW;
END;
$serialize_guard_receipt_lifecycle_event$;

REVOKE ALL ON FUNCTION public.serialize_guard_receipt_lifecycle_event()
  FROM PUBLIC, anon, authenticated, service_role;

DROP TRIGGER IF EXISTS serialize_guard_receipt_lifecycle
  ON public.audit_events;
CREATE TRIGGER serialize_guard_receipt_lifecycle
  BEFORE INSERT ON public.audit_events
  FOR EACH ROW
  EXECUTE FUNCTION public.serialize_guard_receipt_lifecycle_event();

-- Keep the complete, previously reviewed state-lock implementation intact as
-- the private inner state machine. The public wrapper performs a second
-- validity decision with wall-clock time after that inner function has acquired
-- every authoritative lock. Raising here rolls the inner writes back atomically.
ALTER FUNCTION public.consume_signoff_atomic(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) RENAME TO consume_signoff_atomic_state_locked_v1;

REVOKE ALL ON FUNCTION public.consume_signoff_atomic_state_locked_v1(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.consume_signoff_atomic(
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
SET search_path = ''
AS $consume_signoff_atomic$
DECLARE
  v_result JSONB;
  v_validity_checked_at TIMESTAMPTZ;
  v_handshake_expires_at TIMESTAMPTZ;
  v_binding_expires_at TIMESTAMPTZ;
  v_challenge_expires_at TIMESTAMPTZ;
  v_authority_valid_from TIMESTAMPTZ;
  v_authority_valid_to TIMESTAMPTZ;
  v_attestation_expires_at TIMESTAMPTZ;
BEGIN
  v_result := public.consume_signoff_atomic_state_locked_v1(
    p_signoff_id,
    p_binding_hash,
    p_execution_ref,
    p_handshake_id,
    p_challenge_id,
    p_human_entity_ref
  );

  SELECT
    handshake.expires_at,
    binding.expires_at,
    challenge.expires_at,
    authority.valid_from,
    authority.valid_to,
    attestation.expires_at
  INTO
    v_handshake_expires_at,
    v_binding_expires_at,
    v_challenge_expires_at,
    v_authority_valid_from,
    v_authority_valid_to,
    v_attestation_expires_at
  FROM public.signoff_attestations AS attestation
  JOIN public.signoff_challenges AS challenge
    ON challenge.challenge_id = attestation.challenge_id
  JOIN public.handshake_bindings AS binding
    ON binding.id = challenge.handshake_id
  JOIN public.handshakes AS handshake
    ON handshake.handshake_id = binding.handshake_id
  JOIN public.authorities AS authority
    ON authority.authority_id = challenge.authority_id
  WHERE attestation.signoff_id = p_signoff_id::UUID
    AND challenge.challenge_id = p_challenge_id::UUID
    AND binding.id = p_handshake_id::UUID;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0002', MESSAGE = 'SIGNOFF_ATTESTATION_NOT_FOUND';
  END IF;

  v_validity_checked_at := pg_catalog.clock_timestamp();
  IF v_handshake_expires_at IS NOT NULL
     AND v_handshake_expires_at <= v_validity_checked_at THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_HANDSHAKE_EXPIRED';
  END IF;
  IF v_binding_expires_at IS NULL
     OR v_binding_expires_at <= v_validity_checked_at THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_BINDING_EXPIRED';
  END IF;
  IF v_challenge_expires_at IS NULL
     OR v_challenge_expires_at <= v_validity_checked_at THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_CHALLENGE_EXPIRED';
  END IF;
  IF v_authority_valid_from > v_validity_checked_at
     OR (
       v_authority_valid_to IS NOT NULL
       AND v_authority_valid_to <= v_validity_checked_at
     ) THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_AUTHORITY_INVALID_OR_REVOKED';
  END IF;
  IF v_attestation_expires_at IS NULL
     OR v_attestation_expires_at <= v_validity_checked_at THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001', MESSAGE = 'SIGNOFF_ATTESTATION_EXPIRED';
  END IF;

  RETURN v_result;
END;
$consume_signoff_atomic$;

REVOKE ALL ON FUNCTION public.consume_signoff_atomic(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_signoff_atomic(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) TO service_role;

COMMENT ON FUNCTION public.consume_signoff_atomic(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) IS 'Runs the complete locked signoff state machine, then rejects and rolls back if any pinned validity window expired while lock acquisition was pending.';

-- The generic receipt consumer historically captured now() before it waited
-- for authority and credential row locks. Preserve its complete reviewed state
-- machine as an inner function, then make the public entry point decide every
-- registry validity window against a wall-clock instant obtained after the
-- inner function has acquired those locks. A rejection rolls back the inner
-- consume event atomically.
ALTER FUNCTION public.consume_trust_receipt_authorized(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, JSONB
) RENAME TO consume_trust_receipt_authorized_state_locked_v1;

REVOKE ALL ON FUNCTION public.consume_trust_receipt_authorized_state_locked_v1(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, JSONB
) FROM PUBLIC, anon, authenticated, service_role;

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
AS $consume_trust_receipt_authorized$
DECLARE
  v_result JSONB;
  v_created JSONB;
  v_checked_at TIMESTAMPTZ;
  v_required_assurance TEXT;
  v_binding_count INTEGER;
  v_valid_binding_count INTEGER;
BEGIN
  v_result := public.consume_trust_receipt_authorized_state_locked_v1(
    p_receipt_id,
    p_action_hash,
    p_actor_id,
    p_organization_id,
    p_executing_system,
    p_execution_reference_id,
    p_registry_bindings,
    p_authority_facts
  );

  SELECT created_event.after_state
    INTO v_created
    FROM public.audit_events AS created_event
   WHERE created_event.target_type = 'trust_receipt'
     AND created_event.target_id = p_receipt_id
     AND created_event.event_type = 'guard.trust_receipt.created';
  IF NOT FOUND
     OR NOT pg_catalog.pg_input_is_valid(v_created ->> 'expires_at', 'timestamptz') THEN
    RAISE EXCEPTION 'trust_receipt_unavailable'
      USING ERRCODE = '28000';
  END IF;

  v_checked_at := pg_catalog.clock_timestamp();
  IF (v_created ->> 'expires_at')::TIMESTAMPTZ <= v_checked_at THEN
    RAISE EXCEPTION 'trust_receipt_expired'
      USING ERRCODE = '28000';
  END IF;

  v_required_assurance := CASE
    WHEN pg_catalog.jsonb_typeof(v_created -> 'quorum_policy') = 'object'
      THEN 'A'
    ELSE COALESCE(v_created ->> 'required_assurance', 'C')
  END;
  v_binding_count := pg_catalog.jsonb_array_length(p_registry_bindings);

  SELECT count(*)
    INTO v_valid_binding_count
    FROM pg_catalog.jsonb_array_elements(p_registry_bindings) AS binding
    JOIN public.authorities AS authority
      ON authority.authority_id::TEXT = binding ->> 'authority_id'
    LEFT JOIN public.approver_credentials AS credential
      ON credential.credential_id = binding ->> 'credential_id'
     AND credential.organization_id = p_organization_id
     AND credential.approver_id = binding ->> 'approver_id'
   WHERE authority.organization_id = p_organization_id
     AND authority.subject_type = 'human_approver'
     AND authority.subject_ref = binding ->> 'approver_id'
     AND (binding ->> 'role' IS NULL OR authority.role = binding ->> 'role')
     AND authority.status = 'active'
     AND authority.revoked_at IS NULL
     AND authority.valid_from <= v_checked_at
     AND (authority.valid_to IS NULL OR authority.valid_to > v_checked_at)
     AND (
       authority.action_scopes IS NULL
       OR (v_created ->> 'action_type') = ANY (authority.action_scopes)
     )
     AND CASE authority.assurance_class
           WHEN 'A' THEN 3 WHEN 'B' THEN 2 WHEN 'C' THEN 1 ELSE 0
         END >= CASE v_required_assurance
           WHEN 'A' THEN 3 WHEN 'B' THEN 2 ELSE 1
         END
     AND (
       v_required_assurance <> 'A'
       OR (
         binding ->> 'credential_id' IS NOT NULL
         AND credential.key_class = 'A'
         AND credential.revoked_at IS NULL
         AND credential.valid_from <= v_checked_at
         AND (credential.valid_to IS NULL OR credential.valid_to > v_checked_at)
       )
     );

  IF v_valid_binding_count IS DISTINCT FROM v_binding_count THEN
    RAISE EXCEPTION 'trust_receipt_registry_facts_invalid'
      USING ERRCODE = '28000';
  END IF;

  INSERT INTO public.audit_events (
    event_type, actor_id, actor_type, target_type, target_id,
    action, after_state
  ) VALUES (
    'guard.trust_receipt.consume_validity_checked', p_actor_id, 'system',
    'trust_receipt', p_receipt_id, 'post_lock_validity_check',
    pg_catalog.jsonb_build_object(
      'validity_checked_at', v_checked_at,
      'organization_id', p_organization_id,
      'binding_count', v_binding_count
    )
  );

  RETURN v_result || pg_catalog.jsonb_build_object(
    'validity_checked_at', v_checked_at
  );
END;
$consume_trust_receipt_authorized$;

REVOKE ALL ON FUNCTION public.consume_trust_receipt_authorized(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, JSONB
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_trust_receipt_authorized(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, JSONB
) TO service_role;

COMMENT ON FUNCTION public.consume_trust_receipt_authorized(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, JSONB
) IS 'Runs the complete locked receipt-consume state machine and then rechecks receipt, authority, and credential validity against post-lock wall-clock time.';

-- Apply the same post-lock rule to policy rollout. The inner activation locks
-- the policy family, receipt, credentials, and authorities and buffers its one
-- returned row. The wrapper rechecks the exact authority/credential tuples at
-- a wall-clock instant after all of those locks are held. Raising rolls the
-- receipt consume and rollout insert back together.
ALTER FUNCTION public.activate_policy_rollout_authorized(
  UUID, UUID, TEXT, INTEGER, TEXT, TEXT, SMALLINT, TEXT, JSONB,
  TEXT, TEXT, JSONB, JSONB, UUID[], JSONB
) RENAME TO activate_policy_rollout_authorized_state_locked_v1;

REVOKE ALL ON FUNCTION public.activate_policy_rollout_authorized_state_locked_v1(
  UUID, UUID, TEXT, INTEGER, TEXT, TEXT, SMALLINT, TEXT, JSONB,
  TEXT, TEXT, JSONB, JSONB, UUID[], JSONB
) FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.activate_policy_rollout_authorized(
  p_tenant_id UUID,
  p_policy_id UUID,
  p_policy_key TEXT,
  p_version INTEGER,
  p_environment TEXT,
  p_strategy TEXT,
  p_canary_pct SMALLINT,
  p_initiated_by TEXT,
  p_metadata JSONB,
  p_receipt_id TEXT,
  p_action_hash TEXT,
  p_signed_before_state JSONB,
  p_signed_after_state JSONB,
  p_authority_ids UUID[],
  p_quorum_policy JSONB
)
RETURNS SETOF public.policy_rollouts
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $activate_policy_rollout_authorized$
DECLARE
  v_rollout public.policy_rollouts%ROWTYPE;
  v_checked_at TIMESTAMPTZ;
  v_authority JSONB;
  v_member_count INTEGER;
  v_valid_member_count INTEGER;
BEGIN
  SELECT *
    INTO v_rollout
    FROM public.activate_policy_rollout_authorized_state_locked_v1(
      p_tenant_id, p_policy_id, p_policy_key, p_version, p_environment,
      p_strategy, p_canary_pct, p_initiated_by, p_metadata, p_receipt_id,
      p_action_hash, p_signed_before_state, p_signed_after_state,
      p_authority_ids, p_quorum_policy
    );
  IF NOT FOUND THEN
    RAISE EXCEPTION 'policy_rollout_activation_unavailable'
      USING ERRCODE = '28000';
  END IF;

  v_checked_at := pg_catalog.clock_timestamp();
  v_authority := v_rollout.authorization_authority;

  WITH members AS (
    SELECT member
      FROM pg_catalog.jsonb_array_elements(
        CASE
          WHEN v_authority @> '{"quorum": true}'::JSONB
            THEN COALESCE(v_authority -> 'members', '[]'::JSONB)
          ELSE pg_catalog.jsonb_build_array(v_authority)
        END
      ) AS member
  )
  SELECT count(*) INTO v_member_count FROM members;

  WITH members AS (
    SELECT member
      FROM pg_catalog.jsonb_array_elements(
        CASE
          WHEN v_authority @> '{"quorum": true}'::JSONB
            THEN COALESCE(v_authority -> 'members', '[]'::JSONB)
          ELSE pg_catalog.jsonb_build_array(v_authority)
        END
      ) AS member
  )
  SELECT count(*)
    INTO v_valid_member_count
    FROM members
    JOIN public.authorities AS authority
      ON authority.authority_id::TEXT = members.member ->> 'authority_id'
    JOIN public.approver_credentials AS credential
      ON credential.credential_id = members.member ->> 'credential_id'
     AND credential.organization_id = p_tenant_id::TEXT
     AND credential.approver_id = authority.subject_ref
   WHERE authority.authority_id = ANY (p_authority_ids)
     AND authority.organization_id = p_tenant_id::TEXT
     AND authority.subject_type = 'human_approver'
     AND authority.role IN ('policy_admin', 'control_plane_approver')
     AND authority.status = 'active'
     AND authority.revoked_at IS NULL
     AND authority.valid_from <= v_checked_at
     AND (authority.valid_to IS NULL OR authority.valid_to > v_checked_at)
     AND authority.assurance_class = 'A'
     AND authority.action_scopes IS NOT NULL
     AND 'policy_rollout' = ANY (authority.action_scopes)
     AND credential.key_class = 'A'
     AND credential.revoked_at IS NULL
     AND credential.valid_from <= v_checked_at
     AND (credential.valid_to IS NULL OR credential.valid_to > v_checked_at);

  IF v_member_count < 1
     OR v_member_count IS DISTINCT FROM pg_catalog.cardinality(p_authority_ids)
     OR v_valid_member_count IS DISTINCT FROM v_member_count THEN
    RAISE EXCEPTION 'policy_rollout_registry_validity_expired'
      USING ERRCODE = '28000';
  END IF;

  INSERT INTO public.audit_events (
    event_type, actor_id, actor_type, target_type, target_id,
    action, after_state
  ) VALUES (
    'guard.policy_rollout.validity_checked', p_initiated_by, 'system',
    'trust_receipt', p_receipt_id, 'post_lock_validity_check',
    pg_catalog.jsonb_build_object(
      'validity_checked_at', v_checked_at,
      'rollout_id', v_rollout.rollout_id,
      'organization_id', p_tenant_id,
      'member_count', v_member_count
    )
  );

  RETURN NEXT v_rollout;
END;
$activate_policy_rollout_authorized$;

REVOKE ALL ON FUNCTION public.activate_policy_rollout_authorized(
  UUID, UUID, TEXT, INTEGER, TEXT, TEXT, SMALLINT, TEXT, JSONB,
  TEXT, TEXT, JSONB, JSONB, UUID[], JSONB
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.activate_policy_rollout_authorized(
  UUID, UUID, TEXT, INTEGER, TEXT, TEXT, SMALLINT, TEXT, JSONB,
  TEXT, TEXT, JSONB, JSONB, UUID[], JSONB
) TO service_role;

COMMENT ON FUNCTION public.activate_policy_rollout_authorized(
  UUID, UUID, TEXT, INTEGER, TEXT, TEXT, SMALLINT, TEXT, JSONB,
  TEXT, TEXT, JSONB, JSONB, UUID[], JSONB
) IS 'Runs the complete locked rollout activation and then rechecks every authority and credential validity window against post-lock wall-clock time.';
-- END STRIX-TRANSACTIONAL-CLOSURE
