-- Accountable Signoff for policy rollout activation.
--
-- The approved Trust Receipt is consumed in the SAME transaction that locks
-- the policy target, rechecks signed before/after state, supersedes the prior
-- immediate rollout, and inserts the new rollout.
--
-- EXPAND PHASE: service-role table writes remain temporarily available so this
-- migration can land before the application switches to the RPC. The paired
-- 20260719130000 contract migration removes those writes only after the new
-- application path is live.

ALTER TABLE public.policy_rollouts
  ADD COLUMN IF NOT EXISTS authorization_receipt_id TEXT,
  ADD COLUMN IF NOT EXISTS authorization_action_hash TEXT,
  ADD COLUMN IF NOT EXISTS authorization_execution_reference_id TEXT,
  ADD COLUMN IF NOT EXISTS authorization_authority JSONB;

CREATE UNIQUE INDEX IF NOT EXISTS policy_rollouts_authorization_receipt_once
  ON public.policy_rollouts (authorization_receipt_id)
  WHERE authorization_receipt_id IS NOT NULL;

COMMENT ON COLUMN public.policy_rollouts.authorization_receipt_id IS
  'One-time Class-A Trust Receipt atomically consumed to authorize this rollout.';
COMMENT ON COLUMN public.policy_rollouts.authorization_action_hash IS
  'Canonical action hash re-verified immediately before rollout activation.';
COMMENT ON COLUMN public.policy_rollouts.authorization_execution_reference_id IS
  'Executor reference policy-rollout:<rollout_id>, written in the same transaction as consume.';
COMMENT ON COLUMN public.policy_rollouts.authorization_authority IS
  'Consume-time approver authority and verified WebAuthn user-verification facts.';

-- During the expand/deploy/contract window, an old application instance may
-- still use the legacy direct-write path. Make those writes participate in the
-- same target lock as the new RPC so they cannot interleave between signed
-- before-state verification and activation. The trigger remains as
-- defense-in-depth after direct service-role writes are revoked.
CREATE OR REPLACE FUNCTION public.lock_policy_rollout_target()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_old_target TEXT;
  v_new_target TEXT;
  v_old_lock BIGINT;
  v_new_lock BIGINT;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    SELECT OLD.tenant_id || ':' || hp.policy_key || ':' || OLD.environment
    INTO v_old_target
    FROM public.handshake_policies hp
    WHERE hp.policy_id = OLD.policy_id
      AND hp.tenant_id::text = OLD.tenant_id;
    IF v_old_target IS NULL THEN
      RAISE EXCEPTION 'policy_rollout_lock_target_invalid'
        USING ERRCODE = '22023';
    END IF;
    v_old_lock := pg_catalog.hashtextextended(v_old_target, 0);
  END IF;

  IF TG_OP <> 'DELETE' THEN
    SELECT NEW.tenant_id || ':' || hp.policy_key || ':' || NEW.environment
    INTO v_new_target
    FROM public.handshake_policies hp
    WHERE hp.policy_id = NEW.policy_id
      AND hp.tenant_id::text = NEW.tenant_id;
    IF v_new_target IS NULL THEN
      RAISE EXCEPTION 'policy_rollout_lock_target_invalid'
        USING ERRCODE = '22023';
    END IF;
    v_new_lock := pg_catalog.hashtextextended(v_new_target, 0);
  END IF;

  IF v_old_lock IS NOT NULL AND v_new_lock IS NOT NULL AND v_old_lock <> v_new_lock THEN
    PERFORM pg_catalog.pg_advisory_xact_lock(LEAST(v_old_lock, v_new_lock));
    PERFORM pg_catalog.pg_advisory_xact_lock(GREATEST(v_old_lock, v_new_lock));
  ELSE
    PERFORM pg_catalog.pg_advisory_xact_lock(COALESCE(v_old_lock, v_new_lock));
  END IF;

  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

REVOKE ALL ON FUNCTION public.lock_policy_rollout_target()
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.lock_policy_rollout_target()
  TO service_role;

DROP TRIGGER IF EXISTS policy_rollouts_target_lock ON public.policy_rollouts;
CREATE TRIGGER policy_rollouts_target_lock
  BEFORE INSERT OR UPDATE OR DELETE ON public.policy_rollouts
  FOR EACH ROW EXECUTE FUNCTION public.lock_policy_rollout_target();

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
AS $$
DECLARE
  v_created JSONB;
  v_created_actor_id TEXT;
  v_created_at TIMESTAMPTZ;
  v_created_count BIGINT;
  v_consumed_count BIGINT;
  v_request_count BIGINT;
  v_approved_count BIGINT;
  v_distinct_approver_count BIGINT;
  v_distinct_credential_count BIGINT;
  v_approved_approver_id TEXT;
  v_approved_credential_id TEXT;
  v_policy_rules JSONB;
  v_policy_mode TEXT;
  v_policy_status TEXT;
  v_current_before JSONB;
  v_current_after JSONB;
  v_expires_at TIMESTAMPTZ;
  v_authority_assurance TEXT;
  v_authority_role TEXT;
  v_authority_id UUID;
  v_authority JSONB;
  v_authority_members JSONB := '[]'::jsonb;
  v_quorum_mode TEXT;
  v_quorum_required INTEGER;
  v_quorum_window_sec INTEGER;
  v_quorum_roster_count INTEGER;
  v_quorum_distinct_humans BOOLEAN;
  v_quorum_first_issued_at TIMESTAMPTZ;
  v_quorum_last_issued_at TIMESTAMPTZ;
  v_authority_ids_used UUID[] := ARRAY[]::UUID[];
  v_template RECORD;
  v_approval RECORD;
  v_rollout_id UUID := pg_catalog.gen_random_uuid();
  v_execution_reference_id TEXT;
BEGIN
  IF p_tenant_id IS NULL
     OR p_policy_id IS NULL
     OR p_policy_key IS NULL OR btrim(p_policy_key) = ''
     OR p_environment IS NULL OR btrim(p_environment) = ''
     OR p_version IS NULL
     OR p_version < 1
     OR p_strategy IS NULL
     OR p_strategy NOT IN ('immediate', 'canary')
     OR (p_strategy = 'canary' AND (p_canary_pct IS NULL OR p_canary_pct < 1 OR p_canary_pct > 99))
     OR (p_strategy = 'immediate' AND p_canary_pct IS NOT NULL)
     OR p_initiated_by IS NULL
     OR p_initiated_by !~ '^key:.+'
     OR jsonb_typeof(COALESCE(p_metadata, '{}'::jsonb)) <> 'object'
     OR p_receipt_id IS NULL
     OR p_receipt_id !~ '^tr_[a-f0-9]{32}$'
     OR p_action_hash IS NULL
     OR p_action_hash !~ '^[a-f0-9]{64}$'
     OR p_signed_before_state IS NULL OR jsonb_typeof(p_signed_before_state) <> 'object'
     OR p_signed_after_state IS NULL OR jsonb_typeof(p_signed_after_state) <> 'object'
     OR p_authority_ids IS NULL
     OR pg_catalog.cardinality(p_authority_ids) < 1
     OR EXISTS (SELECT 1 FROM unnest(p_authority_ids) AS authority_id WHERE authority_id IS NULL)
     OR pg_catalog.cardinality(p_authority_ids) <> (
       SELECT count(DISTINCT authority_id)
       FROM unnest(p_authority_ids) AS authority_id
     )
     OR (p_quorum_policy IS NOT NULL AND jsonb_typeof(p_quorum_policy) <> 'object')
  THEN
    RAISE EXCEPTION 'invalid_policy_rollout_activation'
      USING ERRCODE = '22023';
  END IF;

  -- Serialize every activation for one tenant/policy/environment even when two
  -- different, otherwise-valid receipts race.
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      p_tenant_id::text || ':' || p_policy_key || ':' || p_environment,
      0
    )
  );

  -- Lock the whole policy family so the selected version/rules cannot change
  -- between stale-state verification and activation.
  PERFORM 1
  FROM public.handshake_policies hp
  WHERE hp.tenant_id = p_tenant_id
    AND hp.policy_key = p_policy_key
  FOR UPDATE;

  SELECT hp.rules, hp.mode, hp.status
  INTO v_policy_rules, v_policy_mode, v_policy_status
  FROM public.handshake_policies hp
  WHERE hp.policy_id = p_policy_id
    AND hp.tenant_id = p_tenant_id
    AND hp.policy_key = p_policy_key
    AND hp.version = p_version;

  IF NOT FOUND OR v_policy_status IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'policy_rollout_version_mismatch'
      USING ERRCODE = '22023';
  END IF;

  -- Check the one-time sentinel after taking the target lock but before
  -- comparing rollout state. This makes a concurrent second use of the SAME
  -- receipt deterministically a replay, while a different receipt approved
  -- against old state remains a stale-state conflict.
  SELECT count(*)
  INTO v_created_count
  FROM public.audit_events ae
  WHERE ae.target_type = 'trust_receipt'
    AND ae.target_id = p_receipt_id
    AND ae.event_type = 'guard.trust_receipt.created';

  SELECT count(*)
  INTO v_consumed_count
  FROM public.audit_events ae
  WHERE ae.target_type = 'trust_receipt'
    AND ae.target_id = p_receipt_id
    AND ae.event_type = 'guard.trust_receipt.consumed';

  IF v_created_count <> 1 OR v_consumed_count <> 0 THEN
    RAISE EXCEPTION 'policy_rollout_receipt_unavailable'
      USING ERRCODE = '28000';
  END IF;

  SELECT pg_catalog.jsonb_build_object(
    'active_rollouts',
    COALESCE(
      pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object(
          'rollout_id', pr.rollout_id::text,
          'policy_id', pr.policy_id::text,
          'version', pr.version,
          'environment', pr.environment,
          'strategy', pr.strategy,
          'canary_pct', pr.canary_pct,
          'metadata', COALESCE(pr.metadata, '{}'::jsonb),
          'authorization_receipt_id', pr.authorization_receipt_id
        )
        ORDER BY pr.rollout_id::text
      ) FILTER (WHERE pr.rollout_id IS NOT NULL),
      '[]'::jsonb
    )
  )
  INTO v_current_before
  FROM public.policy_rollouts pr
  WHERE pr.tenant_id = p_tenant_id::text
    AND pr.policy_id IN (
      SELECT hp.policy_id
      FROM public.handshake_policies hp
      WHERE hp.tenant_id = p_tenant_id
        AND hp.policy_key = p_policy_key
    )
    AND pr.environment = p_environment
    AND pr.status = 'active';

  v_current_after := pg_catalog.jsonb_build_object(
    'policy_id', p_policy_id::text,
    'policy_key', p_policy_key,
    'policy_version', p_version,
    'policy_rules', v_policy_rules,
    'policy_mode', v_policy_mode,
    'policy_status', v_policy_status,
    'environment', p_environment,
    'strategy', p_strategy,
    'canary_pct', p_canary_pct,
    'metadata', COALESCE(p_metadata, '{}'::jsonb)
  );

  IF v_current_before IS DISTINCT FROM p_signed_before_state
     OR v_current_after IS DISTINCT FROM p_signed_after_state
  THEN
    RAISE EXCEPTION 'policy_rollout_signed_state_stale'
      USING ERRCODE = '40001';
  END IF;

  SELECT ae.after_state, ae.actor_id, ae.created_at
  INTO v_created, v_created_actor_id, v_created_at
  FROM public.audit_events ae
  WHERE ae.target_type = 'trust_receipt'
    AND ae.target_id = p_receipt_id
    AND ae.event_type = 'guard.trust_receipt.created';

  IF v_created_actor_id IS NULL
     OR v_created_at IS NULL
     OR v_created_actor_id IS DISTINCT FROM (
       'ep:cloud-key:' || replace(p_initiated_by, 'key:', '')
     )
     OR v_created ->> 'organization_id' IS DISTINCT FROM p_tenant_id::text
     OR v_created #>> '{canonical_action,organization_id}' IS DISTINCT FROM p_tenant_id::text
     OR v_created ->> 'action_type' IS DISTINCT FROM 'policy_rollout'
     OR v_created #>> '{canonical_action,action_type}' IS DISTINCT FROM 'policy_rollout'
     OR v_created ->> 'target_resource_id' IS DISTINCT FROM ('policy:' || p_policy_key)
     OR v_created #>> '{canonical_action,target_resource_id}' IS DISTINCT FROM ('policy:' || p_policy_key)
     OR v_created ->> 'decision' IS DISTINCT FROM 'allow_with_signoff'
     OR v_created ->> 'signoff_required' IS DISTINCT FROM 'true'
     OR v_created ->> 'required_assurance' IS DISTINCT FROM 'A'
     OR COALESCE(v_created -> 'quorum_policy', 'null'::jsonb)
          IS DISTINCT FROM COALESCE(p_quorum_policy, 'null'::jsonb)
     OR v_created ->> 'action_hash' IS DISTINCT FROM p_action_hash
     OR v_created #>> '{canonical_action,before_state_hash}'
          IS DISTINCT FROM v_created ->> 'before_state_hash'
     OR v_created #>> '{canonical_action,after_state_hash}'
          IS DISTINCT FROM v_created ->> 'after_state_hash'
     OR v_created #>> '{canonical_action,rollout_policy_id}' IS DISTINCT FROM p_policy_id::text
     OR v_created #>> '{canonical_action,rollout_policy_key}' IS DISTINCT FROM p_policy_key
     OR v_created #>> '{canonical_action,rollout_policy_version}' IS DISTINCT FROM p_version::text
     OR v_created #> '{canonical_action,rollout_policy_rules}' IS DISTINCT FROM v_policy_rules
     OR v_created #>> '{canonical_action,rollout_policy_mode}' IS DISTINCT FROM v_policy_mode
     OR v_created #>> '{canonical_action,rollout_policy_status}' IS DISTINCT FROM v_policy_status
     OR v_created #>> '{canonical_action,rollout_environment}' IS DISTINCT FROM p_environment
     OR v_created #>> '{canonical_action,rollout_strategy}' IS DISTINCT FROM p_strategy
     OR v_created #> '{canonical_action,rollout_canary_pct}'
          IS DISTINCT FROM COALESCE(pg_catalog.to_jsonb(p_canary_pct), 'null'::jsonb)
     OR v_created #> '{canonical_action,rollout_metadata}'
          IS DISTINCT FROM COALESCE(p_metadata, '{}'::jsonb)
     OR v_created #> '{canonical_action,rollout_before_state}' IS DISTINCT FROM p_signed_before_state
     OR v_created #> '{canonical_action,rollout_after_state}' IS DISTINCT FROM p_signed_after_state
     OR v_created #>> '{canonical_action,executing_key_id}' IS DISTINCT FROM replace(p_initiated_by, 'key:', '')
     OR v_created ->> 'expires_at' IS NULL
  THEN
    RAISE EXCEPTION 'policy_rollout_authorization_mismatch'
      USING ERRCODE = '28000';
  END IF;

  IF NOT pg_catalog.pg_input_is_valid(v_created ->> 'expires_at', 'timestamptz') THEN
    RAISE EXCEPTION 'policy_rollout_authorization_mismatch'
      USING ERRCODE = '28000';
  END IF;
  v_expires_at := (v_created ->> 'expires_at')::timestamptz;
  IF v_created_at > pg_catalog.now()
     OR v_expires_at <= pg_catalog.now()
     OR v_expires_at <= v_created_at
     OR v_expires_at > v_created_at + interval '15 minutes'
  THEN
    RAISE EXCEPTION 'policy_rollout_authorization_expired'
      USING ERRCODE = '28000';
  END IF;

  -- Parse the quorum object only after proving every castable field has the
  -- expected JSON shape. SECURITY DEFINER callers must receive a controlled
  -- fail-closed error for malformed input, never an incidental cast failure.
  IF p_quorum_policy IS NOT NULL THEN
    IF jsonb_typeof(p_quorum_policy -> 'approvers') <> 'array'
       OR pg_catalog.jsonb_array_length(p_quorum_policy -> 'approvers') < 1
       OR p_quorum_policy ->> 'mode' NOT IN ('threshold', 'ordered')
       OR COALESCE((p_quorum_policy ->> 'required') ~ '^[0-9]+$', false) = false
       OR COALESCE(
         pg_catalog.pg_input_is_valid(p_quorum_policy ->> 'required', 'integer'),
         false
       ) = false
       OR (
         p_quorum_policy ? 'window_sec'
         AND (
           COALESCE((p_quorum_policy ->> 'window_sec') ~ '^[0-9]+$', false) = false
           OR COALESCE(
             pg_catalog.pg_input_is_valid(p_quorum_policy ->> 'window_sec', 'integer'),
             false
           ) = false
         )
       )
       OR (
         p_quorum_policy ? 'distinct_humans'
         AND jsonb_typeof(p_quorum_policy -> 'distinct_humans') <> 'boolean'
       )
       OR EXISTS (
         SELECT 1
         FROM pg_catalog.jsonb_array_elements(p_quorum_policy -> 'approvers') submitted
         WHERE jsonb_typeof(submitted) <> 'object'
           OR COALESCE(submitted ->> 'role', '') = ''
           OR COALESCE(submitted ->> 'approver', '') = ''
       )
       OR pg_catalog.jsonb_array_length(p_quorum_policy -> 'approvers') <> (
         SELECT count(DISTINCT (submitted ->> 'role', submitted ->> 'approver'))
         FROM pg_catalog.jsonb_array_elements(p_quorum_policy -> 'approvers') submitted
       )
       OR pg_catalog.jsonb_array_length(p_quorum_policy -> 'approvers') <> (
         SELECT count(DISTINCT submitted ->> 'approver')
         FROM pg_catalog.jsonb_array_elements(p_quorum_policy -> 'approvers') submitted
       )
    THEN
      RAISE EXCEPTION 'policy_rollout_quorum_policy_invalid'
        USING ERRCODE = '28000';
    END IF;

    v_quorum_mode := p_quorum_policy ->> 'mode';
    v_quorum_required := (p_quorum_policy ->> 'required')::integer;
    v_quorum_window_sec := COALESCE((p_quorum_policy ->> 'window_sec')::integer, 900);
    v_quorum_roster_count := pg_catalog.jsonb_array_length(p_quorum_policy -> 'approvers');
    v_quorum_distinct_humans :=
      COALESCE((p_quorum_policy ->> 'distinct_humans')::boolean, true);

    IF v_quorum_required < 1
       OR v_quorum_required > v_quorum_roster_count
       OR (v_quorum_mode = 'ordered' AND v_quorum_required <> v_quorum_roster_count)
       OR v_quorum_distinct_humans = false
       OR v_quorum_window_sec < 1
       OR v_quorum_window_sec > 900
    THEN
      RAISE EXCEPTION 'policy_rollout_quorum_policy_invalid'
        USING ERRCODE = '28000';
    END IF;
  END IF;

  -- Lock and re-evaluate the tenant's current quorum floor. A template can be
  -- tightened after receipt issuance; activation must honor the current row,
  -- not only the application snapshot.
  SELECT oqp.*
  INTO v_template
  FROM public.org_quorum_policies oqp
  WHERE oqp.organization_id = p_tenant_id::text
    AND oqp.action_type = 'policy_rollout'
  FOR UPDATE;

  IF FOUND THEN
    IF v_template.quorum_required AND p_quorum_policy IS NULL THEN
      RAISE EXCEPTION 'policy_rollout_quorum_required'
        USING ERRCODE = '28000';
    END IF;
    IF p_quorum_policy IS NOT NULL THEN
      IF (v_template.min_required IS NOT NULL
             AND v_quorum_required < v_template.min_required)
         OR (v_template.max_window_sec IS NOT NULL
             AND v_quorum_window_sec > v_template.max_window_sec)
         OR (v_template.require_distinct_humans
             AND v_quorum_distinct_humans = false)
         OR (
           jsonb_typeof(v_template.allowed_modes) = 'array'
           AND pg_catalog.jsonb_array_length(v_template.allowed_modes) > 0
           AND NOT EXISTS (
             SELECT 1
             FROM pg_catalog.jsonb_array_elements_text(v_template.allowed_modes) allowed_mode
             WHERE allowed_mode = p_quorum_policy ->> 'mode'
           )
         )
         OR (
           jsonb_typeof(v_template.allowed_approvers) = 'array'
           AND pg_catalog.jsonb_array_length(v_template.allowed_approvers) > 0
           AND EXISTS (
             SELECT 1
             FROM pg_catalog.jsonb_array_elements(p_quorum_policy -> 'approvers') submitted
             WHERE NOT EXISTS (
               SELECT 1
               FROM pg_catalog.jsonb_array_elements(v_template.allowed_approvers) allowed
               WHERE allowed ->> 'role' = submitted ->> 'role'
                 AND allowed ->> 'approver' = submitted ->> 'approver'
             )
           )
         )
      THEN
        RAISE EXCEPTION 'policy_rollout_quorum_policy_invalid'
          USING ERRCODE = '28000';
      END IF;
    END IF;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.audit_events req
    JOIN public.audit_events rejected
      ON rejected.target_type = 'trust_receipt'
     AND rejected.target_id = p_receipt_id
     AND rejected.event_type = 'guard.signoff.rejected'
     AND rejected.after_state ->> 'signoff_id' = req.after_state ->> 'signoff_id'
    WHERE req.target_type = 'trust_receipt'
      AND req.target_id = p_receipt_id
      AND req.event_type = 'guard.signoff.requested'
      AND req.actor_id = v_created_actor_id
  ) THEN
    RAISE EXCEPTION 'policy_rollout_signoff_rejected'
      USING ERRCODE = '28000';
  END IF;

  IF p_quorum_policy IS NULL THEN
    IF pg_catalog.cardinality(p_authority_ids) <> 1 THEN
      RAISE EXCEPTION 'policy_rollout_authority_invalid'
        USING ERRCODE = '28000';
    END IF;

    SELECT count(*)
    INTO v_request_count
    FROM public.audit_events req
    WHERE req.target_type = 'trust_receipt'
      AND req.target_id = p_receipt_id
      AND req.event_type = 'guard.signoff.requested'
      AND req.actor_id = v_created_actor_id
      AND req.after_state -> 'quorum' IS NULL
      AND req.created_at >= v_created_at
      AND req.created_at <= LEAST(v_expires_at, pg_catalog.now());

    SELECT count(*)
    INTO v_approved_count
    FROM public.audit_events req
    JOIN public.audit_events approved
      ON approved.target_type = 'trust_receipt'
     AND approved.target_id = p_receipt_id
     AND approved.event_type = 'guard.signoff.approved'
     AND approved.after_state ->> 'signoff_id' = req.after_state ->> 'signoff_id'
    WHERE req.target_type = 'trust_receipt'
      AND req.target_id = p_receipt_id
      AND req.event_type = 'guard.signoff.requested'
      AND req.actor_id = v_created_actor_id
      AND req.after_state -> 'quorum' IS NULL
      AND approved.after_state ->> 'key_class' = 'A'
      AND approved.after_state #>> '{context,action_hash}' = p_action_hash
      AND approved.after_state ->> 'approved_action_hash' = p_action_hash
      AND pg_catalog.pg_input_is_valid(
        approved.after_state #>> '{context,issued_at}',
        'timestamptz'
      )
      AND (approved.after_state #>> '{context,issued_at}')::timestamptz
        BETWEEN v_created_at - interval '5 minutes'
            AND LEAST(v_expires_at + interval '5 minutes', pg_catalog.now() + interval '5 minutes')
      AND approved.created_at >= req.created_at
      AND approved.created_at <= LEAST(v_expires_at, pg_catalog.now())
      AND (
        req.after_state ->> 'approver_id' IS NULL
        OR COALESCE(approved.after_state ->> 'approver_id', approved.actor_id)
          = req.after_state ->> 'approver_id'
      );

    IF v_request_count <> 1 OR v_approved_count <> 1 THEN
      RAISE EXCEPTION 'accountable_signoff_required'
        USING ERRCODE = '28000';
    END IF;

    SELECT
      COALESCE(approved.after_state ->> 'approver_id', approved.actor_id),
      approved.after_state #>> '{webauthn,credential_id}'
    INTO v_approved_approver_id, v_approved_credential_id
      FROM public.audit_events req
      JOIN public.audit_events approved
        ON approved.target_type = 'trust_receipt'
       AND approved.target_id = p_receipt_id
       AND approved.event_type = 'guard.signoff.approved'
       AND approved.after_state ->> 'signoff_id' = req.after_state ->> 'signoff_id'
      WHERE req.target_type = 'trust_receipt'
        AND req.target_id = p_receipt_id
        AND req.event_type = 'guard.signoff.requested'
        AND req.actor_id = v_created_actor_id
        AND req.after_state -> 'quorum' IS NULL
        AND approved.after_state ->> 'key_class' = 'A'
        AND approved.after_state #>> '{context,action_hash}' = p_action_hash
        AND approved.after_state ->> 'approved_action_hash' = p_action_hash
        AND pg_catalog.pg_input_is_valid(
          approved.after_state #>> '{context,issued_at}',
          'timestamptz'
        )
        AND (approved.after_state #>> '{context,issued_at}')::timestamptz
          BETWEEN v_created_at - interval '5 minutes'
              AND LEAST(v_expires_at + interval '5 minutes', pg_catalog.now() + interval '5 minutes')
        AND approved.created_at >= req.created_at
        AND approved.created_at <= LEAST(v_expires_at, pg_catalog.now())
        AND (
          req.after_state ->> 'approver_id' IS NULL
          OR COALESCE(approved.after_state ->> 'approver_id', approved.actor_id)
            = req.after_state ->> 'approver_id'
        )
      ORDER BY approved.created_at
      LIMIT 1;

    IF v_approved_approver_id IS NULL OR v_approved_credential_id IS NULL THEN
      RAISE EXCEPTION 'accountable_signoff_required'
        USING ERRCODE = '28000';
    END IF;

    PERFORM 1
    FROM public.approver_credentials ac
    WHERE ac.organization_id = p_tenant_id::text
      AND ac.approver_id = v_approved_approver_id
      AND ac.credential_id = v_approved_credential_id
      AND ac.key_class = 'A'
      AND ac.revoked_at IS NULL
      AND ac.valid_from <= pg_catalog.now()
      AND (ac.valid_to IS NULL OR ac.valid_to > pg_catalog.now())
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'policy_rollout_credential_invalid'
        USING ERRCODE = '28000';
    END IF;

    v_authority_id := p_authority_ids[1];
    SELECT a.assurance_class, a.role
    INTO v_authority_assurance, v_authority_role
      FROM public.authorities a
      WHERE a.authority_id = v_authority_id
        AND a.organization_id = p_tenant_id::text
        AND a.subject_type = 'human_approver'
        AND a.subject_ref = v_approved_approver_id
        AND a.role IN ('policy_admin', 'control_plane_approver')
        AND a.status = 'active'
        AND a.revoked_at IS NULL
        AND a.valid_from <= pg_catalog.now()
        AND (a.valid_to IS NULL OR a.valid_to > pg_catalog.now())
        AND a.assurance_class = 'A'
        AND a.action_scopes IS NOT NULL
        AND 'policy_rollout' = ANY (a.action_scopes)
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'policy_rollout_authority_invalid'
        USING ERRCODE = '28000';
    END IF;

    v_authority := pg_catalog.jsonb_build_object(
      'authority_id', v_authority_id::text,
      'assurance_class', v_authority_assurance,
      'authority_check', 'transactionally_reverified',
      'action_scope', 'policy_rollout',
      'role', v_authority_role,
      'credential_id', v_approved_credential_id,
      'user_verification', 'application_reverified'
    );
  ELSE
    IF v_quorum_mode = 'ordered' THEN
      v_quorum_required := v_quorum_roster_count;
    END IF;
    IF v_quorum_required < 1 OR v_quorum_required > v_quorum_roster_count THEN
      RAISE EXCEPTION 'policy_rollout_quorum_policy_invalid'
        USING ERRCODE = '28000';
    END IF;

    SELECT count(*)
    INTO v_request_count
    FROM public.audit_events req
    WHERE req.target_type = 'trust_receipt'
      AND req.target_id = p_receipt_id
      AND req.event_type = 'guard.signoff.requested'
      AND req.actor_id = v_created_actor_id
      AND req.after_state -> 'quorum' IS NOT NULL
      AND req.created_at >= v_created_at
      AND req.created_at <= LEAST(v_expires_at, pg_catalog.now())
      AND req.after_state #>> '{quorum,mode}' = v_quorum_mode
      AND req.after_state #>> '{quorum,required}' = (p_quorum_policy ->> 'required')
      AND EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(p_quorum_policy -> 'approvers') slot
        WHERE slot ->> 'role' = req.after_state #>> '{quorum,role}'
          AND slot ->> 'approver' = req.after_state #>> '{quorum,approver_id}'
      );

    IF v_request_count <> v_quorum_roster_count THEN
      RAISE EXCEPTION 'policy_rollout_quorum_requests_invalid'
        USING ERRCODE = '28000';
    END IF;

    SELECT
      count(*),
      count(DISTINCT COALESCE(approved.after_state ->> 'approver_id', approved.actor_id)),
      count(DISTINCT approved.after_state #>> '{webauthn,credential_id}')
    INTO v_approved_count, v_distinct_approver_count, v_distinct_credential_count
    FROM public.audit_events req
    JOIN public.audit_events approved
      ON approved.target_type = 'trust_receipt'
     AND approved.target_id = p_receipt_id
     AND approved.event_type = 'guard.signoff.approved'
     AND approved.after_state ->> 'signoff_id' = req.after_state ->> 'signoff_id'
    WHERE req.target_type = 'trust_receipt'
      AND req.target_id = p_receipt_id
      AND req.event_type = 'guard.signoff.requested'
      AND req.actor_id = v_created_actor_id
      AND req.after_state -> 'quorum' IS NOT NULL
      AND approved.after_state ->> 'key_class' = 'A'
      AND approved.after_state ->> 'approved_action_hash' = p_action_hash
      AND approved.after_state #>> '{context,action_hash}' = p_action_hash
      AND pg_catalog.pg_input_is_valid(
        approved.after_state #>> '{context,issued_at}',
        'timestamptz'
      )
      AND (approved.after_state #>> '{context,issued_at}')::timestamptz
        BETWEEN v_created_at - interval '5 minutes'
            AND LEAST(v_expires_at + interval '5 minutes', pg_catalog.now() + interval '5 minutes')
      AND approved.created_at >= req.created_at
      AND approved.created_at <= LEAST(v_expires_at, pg_catalog.now())
      AND COALESCE(approved.after_state ->> 'approver_id', approved.actor_id)
        = req.after_state #>> '{quorum,approver_id}'
      AND EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(p_quorum_policy -> 'approvers') slot
        WHERE slot ->> 'role' = req.after_state #>> '{quorum,role}'
          AND slot ->> 'approver' = req.after_state #>> '{quorum,approver_id}'
      );

    IF v_approved_count < v_quorum_required
       OR v_distinct_approver_count <> v_approved_count
       OR v_distinct_credential_count <> v_approved_count
       OR pg_catalog.cardinality(p_authority_ids) <> v_approved_count
    THEN
      RAISE EXCEPTION 'policy_rollout_quorum_not_satisfied'
        USING ERRCODE = '28000';
    END IF;

    IF EXISTS (
      SELECT 1
      FROM public.audit_events req
      JOIN public.audit_events approved
        ON approved.target_type = 'trust_receipt'
       AND approved.target_id = p_receipt_id
       AND approved.event_type = 'guard.signoff.approved'
       AND approved.after_state ->> 'signoff_id' = req.after_state ->> 'signoff_id'
      WHERE req.target_type = 'trust_receipt'
        AND req.target_id = p_receipt_id
        AND req.event_type = 'guard.signoff.requested'
        AND req.actor_id = v_created_actor_id
        AND req.after_state -> 'quorum' IS NOT NULL
        AND (
          NOT pg_catalog.pg_input_is_valid(
            approved.after_state #>> '{context,issued_at}',
            'timestamptz'
          )
          OR approved.created_at < req.created_at
          OR req.created_at < v_created_at
          OR approved.created_at > LEAST(v_expires_at, pg_catalog.now())
          OR (
            pg_catalog.pg_input_is_valid(
              approved.after_state #>> '{context,issued_at}',
              'timestamptz'
            )
            AND (
              (approved.after_state #>> '{context,issued_at}')::timestamptz
                < v_created_at - interval '5 minutes'
              OR (approved.after_state #>> '{context,issued_at}')::timestamptz
                > LEAST(v_expires_at + interval '5 minutes', pg_catalog.now() + interval '5 minutes')
            )
          )
          OR COALESCE(approved.after_state ->> 'approver_id', approved.actor_id)
            = v_created_actor_id
        )
    ) THEN
      RAISE EXCEPTION 'policy_rollout_quorum_not_satisfied'
        USING ERRCODE = '28000';
    END IF;

    SELECT
      min(approved.created_at),
      max(approved.created_at)
    INTO v_quorum_first_issued_at, v_quorum_last_issued_at
    FROM public.audit_events req
    JOIN public.audit_events approved
      ON approved.target_type = 'trust_receipt'
     AND approved.target_id = p_receipt_id
     AND approved.event_type = 'guard.signoff.approved'
     AND approved.after_state ->> 'signoff_id' = req.after_state ->> 'signoff_id'
    WHERE req.target_type = 'trust_receipt'
      AND req.target_id = p_receipt_id
      AND req.event_type = 'guard.signoff.requested'
      AND req.actor_id = v_created_actor_id
      AND req.after_state -> 'quorum' IS NOT NULL;

    IF v_quorum_last_issued_at - v_quorum_first_issued_at
         > pg_catalog.make_interval(secs => v_quorum_window_sec)
    THEN
      RAISE EXCEPTION 'policy_rollout_quorum_not_satisfied'
        USING ERRCODE = '28000';
    END IF;

    IF v_quorum_mode = 'ordered' AND EXISTS (
      WITH roster AS (
        SELECT
          slot.ordinality,
          slot.value ->> 'role' AS seat_role,
          slot.value ->> 'approver' AS approver_id
        FROM pg_catalog.jsonb_array_elements(p_quorum_policy -> 'approvers')
          WITH ORDINALITY AS slot(value, ordinality)
      ),
      approvals AS (
        SELECT
          row_number() OVER (
            ORDER BY approved.created_at, approved.id
          ) AS ordinality,
          req.after_state #>> '{quorum,role}' AS seat_role,
          COALESCE(approved.after_state ->> 'approver_id', approved.actor_id) AS approver_id
        FROM public.audit_events req
        JOIN public.audit_events approved
          ON approved.target_type = 'trust_receipt'
         AND approved.target_id = p_receipt_id
         AND approved.event_type = 'guard.signoff.approved'
         AND approved.after_state ->> 'signoff_id' = req.after_state ->> 'signoff_id'
        WHERE req.target_type = 'trust_receipt'
          AND req.target_id = p_receipt_id
          AND req.event_type = 'guard.signoff.requested'
          AND req.actor_id = v_created_actor_id
          AND req.after_state -> 'quorum' IS NOT NULL
      )
      SELECT 1
      FROM roster
      FULL JOIN approvals USING (ordinality)
      WHERE roster.seat_role IS DISTINCT FROM approvals.seat_role
         OR roster.approver_id IS DISTINCT FROM approvals.approver_id
    ) THEN
      RAISE EXCEPTION 'policy_rollout_quorum_order_invalid'
        USING ERRCODE = '28000';
    END IF;

    FOR v_approval IN
      SELECT
        req.after_state #>> '{quorum,role}' AS seat_role,
        COALESCE(approved.after_state ->> 'approver_id', approved.actor_id) AS approver_id,
        approved.after_state #>> '{webauthn,credential_id}' AS credential_id
      FROM public.audit_events req
      JOIN public.audit_events approved
        ON approved.target_type = 'trust_receipt'
       AND approved.target_id = p_receipt_id
       AND approved.event_type = 'guard.signoff.approved'
       AND approved.after_state ->> 'signoff_id' = req.after_state ->> 'signoff_id'
      WHERE req.target_type = 'trust_receipt'
        AND req.target_id = p_receipt_id
        AND req.event_type = 'guard.signoff.requested'
        AND req.actor_id = v_created_actor_id
        AND req.after_state -> 'quorum' IS NOT NULL
        AND approved.after_state ->> 'key_class' = 'A'
        AND approved.after_state ->> 'approved_action_hash' = p_action_hash
        AND approved.after_state #>> '{context,action_hash}' = p_action_hash
        AND COALESCE(approved.after_state ->> 'approver_id', approved.actor_id)
          = req.after_state #>> '{quorum,approver_id}'
        AND EXISTS (
          SELECT 1
          FROM pg_catalog.jsonb_array_elements(p_quorum_policy -> 'approvers') slot
          WHERE slot ->> 'role' = req.after_state #>> '{quorum,role}'
            AND slot ->> 'approver' = req.after_state #>> '{quorum,approver_id}'
        )
      ORDER BY approved.created_at, approved.id
    LOOP
      PERFORM 1
      FROM public.approver_credentials ac
      WHERE ac.organization_id = p_tenant_id::text
        AND ac.approver_id = v_approval.approver_id
        AND ac.credential_id = v_approval.credential_id
        AND ac.key_class = 'A'
        AND ac.revoked_at IS NULL
        AND ac.valid_from <= pg_catalog.now()
        AND (ac.valid_to IS NULL OR ac.valid_to > pg_catalog.now())
      FOR UPDATE;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'policy_rollout_credential_invalid'
          USING ERRCODE = '28000';
      END IF;

      SELECT a.authority_id, a.assurance_class, a.role
      INTO v_authority_id, v_authority_assurance, v_authority_role
      FROM public.authorities a
      WHERE a.authority_id = ANY (p_authority_ids)
        AND a.organization_id = p_tenant_id::text
        AND a.subject_type = 'human_approver'
        AND a.subject_ref = v_approval.approver_id
        AND a.role IN ('policy_admin', 'control_plane_approver')
        AND a.status = 'active'
        AND a.revoked_at IS NULL
        AND a.valid_from <= pg_catalog.now()
        AND (a.valid_to IS NULL OR a.valid_to > pg_catalog.now())
        AND a.assurance_class = 'A'
        AND a.action_scopes IS NOT NULL
        AND 'policy_rollout' = ANY (a.action_scopes)
      FOR UPDATE;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'policy_rollout_authority_invalid'
          USING ERRCODE = '28000';
      END IF;

      v_authority_ids_used := pg_catalog.array_append(v_authority_ids_used, v_authority_id);
      v_authority_members := v_authority_members || pg_catalog.jsonb_build_array(
        pg_catalog.jsonb_build_object(
          'authority_id', v_authority_id::text,
          'approver_id', v_approval.approver_id,
          'seat_role', v_approval.seat_role,
          'assurance_class', v_authority_assurance,
          'authority_check', 'transactionally_reverified',
          'action_scope', 'policy_rollout',
          'role', v_authority_role,
          'credential_id', v_approval.credential_id,
          'user_verification', 'application_reverified'
        )
      );
    END LOOP;

    IF pg_catalog.cardinality(v_authority_ids_used) <> v_approved_count THEN
      RAISE EXCEPTION 'policy_rollout_authority_invalid'
        USING ERRCODE = '28000';
    END IF;

    v_authority := pg_catalog.jsonb_build_object(
      'quorum', true,
      'policy', p_quorum_policy,
      'members', v_authority_members
    );
  END IF;

  v_execution_reference_id := 'policy-rollout:' || v_rollout_id::text;

  -- This insert and the rollout mutations below commit or roll back together.
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
    p_initiated_by,
    'system',
    'trust_receipt',
    p_receipt_id,
    'consume_for_policy_rollout',
    pg_catalog.jsonb_build_object('receipt_status', 'pending_consume'),
    pg_catalog.jsonb_build_object(
      'receipt_status', 'consumed',
      'consumed_at', pg_catalog.now(),
      'consumed_by_system', 'emilia.cloud.policy_rollout',
      'execution_reference_id', v_execution_reference_id,
      'action_hash', p_action_hash,
      'authority', v_authority
    )
  );

  IF p_strategy = 'immediate' THEN
    UPDATE public.policy_rollouts pr
    SET status = 'superseded',
        completed_at = pg_catalog.now()
    WHERE pr.tenant_id = p_tenant_id::text
      AND pr.policy_id IN (
        SELECT hp.policy_id
        FROM public.handshake_policies hp
        WHERE hp.tenant_id = p_tenant_id
          AND hp.policy_key = p_policy_key
      )
      AND pr.environment = p_environment
      AND pr.status = 'active';
  END IF;

  RETURN QUERY
  INSERT INTO public.policy_rollouts (
    rollout_id,
    policy_id,
    version,
    environment,
    strategy,
    status,
    initiated_by,
    tenant_id,
    canary_pct,
    initiated_at,
    metadata,
    authorization_receipt_id,
    authorization_action_hash,
    authorization_execution_reference_id,
    authorization_authority
  )
  VALUES (
    v_rollout_id,
    p_policy_id,
    p_version,
    p_environment,
    p_strategy,
    'active',
    p_initiated_by,
    p_tenant_id::text,
    p_canary_pct,
    pg_catalog.now(),
    COALESCE(p_metadata, '{}'::jsonb),
    p_receipt_id,
    p_action_hash,
    v_execution_reference_id,
    v_authority
  )
  RETURNING *;
END;
$$;

REVOKE ALL ON FUNCTION public.activate_policy_rollout_authorized(
  UUID, UUID, TEXT, INTEGER, TEXT, TEXT, SMALLINT, TEXT, JSONB, TEXT, TEXT, JSONB, JSONB, UUID[], JSONB
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.activate_policy_rollout_authorized(
  UUID, UUID, TEXT, INTEGER, TEXT, TEXT, SMALLINT, TEXT, JSONB, TEXT, TEXT, JSONB, JSONB, UUID[], JSONB
) TO service_role;
