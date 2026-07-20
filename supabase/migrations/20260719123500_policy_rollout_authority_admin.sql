-- Audited, tenant-bound administration for policy-rollout approver authority.
--
-- A Class-A credential proves that an enrolled approver controls a passkey. It
-- does not itself grant permission to activate policy rollouts. These functions
-- provide the deliberately narrow missing control-plane operation: a tenant
-- admin can grant or revoke only the policy_rollout scope and only one of the
-- two accepted rollout roles. Every mutation and its actor are recorded in the
-- append-only audit log in the same transaction.

-- Authority writes are exclusive to audited owner-controlled functions. The
-- application service role can read authorities, but cannot mint, alter, or
-- delete trust roots directly.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE
  ON TABLE public.authorities
  FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.authorities TO service_role;

CREATE OR REPLACE FUNCTION public.grant_policy_rollout_authority(
  p_tenant_id UUID,
  p_approver_id TEXT,
  p_role TEXT,
  p_valid_to TIMESTAMPTZ,
  p_granted_by TEXT,
  p_reason TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_credential_id TEXT;
  v_public_key TEXT;
  v_authority_id UUID := pg_catalog.gen_random_uuid();
  v_authority public.authorities%ROWTYPE;
BEGIN
  IF p_tenant_id IS NULL
     OR p_approver_id IS NULL OR btrim(p_approver_id) = '' OR length(p_approver_id) > 255
     OR p_role IS NULL OR p_role NOT IN ('policy_admin', 'control_plane_approver')
     OR p_valid_to IS NULL OR p_valid_to <= pg_catalog.now()
     OR p_valid_to > pg_catalog.now() + interval '366 days'
     OR p_granted_by IS NULL OR p_granted_by !~ '^key:.+'
     OR p_reason IS NULL OR btrim(p_reason) = '' OR length(p_reason) > 1000
  THEN
    RAISE EXCEPTION 'invalid_policy_rollout_authority_grant'
      USING ERRCODE = '22023';
  END IF;

  -- Serialize grants for one tenant/approver/role without imposing a new
  -- global uniqueness constraint on legacy authority data.
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      p_tenant_id::text || ':' || p_approver_id || ':' || p_role,
      0
    )
  );

  SELECT ac.credential_id, ac.public_key_spki
  INTO v_credential_id, v_public_key
  FROM public.approver_credentials ac
  WHERE ac.organization_id = p_tenant_id::text
    AND ac.approver_id = p_approver_id
    AND ac.key_class = 'A'
    AND ac.revoked_at IS NULL
    AND ac.valid_from <= pg_catalog.now()
    AND (ac.valid_to IS NULL OR ac.valid_to > pg_catalog.now())
  ORDER BY ac.valid_from DESC, ac.id DESC
  LIMIT 1
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'policy_rollout_class_a_credential_required'
      USING ERRCODE = '28000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.authorities a
    WHERE a.organization_id = p_tenant_id::text
      AND a.subject_type = 'human_approver'
      AND a.subject_ref = p_approver_id
      AND a.role = p_role
      AND a.status = 'active'
      AND a.revoked_at IS NULL
      AND a.valid_from <= pg_catalog.now()
      AND (a.valid_to IS NULL OR a.valid_to > pg_catalog.now())
      AND a.action_scopes IS NOT NULL
      AND 'policy_rollout' = ANY (a.action_scopes)
  ) THEN
    RAISE EXCEPTION 'policy_rollout_authority_already_active'
      USING ERRCODE = '23505';
  END IF;

  INSERT INTO public.authorities (
    authority_id,
    key_id,
    public_key,
    algorithm,
    role,
    status,
    valid_from,
    valid_to,
    metadata_json,
    organization_id,
    subject_type,
    subject_ref,
    assurance_class,
    action_scopes
  )
  VALUES (
    v_authority_id,
    'policy-rollout:' || v_authority_id::text,
    v_public_key,
    'WebAuthn',
    p_role,
    'active',
    pg_catalog.now(),
    p_valid_to,
    pg_catalog.jsonb_build_object(
      'credential_id', v_credential_id,
      'grant_reason', btrim(p_reason),
      'granted_by', p_granted_by
    ),
    p_tenant_id::text,
    'human_approver',
    p_approver_id,
    'A',
    ARRAY['policy_rollout']::TEXT[]
  )
  RETURNING * INTO v_authority;

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
    'guard.authority.granted',
    p_granted_by,
    'system',
    'authority',
    v_authority_id::text,
    'grant_policy_rollout_authority',
    NULL,
    pg_catalog.jsonb_build_object(
      'authority_id', v_authority_id::text,
      'organization_id', p_tenant_id::text,
      'subject_type', 'human_approver',
      'subject_ref', p_approver_id,
      'role', p_role,
      'assurance_class', 'A',
      'action_scopes', ARRAY['policy_rollout']::TEXT[],
      'valid_from', v_authority.valid_from,
      'valid_to', v_authority.valid_to,
      'credential_id', v_credential_id,
      'reason', btrim(p_reason)
    )
  );

  RETURN pg_catalog.jsonb_build_object(
    'authority_id', v_authority_id::text,
    'organization_id', p_tenant_id::text,
    'approver_id', p_approver_id,
    'role', p_role,
    'assurance_class', 'A',
    'action_scopes', ARRAY['policy_rollout']::TEXT[],
    'valid_from', v_authority.valid_from,
    'valid_to', v_authority.valid_to,
    'credential_id', v_credential_id,
    'status', 'active'
  );
END;
$$;

CREATE OR REPLACE FUNCTION public.revoke_policy_rollout_authority(
  p_tenant_id UUID,
  p_authority_id UUID,
  p_revoked_by TEXT,
  p_reason TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_before public.authorities%ROWTYPE;
  v_revoked_at TIMESTAMPTZ := pg_catalog.now();
BEGIN
  IF p_tenant_id IS NULL
     OR p_authority_id IS NULL
     OR p_revoked_by IS NULL OR p_revoked_by !~ '^key:.+'
     OR p_reason IS NULL OR btrim(p_reason) = '' OR length(p_reason) > 1000
  THEN
    RAISE EXCEPTION 'invalid_policy_rollout_authority_revoke'
      USING ERRCODE = '22023';
  END IF;

  SELECT *
  INTO v_before
  FROM public.authorities a
  WHERE a.authority_id = p_authority_id
    AND a.organization_id = p_tenant_id::text
    AND a.subject_type = 'human_approver'
    AND a.role IN ('policy_admin', 'control_plane_approver')
    AND a.assurance_class = 'A'
    AND a.action_scopes IS NOT NULL
    AND 'policy_rollout' = ANY (a.action_scopes)
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'policy_rollout_authority_not_found'
      USING ERRCODE = 'P0002';
  END IF;

  IF v_before.status <> 'active' OR v_before.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'policy_rollout_authority_already_revoked'
      USING ERRCODE = '23505';
  END IF;

  UPDATE public.authorities
  SET status = 'revoked',
      revoked_at = v_revoked_at,
      metadata_json = COALESCE(metadata_json, '{}'::jsonb)
        || pg_catalog.jsonb_build_object(
          'revoked_by', p_revoked_by,
          'revoke_reason', btrim(p_reason)
        )
  WHERE authority_id = p_authority_id;

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
    'guard.authority.revoked',
    p_revoked_by,
    'system',
    'authority',
    p_authority_id::text,
    'revoke_policy_rollout_authority',
    pg_catalog.jsonb_build_object(
      'status', v_before.status,
      'revoked_at', v_before.revoked_at
    ),
    pg_catalog.jsonb_build_object(
      'status', 'revoked',
      'revoked_at', v_revoked_at,
      'reason', btrim(p_reason)
    )
  );

  RETURN pg_catalog.jsonb_build_object(
    'authority_id', p_authority_id::text,
    'status', 'revoked',
    'revoked_at', v_revoked_at
  );
END;
$$;

REVOKE ALL ON FUNCTION public.grant_policy_rollout_authority(
  UUID, TEXT, TEXT, TIMESTAMPTZ, TEXT, TEXT
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.grant_policy_rollout_authority(
  UUID, TEXT, TEXT, TIMESTAMPTZ, TEXT, TEXT
) TO service_role;

REVOKE ALL ON FUNCTION public.revoke_policy_rollout_authority(
  UUID, UUID, TEXT, TEXT
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.revoke_policy_rollout_authority(
  UUID, UUID, TEXT, TEXT
) TO service_role;
