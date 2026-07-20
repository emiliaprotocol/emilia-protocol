-- Forward-only expansion of audited tenant API-key issuance to the
-- approval_request least-privilege capability.

CREATE OR REPLACE FUNCTION public.issue_tenant_api_key_audited(
  p_tenant_id UUID,
  p_environment TEXT,
  p_key_hash TEXT,
  p_key_prefix TEXT,
  p_name TEXT,
  p_permissions TEXT[],
  p_expires_at TIMESTAMPTZ,
  p_issued_by TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_key public.tenant_api_keys%ROWTYPE;
BEGIN
  IF p_tenant_id IS NULL
     OR p_environment NOT IN ('development', 'staging', 'production')
     OR p_key_hash !~ '^[a-f0-9]{64}$'
     OR p_key_prefix NOT IN ('ept_live', 'ept_test')
     OR p_name IS NULL OR btrim(p_name) = '' OR length(p_name) > 120
     OR p_permissions IS NULL OR pg_catalog.cardinality(p_permissions) < 1
     OR NOT p_permissions <@ ARRAY['read', 'write', 'admin', 'policy_rollout', 'approval_request']::TEXT[]
     OR pg_catalog.cardinality(p_permissions) <> (
       SELECT count(DISTINCT permission)
       FROM unnest(p_permissions) permission
     )
     OR p_expires_at IS NULL
     OR p_expires_at <= pg_catalog.now()
     OR p_expires_at > pg_catalog.now() + interval '90 days 5 minutes'
     OR p_issued_by IS NULL OR p_issued_by !~ '^entity:.+'
  THEN
    RAISE EXCEPTION 'invalid_tenant_api_key_issue'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.tenant_api_keys (
    tenant_id,
    environment,
    key_hash,
    key_prefix,
    name,
    permissions,
    expires_at
  )
  VALUES (
    p_tenant_id,
    p_environment,
    p_key_hash,
    p_key_prefix,
    btrim(p_name),
    p_permissions,
    p_expires_at
  )
  RETURNING * INTO v_key;

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
    'cloud.tenant_api_key.issued',
    p_issued_by,
    'principal',
    'tenant_api_key',
    v_key.key_id::text,
    'issue',
    NULL,
    pg_catalog.jsonb_build_object(
      'key_id', v_key.key_id::text,
      'tenant_id', v_key.tenant_id::text,
      'environment', v_key.environment,
      'key_prefix', v_key.key_prefix,
      'name', v_key.name,
      'permissions', v_key.permissions,
      'created_at', v_key.created_at,
      'expires_at', v_key.expires_at
    )
  );

  RETURN pg_catalog.jsonb_build_object(
    'key_id', v_key.key_id::text,
    'tenant_id', v_key.tenant_id::text,
    'environment', v_key.environment,
    'key_prefix', v_key.key_prefix,
    'name', v_key.name,
    'permissions', v_key.permissions,
    'created_at', v_key.created_at,
    'expires_at', v_key.expires_at
  );
END;
$$;

REVOKE ALL ON FUNCTION public.issue_tenant_api_key_audited(
  UUID, TEXT, TEXT, TEXT, TEXT, TEXT[], TIMESTAMPTZ, TEXT
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.issue_tenant_api_key_audited(
  UUID, TEXT, TEXT, TEXT, TEXT, TEXT[], TIMESTAMPTZ, TEXT
) TO service_role;
