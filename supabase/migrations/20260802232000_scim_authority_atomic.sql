-- SPDX-License-Identifier: Apache-2.0
-- Make SCIM deprovisioning and approver-credential revocation one transaction.

CREATE OR REPLACE FUNCTION public.apply_scim_user_and_authority_atomic(
  p_tenant_id TEXT,
  p_organization_id TEXT,
  p_user_id UUID,
  p_expected_version INTEGER,
  p_fields JSONB,
  p_delete BOOLEAN DEFAULT FALSE,
  p_reason TEXT DEFAULT 'scim_update'
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $function$
DECLARE
  v_current public.scim_users%ROWTYPE;
  v_updated public.scim_users%ROWTYPE;
  v_org_scope TEXT;
  v_revoked_at TIMESTAMPTZ;
  v_revoked_count INTEGER := 0;
  v_allowed_fields CONSTANT TEXT[] := ARRAY[
    'user_name', 'external_id', 'active', 'formatted_name', 'given_name',
    'family_name', 'display_name', 'title', 'emails', 'phone_numbers', 'raw'
  ];
BEGIN
  IF p_tenant_id IS NULL OR p_tenant_id = ''
    OR p_user_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 1
    OR p_delete IS NULL
  THEN
    RAISE EXCEPTION 'SCIM authority write input is invalid' USING ERRCODE = '22023';
  END IF;
  v_org_scope := COALESCE(NULLIF(p_organization_id, ''), p_tenant_id);

  SELECT user_row.* INTO v_current
  FROM public.scim_users AS user_row
  WHERE user_row.tenant_id = p_tenant_id
    AND user_row.id = p_user_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('error', 'user_not_found');
  END IF;
  IF v_current.version IS DISTINCT FROM p_expected_version THEN
    RETURN pg_catalog.jsonb_build_object('error', 'version_conflict');
  END IF;

  IF p_delete THEN
    v_revoked_at := pg_catalog.clock_timestamp();
    UPDATE public.approver_credentials AS credential
    SET revoked_at = v_revoked_at
    WHERE credential.organization_id = v_org_scope
      AND credential.approver_id = v_current.user_name
      AND credential.revoked_at IS NULL;
    GET DIAGNOSTICS v_revoked_count = ROW_COUNT;

    INSERT INTO public.audit_events (
      event_type, actor_id, actor_type, target_type, target_id,
      action, before_state, after_state
    ) VALUES (
      'scim.approver.deprovisioned', p_tenant_id, 'system', 'approver',
      v_current.user_name, 'deprovision', pg_catalog.to_jsonb(v_current),
      pg_catalog.jsonb_build_object(
        'tenant_id', p_tenant_id,
        'organization_id', v_org_scope,
        'reason', COALESCE(NULLIF(p_reason, ''), 'scim_delete'),
        'credentials_revoked', v_revoked_count,
        'revoked_at', v_revoked_at,
        'directory_row_deleted', TRUE
      )
    );
    DELETE FROM public.scim_users AS user_row
    WHERE user_row.tenant_id = p_tenant_id AND user_row.id = p_user_id;
    RETURN pg_catalog.jsonb_build_object(
      'status', 'deleted',
      'credentials_revoked', v_revoked_count
    );
  END IF;

  IF p_fields IS NULL
    OR pg_catalog.jsonb_typeof(p_fields) <> 'object'
    OR NOT (p_fields ?& v_allowed_fields)
    OR EXISTS (
      SELECT 1 FROM pg_catalog.jsonb_object_keys(p_fields) AS fields(field_name)
      WHERE NOT (fields.field_name = ANY(v_allowed_fields))
    )
    OR pg_catalog.jsonb_typeof(p_fields -> 'active') <> 'boolean'
    OR pg_catalog.jsonb_typeof(p_fields -> 'emails') <> 'array'
    OR pg_catalog.jsonb_typeof(p_fields -> 'phone_numbers') <> 'array'
    OR pg_catalog.jsonb_typeof(p_fields -> 'raw') <> 'object'
  THEN
    RAISE EXCEPTION 'SCIM user field set is invalid' USING ERRCODE = '22023';
  END IF;

  UPDATE public.scim_users AS user_row
  SET user_name = p_fields ->> 'user_name',
      external_id = NULLIF(p_fields ->> 'external_id', ''),
      active = (p_fields ->> 'active')::BOOLEAN,
      formatted_name = NULLIF(p_fields ->> 'formatted_name', ''),
      given_name = NULLIF(p_fields ->> 'given_name', ''),
      family_name = NULLIF(p_fields ->> 'family_name', ''),
      display_name = NULLIF(p_fields ->> 'display_name', ''),
      title = NULLIF(p_fields ->> 'title', ''),
      emails = p_fields -> 'emails',
      phone_numbers = p_fields -> 'phone_numbers',
      raw = p_fields -> 'raw',
      version = v_current.version + 1,
      updated_at = pg_catalog.clock_timestamp()
  WHERE user_row.tenant_id = p_tenant_id AND user_row.id = p_user_id
  RETURNING user_row.* INTO v_updated;

  IF v_current.active AND NOT v_updated.active THEN
    v_revoked_at := pg_catalog.clock_timestamp();
    UPDATE public.approver_credentials AS credential
    SET revoked_at = v_revoked_at
    WHERE credential.organization_id = v_org_scope
      AND credential.approver_id = v_current.user_name
      AND credential.revoked_at IS NULL;
    GET DIAGNOSTICS v_revoked_count = ROW_COUNT;

    INSERT INTO public.audit_events (
      event_type, actor_id, actor_type, target_type, target_id,
      action, before_state, after_state
    ) VALUES (
      'scim.approver.deprovisioned', p_tenant_id, 'system', 'approver',
      v_current.user_name, 'deprovision', pg_catalog.to_jsonb(v_current),
      pg_catalog.jsonb_build_object(
        'tenant_id', p_tenant_id,
        'organization_id', v_org_scope,
        'reason', COALESCE(NULLIF(p_reason, ''), 'scim_deactivate'),
        'credentials_revoked', v_revoked_count,
        'revoked_at', v_revoked_at
      )
    );
  END IF;

  RETURN pg_catalog.jsonb_build_object(
    'status', 'updated',
    'credentials_revoked', v_revoked_count,
    'user', pg_catalog.to_jsonb(v_updated),
    'reactivated', (NOT v_current.active AND v_updated.active)
  );
END;
$function$;

REVOKE ALL ON FUNCTION public.apply_scim_user_and_authority_atomic(
  TEXT, TEXT, UUID, INTEGER, JSONB, BOOLEAN, TEXT
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.apply_scim_user_and_authority_atomic(
  TEXT, TEXT, UUID, INTEGER, JSONB, BOOLEAN, TEXT
) TO service_role;

CREATE OR REPLACE FUNCTION public.revoke_operator_credentials_on_directory_enable()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $trigger$
DECLARE
  v_org_scope TEXT;
BEGIN
  v_org_scope := COALESCE(NULLIF(NEW.organization_id, ''), NEW.tenant_id);
  UPDATE public.approver_credentials AS credential
  SET revoked_at = pg_catalog.clock_timestamp()
  WHERE credential.organization_id = v_org_scope
    AND credential.enrollment_basis = 'operator_attested'
    AND credential.revoked_at IS NULL;
  RETURN NEW;
END;
$trigger$;

DROP TRIGGER IF EXISTS scim_directory_enable_revokes_operator_credentials
  ON public.scim_provisioning_tokens;
CREATE TRIGGER scim_directory_enable_revokes_operator_credentials
AFTER INSERT ON public.scim_provisioning_tokens
FOR EACH ROW
EXECUTE FUNCTION public.revoke_operator_credentials_on_directory_enable();

REVOKE ALL ON FUNCTION public.revoke_operator_credentials_on_directory_enable()
  FROM PUBLIC, anon, authenticated, service_role;
