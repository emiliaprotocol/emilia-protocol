-- SPDX-License-Identifier: Apache-2.0
-- Restore the directory enrollment fields lost when the lexically later
-- atomic-registration migration replaced this function with an older body.

CREATE OR REPLACE FUNCTION public.complete_webauthn_registration_atomic(
  p_challenge_id UUID,
  p_organization_id TEXT,
  p_approver_id TEXT,
  p_credential JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $function$
DECLARE
  v_challenge RECORD;
  v_directory_user RECORD;
  v_transports TEXT[];
  v_credential_id TEXT;
  v_enrollment_basis TEXT;
  v_directory_user_id UUID;
  v_completed_at TIMESTAMPTZ;
BEGIN
  SELECT id, kind, organization_id, approver_id, consumed_at, expires_at
  INTO v_challenge
  FROM public.webauthn_challenges
  WHERE id = p_challenge_id
  FOR UPDATE;

  IF NOT FOUND
     OR v_challenge.kind <> 'registration'
     OR v_challenge.organization_id IS DISTINCT FROM p_organization_id
     OR v_challenge.approver_id IS DISTINCT FROM p_approver_id THEN
    RETURN jsonb_build_object('error', 'challenge_not_found');
  END IF;
  IF v_challenge.consumed_at IS NOT NULL THEN
    RETURN jsonb_build_object('error', 'challenge_consumed');
  END IF;
  v_credential_id := NULLIF(p_credential->>'credential_id', '');
  IF v_credential_id IS NULL THEN
    RETURN jsonb_build_object('error', 'credential_missing');
  END IF;

  v_enrollment_basis := COALESCE(
    NULLIF(p_credential->>'enrollment_basis', ''),
    'operator_attested'
  );
  IF v_enrollment_basis NOT IN ('directory', 'operator_attested') THEN
    RETURN jsonb_build_object('error', 'enrollment_basis_invalid');
  END IF;

  BEGIN
    v_directory_user_id := NULLIF(p_credential->>'directory_user_id', '')::UUID;
  EXCEPTION
    WHEN invalid_text_representation THEN
      RETURN jsonb_build_object('error', 'directory_user_invalid');
  END;

  IF (v_enrollment_basis = 'directory') IS DISTINCT FROM (v_directory_user_id IS NOT NULL) THEN
    RETURN jsonb_build_object('error', 'directory_basis_mismatch');
  END IF;

  -- Serialize enrollment against enabling a directory for this deployment.
  -- If registration wins the lock first, the token-insert trigger revokes the
  -- operator-attested credential before directory enable commits. If token
  -- creation wins, this transaction observes it and requires directory basis.
  LOCK TABLE public.scim_provisioning_tokens IN SHARE MODE;
  IF v_enrollment_basis = 'operator_attested' AND EXISTS (
    SELECT 1
    FROM public.scim_provisioning_tokens AS token
    WHERE token.revoked_at IS NULL
      AND (
        token.organization_id = p_organization_id
        OR (token.organization_id IS NULL AND token.tenant_id = p_organization_id)
      )
  ) THEN
    RETURN jsonb_build_object('error', 'directory_required');
  END IF;

  -- The route's pre-ceremony directory lookup is only advisory. Re-lock and
  -- revalidate the exact source row here, in the same transaction that mints
  -- the credential, so a concurrent SCIM deactivate or delete cannot race a
  -- stale active-user observation into durable signing authority.
  IF v_enrollment_basis = 'directory' THEN
    SELECT directory_user.id, directory_user.user_name, directory_user.active
    INTO v_directory_user
    FROM public.scim_users AS directory_user
    WHERE directory_user.id = v_directory_user_id
      AND directory_user.user_name = p_approver_id
      AND directory_user.active = TRUE
      AND EXISTS (
        SELECT 1
        FROM public.scim_provisioning_tokens AS token
        WHERE token.tenant_id = directory_user.tenant_id
          AND (
            token.organization_id = p_organization_id
            OR token.tenant_id = p_organization_id
          )
      )
    FOR UPDATE;
    IF NOT FOUND THEN
      RETURN jsonb_build_object('error', 'directory_user_inactive');
    END IF;
  END IF;

  -- Capture completion time after every row lock. statement_timestamp()/now()
  -- would freeze at transaction start and could accept an already-expired
  -- challenge after lock contention.
  v_completed_at := pg_catalog.clock_timestamp();
  IF v_challenge.expires_at <= v_completed_at THEN
    RETURN jsonb_build_object('error', 'challenge_expired');
  END IF;

  IF pg_catalog.jsonb_typeof(p_credential->'transports') = 'array' THEN
    SELECT pg_catalog.array_agg(value)
    INTO v_transports
    FROM pg_catalog.jsonb_array_elements_text(p_credential->'transports');
  END IF;

  INSERT INTO public.approver_credentials (
    organization_id,
    approver_id,
    approver_name,
    credential_id,
    public_key_cose,
    public_key_spki,
    key_class,
    sign_count,
    transports,
    attestation_fmt,
    attested_by,
    enrollment_basis,
    directory_user_id
  ) VALUES (
    p_organization_id,
    p_approver_id,
    NULLIF(p_credential->>'approver_name', ''),
    v_credential_id,
    p_credential->>'public_key_cose',
    p_credential->>'public_key_spki',
    COALESCE(NULLIF(p_credential->>'key_class', ''), 'A'),
    COALESCE((p_credential->>'sign_count')::BIGINT, 0),
    v_transports,
    NULLIF(p_credential->>'attestation_fmt', ''),
    NULLIF(p_credential->>'attested_by', ''),
    v_enrollment_basis,
    v_directory_user_id
  );

  UPDATE public.webauthn_challenges
  SET consumed_at = v_completed_at
  WHERE id = p_challenge_id;

  RETURN jsonb_build_object(
    'credential_id', v_credential_id,
    'consumed', true,
    'enrollment_basis', v_enrollment_basis,
    'directory_user_id', v_directory_user_id
  );
EXCEPTION
  WHEN unique_violation THEN
    RETURN jsonb_build_object('error', 'credential_exists');
END;
$function$;

REVOKE ALL ON FUNCTION public.complete_webauthn_registration_atomic(UUID, TEXT, TEXT, JSONB)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.complete_webauthn_registration_atomic(UUID, TEXT, TEXT, JSONB)
  TO service_role;
