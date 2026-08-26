-- SPDX-License-Identifier: Apache-2.0
-- Residual identity-runtime closure for STRIX-42, STRIX-44, and STRIX-48.
-- This forward migration intentionally follows the concurrently-owned 160000
-- continuity migration and does not rewrite any historical migration.

-- ==========================================================================
-- STRIX-44: exact directory identity for mobile pairing and every live session
-- ==========================================================================

ALTER TABLE public.mobile_pairings
  ADD COLUMN IF NOT EXISTS organization_id TEXT,
  ADD COLUMN IF NOT EXISTS directory_user_id UUID;

ALTER TABLE public.mobile_sessions
  ADD COLUMN IF NOT EXISTS organization_id TEXT,
  ADD COLUMN IF NOT EXISTS directory_user_id UUID,
  ADD COLUMN IF NOT EXISTS identity_credential_id TEXT,
  ADD COLUMN IF NOT EXISTS identity_proof_digest TEXT,
  ADD COLUMN IF NOT EXISTS identity_verified_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

-- Pre-closure pairings and sessions did not retain the identity facts needed
-- for a future transactional recheck. Quarantine them instead of guessing.
UPDATE public.mobile_pairings
   SET consumed_at = COALESCE(consumed_at, pg_catalog.clock_timestamp())
 WHERE organization_id IS NULL OR directory_user_id IS NULL;

UPDATE public.mobile_sessions
   SET revoked_at = COALESCE(revoked_at, pg_catalog.clock_timestamp())
 WHERE organization_id IS NULL
    OR directory_user_id IS NULL
    OR identity_credential_id IS NULL
    OR identity_proof_digest IS NULL
    OR identity_verified_at IS NULL;

ALTER TABLE public.mobile_pairings
  DROP CONSTRAINT IF EXISTS mobile_pairings_active_identity_binding;
ALTER TABLE public.mobile_pairings
  ADD CONSTRAINT mobile_pairings_active_identity_binding CHECK (
    consumed_at IS NOT NULL OR (
      NULLIF(organization_id, '') IS NOT NULL
      AND directory_user_id IS NOT NULL
    )
  );

ALTER TABLE public.mobile_sessions
  DROP CONSTRAINT IF EXISTS mobile_sessions_active_identity_binding;
ALTER TABLE public.mobile_sessions
  ADD CONSTRAINT mobile_sessions_active_identity_binding CHECK (
    revoked_at IS NOT NULL OR (
      NULLIF(organization_id, '') IS NOT NULL
      AND directory_user_id IS NOT NULL
      AND NULLIF(identity_credential_id, '') IS NOT NULL
      AND identity_proof_digest ~ '^sha256:[0-9a-f]{64}$'
      AND identity_verified_at IS NOT NULL
    )
  );

CREATE INDEX IF NOT EXISTS mobile_sessions_identity_credential_active_idx
  ON public.mobile_sessions (identity_credential_id)
  WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS mobile_sessions_directory_user_active_idx
  ON public.mobile_sessions (directory_user_id)
  WHERE revoked_at IS NULL;

CREATE OR REPLACE FUNCTION public.create_mobile_pairing_verified(
  p_code_hash TEXT,
  p_entity_ref TEXT,
  p_organization_id TEXT,
  p_approver_id TEXT,
  p_directory_user_id UUID,
  p_profile_id TEXT,
  p_allowed_apps JSONB,
  p_expires_at TIMESTAMPTZ,
  p_session_expires_at TIMESTAMPTZ
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $function$
DECLARE
  v_entity RECORD;
  v_directory_user_lookup RECORD;
  v_directory_user RECORD;
  v_token RECORD;
  v_token_id UUID;
  v_now TIMESTAMPTZ;
  v_directory_bound BOOLEAN := FALSE;
  v_has_class_a BOOLEAN := FALSE;
BEGIN
  IF p_code_hash IS NULL OR p_code_hash !~ '^[0-9a-f]{64}$'
     OR NULLIF(p_entity_ref, '') IS NULL
     OR NULLIF(p_organization_id, '') IS NULL
     OR char_length(COALESCE(p_approver_id, '')) NOT BETWEEN 3 AND 128
     OR p_directory_user_id IS NULL
     OR char_length(COALESCE(p_profile_id, '')) NOT BETWEEN 3 AND 128
     OR p_allowed_apps IS NULL OR pg_catalog.jsonb_typeof(p_allowed_apps) <> 'object'
     OR p_allowed_apps - 'ios' - 'android' <> '{}'::JSONB
     OR pg_catalog.jsonb_typeof(p_allowed_apps -> 'ios') <> 'array'
     OR pg_catalog.jsonb_typeof(p_allowed_apps -> 'android') <> 'array'
     OR p_expires_at IS NULL OR p_session_expires_at IS NULL THEN
    RETURN FALSE;
  END IF;
  IF pg_catalog.jsonb_array_length(p_allowed_apps -> 'ios') < 1
     OR pg_catalog.jsonb_array_length(p_allowed_apps -> 'ios') > 8
     OR pg_catalog.jsonb_array_length(p_allowed_apps -> 'android') > 8
     OR EXISTS (
       SELECT 1
         FROM pg_catalog.jsonb_array_elements(
           (p_allowed_apps -> 'ios') || (p_allowed_apps -> 'android')
         ) AS app(value)
        WHERE pg_catalog.jsonb_typeof(app.value) <> 'string'
           OR char_length(app.value #>> '{}') NOT BETWEEN 3 AND 256
     ) THEN
    RETURN FALSE;
  END IF;

  -- Resolve immutable identifiers without locks, then acquire every mutable
  -- identity row in the global order entity -> token -> directory user ->
  -- credential. Offboarding triggers take the same order before touching a
  -- pairing/session, so an identity revocation cannot deadlock behind admission.
  SELECT directory_user.id, directory_user.tenant_id, directory_user.user_name,
         directory_user.active
    INTO v_directory_user_lookup
    FROM public.scim_users AS directory_user
   WHERE directory_user.id = p_directory_user_id;
  IF NOT FOUND THEN RETURN FALSE; END IF;

  SELECT token.id INTO v_token_id
    FROM public.scim_provisioning_tokens AS token
   WHERE token.tenant_id = v_directory_user_lookup.tenant_id
     AND token.organization_id = p_organization_id
     AND token.revoked_at IS NULL
   ORDER BY token.id
   LIMIT 1;
  IF NOT FOUND THEN RETURN FALSE; END IF;

  SELECT entity.entity_id, entity.organization_id, entity.status
    INTO v_entity
    FROM public.entities AS entity
   WHERE entity.entity_id = p_entity_ref
   FOR UPDATE;
  IF NOT FOUND
     OR v_entity.status IS DISTINCT FROM 'active'
     OR v_entity.organization_id IS DISTINCT FROM p_organization_id THEN
    RETURN FALSE;
  END IF;

  SELECT token.id, token.tenant_id, token.organization_id, token.revoked_at
    INTO v_token
    FROM public.scim_provisioning_tokens AS token
   WHERE token.id = v_token_id
   FOR UPDATE;
  IF NOT FOUND THEN RETURN FALSE; END IF;

  SELECT directory_user.id, directory_user.tenant_id, directory_user.user_name,
         directory_user.active
    INTO v_directory_user
    FROM public.scim_users AS directory_user
   WHERE directory_user.id = p_directory_user_id
   FOR UPDATE;
  IF NOT FOUND
     OR v_directory_user.active IS DISTINCT FROM TRUE
     OR v_directory_user.user_name IS DISTINCT FROM p_approver_id
     OR v_directory_user.tenant_id IS DISTINCT FROM v_token.tenant_id
     OR v_token.organization_id IS DISTINCT FROM p_organization_id
     OR v_token.revoked_at IS NOT NULL THEN
    RETURN FALSE;
  END IF;
  v_directory_bound := TRUE;

  -- Lock every candidate before consulting the server clock. The post-lock
  -- validity check below cannot be satisfied by a credential that expired
  -- while this transaction waited.
  PERFORM credential.id
    FROM public.approver_credentials AS credential
   WHERE credential.organization_id = p_organization_id
     AND credential.approver_id = p_approver_id
     AND credential.directory_user_id = p_directory_user_id
     AND credential.enrollment_basis = 'directory'
     AND credential.key_class = 'A'
     AND credential.revoked_at IS NULL
   FOR UPDATE;
  v_now := pg_catalog.clock_timestamp();
  SELECT EXISTS (
    SELECT 1
      FROM public.approver_credentials AS credential
     WHERE credential.organization_id = p_organization_id
       AND credential.approver_id = p_approver_id
       AND credential.directory_user_id = p_directory_user_id
       AND credential.enrollment_basis = 'directory'
       AND credential.key_class = 'A'
       AND credential.revoked_at IS NULL
       AND credential.valid_from <= v_now
       AND (credential.valid_to IS NULL OR credential.valid_to > v_now)
  ) INTO v_has_class_a;
  IF NOT v_has_class_a
     OR p_expires_at <= v_now
     OR p_session_expires_at <= p_expires_at THEN
    RETURN FALSE;
  END IF;

  INSERT INTO public.mobile_pairings (
    code_hash, entity_ref, organization_id, approver_id, directory_user_id,
    profile_id, allowed_apps, expires_at, session_expires_at
  ) VALUES (
    p_code_hash, p_entity_ref, p_organization_id, p_approver_id,
    p_directory_user_id, p_profile_id, p_allowed_apps, p_expires_at,
    p_session_expires_at
  );
  RETURN TRUE;
EXCEPTION
  WHEN unique_violation OR check_violation OR foreign_key_violation OR not_null_violation THEN
    RETURN FALSE;
END;
$function$;

REVOKE ALL ON FUNCTION public.create_mobile_pairing_verified(
  TEXT, TEXT, TEXT, TEXT, UUID, TEXT, JSONB, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.create_mobile_pairing_verified(
  TEXT, TEXT, TEXT, TEXT, UUID, TEXT, JSONB, TIMESTAMPTZ, TIMESTAMPTZ
) TO service_role;

CREATE OR REPLACE FUNCTION public.exchange_mobile_pairing_verified(
  p_code_hash TEXT,
  p_token_hash TEXT,
  p_platform TEXT,
  p_app_id TEXT,
  p_credential_id TEXT,
  p_expected_approver_id TEXT,
  p_new_sign_count BIGINT,
  p_identity_proof_digest TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $function$
DECLARE
  v_pairing_lookup public.mobile_pairings%ROWTYPE;
  v_pairing public.mobile_pairings%ROWTYPE;
  v_entity RECORD;
  v_directory_user_lookup RECORD;
  v_directory_user RECORD;
  v_token RECORD;
  v_token_id UUID;
  v_credential public.approver_credentials%ROWTYPE;
  v_created public.mobile_sessions%ROWTYPE;
  v_now TIMESTAMPTZ;
  v_directory_bound BOOLEAN := FALSE;
BEGIN
  IF p_code_hash IS NULL OR p_code_hash !~ '^[0-9a-f]{64}$'
     OR p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$'
     OR p_platform NOT IN ('ios', 'android')
     OR char_length(COALESCE(p_app_id, '')) NOT BETWEEN 3 AND 256
     OR char_length(COALESCE(p_credential_id, '')) NOT BETWEEN 8 AND 4096
     OR char_length(COALESCE(p_expected_approver_id, '')) NOT BETWEEN 3 AND 128
     OR p_new_sign_count IS NULL OR p_new_sign_count < 0
     OR p_identity_proof_digest !~ '^sha256:[0-9a-f]{64}$' THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'malformed');
  END IF;

  -- Read only enough identity to determine the rows to lock. Every decision is
  -- repeated after acquiring the global control order and the pairing last.
  SELECT pairing.* INTO v_pairing_lookup
    FROM public.mobile_pairings AS pairing
   WHERE pairing.code_hash = p_code_hash;
  IF NOT FOUND OR v_pairing_lookup.consumed_at IS NOT NULL
     OR v_pairing_lookup.organization_id IS NULL
     OR v_pairing_lookup.directory_user_id IS NULL THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'invalid_or_consumed');
  END IF;
  IF v_pairing_lookup.approver_id IS DISTINCT FROM p_expected_approver_id THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'approver_mismatch');
  END IF;
  IF NOT COALESCE(v_pairing_lookup.allowed_apps -> p_platform, '[]'::JSONB) ? p_app_id THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'app_not_allowed');
  END IF;

  SELECT directory_user.id, directory_user.tenant_id
    INTO v_directory_user_lookup
    FROM public.scim_users AS directory_user
   WHERE directory_user.id = v_pairing_lookup.directory_user_id;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'identity_not_active');
  END IF;
  SELECT token.id INTO v_token_id
    FROM public.scim_provisioning_tokens AS token
   WHERE token.tenant_id = v_directory_user_lookup.tenant_id
     AND token.organization_id = v_pairing_lookup.organization_id
     AND token.revoked_at IS NULL
   ORDER BY token.id
   LIMIT 1;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'identity_not_active');
  END IF;

  SELECT entity.entity_id, entity.organization_id, entity.status
    INTO v_entity
    FROM public.entities AS entity
   WHERE entity.entity_id = v_pairing_lookup.entity_ref
   FOR UPDATE;

  SELECT token.id, token.tenant_id, token.organization_id, token.revoked_at
    INTO v_token
    FROM public.scim_provisioning_tokens AS token
   WHERE token.id = v_token_id
   FOR UPDATE;

  SELECT directory_user.id, directory_user.tenant_id, directory_user.user_name,
         directory_user.active
    INTO v_directory_user
    FROM public.scim_users AS directory_user
   WHERE directory_user.id = v_pairing_lookup.directory_user_id
   FOR UPDATE;

  SELECT credential.* INTO v_credential
    FROM public.approver_credentials AS credential
   WHERE credential.credential_id = p_credential_id
   FOR UPDATE;

  SELECT pairing.* INTO v_pairing
    FROM public.mobile_pairings AS pairing
   WHERE pairing.code_hash = p_code_hash
   FOR UPDATE;

  -- Time is sampled only after all identity rows have been locked.
  v_now := pg_catalog.clock_timestamp();
  IF v_pairing.code_hash IS NULL
     OR v_pairing.consumed_at IS NOT NULL
     OR v_pairing.entity_ref IS DISTINCT FROM v_pairing_lookup.entity_ref
     OR v_pairing.organization_id IS DISTINCT FROM v_pairing_lookup.organization_id
     OR v_pairing.directory_user_id IS DISTINCT FROM v_pairing_lookup.directory_user_id
     OR v_pairing.approver_id IS DISTINCT FROM p_expected_approver_id THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'invalid_or_consumed');
  END IF;
  IF NOT COALESCE(v_pairing.allowed_apps -> p_platform, '[]'::JSONB) ? p_app_id THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'app_not_allowed');
  END IF;
  IF v_pairing.expires_at <= v_now OR v_pairing.session_expires_at <= v_now THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'invalid_or_expired');
  END IF;
  v_directory_bound := v_token.id IS NOT NULL
    AND v_token.tenant_id IS NOT DISTINCT FROM v_directory_user.tenant_id
    AND v_token.organization_id IS NOT DISTINCT FROM v_pairing.organization_id
    AND v_token.revoked_at IS NULL;
  IF v_entity.entity_id IS NULL
     OR v_entity.status IS DISTINCT FROM 'active'
     OR v_entity.organization_id IS DISTINCT FROM v_pairing.organization_id
     OR v_directory_user.id IS NULL
     OR v_directory_user.active IS DISTINCT FROM TRUE
     OR v_directory_user.user_name IS DISTINCT FROM v_pairing.approver_id
     OR NOT v_directory_bound
     OR v_credential.id IS NULL
     OR v_credential.organization_id IS DISTINCT FROM v_pairing.organization_id
     OR v_credential.approver_id IS DISTINCT FROM v_pairing.approver_id
     OR v_credential.directory_user_id IS DISTINCT FROM v_pairing.directory_user_id
     OR v_credential.enrollment_basis IS DISTINCT FROM 'directory'
     OR v_credential.key_class IS DISTINCT FROM 'A'
     OR v_credential.revoked_at IS NOT NULL
     OR v_credential.valid_from > v_now
     OR (v_credential.valid_to IS NOT NULL AND v_credential.valid_to <= v_now) THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'identity_not_active');
  END IF;
  IF v_credential.sign_count > 0 AND p_new_sign_count <= v_credential.sign_count THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'credential_counter_replay');
  END IF;

  UPDATE public.approver_credentials
     SET sign_count = GREATEST(sign_count, p_new_sign_count)
   WHERE id = v_credential.id;
  UPDATE public.mobile_pairings
     SET consumed_at = v_now
   WHERE code_hash = p_code_hash;
  INSERT INTO public.mobile_sessions (
    token_hash, entity_ref, organization_id, approver_id, directory_user_id,
    identity_credential_id, identity_proof_digest, identity_verified_at,
    profile_id, platform, app_id, expires_at
  ) VALUES (
    p_token_hash, v_pairing.entity_ref, v_pairing.organization_id,
    v_pairing.approver_id, v_pairing.directory_user_id,
    v_credential.credential_id, p_identity_proof_digest, v_now,
    v_pairing.profile_id, p_platform, p_app_id, v_pairing.session_expires_at
  ) RETURNING * INTO v_created;

  RETURN pg_catalog.jsonb_build_object(
    'ok', TRUE,
    'session_id', v_created.session_id,
    'entity_ref', v_created.entity_ref,
    'organization_id', v_created.organization_id,
    'directory_user_id', v_created.directory_user_id,
    'approver_id', v_created.approver_id,
    'profile_id', v_created.profile_id,
    'expires_at', v_created.expires_at
  );
END;
$function$;

REVOKE ALL ON FUNCTION public.exchange_mobile_pairing_verified(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.exchange_mobile_pairing_verified(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT
) TO service_role;

-- Disable the pre-closure overload whose caller-supplied clock and unbound
-- directory-user state cannot satisfy the new invariant.
CREATE OR REPLACE FUNCTION public.exchange_mobile_pairing_verified(
  p_code_hash TEXT, p_token_hash TEXT, p_platform TEXT, p_app_id TEXT,
  p_credential_id TEXT, p_expected_approver_id TEXT,
  p_new_sign_count BIGINT, p_now TIMESTAMPTZ DEFAULT now()
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $function$
BEGIN
  RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'identity_runtime_upgrade_required');
END;
$function$;
REVOKE ALL ON FUNCTION public.exchange_mobile_pairing_verified(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.mobile_session_identity_is_active(
  p_session_id UUID,
  p_expected_entity_ref TEXT,
  p_expected_approver_id TEXT,
  p_expected_token_hash TEXT,
  p_require_device_key BOOLEAN
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $function$
DECLARE
  v_lookup public.mobile_sessions%ROWTYPE;
  v_session public.mobile_sessions%ROWTYPE;
  v_entity RECORD;
  v_directory_user_lookup RECORD;
  v_directory_user RECORD;
  v_token RECORD;
  v_token_id UUID;
  v_credential public.approver_credentials%ROWTYPE;
  v_now TIMESTAMPTZ;
BEGIN
  IF p_session_id IS NULL OR p_require_device_key IS NULL
     OR (p_expected_token_hash IS NOT NULL
       AND p_expected_token_hash !~ '^[0-9a-f]{64}$') THEN
    RETURN FALSE;
  END IF;

  SELECT session.* INTO v_lookup
    FROM public.mobile_sessions AS session
   WHERE session.session_id = p_session_id;
  IF NOT FOUND
     OR v_lookup.organization_id IS NULL
     OR v_lookup.directory_user_id IS NULL
     OR v_lookup.identity_credential_id IS NULL
     OR v_lookup.identity_proof_digest IS NULL
     OR (p_expected_entity_ref IS NOT NULL
       AND v_lookup.entity_ref IS DISTINCT FROM p_expected_entity_ref)
     OR (p_expected_approver_id IS NOT NULL
       AND v_lookup.approver_id IS DISTINCT FROM p_expected_approver_id)
     OR (p_expected_token_hash IS NOT NULL
       AND v_lookup.token_hash IS DISTINCT FROM p_expected_token_hash) THEN
    RETURN FALSE;
  END IF;

  SELECT directory_user.id, directory_user.tenant_id
    INTO v_directory_user_lookup
    FROM public.scim_users AS directory_user
   WHERE directory_user.id = v_lookup.directory_user_id;
  IF NOT FOUND THEN RETURN FALSE; END IF;
  SELECT token.id INTO v_token_id
    FROM public.scim_provisioning_tokens AS token
   WHERE token.tenant_id = v_directory_user_lookup.tenant_id
     AND token.organization_id = v_lookup.organization_id
     AND token.revoked_at IS NULL
   ORDER BY token.id
   LIMIT 1;
  IF NOT FOUND THEN RETURN FALSE; END IF;

  SELECT entity.entity_id, entity.organization_id, entity.status
    INTO v_entity
    FROM public.entities AS entity
   WHERE entity.entity_id = v_lookup.entity_ref
   FOR UPDATE;

  SELECT token.id, token.tenant_id, token.organization_id, token.revoked_at
    INTO v_token
    FROM public.scim_provisioning_tokens AS token
   WHERE token.id = v_token_id
   FOR UPDATE;

  SELECT directory_user.id, directory_user.tenant_id, directory_user.user_name,
         directory_user.active
    INTO v_directory_user
    FROM public.scim_users AS directory_user
   WHERE directory_user.id = v_lookup.directory_user_id
   FOR UPDATE;

  SELECT credential.* INTO v_credential
    FROM public.approver_credentials AS credential
   WHERE credential.credential_id = v_lookup.identity_credential_id
   FOR UPDATE;

  -- Lease/session rows are always locked last. Every offboarding trigger locks
  -- its control row first and then this lease, so authority loss wins without
  -- an AB/BA deadlock victim.
  SELECT session.* INTO v_session
    FROM public.mobile_sessions AS session
   WHERE session.session_id = p_session_id
   FOR UPDATE;

  v_now := pg_catalog.clock_timestamp();
  IF v_session.session_id IS NULL
     OR v_session.entity_ref IS DISTINCT FROM v_lookup.entity_ref
     OR v_session.organization_id IS DISTINCT FROM v_lookup.organization_id
     OR v_session.directory_user_id IS DISTINCT FROM v_lookup.directory_user_id
     OR v_session.identity_credential_id IS DISTINCT FROM v_lookup.identity_credential_id
     OR v_session.approver_id IS DISTINCT FROM v_lookup.approver_id
     OR v_session.token_hash IS DISTINCT FROM v_lookup.token_hash
     OR (p_expected_entity_ref IS NOT NULL
       AND v_session.entity_ref IS DISTINCT FROM p_expected_entity_ref)
     OR (p_expected_approver_id IS NOT NULL
       AND v_session.approver_id IS DISTINCT FROM p_expected_approver_id)
     OR (p_expected_token_hash IS NOT NULL
       AND v_session.token_hash IS DISTINCT FROM p_expected_token_hash) THEN
    RETURN FALSE;
  END IF;

  IF v_session.revoked_at IS NOT NULL
     OR v_session.expires_at <= v_now
     OR v_session.identity_proof_digest !~ '^sha256:[0-9a-f]{64}$'
     OR v_session.identity_verified_at IS NULL
     OR v_session.identity_verified_at > v_now
     OR (p_require_device_key AND v_session.device_key_id IS NULL)
     OR v_entity.entity_id IS NULL
     OR v_entity.status IS DISTINCT FROM 'active'
     OR v_entity.organization_id IS DISTINCT FROM v_session.organization_id
     OR v_token.id IS NULL
     OR v_token.tenant_id IS DISTINCT FROM v_directory_user.tenant_id
     OR v_token.organization_id IS DISTINCT FROM v_session.organization_id
     OR v_token.revoked_at IS NOT NULL
     OR v_directory_user.id IS NULL
     OR v_directory_user.active IS DISTINCT FROM TRUE
     OR v_directory_user.user_name IS DISTINCT FROM v_session.approver_id
     OR v_credential.id IS NULL
     OR v_credential.organization_id IS DISTINCT FROM v_session.organization_id
     OR v_credential.approver_id IS DISTINCT FROM v_session.approver_id
     OR v_credential.directory_user_id IS DISTINCT FROM v_session.directory_user_id
     OR v_credential.enrollment_basis IS DISTINCT FROM 'directory'
     OR v_credential.key_class IS DISTINCT FROM 'A'
     OR v_credential.revoked_at IS NOT NULL
     OR v_credential.valid_from > v_now
     OR (v_credential.valid_to IS NOT NULL AND v_credential.valid_to <= v_now) THEN
    UPDATE public.mobile_sessions
       SET revoked_at = COALESCE(revoked_at, v_now)
     WHERE session_id = v_session.session_id;
    RETURN FALSE;
  END IF;
  RETURN TRUE;
END;
$function$;

REVOKE ALL ON FUNCTION public.mobile_session_identity_is_active(
  UUID, TEXT, TEXT, TEXT, BOOLEAN
) FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.touch_mobile_session_verified(
  p_session_id UUID,
  p_token_hash TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $function$
DECLARE
  v_now TIMESTAMPTZ;
  v_updated INTEGER;
BEGIN
  IF NOT public.mobile_session_identity_is_active(
    p_session_id, NULL, NULL, p_token_hash, TRUE
  ) THEN
    RETURN FALSE;
  END IF;
  v_now := pg_catalog.clock_timestamp();
  UPDATE public.mobile_sessions
     SET last_used_at = v_now
   WHERE session_id = p_session_id
     AND token_hash = p_token_hash
     AND revoked_at IS NULL;
  GET DIAGNOSTICS v_updated = ROW_COUNT;
  RETURN v_updated = 1;
END;
$function$;

REVOKE ALL ON FUNCTION public.touch_mobile_session_verified(UUID, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.touch_mobile_session_verified(UUID, TEXT)
  TO service_role;

-- Every consequential mobile ceremony must repeat the same durable identity
-- admission in the transaction that changes device/action state. Preserve the
-- mature ceremony state machines as private inners, and pass them only a
-- server wall-clock instant obtained after all identity locks are held.
ALTER FUNCTION public.enroll_mobile_device(TEXT, UUID, JSONB, JSONB)
  RENAME TO enroll_mobile_device_identity_unchecked_v1;
REVOKE ALL ON FUNCTION public.enroll_mobile_device_identity_unchecked_v1(
  TEXT, UUID, JSONB, JSONB
) FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.enroll_mobile_device(
  p_entity_ref TEXT,
  p_session_id UUID,
  p_enrollment JSONB,
  p_event JSONB
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
SET lock_timeout = '2s' SET statement_timeout = '5s'
AS $function$
BEGIN
  IF p_enrollment IS NULL OR pg_catalog.jsonb_typeof(p_enrollment) <> 'object'
     OR NOT public.mobile_session_identity_is_active(
       p_session_id, p_entity_ref, p_enrollment ->> 'approver_id', NULL, FALSE
     ) THEN
    RETURN FALSE;
  END IF;
  RETURN public.enroll_mobile_device_identity_unchecked_v1(
    p_entity_ref, p_session_id, p_enrollment, p_event
  );
END;
$function$;
REVOKE ALL ON FUNCTION public.enroll_mobile_device(TEXT, UUID, JSONB, JSONB)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.enroll_mobile_device(TEXT, UUID, JSONB, JSONB)
  TO service_role;

ALTER FUNCTION public.register_mobile_action_challenge(
  TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ
) RENAME TO register_mobile_action_challenge_identity_unchecked_v1;
REVOKE ALL ON FUNCTION public.register_mobile_action_challenge_identity_unchecked_v1(
  TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.register_mobile_action_challenge(
  p_entity_ref TEXT,
  p_session_id UUID,
  p_action_reference TEXT,
  p_approver_id TEXT,
  p_challenge_id TEXT,
  p_action_hash TEXT,
  p_decision TEXT,
  p_expires_at TIMESTAMPTZ,
  p_now TIMESTAMPTZ DEFAULT now()
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
SET lock_timeout = '2s' SET statement_timeout = '5s'
AS $function$
DECLARE
  v_now TIMESTAMPTZ;
BEGIN
  IF p_now IS NULL OR NOT public.mobile_session_identity_is_active(
    p_session_id, p_entity_ref, p_approver_id, NULL, TRUE
  ) THEN
    RETURN FALSE;
  END IF;
  v_now := pg_catalog.clock_timestamp();
  RETURN public.register_mobile_action_challenge_identity_unchecked_v1(
    p_entity_ref, p_session_id, p_action_reference, p_approver_id,
    p_challenge_id, p_action_hash, p_decision, p_expires_at, v_now
  );
END;
$function$;
REVOKE ALL ON FUNCTION public.register_mobile_action_challenge(
  TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.register_mobile_action_challenge(
  TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ
) TO service_role;

ALTER FUNCTION public.commit_mobile_action_decision(
  TEXT, UUID, TEXT, TEXT, TEXT, TEXT, JSONB, TEXT, JSONB, TEXT, TIMESTAMPTZ
) RENAME TO commit_mobile_action_decision_identity_unchecked_v1;
REVOKE ALL ON FUNCTION public.commit_mobile_action_decision_identity_unchecked_v1(
  TEXT, UUID, TEXT, TEXT, TEXT, TEXT, JSONB, TEXT, JSONB, TEXT, TIMESTAMPTZ
) FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.commit_mobile_action_decision(
  p_entity_ref TEXT,
  p_session_id UUID,
  p_challenge_id TEXT,
  p_action_hash TEXT,
  p_decision TEXT,
  p_verdict TEXT,
  p_decision_evidence JSONB,
  p_expected_hash TEXT,
  p_record JSONB,
  p_canonical_body TEXT,
  p_now TIMESTAMPTZ DEFAULT now()
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
SET lock_timeout = '2s' SET statement_timeout = '5s'
AS $function$
DECLARE
  v_now TIMESTAMPTZ;
BEGIN
  IF p_now IS NULL OR NOT public.mobile_session_identity_is_active(
    p_session_id, p_entity_ref, p_record ->> 'approver_id', NULL, TRUE
  ) THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'session_inactive');
  END IF;
  v_now := pg_catalog.clock_timestamp();
  RETURN public.commit_mobile_action_decision_identity_unchecked_v1(
    p_entity_ref, p_session_id, p_challenge_id, p_action_hash, p_decision,
    p_verdict, p_decision_evidence, p_expected_hash, p_record,
    p_canonical_body, v_now
  );
END;
$function$;
REVOKE ALL ON FUNCTION public.commit_mobile_action_decision(
  TEXT, UUID, TEXT, TEXT, TEXT, TEXT, JSONB, TEXT, JSONB, TEXT, TIMESTAMPTZ
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.commit_mobile_action_decision(
  TEXT, UUID, TEXT, TEXT, TEXT, TEXT, JSONB, TEXT, JSONB, TEXT, TIMESTAMPTZ
) TO service_role;

-- Stale application versions must not retain either unbound path.
CREATE OR REPLACE FUNCTION public.exchange_mobile_pairing(
  p_code_hash TEXT, p_token_hash TEXT, p_platform TEXT, p_app_id TEXT,
  p_now TIMESTAMPTZ DEFAULT now()
) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $function$
BEGIN
  RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'identity_proof_required');
END;
$function$;
REVOKE ALL ON FUNCTION public.exchange_mobile_pairing(TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.create_mobile_pairing(
  p_code_hash TEXT, p_entity_ref TEXT, p_approver_id TEXT, p_profile_id TEXT,
  p_allowed_apps JSONB, p_expires_at TIMESTAMPTZ,
  p_session_expires_at TIMESTAMPTZ, p_now TIMESTAMPTZ DEFAULT now()
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $function$
BEGIN
  RETURN FALSE;
END;
$function$;
REVOKE ALL ON FUNCTION public.create_mobile_pairing(
  TEXT, TEXT, TEXT, TEXT, JSONB, TIMESTAMPTZ, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.touch_mobile_session(
  p_session_id UUID, p_token_hash TEXT, p_now TIMESTAMPTZ DEFAULT now()
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $function$
BEGIN
  RETURN FALSE;
END;
$function$;
REVOKE ALL ON FUNCTION public.touch_mobile_session(UUID, TEXT, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.revoke_mobile_sessions_on_identity_credential_change()
RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $function$
BEGIN
  IF NEW.revoked_at IS NOT NULL
     OR NEW.key_class IS DISTINCT FROM 'A'
     OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.approver_id IS DISTINCT FROM OLD.approver_id
     OR NEW.directory_user_id IS DISTINCT FROM OLD.directory_user_id
     OR NEW.enrollment_basis IS DISTINCT FROM 'directory'
     OR (NEW.valid_to IS NOT NULL AND NEW.valid_to <= pg_catalog.clock_timestamp()) THEN
    UPDATE public.mobile_sessions
       SET revoked_at = COALESCE(revoked_at, pg_catalog.clock_timestamp())
     WHERE identity_credential_id = OLD.credential_id
       AND revoked_at IS NULL;
    UPDATE public.mobile_pairings
       SET consumed_at = COALESCE(consumed_at, pg_catalog.clock_timestamp())
     WHERE organization_id = OLD.organization_id
       AND directory_user_id = OLD.directory_user_id
       AND consumed_at IS NULL
       AND NOT EXISTS (
         SELECT 1 FROM public.approver_credentials AS remaining
          WHERE remaining.organization_id = OLD.organization_id
            AND remaining.approver_id = OLD.approver_id
            AND remaining.directory_user_id = OLD.directory_user_id
            AND remaining.enrollment_basis = 'directory'
            AND remaining.key_class = 'A'
            AND remaining.revoked_at IS NULL
            AND remaining.valid_from <= pg_catalog.clock_timestamp()
            AND (remaining.valid_to IS NULL OR remaining.valid_to > pg_catalog.clock_timestamp())
       );
  END IF;
  RETURN NEW;
END;
$function$;
DROP TRIGGER IF EXISTS mobile_session_identity_credential_revocation
  ON public.approver_credentials;
CREATE TRIGGER mobile_session_identity_credential_revocation
AFTER UPDATE OF revoked_at, key_class, organization_id, approver_id,
  directory_user_id, enrollment_basis, valid_to
ON public.approver_credentials
FOR EACH ROW EXECUTE FUNCTION public.revoke_mobile_sessions_on_identity_credential_change();
REVOKE ALL ON FUNCTION public.revoke_mobile_sessions_on_identity_credential_change()
  FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.revoke_mobile_sessions_on_directory_user_change()
RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    UPDATE public.mobile_sessions
       SET revoked_at = COALESCE(revoked_at, pg_catalog.clock_timestamp())
     WHERE directory_user_id = OLD.id
       AND revoked_at IS NULL;
    UPDATE public.mobile_pairings
       SET consumed_at = COALESCE(consumed_at, pg_catalog.clock_timestamp())
     WHERE directory_user_id = OLD.id AND consumed_at IS NULL;
    RETURN OLD;
  END IF;
  -- The mature atomic SCIM routine owns active -> inactive deprovisioning,
  -- including its exact revoked-count result and one audit event. Its later
  -- credential UPDATE invokes the credential trigger, which revokes leases in
  -- control-row -> session order. Do not take a session lock first here.
  IF NEW.active IS TRUE AND (
    NEW.user_name IS DISTINCT FROM OLD.user_name
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
  ) THEN
    -- Active username/tenant rebind is not covered by the mature deactivation
    -- branch. Revoke the exact directory credential first; its trigger then
    -- invalidates sessions/pairings without an inverse lock order.
    UPDATE public.approver_credentials AS credential
       SET revoked_at = COALESCE(credential.revoked_at, pg_catalog.clock_timestamp())
     WHERE credential.approver_id = OLD.user_name
       AND credential.directory_user_id = OLD.id
       AND credential.revoked_at IS NULL;
    INSERT INTO public.audit_events (
      event_type, actor_id, actor_type, target_type, target_id, action,
      before_state, after_state
    ) VALUES (
      'scim.approver.deprovisioned', OLD.tenant_id, 'system', 'approver',
      OLD.user_name, 'deprovision', pg_catalog.to_jsonb(OLD),
      pg_catalog.jsonb_build_object(
        'reason', CASE
          WHEN NEW.user_name IS DISTINCT FROM OLD.user_name
            THEN 'scim_username_changed'
          ELSE 'scim_tenant_changed'
        END,
        'directory_user_id', OLD.id,
        'replacement_user_name', NEW.user_name
      )
    );
    UPDATE public.mobile_sessions
       SET revoked_at = COALESCE(revoked_at, pg_catalog.clock_timestamp())
     WHERE directory_user_id = OLD.id
       AND revoked_at IS NULL;
    UPDATE public.mobile_pairings
       SET consumed_at = COALESCE(consumed_at, pg_catalog.clock_timestamp())
     WHERE directory_user_id = OLD.id AND consumed_at IS NULL;
  END IF;
  RETURN NEW;
END;
$function$;
DROP TRIGGER IF EXISTS mobile_session_directory_user_revocation
  ON public.scim_users;
CREATE TRIGGER mobile_session_directory_user_revocation
AFTER UPDATE OF active, tenant_id, user_name OR DELETE
ON public.scim_users
FOR EACH ROW EXECUTE FUNCTION public.revoke_mobile_sessions_on_directory_user_change();
REVOKE ALL ON FUNCTION public.revoke_mobile_sessions_on_directory_user_change()
  FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.revoke_mobile_sessions_on_entity_change()
RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $function$
BEGIN
  IF NEW.status IS DISTINCT FROM 'active'
     OR NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
    UPDATE public.mobile_sessions
       SET revoked_at = COALESCE(revoked_at, pg_catalog.clock_timestamp())
     WHERE entity_ref = OLD.entity_id
       AND revoked_at IS NULL;
    UPDATE public.mobile_pairings
       SET consumed_at = COALESCE(consumed_at, pg_catalog.clock_timestamp())
     WHERE entity_ref = OLD.entity_id AND consumed_at IS NULL;
  END IF;
  RETURN NEW;
END;
$function$;
DROP TRIGGER IF EXISTS mobile_session_entity_revocation ON public.entities;
CREATE TRIGGER mobile_session_entity_revocation
AFTER UPDATE OF status, organization_id ON public.entities
FOR EACH ROW EXECUTE FUNCTION public.revoke_mobile_sessions_on_entity_change();
REVOKE ALL ON FUNCTION public.revoke_mobile_sessions_on_entity_change()
  FROM PUBLIC, anon, authenticated, service_role;

-- END STRIX-44-MOBILE-IDENTITY

-- ===========================================================================
-- STRIX-48: exact issuer key, locked handshake state, and durable proof linkage
-- ===========================================================================

ALTER TABLE public.handshake_presentations
  ADD COLUMN IF NOT EXISTS authority_key_digest TEXT,
  ADD COLUMN IF NOT EXISTS issuer_proof_digest TEXT,
  ADD COLUMN IF NOT EXISTS issuer_proof JSONB,
  ADD COLUMN IF NOT EXISTS issuer_proof_statement JSONB;

ALTER TABLE public.handshake_results
  ADD COLUMN IF NOT EXISTS prior_outcome TEXT,
  ADD COLUMN IF NOT EXISTS invalidated_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS invalidation_reason TEXT;

-- Any pre-closure row that still lacks the exact key/proof projection is not a
-- cryptographically reproducible verified presentation.
UPDATE public.handshake_presentations
   SET verified = FALSE,
       verified_at = NULL,
       issuer_status = 'legacy_issuer_unproven',
       revocation_status = 'unproven'
 WHERE verified = TRUE
   AND (
     authority_key_digest IS NULL
     OR issuer_proof_digest IS NULL
     OR issuer_proof IS NULL
     OR issuer_proof_statement IS NULL
   );

-- Preserve the prior accepted outcome explicitly, append an immutable lifecycle
-- event, and move the live projection to rejected. No historical row is erased.
INSERT INTO public.handshake_events (
  handshake_id, event_type, event_payload, actor_entity_ref, detail, created_at
)
SELECT handshake.handshake_id, 'status_changed',
       pg_catalog.jsonb_build_object(
         'from', handshake.status,
         'to', 'rejected',
         'reason', 'legacy_issuer_unproven'
       ),
       'system',
       pg_catalog.jsonb_build_object(
         'from', handshake.status,
         'to', 'rejected',
         'trigger', 'identity_runtime_residual_closure',
         'reason', 'legacy_issuer_unproven'
       ),
       pg_catalog.clock_timestamp()
  FROM public.handshakes AS handshake
 WHERE handshake.status = 'verified'
   AND EXISTS (
     SELECT 1 FROM public.handshake_presentations AS presentation
      WHERE presentation.handshake_id = handshake.handshake_id
        AND presentation.issuer_status = 'legacy_issuer_unproven'
   );

UPDATE public.handshake_results AS result
   SET prior_outcome = COALESCE(result.prior_outcome, result.outcome),
       outcome = 'rejected',
       invalidated_at = COALESCE(result.invalidated_at, pg_catalog.clock_timestamp()),
       invalidation_reason = COALESCE(result.invalidation_reason, 'legacy_issuer_unproven'),
       reason_codes = CASE
         WHEN 'legacy_issuer_unproven' = ANY(COALESCE(result.reason_codes, ARRAY[]::TEXT[]))
           THEN COALESCE(result.reason_codes, ARRAY[]::TEXT[])
         ELSE COALESCE(result.reason_codes, ARRAY[]::TEXT[]) || ARRAY['legacy_issuer_unproven']::TEXT[]
       END
 WHERE result.outcome = 'accepted'
   AND EXISTS (
     SELECT 1 FROM public.handshake_presentations AS presentation
      WHERE presentation.handshake_id = result.handshake_id
        AND presentation.issuer_status = 'legacy_issuer_unproven'
   );

UPDATE public.handshakes AS handshake
   SET metadata_json = COALESCE(handshake.metadata_json, '{}'::JSONB)
       || pg_catalog.jsonb_build_object(
         'identity_runtime_invalidation', pg_catalog.jsonb_build_object(
           'prior_status', handshake.status,
           'reason', 'legacy_issuer_unproven',
           'invalidated_at', pg_catalog.clock_timestamp()
         )
       ),
       status = 'rejected',
       verified_at = NULL
 WHERE handshake.status = 'verified'
   AND EXISTS (
     SELECT 1 FROM public.handshake_presentations AS presentation
      WHERE presentation.handshake_id = handshake.handshake_id
        AND presentation.issuer_status = 'legacy_issuer_unproven'
   );

ALTER TABLE public.handshake_presentations
  DROP CONSTRAINT IF EXISTS handshake_presentations_verified_issuer_proof;
ALTER TABLE public.handshake_presentations
  ADD CONSTRAINT handshake_presentations_verified_issuer_proof CHECK (
    NOT verified OR (
      issuer_ref IS NOT NULL
      AND authority_id IS NOT NULL
      AND issuer_status = 'authority_signature_valid'
      AND canonical_claims_hash IS NOT NULL
      AND verified_at IS NOT NULL
      AND revocation_checked = TRUE
      AND revocation_status = 'good'
      AND authority_key_digest ~ '^sha256:[0-9a-f]{64}$'
      AND issuer_proof_digest ~ '^sha256:[0-9a-f]{64}$'
      AND pg_catalog.jsonb_typeof(issuer_proof) = 'object'
      AND pg_catalog.jsonb_typeof(issuer_proof_statement) = 'object'
    )
  );

-- Remove the caller-status overload. A stale application cannot bypass the
-- locked handshake and party projection implemented below.
DROP FUNCTION IF EXISTS public.present_handshake_writes(
  UUID, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, JSONB, TEXT, TEXT, TEXT, TEXT,
  BOOLEAN, BOOLEAN, TEXT, TEXT, TEXT, BOOLEAN, JSONB
);

CREATE OR REPLACE FUNCTION public.present_handshake_writes(
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
  p_authority_key_digest TEXT,
  p_issuer_status TEXT,
  p_verified BOOLEAN,
  p_revocation_checked BOOLEAN,
  p_revocation_status TEXT,
  p_actor_id TEXT,
  p_issuer_trusted BOOLEAN,
  p_event_detail JSONB
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $function$
DECLARE
  v_handshake RECORD;
  v_party RECORD;
  v_now TIMESTAMPTZ;
  v_presentation_id UUID;
  v_verified_at TIMESTAMPTZ;
  v_verified BOOLEAN := COALESCE(p_verified, FALSE);
  v_issuer_status TEXT := p_issuer_status;
  v_revocation_status TEXT := p_revocation_status;
  v_authority RECORD;
  v_actual_key_digest TEXT;
  v_event_detail JSONB := COALESCE(p_event_detail, '{}'::JSONB);
  v_payload_hash TEXT;
BEGIN
  SELECT handshake.handshake_id, handshake.status, handshake.expires_at
    INTO v_handshake
    FROM public.handshakes AS handshake
   WHERE handshake.handshake_id = p_handshake_id
   FOR UPDATE;
  IF NOT FOUND OR v_handshake.status NOT IN ('initiated', 'pending_verification') THEN
    RETURN pg_catalog.jsonb_build_object('error', 'invalid_state');
  END IF;

  SELECT party.id, party.entity_ref
    INTO v_party
    FROM public.handshake_parties AS party
   WHERE party.handshake_id = p_handshake_id
     AND party.party_role = p_party_role
   FOR UPDATE;
  IF NOT FOUND
     OR (p_actor_entity_ref IS DISTINCT FROM 'system'
         AND v_party.entity_ref IS DISTINCT FROM p_actor_entity_ref) THEN
    RETURN pg_catalog.jsonb_build_object('error', 'party_binding_invalid');
  END IF;

  IF v_verified THEN
    IF p_issuer_status IS DISTINCT FROM 'authority_signature_valid'
       OR p_issuer_trusted IS DISTINCT FROM TRUE
       OR NULLIF(p_issuer_ref, '') IS NULL
       OR NULLIF(p_authority_id, '') IS NULL
       OR p_authority_key_digest !~ '^sha256:[0-9a-f]{64}$'
       OR NULLIF(p_canonical_claims_hash, '') IS NULL
       OR p_revocation_checked IS DISTINCT FROM TRUE
       OR p_revocation_status IS DISTINCT FROM 'good'
       OR pg_catalog.jsonb_typeof(v_event_detail -> 'issuer_proof') IS DISTINCT FROM 'object'
       OR pg_catalog.jsonb_typeof(v_event_detail -> 'issuer_proof_statement') IS DISTINCT FROM 'object'
       OR (v_event_detail ->> 'issuer_proof_digest') !~ '^sha256:[0-9a-f]{64}$' THEN
      v_verified := FALSE;
      v_issuer_status := 'issuer_proof_incomplete_at_write';
      v_revocation_status := 'unproven';
    ELSE
      SELECT authority.authority_id, authority.key_id, authority.public_key,
             authority.algorithm, authority.status, authority.valid_from,
             authority.valid_to, authority.revoked_at
        INTO v_authority
        FROM public.authorities AS authority
       WHERE authority.authority_id::TEXT = p_authority_id
         AND authority.key_id = p_issuer_ref
       FOR UPDATE;
    END IF;
  END IF;

  -- Sample time only after every state and key row used by the decision is
  -- locked. Waiting behind expiry cannot preserve a stale successful result.
  v_now := pg_catalog.clock_timestamp();
  IF v_handshake.expires_at IS NOT NULL AND v_handshake.expires_at <= v_now THEN
    RETURN pg_catalog.jsonb_build_object('error', 'invalid_state');
  END IF;

  IF v_verified THEN
    IF v_authority.authority_id IS NULL THEN
      v_verified := FALSE;
      v_issuer_status := 'authority_identity_mismatch_at_write';
      v_revocation_status := 'unknown';
    ELSE
      v_actual_key_digest := 'sha256:' || pg_catalog.encode(
        extensions.digest(pg_catalog.convert_to(v_authority.public_key, 'UTF8'), 'sha256'),
        'hex'
      );
      IF v_actual_key_digest IS DISTINCT FROM p_authority_key_digest THEN
        v_verified := FALSE;
        v_issuer_status := 'authority_key_changed_at_write';
        v_revocation_status := 'invalid_proof';
      ELSIF v_authority.status IS DISTINCT FROM 'active'
         OR v_authority.algorithm IS DISTINCT FROM 'Ed25519'
         OR v_authority.revoked_at IS NOT NULL
         OR v_authority.valid_from > v_now
         OR (v_authority.valid_to IS NOT NULL AND v_authority.valid_to <= v_now) THEN
        v_verified := FALSE;
        v_issuer_status := 'authority_not_active_at_write';
        v_revocation_status := 'revoked_or_invalid';
      END IF;
    END IF;
  END IF;

  v_verified_at := CASE WHEN v_verified THEN v_now ELSE NULL END;
  INSERT INTO public.handshake_presentations (
    handshake_id, party_role, presentation_type, issuer_ref,
    presentation_hash, disclosure_mode, raw_claims, normalized_claims,
    canonical_claims_hash, actor_entity_ref, authority_id,
    authority_key_digest, issuer_proof_digest, issuer_proof,
    issuer_proof_statement, issuer_status, verified, verified_at,
    revocation_checked, revocation_status
  ) VALUES (
    p_handshake_id, p_party_role, p_presentation_type, p_issuer_ref,
    p_presentation_hash, p_disclosure_mode, p_raw_claims, p_normalized_claims,
    p_canonical_claims_hash, p_actor_entity_ref, p_authority_id,
    CASE WHEN v_verified THEN p_authority_key_digest ELSE NULL END,
    CASE WHEN v_verified THEN v_event_detail ->> 'issuer_proof_digest' ELSE NULL END,
    CASE WHEN v_verified THEN v_event_detail -> 'issuer_proof' ELSE NULL END,
    CASE WHEN v_verified THEN v_event_detail -> 'issuer_proof_statement' ELSE NULL END,
    v_issuer_status, v_verified, v_verified_at,
    COALESCE(p_revocation_checked, FALSE), v_revocation_status
  ) RETURNING id INTO v_presentation_id;

  v_event_detail := v_event_detail || pg_catalog.jsonb_build_object(
    'presentation_id', v_presentation_id,
    'issuer_trusted', v_verified,
    'issuer_status', v_issuer_status,
    'authority_key_digest', CASE WHEN v_verified THEN p_authority_key_digest ELSE NULL END
  );
  v_payload_hash := 'sha256:' || pg_catalog.encode(
    extensions.digest(pg_catalog.convert_to(v_event_detail::TEXT, 'UTF8'), 'sha256'),
    'hex'
  );

  INSERT INTO public.handshake_events (
    handshake_id, event_type, event_payload, actor_entity_ref, detail, created_at
  ) VALUES (
    p_handshake_id, 'presentation_added',
    pg_catalog.jsonb_build_object('presentation_id', v_presentation_id),
    p_actor_id, v_event_detail, v_now
  );

  IF v_handshake.status = 'initiated' THEN
    INSERT INTO public.handshake_events (
      handshake_id, event_type, event_payload, actor_entity_ref, detail, created_at
    ) VALUES (
      p_handshake_id, 'status_changed',
      pg_catalog.jsonb_build_object('from', 'initiated', 'to', 'pending_verification'),
      p_actor_id,
      pg_catalog.jsonb_build_object(
        'from', 'initiated', 'to', 'pending_verification',
        'trigger', 'presentation_added', 'presentation_id', v_presentation_id
      ),
      v_now
    );
    UPDATE public.handshakes
       SET status = 'pending_verification'
     WHERE handshake_id = p_handshake_id;
  END IF;

  INSERT INTO public.protocol_events (
    aggregate_type, aggregate_id, command_type, payload_json, payload_hash,
    actor_authority_id, created_at
  ) VALUES (
    'handshake', p_handshake_id::TEXT, 'add_presentation', v_event_detail,
    v_payload_hash, p_actor_id, v_now
  );

  RETURN pg_catalog.jsonb_build_object(
    'id', v_presentation_id,
    'handshake_id', p_handshake_id,
    'party_role', p_party_role,
    'presentation_type', p_presentation_type,
    'issuer_ref', p_issuer_ref,
    'presentation_hash', p_presentation_hash,
    'disclosure_mode', p_disclosure_mode,
    'verified', v_verified,
    'verified_at', v_verified_at,
    'revocation_checked', COALESCE(p_revocation_checked, FALSE),
    'revocation_status', v_revocation_status,
    'issuer_status', v_issuer_status,
    'authority_id', p_authority_id,
    'authority_key_digest', CASE WHEN v_verified THEN p_authority_key_digest ELSE NULL END,
    'actor_entity_ref', p_actor_entity_ref,
    'canonical_claims_hash', p_canonical_claims_hash,
    'protocol_payload_hash', v_payload_hash
  );
END;
$function$;

REVOKE ALL ON FUNCTION public.present_handshake_writes(
  UUID, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, JSONB, TEXT, TEXT, TEXT, TEXT,
  TEXT, BOOLEAN, BOOLEAN, TEXT, TEXT, BOOLEAN, JSONB
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.present_handshake_writes(
  UUID, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB, JSONB, TEXT, TEXT, TEXT, TEXT,
  TEXT, BOOLEAN, BOOLEAN, TEXT, TEXT, BOOLEAN, JSONB
) TO service_role;

-- END STRIX-48-HANDSHAKE-ISSUER-PROOF

-- ===========================================================================
-- STRIX-42: the exact live SCIM bearer participates in every mutation commit
-- ===========================================================================

ALTER TABLE public.scim_groups
  ADD COLUMN IF NOT EXISTS raw JSONB NOT NULL DEFAULT '{}'::JSONB;

CREATE OR REPLACE FUNCTION public.scim_mutation_token_is_active(
  p_token_id UUID,
  p_tenant_id TEXT,
  p_organization_id TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $function$
DECLARE
  v_entity RECORD;
  v_token RECORD;
BEGIN
  IF p_token_id IS NULL OR NULLIF(p_tenant_id, '') IS NULL
     OR NULLIF(p_organization_id, '') IS NULL
     OR p_organization_id = p_tenant_id THEN
    RETURN FALSE;
  END IF;

  -- Global identity lock order is entity -> provisioning token -> directory row.
  SELECT entity.entity_id, entity.organization_id, entity.status
    INTO v_entity
    FROM public.entities AS entity
   WHERE entity.entity_id = p_tenant_id
   FOR UPDATE;
  IF NOT FOUND
     OR v_entity.status IS DISTINCT FROM 'active'
     OR v_entity.organization_id IS DISTINCT FROM p_organization_id THEN
    RETURN FALSE;
  END IF;

  SELECT token.id, token.tenant_id, token.organization_id, token.revoked_at
    INTO v_token
    FROM public.scim_provisioning_tokens AS token
   WHERE token.id = p_token_id
   FOR UPDATE;
  RETURN FOUND
    AND v_token.revoked_at IS NULL
    AND v_token.tenant_id IS NOT DISTINCT FROM p_tenant_id
    AND v_token.organization_id IS NOT DISTINCT FROM p_organization_id;
END;
$function$;
REVOKE ALL ON FUNCTION public.scim_mutation_token_is_active(UUID, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.create_scim_user_authorized(
  p_token_id UUID,
  p_tenant_id TEXT,
  p_organization_id TEXT,
  p_fields JSONB
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $function$
DECLARE
  v_user public.scim_users%ROWTYPE;
  v_allowed_fields CONSTANT TEXT[] := ARRAY[
    'user_name', 'external_id', 'active', 'formatted_name', 'given_name',
    'family_name', 'display_name', 'title', 'emails', 'phone_numbers', 'raw'
  ];
BEGIN
  IF NOT public.scim_mutation_token_is_active(
    p_token_id, p_tenant_id, p_organization_id
  ) THEN
    RETURN pg_catalog.jsonb_build_object('error', 'token_authority_invalid');
  END IF;
  IF p_fields IS NULL OR pg_catalog.jsonb_typeof(p_fields) <> 'object'
     OR NOT (p_fields ?& v_allowed_fields)
     OR EXISTS (
       SELECT 1 FROM pg_catalog.jsonb_object_keys(p_fields) AS field(name)
        WHERE NOT (field.name = ANY(v_allowed_fields))
     )
     OR NULLIF(p_fields ->> 'user_name', '') IS NULL
     OR pg_catalog.jsonb_typeof(p_fields -> 'active') <> 'boolean'
     OR pg_catalog.jsonb_typeof(p_fields -> 'emails') <> 'array'
     OR pg_catalog.jsonb_typeof(p_fields -> 'phone_numbers') <> 'array'
     OR pg_catalog.jsonb_typeof(p_fields -> 'raw') <> 'object' THEN
    RAISE EXCEPTION 'SCIM user field set is invalid' USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.scim_users (
    tenant_id, user_name, external_id, active, formatted_name, given_name,
    family_name, display_name, title, emails, phone_numbers, raw
  ) VALUES (
    p_tenant_id, p_fields ->> 'user_name', NULLIF(p_fields ->> 'external_id', ''),
    (p_fields ->> 'active')::BOOLEAN, NULLIF(p_fields ->> 'formatted_name', ''),
    NULLIF(p_fields ->> 'given_name', ''), NULLIF(p_fields ->> 'family_name', ''),
    NULLIF(p_fields ->> 'display_name', ''), NULLIF(p_fields ->> 'title', ''),
    p_fields -> 'emails', p_fields -> 'phone_numbers', p_fields -> 'raw'
  ) RETURNING * INTO v_user;
  RETURN pg_catalog.jsonb_build_object('status', 'created', 'user', pg_catalog.to_jsonb(v_user));
END;
$function$;
REVOKE ALL ON FUNCTION public.create_scim_user_authorized(UUID, TEXT, TEXT, JSONB)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.create_scim_user_authorized(UUID, TEXT, TEXT, JSONB)
  TO service_role;

-- Keep the mature user/deprovision logic in the seven-argument routine, but
-- make the exact-token wrapper its only service-role entry point.
REVOKE ALL ON FUNCTION public.apply_scim_user_and_authority_atomic(
  TEXT, TEXT, UUID, INTEGER, JSONB, BOOLEAN, TEXT
) FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.apply_scim_user_and_authority_atomic(
  p_token_id UUID,
  p_tenant_id TEXT,
  p_organization_id TEXT,
  p_user_id UUID,
  p_expected_version INTEGER,
  p_fields JSONB,
  p_delete BOOLEAN DEFAULT FALSE,
  p_reason TEXT DEFAULT 'scim_update'
) RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $function$
BEGIN
  IF NOT public.scim_mutation_token_is_active(
    p_token_id, p_tenant_id, p_organization_id
  ) THEN
    RETURN pg_catalog.jsonb_build_object('error', 'token_authority_invalid');
  END IF;
  RETURN public.apply_scim_user_and_authority_atomic(
    p_tenant_id, p_organization_id, p_user_id, p_expected_version,
    p_fields, p_delete, p_reason
  );
END;
$function$;
REVOKE ALL ON FUNCTION public.apply_scim_user_and_authority_atomic(
  UUID, TEXT, TEXT, UUID, INTEGER, JSONB, BOOLEAN, TEXT
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.apply_scim_user_and_authority_atomic(
  UUID, TEXT, TEXT, UUID, INTEGER, JSONB, BOOLEAN, TEXT
) TO service_role;

CREATE OR REPLACE FUNCTION public.apply_scim_group_authorized(
  p_token_id UUID,
  p_tenant_id TEXT,
  p_organization_id TEXT,
  p_group_id UUID,
  p_expected_version INTEGER,
  p_fields JSONB,
  p_delete BOOLEAN DEFAULT FALSE
) RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
SET lock_timeout = '2s'
SET statement_timeout = '5s'
AS $function$
DECLARE
  v_group public.scim_groups%ROWTYPE;
  v_allowed_fields CONSTANT TEXT[] := ARRAY['display_name', 'external_id', 'members', 'raw'];
BEGIN
  IF NOT public.scim_mutation_token_is_active(
    p_token_id, p_tenant_id, p_organization_id
  ) THEN
    RETURN pg_catalog.jsonb_build_object('error', 'token_authority_invalid');
  END IF;
  IF p_delete IS NULL THEN
    RAISE EXCEPTION 'SCIM group write input is invalid' USING ERRCODE = '22023';
  END IF;

  IF p_group_id IS NULL THEN
    IF p_delete OR p_expected_version IS NOT NULL THEN
      RAISE EXCEPTION 'SCIM group create input is invalid' USING ERRCODE = '22023';
    END IF;
    IF p_fields IS NULL OR pg_catalog.jsonb_typeof(p_fields) <> 'object'
       OR NOT (p_fields ?& v_allowed_fields)
       OR EXISTS (
         SELECT 1 FROM pg_catalog.jsonb_object_keys(p_fields) AS field(name)
          WHERE NOT (field.name = ANY(v_allowed_fields))
       )
       OR NULLIF(p_fields ->> 'display_name', '') IS NULL
       OR pg_catalog.jsonb_typeof(p_fields -> 'members') <> 'array' THEN
      RAISE EXCEPTION 'SCIM group field set is invalid' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.scim_groups (tenant_id, display_name, external_id, members, raw)
    VALUES (
      p_tenant_id, p_fields ->> 'display_name',
      NULLIF(p_fields ->> 'external_id', ''), p_fields -> 'members',
      COALESCE(p_fields -> 'raw', '{}'::JSONB)
    ) RETURNING * INTO v_group;
    RETURN pg_catalog.jsonb_build_object('status', 'created', 'group', pg_catalog.to_jsonb(v_group));
  END IF;

  SELECT group_row.* INTO v_group
    FROM public.scim_groups AS group_row
   WHERE group_row.id = p_group_id
     AND group_row.tenant_id = p_tenant_id
   FOR UPDATE;
  IF NOT FOUND THEN RETURN pg_catalog.jsonb_build_object('error', 'group_not_found'); END IF;
  IF v_group.version IS DISTINCT FROM p_expected_version THEN
    RETURN pg_catalog.jsonb_build_object('error', 'version_conflict');
  END IF;
  IF p_delete THEN
    DELETE FROM public.scim_groups WHERE id = p_group_id AND tenant_id = p_tenant_id;
    RETURN pg_catalog.jsonb_build_object('status', 'deleted');
  END IF;
  IF p_fields IS NULL OR pg_catalog.jsonb_typeof(p_fields) <> 'object'
     OR NOT (p_fields ?& v_allowed_fields)
     OR EXISTS (
       SELECT 1 FROM pg_catalog.jsonb_object_keys(p_fields) AS field(name)
        WHERE NOT (field.name = ANY(v_allowed_fields))
     )
     OR NULLIF(p_fields ->> 'display_name', '') IS NULL
     OR pg_catalog.jsonb_typeof(p_fields -> 'members') <> 'array' THEN
    RAISE EXCEPTION 'SCIM group field set is invalid' USING ERRCODE = '22023';
  END IF;
  UPDATE public.scim_groups AS group_row
     SET display_name = p_fields ->> 'display_name',
         external_id = NULLIF(p_fields ->> 'external_id', ''),
         members = p_fields -> 'members',
         raw = COALESCE(p_fields -> 'raw', '{}'::JSONB),
         version = v_group.version + 1,
         updated_at = pg_catalog.clock_timestamp()
   WHERE group_row.id = p_group_id AND group_row.tenant_id = p_tenant_id
   RETURNING * INTO v_group;
  RETURN pg_catalog.jsonb_build_object('status', 'updated', 'group', pg_catalog.to_jsonb(v_group));
END;
$function$;
REVOKE ALL ON FUNCTION public.apply_scim_group_authorized(
  UUID, TEXT, TEXT, UUID, INTEGER, JSONB, BOOLEAN
) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.apply_scim_group_authorized(
  UUID, TEXT, TEXT, UUID, INTEGER, JSONB, BOOLEAN
) TO service_role;

CREATE OR REPLACE FUNCTION public.revoke_mobile_sessions_on_scim_token_change()
RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $function$
BEGIN
  IF NEW.revoked_at IS NOT NULL
     OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.scim_provisioning_tokens AS token
       WHERE token.tenant_id = OLD.tenant_id
         AND token.organization_id = OLD.organization_id
         AND token.revoked_at IS NULL
    ) THEN
      UPDATE public.mobile_sessions AS session
         SET revoked_at = COALESCE(session.revoked_at, pg_catalog.clock_timestamp())
       WHERE session.organization_id = OLD.organization_id
         AND session.directory_user_id IN (
           SELECT directory_user.id FROM public.scim_users AS directory_user
            WHERE directory_user.tenant_id = OLD.tenant_id
         )
         AND session.revoked_at IS NULL;
      UPDATE public.mobile_pairings AS pairing
         SET consumed_at = COALESCE(pairing.consumed_at, pg_catalog.clock_timestamp())
       WHERE pairing.organization_id = OLD.organization_id
         AND pairing.directory_user_id IN (
           SELECT directory_user.id FROM public.scim_users AS directory_user
            WHERE directory_user.tenant_id = OLD.tenant_id
         )
         AND pairing.consumed_at IS NULL;
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;
DROP TRIGGER IF EXISTS mobile_session_scim_token_revocation
  ON public.scim_provisioning_tokens;
CREATE TRIGGER mobile_session_scim_token_revocation
AFTER UPDATE OF revoked_at, organization_id, tenant_id
ON public.scim_provisioning_tokens
FOR EACH ROW EXECUTE FUNCTION public.revoke_mobile_sessions_on_scim_token_change();
REVOKE ALL ON FUNCTION public.revoke_mobile_sessions_on_scim_token_change()
  FROM PUBLIC, anon, authenticated, service_role;

-- The route surface now mutates these tables only through the exact-token
-- SECURITY DEFINER routines above. Remove the service-role direct-DML escape.
REVOKE INSERT, UPDATE, DELETE ON TABLE public.scim_users
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE INSERT, UPDATE, DELETE ON TABLE public.scim_groups
  FROM PUBLIC, anon, authenticated, service_role;

-- END STRIX-42-SCIM-EXACT-BEARER
