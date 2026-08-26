-- SPDX-License-Identifier: Apache-2.0
-- STRIX identity closure:
--   1. A mobile pairing can be exchanged only after the exact, active,
--      directory-backed approver proves control of an existing Class-A key.
--   2. A handshake presentation is verified only when the registered issuer
--      signed the exact handshake/party/claims projection, with an in-
--      transaction authority recheck keyed by BOTH authority UUID and key id.

-- BEGIN STRIX-40-SCIM-ORG-PROVENANCE
-- A SCIM tenant id is the minting entity's public label. It is not organization
-- provenance: treating tenant_id = organization_id as an implicit binding lets
-- a public entity slug collide with an unrelated organization's directory
-- boundary. Backfill only when the current active entity row proves the exact
-- relationship, and quarantine every remaining ambiguous or stale bearer.
UPDATE public.scim_provisioning_tokens AS token
   SET organization_id = entity.organization_id
  FROM public.entities AS entity
 WHERE NULLIF(token.organization_id, '') IS NULL
   AND entity.entity_id = token.tenant_id
   AND entity.status = 'active'
   AND NULLIF(entity.organization_id, '') IS NOT NULL
   AND entity.organization_id IS DISTINCT FROM entity.entity_id;

-- The old self-service shape wrote organization_id = entity_id. That equality
-- is precisely the ambiguous public-slug namespace and cannot be repaired from
-- the row itself. Revoke and detach it so sticky directory governance cannot
-- keep importing the squatted tenant after bearer revocation.
UPDATE public.scim_provisioning_tokens AS token
   SET revoked_at = COALESCE(token.revoked_at, pg_catalog.clock_timestamp()),
       organization_id = NULL
 WHERE token.organization_id = token.tenant_id;

UPDATE public.scim_provisioning_tokens AS token
   SET revoked_at = COALESCE(token.revoked_at, pg_catalog.clock_timestamp())
 WHERE NULLIF(token.organization_id, '') IS NULL
    OR NOT EXISTS (
      SELECT 1
        FROM public.entities AS entity
       WHERE entity.entity_id = token.tenant_id
         AND entity.status = 'active'
         AND entity.organization_id = token.organization_id
    );

ALTER TABLE public.scim_provisioning_tokens
  DROP CONSTRAINT IF EXISTS scim_tokens_live_org_provenance;
ALTER TABLE public.scim_provisioning_tokens
  ADD CONSTRAINT scim_tokens_live_org_provenance CHECK (
    organization_id IS DISTINCT FROM tenant_id
    AND (revoked_at IS NOT NULL OR NULLIF(organization_id, '') IS NOT NULL)
  );

CREATE OR REPLACE FUNCTION public.enforce_scim_token_organization_provenance()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $function$
DECLARE
  v_entity_organization_id TEXT;
  v_entity_status TEXT;
BEGIN
  -- Historical revoked rows remain evidence even when their old tenant binding
  -- can no longer be proved. A live bearer, however, must match the current
  -- active entity binding exactly.
  IF NEW.revoked_at IS NOT NULL THEN
    RETURN NEW;
  END IF;
  IF NULLIF(NEW.organization_id, '') IS NULL THEN
    RAISE EXCEPTION 'active SCIM token requires explicit organization provenance'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.organization_id = NEW.tenant_id THEN
    RAISE EXCEPTION 'SCIM tenant id cannot serve as organization provenance'
      USING ERRCODE = '23514';
  END IF;

  SELECT entity.organization_id, entity.status
    INTO v_entity_organization_id, v_entity_status
    FROM public.entities AS entity
   WHERE entity.entity_id = NEW.tenant_id
   FOR KEY SHARE;
  IF NOT FOUND
     OR v_entity_status IS DISTINCT FROM 'active'
     OR v_entity_organization_id IS DISTINCT FROM NEW.organization_id THEN
    RAISE EXCEPTION 'SCIM token organization provenance does not match its live tenant'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION public.enforce_scim_token_organization_provenance()
  FROM PUBLIC, anon, authenticated, service_role;
DROP TRIGGER IF EXISTS scim_token_organization_provenance
  ON public.scim_provisioning_tokens;
CREATE TRIGGER scim_token_organization_provenance
BEFORE INSERT OR UPDATE OF tenant_id, organization_id, revoked_at
ON public.scim_provisioning_tokens
FOR EACH ROW
EXECUTE FUNCTION public.enforce_scim_token_organization_provenance();

-- Replace the directory-enable trigger body so even internal writes never
-- interpret tenant_id as an organization id.
CREATE OR REPLACE FUNCTION public.revoke_operator_credentials_on_directory_enable()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $trigger$
BEGIN
  IF NEW.revoked_at IS NOT NULL THEN
    RETURN NEW;
  END IF;
  IF NULLIF(NEW.organization_id, '') IS NULL THEN
    RAISE EXCEPTION 'SCIM directory enable requires explicit organization provenance'
      USING ERRCODE = '23514';
  END IF;
  UPDATE public.approver_credentials AS credential
     SET revoked_at = pg_catalog.clock_timestamp()
   WHERE credential.organization_id = NEW.organization_id
     AND credential.enrollment_basis = 'operator_attested'
     AND credential.revoked_at IS NULL;
  RETURN NEW;
END;
$trigger$;

REVOKE ALL ON FUNCTION public.revoke_operator_credentials_on_directory_enable()
  FROM PUBLIC, anon, authenticated, service_role;
DROP TRIGGER IF EXISTS scim_directory_enable_revokes_operator_credentials
  ON public.scim_provisioning_tokens;
CREATE TRIGGER scim_directory_enable_revokes_operator_credentials
AFTER INSERT ON public.scim_provisioning_tokens
FOR EACH ROW
EXECUTE FUNCTION public.revoke_operator_credentials_on_directory_enable();

-- Forward replacement of the enrollment completion routine. Both the sticky
-- directory check and the exact SCIM-user check use token.organization_id as
-- their sole organization provenance.
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
    RETURN pg_catalog.jsonb_build_object('error', 'challenge_not_found');
  END IF;
  IF v_challenge.consumed_at IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('error', 'challenge_consumed');
  END IF;
  v_credential_id := NULLIF(p_credential->>'credential_id', '');
  IF v_credential_id IS NULL THEN
    RETURN pg_catalog.jsonb_build_object('error', 'credential_missing');
  END IF;

  v_enrollment_basis := COALESCE(
    NULLIF(p_credential->>'enrollment_basis', ''),
    'operator_attested'
  );
  IF v_enrollment_basis NOT IN ('directory', 'operator_attested') THEN
    RETURN pg_catalog.jsonb_build_object('error', 'enrollment_basis_invalid');
  END IF;

  BEGIN
    v_directory_user_id := NULLIF(p_credential->>'directory_user_id', '')::UUID;
  EXCEPTION
    WHEN invalid_text_representation THEN
      RETURN pg_catalog.jsonb_build_object('error', 'directory_user_invalid');
  END;
  IF (v_enrollment_basis = 'directory') IS DISTINCT FROM (v_directory_user_id IS NOT NULL) THEN
    RETURN pg_catalog.jsonb_build_object('error', 'directory_basis_mismatch');
  END IF;

  LOCK TABLE public.scim_provisioning_tokens IN SHARE MODE;
  IF v_enrollment_basis = 'operator_attested' AND EXISTS (
    SELECT 1
      FROM public.scim_provisioning_tokens AS token
     WHERE token.organization_id = p_organization_id
  ) THEN
    RETURN pg_catalog.jsonb_build_object('error', 'directory_required');
  END IF;

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
            AND token.organization_id = p_organization_id
       )
     FOR UPDATE;
    IF NOT FOUND THEN
      RETURN pg_catalog.jsonb_build_object('error', 'directory_user_inactive');
    END IF;
  END IF;

  v_completed_at := pg_catalog.clock_timestamp();
  IF v_challenge.expires_at <= v_completed_at THEN
    RETURN pg_catalog.jsonb_build_object('error', 'challenge_expired');
  END IF;

  IF pg_catalog.jsonb_typeof(p_credential->'transports') = 'array' THEN
    SELECT pg_catalog.array_agg(value)
      INTO v_transports
      FROM pg_catalog.jsonb_array_elements_text(p_credential->'transports');
  END IF;

  INSERT INTO public.approver_credentials (
    organization_id, approver_id, approver_name, credential_id,
    public_key_cose, public_key_spki, key_class, sign_count, transports,
    attestation_fmt, attested_by, enrollment_basis, directory_user_id
  ) VALUES (
    p_organization_id, p_approver_id,
    NULLIF(p_credential->>'approver_name', ''), v_credential_id,
    p_credential->>'public_key_cose', p_credential->>'public_key_spki',
    COALESCE(NULLIF(p_credential->>'key_class', ''), 'A'),
    COALESCE((p_credential->>'sign_count')::BIGINT, 0), v_transports,
    NULLIF(p_credential->>'attestation_fmt', ''),
    NULLIF(p_credential->>'attested_by', ''),
    v_enrollment_basis, v_directory_user_id
  );

  UPDATE public.webauthn_challenges
     SET consumed_at = v_completed_at
   WHERE id = p_challenge_id;

  RETURN pg_catalog.jsonb_build_object(
    'credential_id', v_credential_id,
    'consumed', true,
    'enrollment_basis', v_enrollment_basis,
    'directory_user_id', v_directory_user_id
  );
EXCEPTION
  WHEN unique_violation THEN
    RETURN pg_catalog.jsonb_build_object('error', 'credential_exists');
END;
$function$;

REVOKE ALL ON FUNCTION public.complete_webauthn_registration_atomic(UUID, TEXT, TEXT, JSONB)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.complete_webauthn_registration_atomic(UUID, TEXT, TEXT, JSONB)
  TO service_role;

-- Deprovisioning must recheck the current tenant/org binding inside the same
-- transaction that updates the directory row and revokes its credentials. A
-- request-time check alone can race a tenant rebind.
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
  v_live_organization_id TEXT;
  v_live_tenant_status TEXT;
  v_revoked_at TIMESTAMPTZ;
  v_revoked_count INTEGER := 0;
  v_allowed_fields CONSTANT TEXT[] := ARRAY[
    'user_name', 'external_id', 'active', 'formatted_name', 'given_name',
    'family_name', 'display_name', 'title', 'emails', 'phone_numbers', 'raw'
  ];
BEGIN
  IF NULLIF(p_tenant_id, '') IS NULL
    OR NULLIF(p_organization_id, '') IS NULL
    OR p_user_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 1
    OR p_delete IS NULL
  THEN
    RAISE EXCEPTION 'SCIM authority write input is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT entity.organization_id, entity.status
    INTO v_live_organization_id, v_live_tenant_status
    FROM public.entities AS entity
   WHERE entity.entity_id = p_tenant_id
   FOR KEY SHARE;
  IF NOT FOUND
     OR v_live_tenant_status IS DISTINCT FROM 'active'
     OR v_live_organization_id = p_tenant_id
     OR v_live_organization_id IS DISTINCT FROM p_organization_id THEN
    RETURN pg_catalog.jsonb_build_object('error', 'tenant_binding_invalid');
  END IF;

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
     WHERE credential.organization_id = p_organization_id
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
        'organization_id', p_organization_id,
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
     WHERE credential.organization_id = p_organization_id
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
        'organization_id', p_organization_id,
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
-- END STRIX-40-SCIM-ORG-PROVENANCE

CREATE OR REPLACE FUNCTION public.exchange_mobile_pairing_verified(
  p_code_hash text,
  p_token_hash text,
  p_platform text,
  p_app_id text,
  p_credential_id text,
  p_expected_approver_id text,
  p_new_sign_count bigint,
  p_now timestamptz DEFAULT now()
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  pairing public.mobile_pairings%ROWTYPE;
  credential public.approver_credentials%ROWTYPE;
  created public.mobile_sessions%ROWTYPE;
  v_organization_id text;
BEGIN
  IF p_code_hash IS NULL OR p_code_hash !~ '^[0-9a-f]{64}$'
     OR p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$'
     OR p_platform NOT IN ('ios', 'android')
     OR char_length(coalesce(p_app_id, '')) NOT BETWEEN 3 AND 256
     OR char_length(coalesce(p_credential_id, '')) NOT BETWEEN 8 AND 4096
     OR char_length(coalesce(p_expected_approver_id, '')) NOT BETWEEN 3 AND 128
     OR p_new_sign_count IS NULL OR p_new_sign_count < 0
     OR p_now IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'malformed');
  END IF;

  SELECT * INTO pairing
    FROM public.mobile_pairings
   WHERE code_hash = p_code_hash
   FOR UPDATE;
  IF NOT FOUND OR pairing.consumed_at IS NOT NULL OR pairing.expires_at <= p_now THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'invalid_or_expired');
  END IF;
  IF pairing.approver_id IS DISTINCT FROM p_expected_approver_id THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'approver_mismatch');
  END IF;
  IF NOT coalesce(pairing.allowed_apps -> p_platform, '[]'::jsonb) ? p_app_id THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'app_not_allowed');
  END IF;

  SELECT entity.organization_id INTO v_organization_id
    FROM public.entities AS entity
   WHERE entity.entity_id = pairing.entity_ref
     AND entity.status = 'active'
   FOR SHARE;
  IF NOT FOUND OR v_organization_id IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'tenant_inactive');
  END IF;

  SELECT * INTO credential
    FROM public.approver_credentials AS candidate
   WHERE candidate.credential_id = p_credential_id
     AND candidate.organization_id = v_organization_id
     AND candidate.approver_id = pairing.approver_id
     AND candidate.enrollment_basis = 'directory'
     AND candidate.directory_user_id IS NOT NULL
     AND candidate.revoked_at IS NULL
     AND candidate.valid_from <= p_now
     AND (candidate.valid_to IS NULL OR candidate.valid_to > p_now)
   FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'identity_not_active');
  END IF;
  -- Authenticators that implement counters must advance. Multi-device passkeys
  -- commonly report zero forever, which WebAuthn explicitly permits.
  IF credential.sign_count > 0 AND p_new_sign_count <= credential.sign_count THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'credential_counter_replay');
  END IF;

  UPDATE public.approver_credentials
     SET sign_count = greatest(sign_count, p_new_sign_count)
   WHERE id = credential.id;
  UPDATE public.mobile_pairings
     SET consumed_at = p_now
   WHERE code_hash = p_code_hash;
  INSERT INTO public.mobile_sessions (
    token_hash, entity_ref, approver_id, profile_id, platform, app_id, expires_at
  ) VALUES (
    p_token_hash, pairing.entity_ref, pairing.approver_id, pairing.profile_id,
    p_platform, p_app_id, pairing.session_expires_at
  ) RETURNING * INTO created;

  RETURN jsonb_build_object(
    'ok', true,
    'session_id', created.session_id,
    'entity_ref', created.entity_ref,
    'approver_id', created.approver_id,
    'profile_id', created.profile_id,
    'expires_at', created.expires_at
  );
END;
$$;

REVOKE ALL ON FUNCTION public.exchange_mobile_pairing_verified(
  text, text, text, text, text, text, bigint, timestamptz
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.exchange_mobile_pairing_verified(
  text, text, text, text, text, text, bigint, timestamptz
) TO service_role;

-- Stored `verified=true` from the pre-proof implementation meant only that a
-- caller supplied the key id of an active registry row. It was not evidence of
-- issuer participation. Quarantine those rows before enforcing the new
-- invariant; finalized historical result rows remain an auditable record.
UPDATE public.handshake_presentations
   SET verified = false,
       verified_at = NULL,
       issuer_status = 'legacy_issuer_unproven',
       revocation_status = 'unproven'
 WHERE verified = true
   AND issuer_status IS DISTINCT FROM 'authority_signature_valid';

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
      AND revocation_checked = true
      AND revocation_status = 'good'
    )
  );

CREATE OR REPLACE FUNCTION public.present_handshake_writes(
  p_handshake_id uuid,
  p_party_role text,
  p_presentation_type text,
  p_issuer_ref text,
  p_presentation_hash text,
  p_disclosure_mode text,
  p_raw_claims jsonb,
  p_normalized_claims jsonb,
  p_canonical_claims_hash text,
  p_actor_entity_ref text,
  p_authority_id text,
  p_issuer_status text,
  p_verified boolean,
  p_revocation_checked boolean,
  p_revocation_status text,
  p_current_hs_status text,
  p_actor_id text,
  p_issuer_trusted boolean,
  p_event_detail jsonb
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_now timestamptz := now();
  v_presentation_id uuid;
  v_verified_at timestamptz;
  v_verified boolean := coalesce(p_verified, false);
  v_issuer_status text := p_issuer_status;
  v_revocation_status text := p_revocation_status;
  v_authority_status text;
  v_authority_algorithm text;
  v_authority_valid_from timestamptz;
  v_authority_valid_to timestamptz;
  v_authority_revoked_at timestamptz;
  v_event_detail jsonb := coalesce(p_event_detail, '{}'::jsonb);
BEGIN
  -- An application boolean is never sufficient. Only the cryptographic proof
  -- result vocabulary is eligible, and the registry row is locked/rechecked
  -- by both its immutable UUID and caller-visible key id in this transaction.
  IF v_verified THEN
    IF p_issuer_status IS DISTINCT FROM 'authority_signature_valid'
       OR p_issuer_ref IS NULL
       OR p_authority_id IS NULL
       OR p_canonical_claims_hash IS NULL
       OR p_revocation_checked IS DISTINCT FROM true
       OR p_revocation_status IS DISTINCT FROM 'good' THEN
      v_verified := false;
      v_issuer_status := 'issuer_proof_incomplete_at_write';
      v_revocation_status := 'unproven';
    ELSE
      SELECT status, algorithm, valid_from, valid_to, revoked_at
        INTO v_authority_status, v_authority_algorithm, v_authority_valid_from,
             v_authority_valid_to, v_authority_revoked_at
        FROM public.authorities
       WHERE authority_id::text = p_authority_id
         AND key_id = p_issuer_ref
       FOR UPDATE;
      IF NOT FOUND THEN
        v_verified := false;
        v_issuer_status := 'authority_identity_mismatch_at_write';
        v_revocation_status := 'unknown';
      ELSIF v_authority_status IS DISTINCT FROM 'active'
         OR v_authority_algorithm IS DISTINCT FROM 'Ed25519'
         OR v_authority_revoked_at IS NOT NULL
         OR v_authority_valid_from > v_now
         OR (v_authority_valid_to IS NOT NULL AND v_authority_valid_to <= v_now) THEN
        v_verified := false;
        v_issuer_status := 'authority_not_active_at_write';
        v_revocation_status := 'revoked_or_invalid';
      END IF;
    END IF;
  END IF;

  IF v_verified THEN v_verified_at := v_now; ELSE v_verified_at := NULL; END IF;
  v_event_detail := v_event_detail || jsonb_build_object(
    'issuer_trusted', v_verified,
    'issuer_status', v_issuer_status
  );

  INSERT INTO public.handshake_presentations (
    handshake_id, party_role, presentation_type,
    issuer_ref, presentation_hash, disclosure_mode,
    raw_claims, normalized_claims, canonical_claims_hash,
    actor_entity_ref, authority_id, issuer_status,
    verified, verified_at, revocation_checked, revocation_status
  ) VALUES (
    p_handshake_id, p_party_role, p_presentation_type,
    p_issuer_ref, p_presentation_hash, p_disclosure_mode,
    p_raw_claims, p_normalized_claims, p_canonical_claims_hash,
    p_actor_entity_ref, p_authority_id, v_issuer_status,
    v_verified, v_verified_at, p_revocation_checked, v_revocation_status
  ) RETURNING id INTO v_presentation_id;

  INSERT INTO public.handshake_events (
    handshake_id, event_type, event_payload, actor_entity_ref, detail, created_at
  ) VALUES (
    p_handshake_id, 'presentation_added', '{}'::jsonb,
    p_actor_id, v_event_detail, v_now
  );

  IF p_current_hs_status = 'initiated' THEN
    INSERT INTO public.handshake_events (
      handshake_id, event_type, event_payload, actor_entity_ref, detail, created_at
    ) VALUES (
      p_handshake_id, 'status_changed', '{}'::jsonb, p_actor_id,
      jsonb_build_object('from', 'initiated', 'to', 'pending_verification', 'trigger', 'presentation_added'),
      v_now
    );
    UPDATE public.handshakes
       SET status = 'pending_verification'
     WHERE handshake_id = p_handshake_id
       AND status = 'initiated';
  END IF;

  INSERT INTO public.protocol_events (
    aggregate_type, aggregate_id, command_type,
    payload_json, payload_hash, actor_authority_id, created_at
  ) VALUES (
    'handshake', p_handshake_id::text, 'add_presentation',
    v_event_detail, '', p_actor_id, v_now
  );

  RETURN jsonb_build_object(
    'id', v_presentation_id,
    'handshake_id', p_handshake_id,
    'party_role', p_party_role,
    'presentation_type', p_presentation_type,
    'issuer_ref', p_issuer_ref,
    'presentation_hash', p_presentation_hash,
    'disclosure_mode', p_disclosure_mode,
    'verified', v_verified,
    'verified_at', v_verified_at,
    'revocation_checked', p_revocation_checked,
    'revocation_status', v_revocation_status,
    'issuer_status', v_issuer_status,
    'authority_id', p_authority_id,
    'actor_entity_ref', p_actor_entity_ref,
    'canonical_claims_hash', p_canonical_claims_hash
  );
END;
$$;
