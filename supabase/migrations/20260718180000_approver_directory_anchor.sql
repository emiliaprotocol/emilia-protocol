-- SPDX-License-Identifier: Apache-2.0
-- Anchor approver enrollment to the deployment's provisioned directory.
--
-- Holding `approver.enroll` lets an operator register a passkey under any
-- `approver_id` string it names (e.g. "cfo@corp"), so a Class-A receipt's named
-- approver rested on the operator's say-so. This records, per credential, the
-- BASIS on which the operator was allowed to bind that approver:
--
--   'directory'         — the approver_id matched an active SCIM-provisioned
--                         user in the org's directory (the operator cannot
--                         invent an approver the directory does not carry).
--   'operator_attested' — the org has no provisioned directory, so the
--                         enrollment rests on the second-party attestation
--                         (attested_by) alone. This is the pilot/non-SCIM path.
--
-- `directory_user_id` pins the exact scim_users row that authorized a
-- 'directory' enrollment, for audit. It is NULL for operator_attested rows.
--
-- Existing rows predate SCIM and were operator-vouched, so the column defaults
-- to 'operator_attested' — the honest basis for every credential enrolled
-- before this gate existed. No prod org has a directory yet (0 SCIM rows), so
-- this changes no live enrollment today; it engages automatically the moment a
-- tenant wires SCIM.

ALTER TABLE public.approver_credentials
  ADD COLUMN IF NOT EXISTS enrollment_basis TEXT NOT NULL DEFAULT 'operator_attested';

ALTER TABLE public.approver_credentials
  ADD COLUMN IF NOT EXISTS directory_user_id UUID DEFAULT NULL;

COMMENT ON COLUMN public.approver_credentials.enrollment_basis IS
  'How the operator was authorized to bind this approver_id: ''directory'' (matched an active SCIM user in the org directory) or ''operator_attested'' (no directory; rests on attested_by). Defaults to operator_attested for pre-directory rows.';

COMMENT ON COLUMN public.approver_credentials.directory_user_id IS
  'The scim_users.id that authorized a directory-basis enrollment; NULL for operator_attested.';

-- Constrain the basis to the known vocabulary. Existing rows carry the default
-- 'operator_attested', which satisfies the check, so this validates in place.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'approver_credentials_enrollment_basis_chk'
  ) THEN
    ALTER TABLE public.approver_credentials
      ADD CONSTRAINT approver_credentials_enrollment_basis_chk
      CHECK (enrollment_basis IN ('directory', 'operator_attested'));
  END IF;
END$$;

-- Re-declare the atomic registration completion so the enrollment basis and the
-- matched directory identity are written in the SAME transaction as the
-- credential. The signature is unchanged (UUID, TEXT, TEXT, JSONB), so no grant
-- changes are needed; only the INSERT column list grows.
CREATE OR REPLACE FUNCTION public.complete_webauthn_registration_atomic(
  p_challenge_id UUID,
  p_organization_id TEXT,
  p_approver_id TEXT,
  p_credential JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
DECLARE
  v_challenge RECORD;
  v_transports TEXT[];
  v_credential_id TEXT;
  v_enrollment_basis TEXT;
BEGIN
  SELECT id, kind, organization_id, approver_id, consumed_at, expires_at
  INTO v_challenge
  FROM webauthn_challenges
  WHERE id = p_challenge_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'challenge_not_found');
  END IF;
  IF v_challenge.kind <> 'registration'
     OR v_challenge.organization_id IS DISTINCT FROM p_organization_id
     OR v_challenge.approver_id IS DISTINCT FROM p_approver_id THEN
    RETURN jsonb_build_object('error', 'challenge_not_found');
  END IF;
  IF v_challenge.consumed_at IS NOT NULL THEN
    RETURN jsonb_build_object('error', 'challenge_consumed');
  END IF;
  IF v_challenge.expires_at <= now() THEN
    RETURN jsonb_build_object('error', 'challenge_expired');
  END IF;

  v_credential_id := NULLIF(p_credential->>'credential_id', '');
  IF v_credential_id IS NULL THEN
    RETURN jsonb_build_object('error', 'credential_missing');
  END IF;

  -- Never trust a client-supplied basis blindly: default to operator_attested
  -- and only honor the two known values. The route computes this server-side
  -- from the directory, but the DB stays fail-safe if it is ever absent/garbage.
  v_enrollment_basis := COALESCE(NULLIF(p_credential->>'enrollment_basis', ''), 'operator_attested');
  IF v_enrollment_basis NOT IN ('directory', 'operator_attested') THEN
    v_enrollment_basis := 'operator_attested';
  END IF;

  IF jsonb_typeof(p_credential->'transports') = 'array' THEN
    SELECT array_agg(value) INTO v_transports
    FROM jsonb_array_elements_text(p_credential->'transports');
  END IF;

  INSERT INTO approver_credentials (
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
    NULLIF(p_credential->>'directory_user_id', '')::UUID
  );

  UPDATE webauthn_challenges
  SET consumed_at = now()
  WHERE id = p_challenge_id;

  RETURN jsonb_build_object('credential_id', v_credential_id, 'consumed', true, 'enrollment_basis', v_enrollment_basis);
EXCEPTION
  WHEN unique_violation THEN
    RETURN jsonb_build_object('error', 'credential_exists');
END;
$function$;

REVOKE EXECUTE ON FUNCTION public.complete_webauthn_registration_atomic(UUID, TEXT, TEXT, JSONB) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.complete_webauthn_registration_atomic(UUID, TEXT, TEXT, JSONB) TO service_role;
