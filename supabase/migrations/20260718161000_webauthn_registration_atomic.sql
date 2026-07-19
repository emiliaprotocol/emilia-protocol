-- Atomic WebAuthn registration completion.
-- A verified assertion must not race another request between challenge lookup,
-- credential insertion, and challenge consumption.

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
    attested_by
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
    NULLIF(p_credential->>'attested_by', '')
  );

  UPDATE webauthn_challenges
  SET consumed_at = now()
  WHERE id = p_challenge_id;

  RETURN jsonb_build_object('credential_id', v_credential_id, 'consumed', true);
EXCEPTION
  WHEN unique_violation THEN
    RETURN jsonb_build_object('error', 'credential_exists');
END;
$function$;

REVOKE EXECUTE ON FUNCTION public.complete_webauthn_registration_atomic(UUID, TEXT, TEXT, JSONB) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.complete_webauthn_registration_atomic(UUID, TEXT, TEXT, JSONB) TO service_role;
