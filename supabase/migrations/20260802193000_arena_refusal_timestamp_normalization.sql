-- SPDX-License-Identifier: Apache-2.0
-- Normalize the public Arena projection timestamp to the millisecond precision
-- carried by EP-ACTION-REFUSAL-STATEMENT-v1. Existing projections remain
-- verifiable through the runtime's instant-equivalence compatibility check.

CREATE OR REPLACE FUNCTION public.publish_arena_refusal(
  p_token_hash TEXT,
  p_attempt_id TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $arena_publish$
DECLARE
  v_attempt public.arena_attempts%ROWTYPE;
  v_session public.arena_sessions%ROWTYPE;
  v_share public.arena_shares%ROWTYPE;
  v_share_id TEXT;
  v_projection JSONB;
BEGIN
  SELECT attempt.* INTO v_attempt
  FROM public.arena_attempts AS attempt
  JOIN public.arena_sessions AS session ON session.id = attempt.session_row_id
  WHERE attempt.attempt_id = p_attempt_id AND session.token_hash = p_token_hash
  FOR UPDATE OF attempt;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'status', 404, 'reason', 'arena_attempt_not_found');
  END IF;
  SELECT * INTO v_session
  FROM public.arena_sessions
  WHERE id = v_attempt.session_row_id;
  IF v_attempt.decision <> 'refuse' OR v_attempt.evidence_status <> 'complete' THEN
    RETURN jsonb_build_object('ok', false, 'status', 409, 'reason', 'arena_refusal_not_publishable');
  END IF;

  SELECT * INTO v_share FROM public.arena_shares WHERE attempt_id = p_attempt_id;
  IF FOUND THEN
    RETURN jsonb_build_object('ok', true, 'idempotent', true, 'share_id', v_share.share_id);
  END IF;

  v_share_id := 'arena_share_' || pg_catalog.encode(extensions.gen_random_bytes(20), 'hex');
  v_projection := jsonb_build_object(
    'profile', 'EP-ARENA-PUBLIC-REFUSAL-v1',
    'challenge_id', v_session.challenge_id,
    'challenge_version', v_session.challenge_version,
    'attempt', jsonb_build_object(
      'attempt_id', v_attempt.attempt_id,
      'action', v_attempt.action,
      'caid', v_attempt.caid,
      'action_digest', v_attempt.action_digest,
      'decision', v_attempt.decision,
      'reason', v_attempt.reason,
      'created_at', pg_catalog.to_char(
        v_attempt.created_at AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
      )
    ),
    'refusal_artifact', v_attempt.refusal_artifact,
    'refusal_digest', v_attempt.refusal_digest,
    'issuer', jsonb_build_object(
      'issuer_id', v_session.issuer_id,
      'key_id', v_session.key_id,
      'public_key', v_session.public_key
    ),
    'claim_boundary', 'synthetic_challenge_not_identity_competence_certification_money_or_production_authority'
  );

  INSERT INTO public.arena_shares (
    share_id, tenant_id, session_row_id, session_id, challenge_id,
    challenge_version, attempt_id, attempt_nonce, public_projection
  ) VALUES (
    v_share_id, v_session.tenant_id, v_session.id, v_session.session_id,
    v_session.challenge_id, v_session.challenge_version, v_attempt.attempt_id,
    v_attempt.attempt_nonce, v_projection
  );
  RETURN jsonb_build_object('ok', true, 'idempotent', false, 'share_id', v_share_id);
END
$arena_publish$;

REVOKE ALL ON FUNCTION public.publish_arena_refusal(TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.publish_arena_refusal(TEXT, TEXT)
  TO service_role;
