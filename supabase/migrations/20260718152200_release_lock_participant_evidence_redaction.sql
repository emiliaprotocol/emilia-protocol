-- SPDX-License-Identifier: Apache-2.0
-- Forward fix for projects that already applied 20260718083723_release_lock.sql.
-- Participant invitation sessions must never receive the organization-wide
-- evidence projection or unscoped session data.

CREATE OR REPLACE FUNCTION public.release_lock_participant_evidence(
  p_session_digest TEXT,
  p_lock_id TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_session public.release_lock_sessions%ROWTYPE;
  v_lock public.release_locks%ROWTYPE;
  v_current_action_hash TEXT;
  v_evidence JSONB;
  v_scoped_versions JSONB;
  v_scoped_draws JSONB;
  v_scoped_decisions JSONB;
  v_scoped_acceptances JSONB;
BEGIN
  IF p_session_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
     OR p_lock_id !~ '^rlk_[a-f0-9]{32}$'
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;

  SELECT * INTO v_session
  FROM public.release_lock_sessions
  WHERE token_digest = p_session_digest;
  IF NOT FOUND
     OR v_session.lock_id IS DISTINCT FROM p_lock_id
     OR v_session.revoked_at IS NOT NULL
     OR v_session.expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;

  SELECT * INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id;
  IF NOT FOUND OR v_lock.max_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;

  -- Invitation exchange must bind a participant session to one round, one
  -- version, and one action hash. A null scope is never a valid evidence query.
  IF v_session.scope_round IS NULL
     OR v_session.scope_version IS NULL
     OR v_session.scope_action_hash IS NULL
  THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.scope_version IS DISTINCT FROM v_lock.current_version THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;

  IF v_session.scope_round = 'CO_ACCEPTED' THEN
    SELECT co_action_hash INTO STRICT v_current_action_hash
    FROM public.release_lock_versions
    WHERE lock_id = p_lock_id AND version = v_session.scope_version;
  ELSIF v_session.scope_round = 'DRAW_RELEASE' THEN
    SELECT draw_action_hash INTO STRICT v_current_action_hash
    FROM public.release_lock_draw_actions
    WHERE lock_id = p_lock_id AND version = v_session.scope_version;
  ELSE
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;
  IF v_current_action_hash IS DISTINCT FROM v_session.scope_action_hash THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;

  v_evidence := public.release_lock_evidence(p_lock_id, v_lock.organization_id);

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'version', value->'version',
    'co_action', value->'co_action',
    'co_action_hash', value->'co_action_hash',
    'co_material_hash', value->'co_material_hash',
    'document_evidence', value->'document_evidence',
    'expires_at', value->'expires_at',
    'created_at', value->'created_at'
  ) ORDER BY (value->>'version')::INTEGER), '[]'::JSONB)
  INTO v_scoped_versions
  FROM jsonb_array_elements(v_evidence->'change_order_versions') AS entry(value)
  WHERE value->>'version' = v_session.scope_version::TEXT;
  IF jsonb_array_length(v_scoped_versions) <> 1 THEN
    RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
  END IF;

  IF v_session.scope_round = 'DRAW_RELEASE' THEN
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
      'version', value->'version',
      'draw_action', (value->'draw_action') - 'custodian',
      'draw_action_hash', value->'draw_action_hash',
      'draw_material_hash', value->'draw_material_hash',
      'accepted_co_action_hash', value->'accepted_co_action_hash',
      'accepted_co_digest', value->'accepted_co_digest',
      'expires_at', value->'expires_at',
      'created_at', value->'created_at'
    ) ORDER BY (value->>'version')::INTEGER), '[]'::JSONB)
    INTO v_scoped_draws
    FROM jsonb_array_elements(v_evidence->'draw_release_actions') AS entry(value)
    WHERE value->>'version' = v_session.scope_version::TEXT;
    IF jsonb_array_length(v_scoped_draws) <> 1 THEN
      RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
    END IF;
  ELSE
    v_scoped_draws := '[]'::JSONB;
  END IF;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'version', value->'version',
    'round', value->'round',
    'role', value->'role',
    'action_hash', value->'action_hash',
    'resolution_digest', value->'resolution_digest',
    'decided_at', value->'decided_at',
    'invalidated', value->'invalidated'
  ) ORDER BY value->>'round', value->>'role'), '[]'::JSONB)
  INTO v_scoped_decisions
  FROM jsonb_array_elements(v_evidence->'decisions') AS entry(value)
  WHERE value->>'version' = v_session.scope_version::TEXT
    AND value->>'round' = v_session.scope_round
    AND value->>'role' = v_session.role;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'version', value->'version',
    'round', value->'round',
    'action_hash', value->'action_hash',
    'acceptance_digest', value->'acceptance_digest',
    'accepted_at', value->'accepted_at'
  ) ORDER BY value->>'round'), '[]'::JSONB)
  INTO v_scoped_acceptances
  FROM jsonb_array_elements(v_evidence->'round_acceptances') AS entry(value)
  WHERE value->>'version' = v_session.scope_version::TEXT
    AND value->>'round' = v_session.scope_round;

  RETURN jsonb_build_object(
    'participant_scope', jsonb_build_object(
      'role', v_session.role,
      'round', v_session.scope_round,
      'version', v_session.scope_version,
      'action_hash', v_session.scope_action_hash
    ),
    'lock', jsonb_build_object(
      'lock_id', v_lock.lock_id,
      'current_version', v_lock.current_version,
      'status', CASE
        WHEN v_session.scope_round = 'CO_ACCEPTED'
             AND v_lock.status NOT IN ('co_pending', 'co_frozen', 'co_accepted')
          THEN 'co_scope_complete'
        ELSE v_lock.status
      END,
      'max_expires_at', v_lock.max_expires_at,
      'created_at', v_lock.created_at,
      'updated_at', v_lock.updated_at
    ),
    'change_order_versions', v_scoped_versions,
    'draw_release_actions', v_scoped_draws,
    'contact_bindings', '[]'::JSONB,
    'credentials', '[]'::JSONB,
    'decisions', v_scoped_decisions,
    'round_acceptances', v_scoped_acceptances,
    'effects', '[]'::JSONB
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_participant_evidence(TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_participant_evidence(TEXT, TEXT)
  TO service_role;
