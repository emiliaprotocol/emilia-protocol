-- SPDX-License-Identifier: Apache-2.0
-- Migration version: 20260718090000
--
-- Narrows public.release_lock_participant_evidence from the operator evidence
-- projection to a caller-bound participant projection, and removes the
-- whole-row acceptances aggregate from public.release_lock_evidence.
--
-- Shipped behaviour being replaced: release_lock_participant_evidence called
-- release_lock_evidence and returned that operator bundle for one lock, either
-- whole (unscoped invitation sessions) or with only 'decisions' and
-- 'round_acceptances' replaced by round-scoped subsets. Both branches exported
-- the counterparty's contact binding, the counterparty's credential key, and
-- every party's Action Check prompt set, nonce, resolution context, and
-- submitted answers. Nothing here widens an input: every session, scope,
-- expiry, and revocation check is preserved verbatim; only output narrows.
--
-- Invariant: scope selects ROWS, never FIELDS. The unscoped and scoped cases
-- return the identical key set and identical per-object field lists; scope
-- changes only which rows are included.

CREATE OR REPLACE FUNCTION public.release_lock_evidence(
  p_lock_id TEXT,
  p_organization_id TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  v_lock public.release_locks%ROWTYPE;
  v_versions JSONB;
  v_draws JSONB;
  v_contacts JSONB;
  v_credentials JSONB;
  v_decisions JSONB;
  v_acceptances JSONB;
  v_effects JSONB;
BEGIN
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.organization_id IS DISTINCT FROM p_organization_id THEN
    RAISE EXCEPTION 'RL_ORGANIZATION_MISMATCH' USING ERRCODE = 'P0002';
  END IF;
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'version', v.version,
    'co_action', v.co_action,
    'co_action_hash', v.co_action_hash,
    'co_material_hash', v.co_material_hash,
    'document_evidence', v.document_evidence,
    'expires_at', v.expires_at,
    'created_by', v.created_by,
    'created_at', v.created_at
  ) ORDER BY v.version), '[]'::JSONB)
  INTO v_versions
  FROM public.release_lock_versions v
  WHERE v.lock_id = p_lock_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'version', d.version,
    'draw_action', d.draw_action,
    'draw_action_hash', d.draw_action_hash,
    'draw_material_hash', d.draw_material_hash,
    'accepted_co_action_hash', d.accepted_co_action_hash,
    'accepted_co_digest', d.accepted_co_digest,
    'expires_at', d.expires_at,
    'created_by', d.created_by,
    'created_at', d.created_at
  ) ORDER BY d.version), '[]'::JSONB)
  INTO v_draws
  FROM public.release_lock_draw_actions d
  WHERE d.lock_id = p_lock_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'contact_binding_id', c.contact_binding_id,
    'role', c.role,
    'channel', c.channel,
    'identifier_digest', c.identifier_digest,
    'verification_provider', c.verification_provider,
    'verification_reference', c.verification_reference,
    'verification_proof_digest', c.verification_proof_digest,
    'verified_at', c.verified_at,
    'verification_expires_at', c.verification_expires_at,
    'authority_provider', c.authority_provider,
    'authority_key_id', c.authority_key_id,
    'authority_reference', c.authority_reference,
    'authority_assertion', c.authority_assertion,
    'authority_signature', c.authority_signature,
    'authority_assertion_digest', c.authority_assertion_digest,
    'authority_subject_digest', c.authority_subject_digest,
    'authority_contact_binding_digest', c.authority_contact_binding_digest,
    'authority_verified_at', c.authority_verified_at,
    'authority_expires_at', c.authority_expires_at,
    'external_identity_proof_required', true
  ) ORDER BY c.role), '[]'::JSONB)
  INTO v_contacts
  FROM public.release_lock_contact_bindings c
  WHERE c.lock_id = p_lock_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'credential_id', c.credential_id,
    'role', c.role,
    'contact_binding_id', c.contact_binding_id,
    'public_key_spki', c.public_key_spki,
    'sign_count', c.sign_count,
    'device_type', c.device_type,
    'backed_up', c.backed_up,
    'attestation_format', c.attestation_format,
    'rp_id', c.rp_id,
    'origin', c.origin,
    'enrolled_at', c.enrolled_at,
    'revoked_at', c.revoked_at
  ) ORDER BY c.role), '[]'::JSONB)
  INTO v_credentials
  FROM public.release_lock_credentials c
  WHERE c.lock_id = p_lock_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'decision_id', d.decision_id,
    'version', d.version,
    'round', d.round,
    'role', d.role,
    'challenge_id', d.challenge_id,
    'contact_binding_id', d.contact_binding_id,
    'credential_id', d.credential_id,
    'action_hash', d.action_hash,
    'prompt_set_digest', d.prompt_set_digest,
    'answer_digest', d.answer_digest,
    'submitted_answers', d.submitted_answers,
    'action_check', jsonb_build_object(
      'prompt_set', h.prompt_set,
      'prompt_set_digest', h.prompt_set_digest,
      'answer_digest', h.answer_digest,
      'binding_moment', h.binding_moment,
      'random_nonce', h.random_nonce,
      'nonce', h.nonce,
      'resolution_context', h.resolution_context,
      'challenge', h.challenge,
      'issued_at', h.issued_at,
      'expires_at', h.expires_at,
      'consumed_at', h.consumed_at
    ),
    'resolution', d.resolution,
    'resolution_digest', d.resolution_digest,
    'sign_count', d.sign_count,
    'decided_at', d.decided_at,
    'invalidation', CASE WHEN i.decision_id IS NULL THEN NULL ELSE jsonb_build_object(
      'reason', i.reason,
      'superseded_by_version', i.superseded_by_version,
      'invalidated_at', i.invalidated_at
    ) END
  ) ORDER BY d.version, d.round, d.role), '[]'::JSONB)
  INTO v_decisions
  FROM public.release_lock_decisions d
  JOIN public.release_lock_action_challenges h
    ON h.challenge_id = d.challenge_id
  LEFT JOIN public.release_lock_decision_invalidations i
    ON i.decision_id = d.decision_id
  WHERE d.lock_id = p_lock_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'version', a.version,
    'round', a.round,
    'action_hash', a.action_hash,
    'acceptance_digest', a.acceptance_digest,
    'accepted_at', a.accepted_at
  ) ORDER BY a.version, a.round), '[]'::JSONB)
  INTO v_acceptances
  FROM public.release_lock_round_acceptances a
  WHERE a.lock_id = p_lock_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'effect_id', e.effect_id,
    'version', e.version,
    'draw_action_hash', e.draw_action_hash,
    'draw_acceptance_digest', e.draw_acceptance_digest,
    'effect_reference', e.effect_reference,
    'provider', e.provider,
    'environment', e.environment,
    'transaction_id', e.transaction_id,
    'milestone_id', e.milestone_id,
    'instruction', e.instruction,
    'effect_contract', e.effect_contract,
    'effect_contract_digest', e.effect_contract_digest,
    'status', e.status,
    'provider_result', e.provider_result,
    'reserved_at', e.reserved_at,
    'reservation_expires_at', e.reservation_expires_at,
    'reservation_attempts', e.reservation_attempts,
    'claim_attempts', e.claim_attempts,
    'retryable', e.retryable,
    'claimed_at', e.claimed_at,
    'released_at', e.released_at,
    'last_recovery_at', e.last_recovery_at,
    'recovery_evidence', e.recovery_evidence,
    'completed_at', e.completed_at,
    'reconciled_at', e.reconciled_at
  ) ORDER BY e.version), '[]'::JSONB)
  INTO v_effects
  FROM public.release_lock_effects e
  WHERE e.lock_id = p_lock_id;

  RETURN jsonb_build_object(
    'lock', jsonb_build_object(
      'lock_id', v_lock.lock_id,
      'organization_id', v_lock.organization_id,
      'contractor_entity_id', v_lock.contractor_entity_id,
      'current_version', v_lock.current_version,
      'frozen_version', v_lock.frozen_version,
      'frozen_round', v_lock.frozen_round,
      'status', v_lock.status,
      'max_expires_at', v_lock.max_expires_at,
      'created_at', v_lock.created_at,
      'updated_at', v_lock.updated_at
    ),
    'change_order_versions', v_versions,
    'draw_release_actions', v_draws,
    'contact_bindings', v_contacts,
    'credentials', v_credentials,
    'decisions', v_decisions,
    'round_acceptances', v_acceptances,
    'effects', v_effects
  );
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_evidence(TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_evidence(TEXT, TEXT)
  TO service_role;

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
  v_included_versions INTEGER[];
  v_included_rounds TEXT[];
  v_scoped_status TEXT;
  v_versions JSONB;
  v_draws JSONB;
  v_contact JSONB;
  v_credential JSONB;
  v_own_decisions JSONB;
  v_counterparty_decisions JSONB;
  v_acceptances JSONB;
  v_effects JSONB;
  v_draw_scope JSONB;
BEGIN
  IF p_session_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
     OR p_lock_id !~ '^rlk_[a-f0-9]{32}$'
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_session
  FROM public.release_lock_sessions
  WHERE token_digest = p_session_digest;
  IF NOT FOUND
     OR v_session.lock_id IS DISTINCT FROM p_lock_id
     OR v_session.revoked_at IS NOT NULL
     OR v_session.expires_at <= clock_timestamp()
  THEN
    RAISE EXCEPTION 'RL_SESSION_INVALID' USING ERRCODE = 'P0002';
  END IF;
  SELECT *
  INTO v_lock
  FROM public.release_locks
  WHERE lock_id = p_lock_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RL_LOCK_NOT_FOUND' USING ERRCODE = 'P0002';
  END IF;
  IF v_lock.max_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'RL_LOCK_EXPIRED' USING ERRCODE = 'P0002';
  END IF;
  IF v_session.scope_version IS NOT NULL THEN
    IF v_session.scope_version IS DISTINCT FROM v_lock.current_version THEN
      RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
    END IF;
    IF v_session.scope_round = 'CO_ACCEPTED' THEN
      SELECT co_action_hash
      INTO STRICT v_current_action_hash
      FROM public.release_lock_versions
      WHERE lock_id = p_lock_id
        AND version = v_session.scope_version;
    ELSE
      SELECT draw_action_hash
      INTO STRICT v_current_action_hash
      FROM public.release_lock_draw_actions
      WHERE lock_id = p_lock_id
        AND version = v_session.scope_version;
    END IF;
    IF v_current_action_hash IS DISTINCT FROM v_session.scope_action_hash THEN
      RAISE EXCEPTION 'RL_SESSION_SCOPE' USING ERRCODE = 'P0002';
    END IF;
  END IF;


  -- Row selection. Scope selects ROWS, never FIELDS: the unscoped and scoped
  -- cases return the identical key set and identical per-object field lists.
  IF v_session.scope_version IS NULL THEN
    SELECT COALESCE(array_agg(DISTINCT s.ver), ARRAY[v_lock.current_version])
    INTO v_included_versions
    FROM (
      SELECT v_lock.current_version AS ver
      UNION
      SELECT d.version AS ver
      FROM public.release_lock_decisions d
      WHERE d.lock_id = p_lock_id
        AND d.role = v_session.role
    ) s;
    v_included_rounds := ARRAY['CO_ACCEPTED', 'DRAW_RELEASE'];
  ELSE
    v_included_versions := ARRAY[v_session.scope_version];
    v_included_rounds := ARRAY[v_session.scope_round];
  END IF;

  v_scoped_status := CASE
    WHEN v_session.scope_round = 'CO_ACCEPTED'
         AND v_lock.status NOT IN ('co_pending', 'co_frozen', 'co_accepted')
      THEN 'co_scope_complete'
    ELSE v_lock.status
  END;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'version', v.version,
    'co_action', v.co_action,
    'co_action_hash', v.co_action_hash,
    'document_evidence', v.document_evidence,
    'expires_at', v.expires_at,
    'created_at', v.created_at
  ) ORDER BY v.version), '[]'::JSONB)
  INTO v_versions
  FROM public.release_lock_versions v
  WHERE v.lock_id = p_lock_id
    AND v.version = ANY(v_included_versions);

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'version', d.version,
    'draw_action', d.draw_action,
    'draw_action_hash', d.draw_action_hash,
    'accepted_co_action_hash', d.accepted_co_action_hash,
    'accepted_co_digest', d.accepted_co_digest,
    'expires_at', d.expires_at,
    'created_at', d.created_at
  ) ORDER BY d.version), '[]'::JSONB)
  INTO v_draws
  FROM public.release_lock_draw_actions d
  WHERE d.lock_id = p_lock_id
    AND d.version = ANY(v_included_versions);

  -- The caller's own contact binding only. The counterparty's binding is never
  -- exported: their authority assertion and signature already reach this caller
  -- inside co_action.parties[].authority, so nothing checkable is withheld,
  -- while channel, verification state, and the stable identifier_digest
  -- correlator stay out of a self-served participant export.
  SELECT jsonb_build_object(
    'contact_binding_id', c.contact_binding_id,
    'role', c.role,
    'channel', c.channel,
    'identifier_digest', c.identifier_digest,
    'verification_provider', c.verification_provider,
    'verification_proof_digest', c.verification_proof_digest,
    'verified_at', c.verified_at,
    'verification_expires_at', c.verification_expires_at,
    'authority_provider', c.authority_provider,
    'authority_key_id', c.authority_key_id,
    'authority_assertion', c.authority_assertion,
    'authority_signature', c.authority_signature,
    'authority_assertion_digest', c.authority_assertion_digest,
    'authority_subject_digest', c.authority_subject_digest,
    'authority_verified_at', c.authority_verified_at,
    'authority_expires_at', c.authority_expires_at,
    'external_identity_proof_required', true
  )
  INTO v_contact
  FROM public.release_lock_contact_bindings c
  WHERE c.lock_id = p_lock_id
    AND c.contact_binding_id = v_session.contact_binding_id
    AND c.role = v_session.role;

  -- The caller's own credential only. sign_count is a live global authenticator
  -- counter and is exported per decision instead of per credential.
  SELECT jsonb_build_object(
    'credential_id', c.credential_id,
    'role', c.role,
    'public_key_spki', c.public_key_spki,
    'device_type', c.device_type,
    'backed_up', c.backed_up,
    'attestation_format', c.attestation_format,
    'rp_id', c.rp_id,
    'origin', c.origin,
    'enrolled_at', c.enrolled_at,
    'revoked_at', c.revoked_at
  )
  INTO v_credential
  FROM public.release_lock_credentials c
  WHERE c.lock_id = p_lock_id
    AND c.role = v_session.role
    AND c.contact_binding_id = v_session.contact_binding_id;

  -- BEGIN participant own-role decision projection
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'version', d.version,
    'round', d.round,
    'role', d.role,
    'credential_id', d.credential_id,
    'action_hash', d.action_hash,
    'prompt_set_digest', d.prompt_set_digest,
    'answer_digest', d.answer_digest,
    'submitted_answers', d.submitted_answers,
    'action_check', jsonb_build_object(
      'prompt_set', h.prompt_set,
      'prompt_set_digest', h.prompt_set_digest,
      'answer_digest', h.answer_digest,
      'binding_moment', h.binding_moment,
      'random_nonce', h.random_nonce,
      'nonce', h.nonce,
      'resolution_context', h.resolution_context,
      'challenge', h.challenge,
      'issued_at', h.issued_at,
      'expires_at', h.expires_at,
      'consumed_at', h.consumed_at
    ),
    'resolution', d.resolution,
    'resolution_digest', d.resolution_digest,
    'sign_count', d.sign_count,
    'decided_at', d.decided_at,
    'invalidation', CASE WHEN i.decision_id IS NULL THEN NULL ELSE jsonb_build_object(
      'reason', i.reason,
      'superseded_by_version', i.superseded_by_version,
      'invalidated_at', i.invalidated_at
    ) END
  ) ORDER BY d.version, d.round), '[]'::JSONB)
  INTO v_own_decisions
  FROM public.release_lock_decisions d
  JOIN public.release_lock_action_challenges h
    ON h.challenge_id = d.challenge_id
  LEFT JOIN public.release_lock_decision_invalidations i
    ON i.decision_id = d.decision_id
  WHERE d.lock_id = p_lock_id
    AND d.role = v_session.role
    AND d.version = ANY(v_included_versions)
    AND d.round = ANY(v_included_rounds);
  -- END participant own-role decision projection

  -- BEGIN participant counterparty decision projection
  -- Existence and binding only. The Action Check answer key is identical across
  -- roles for one action, so exporting the counterparty's answers, prompt set,
  -- or challenge material would hand this caller the answers to their own
  -- comprehension check. Never widen this projection.
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'version', d.version,
    'round', d.round,
    'role', d.role,
    'action_hash', d.action_hash,
    'resolution_digest', d.resolution_digest,
    'decided_at', d.decided_at,
    'invalidation', CASE WHEN i.decision_id IS NULL THEN NULL ELSE jsonb_build_object(
      'reason', i.reason,
      'superseded_by_version', i.superseded_by_version,
      'invalidated_at', i.invalidated_at
    ) END
  ) ORDER BY d.version, d.round), '[]'::JSONB)
  INTO v_counterparty_decisions
  FROM public.release_lock_decisions d
  LEFT JOIN public.release_lock_decision_invalidations i
    ON i.decision_id = d.decision_id
  WHERE d.lock_id = p_lock_id
    AND d.role <> v_session.role
    AND d.version = ANY(v_included_versions)
    AND d.round = ANY(v_included_rounds);
  -- END participant counterparty decision projection

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'version', a.version,
    'round', a.round,
    'action_hash', a.action_hash,
    'acceptance_digest', a.acceptance_digest,
    'accepted_at', a.accepted_at
  ) ORDER BY a.version, a.round), '[]'::JSONB)
  INTO v_acceptances
  FROM public.release_lock_round_acceptances a
  WHERE a.lock_id = p_lock_id
    AND a.version = ANY(v_included_versions)
    AND a.round = ANY(v_included_rounds);

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'version', e.version,
    'draw_action_hash', e.draw_action_hash,
    'effect_reference', e.effect_reference,
    'provider', e.provider,
    'environment', e.environment,
    'transaction_id', e.transaction_id,
    'milestone_id', e.milestone_id,
    'status', e.status,
    'reserved_at', e.reserved_at,
    'reservation_expires_at', e.reservation_expires_at,
    'reservation_attempts', e.reservation_attempts,
    'claim_attempts', e.claim_attempts,
    'retryable', e.retryable,
    'claimed_at', e.claimed_at,
    'released_at', e.released_at,
    'last_recovery_at', e.last_recovery_at,
    'completed_at', e.completed_at,
    'reconciled_at', e.reconciled_at
  ) ORDER BY e.version), '[]'::JSONB)
  INTO v_effects
  FROM public.release_lock_effects e
  WHERE e.lock_id = p_lock_id
    AND e.version = ANY(v_included_versions);

  -- Draw and custodian evidence exist only outside a CO_ACCEPTED-scoped session.
  IF v_session.scope_round = 'CO_ACCEPTED' THEN
    v_draw_scope := jsonb_build_object(
      'draw_release_actions', '[]'::JSONB,
      'effects', '[]'::JSONB
    );
  ELSE
    v_draw_scope := jsonb_build_object(
      'draw_release_actions', v_draws,
      'effects', v_effects
    );
  END IF;

  RETURN jsonb_build_object(
    'participant_scope', jsonb_build_object(
      'role', v_session.role,
      'round', v_session.scope_round,
      'version', v_session.scope_version,
      'action_hash', v_session.scope_action_hash,
      'included_versions', array_to_json(v_included_versions)::JSONB
    ),
    'lock', jsonb_build_object(
      'lock_id', v_lock.lock_id,
      'current_version', v_lock.current_version,
      'status', v_scoped_status,
      'max_expires_at', v_lock.max_expires_at,
      'created_at', v_lock.created_at,
      'updated_at', v_lock.updated_at
    ),
    'change_order_versions', v_versions,
    'contact_binding', v_contact,
    'credential', v_credential,
    'decisions', v_own_decisions || v_counterparty_decisions,
    'round_acceptances', v_acceptances
  ) || v_draw_scope;
END;
$$;

REVOKE ALL ON FUNCTION public.release_lock_participant_evidence(TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.release_lock_participant_evidence(TEXT, TEXT)
  TO service_role;
