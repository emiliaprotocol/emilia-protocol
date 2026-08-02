-- SPDX-License-Identifier: Apache-2.0
-- EMILIA Arena: isolated synthetic allowance sessions and refusal publication.
--
-- This store is deliberately separate from entities/api_keys. Arena tokens can
-- authenticate only the Arena routes, carry no general EP permissions, and
-- cannot resolve to a provider credential or real execution connector.

CREATE TABLE IF NOT EXISTS public.arena_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL DEFAULT gen_random_uuid(),
  session_id TEXT NOT NULL UNIQUE CHECK (session_id ~ '^arena_session_[0-9a-f]{32}$'),
  token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  agent_name TEXT NOT NULL CHECK (length(agent_name) BETWEEN 1 AND 64),
  challenge_id TEXT NOT NULL CHECK (
    length(challenge_id) BETWEEN 1 AND 512
    AND challenge_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/+-]*$'
  ),
  challenge_version BIGINT NOT NULL CHECK (challenge_version > 0),
  currency TEXT NOT NULL DEFAULT 'CREDITS' CHECK (currency = 'CREDITS'),
  total_amount BIGINT NOT NULL CHECK (total_amount > 0),
  remaining_amount BIGINT NOT NULL CHECK (remaining_amount >= 0 AND remaining_amount <= total_amount),
  max_amount_per_action BIGINT NOT NULL CHECK (max_amount_per_action > 0 AND max_amount_per_action <= total_amount),
  allowed_targets TEXT[] NOT NULL CHECK (cardinality(allowed_targets) BETWEEN 1 AND 32),
  allowance_profile JSONB NOT NULL CHECK (jsonb_typeof(allowance_profile) = 'object'),
  issuer_id TEXT NOT NULL CHECK (
    length(issuer_id) BETWEEN 1 AND 512
    AND issuer_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/+-]*$'
  ),
  key_id TEXT NOT NULL CHECK (
    length(key_id) BETWEEN 1 AND 512
    AND key_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/+-]*$'
  ),
  public_key TEXT NOT NULL CHECK (public_key ~ '^[A-Za-z0-9_-]+$'),
  private_key_encrypted TEXT NOT NULL CHECK (private_key_encrypted LIKE 'epenc:v1:%'),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  CHECK (expires_at > created_at),
  UNIQUE (id, tenant_id, session_id, challenge_id, challenge_version)
);

CREATE TABLE IF NOT EXISTS public.arena_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  session_row_id UUID NOT NULL,
  session_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  challenge_version BIGINT NOT NULL CHECK (challenge_version > 0),
  attempt_id TEXT NOT NULL UNIQUE CHECK (attempt_id ~ '^arena_attempt_[0-9a-f]{32}$'),
  attempt_nonce TEXT NOT NULL CHECK (attempt_nonce ~ '^[A-Za-z0-9_-]{22,128}$'),
  operation_id TEXT NOT NULL CHECK (
    length(operation_id) BETWEEN 1 AND 512
    AND operation_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/+-]*$'
  ),
  action JSONB NOT NULL CHECK (jsonb_typeof(action) = 'object'),
  action_digest TEXT NOT NULL CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  caid TEXT NOT NULL CHECK (caid ~ '^caid:1:arena\.resource\.allocate\.1:jcs-sha256:[A-Za-z0-9_-]{43}$'),
  decision TEXT NOT NULL CHECK (decision IN ('allow', 'refuse')),
  reason TEXT,
  remaining_amount BIGINT NOT NULL CHECK (remaining_amount >= 0),
  evidence_status TEXT NOT NULL CHECK (evidence_status IN ('not_applicable', 'pending', 'complete', 'failed')),
  refusal_artifact JSONB,
  refusal_digest TEXT CHECK (refusal_digest ~ '^sha256:[0-9a-f]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (session_row_id, operation_id),
  UNIQUE (session_row_id, attempt_nonce),
  UNIQUE (attempt_id, attempt_nonce, session_row_id, tenant_id, session_id, challenge_id, challenge_version),
  FOREIGN KEY (session_row_id, tenant_id, session_id, challenge_id, challenge_version)
    REFERENCES public.arena_sessions (id, tenant_id, session_id, challenge_id, challenge_version)
    ON DELETE CASCADE,
  CHECK ((decision = 'allow' AND reason IS NULL AND evidence_status = 'not_applicable'
      AND refusal_artifact IS NULL AND refusal_digest IS NULL)
    OR (decision = 'refuse' AND reason IS NOT NULL AND evidence_status IN ('pending', 'complete', 'failed'))),
  CHECK ((evidence_status = 'complete' AND refusal_artifact IS NOT NULL AND refusal_digest IS NOT NULL)
    OR (evidence_status <> 'complete' AND refusal_artifact IS NULL AND refusal_digest IS NULL))
);

CREATE TABLE IF NOT EXISTS public.arena_shares (
  share_id TEXT PRIMARY KEY CHECK (share_id ~ '^arena_share_[0-9a-f]{40}$'),
  tenant_id UUID NOT NULL,
  session_row_id UUID NOT NULL,
  session_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  challenge_version BIGINT NOT NULL CHECK (challenge_version > 0),
  attempt_id TEXT NOT NULL UNIQUE,
  attempt_nonce TEXT NOT NULL,
  public_projection JSONB NOT NULL CHECK (jsonb_typeof(public_projection) = 'object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  revoked_at TIMESTAMPTZ,
  FOREIGN KEY (session_row_id, tenant_id, session_id, challenge_id, challenge_version)
    REFERENCES public.arena_sessions (id, tenant_id, session_id, challenge_id, challenge_version)
    ON DELETE RESTRICT,
  FOREIGN KEY (attempt_id, attempt_nonce, session_row_id, tenant_id, session_id, challenge_id, challenge_version)
    REFERENCES public.arena_attempts (attempt_id, attempt_nonce, session_row_id, tenant_id, session_id, challenge_id, challenge_version)
    ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS arena_attempts_session_time_idx
  ON public.arena_attempts (session_row_id, created_at);
CREATE INDEX IF NOT EXISTS arena_sessions_expiry_idx
  ON public.arena_sessions (status, expires_at);

ALTER TABLE public.arena_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.arena_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.arena_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.arena_attempts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.arena_shares ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.arena_shares FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.arena_sessions FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.arena_attempts FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.arena_shares FROM PUBLIC, anon, authenticated;
GRANT SELECT ON TABLE public.arena_sessions TO service_role;
GRANT SELECT ON TABLE public.arena_attempts TO service_role;
GRANT SELECT ON TABLE public.arena_shares TO service_role;

CREATE OR REPLACE FUNCTION public.arena_sessions_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $arena_sessions_guard$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF pg_catalog.current_setting('emilia.arena_prune', true) IS DISTINCT FROM '1' THEN
      RAISE EXCEPTION 'arena session rows may be deleted only by the bounded prune RPC';
    END IF;
    IF OLD.expires_at >= clock_timestamp() THEN
      RAISE EXCEPTION 'active arena session rows cannot be pruned';
    END IF;
    IF EXISTS (
      SELECT 1 FROM public.arena_shares AS share
      WHERE share.session_row_id = OLD.id
    ) THEN
      RAISE EXCEPTION 'arena published source rows cannot be pruned';
    END IF;
    RETURN OLD;
  END IF;
  IF ROW(
    OLD.id, OLD.tenant_id, OLD.session_id, OLD.token_hash, OLD.agent_name,
    OLD.challenge_id, OLD.challenge_version, OLD.currency, OLD.total_amount,
    OLD.max_amount_per_action, OLD.allowed_targets, OLD.allowance_profile,
    OLD.issuer_id, OLD.key_id, OLD.public_key, OLD.private_key_encrypted,
    OLD.created_at, OLD.expires_at
  ) IS DISTINCT FROM ROW(
    NEW.id, NEW.tenant_id, NEW.session_id, NEW.token_hash, NEW.agent_name,
    NEW.challenge_id, NEW.challenge_version, NEW.currency, NEW.total_amount,
    NEW.max_amount_per_action, NEW.allowed_targets, NEW.allowance_profile,
    NEW.issuer_id, NEW.key_id, NEW.public_key, NEW.private_key_encrypted,
    NEW.created_at, NEW.expires_at
  ) THEN
    RAISE EXCEPTION 'arena session identity and limits are immutable';
  END IF;
  IF NEW.remaining_amount > OLD.remaining_amount THEN
    RAISE EXCEPTION 'arena session remaining allowance cannot increase';
  END IF;
  IF OLD.status IS DISTINCT FROM NEW.status
     AND NOT (OLD.status = 'active' AND NEW.status IN ('suspended', 'expired')) THEN
    RAISE EXCEPTION 'arena session status transition is invalid';
  END IF;
  IF OLD.status <> 'active' AND NEW.remaining_amount IS DISTINCT FROM OLD.remaining_amount THEN
    RAISE EXCEPTION 'inactive arena session allowance is immutable';
  END IF;
  RETURN NEW;
END
$arena_sessions_guard$;

CREATE OR REPLACE FUNCTION public.arena_attempts_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $arena_attempts_guard$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF pg_catalog.current_setting('emilia.arena_prune', true) = '1'
       AND NOT EXISTS (
         SELECT 1 FROM public.arena_shares AS share
         WHERE share.attempt_id = OLD.attempt_id
       ) THEN
      RETURN OLD;
    END IF;
    RAISE EXCEPTION 'arena attempt rows may be deleted only with an expired unpublished session';
  END IF;
  IF OLD.evidence_status = 'pending'
     AND NEW.evidence_status = 'complete'
     AND NEW.refusal_artifact IS NOT NULL
     AND NEW.refusal_digest IS NOT NULL
     AND (pg_catalog.to_jsonb(NEW) - 'evidence_status' - 'refusal_artifact' - 'refusal_digest')
         IS NOT DISTINCT FROM
         (pg_catalog.to_jsonb(OLD) - 'evidence_status' - 'refusal_artifact' - 'refusal_digest') THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'arena attempt rows permit only pending-to-complete evidence commitment';
END
$arena_attempts_guard$;

CREATE OR REPLACE FUNCTION public.arena_shares_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $arena_shares_immutable$
BEGIN
  RAISE EXCEPTION 'arena share rows are immutable';
END
$arena_shares_immutable$;

CREATE TRIGGER arena_sessions_guard_trigger
  BEFORE UPDATE OR DELETE ON public.arena_sessions
  FOR EACH ROW EXECUTE FUNCTION public.arena_sessions_guard();
CREATE TRIGGER arena_attempts_guard_trigger
  BEFORE UPDATE OR DELETE ON public.arena_attempts
  FOR EACH ROW EXECUTE FUNCTION public.arena_attempts_guard();
CREATE TRIGGER arena_shares_immutable_trigger
  BEFORE UPDATE OR DELETE ON public.arena_shares
  FOR EACH ROW EXECUTE FUNCTION public.arena_shares_immutable();

REVOKE ALL ON FUNCTION public.arena_sessions_guard() FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.arena_attempts_guard() FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.arena_shares_immutable() FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.provision_arena_session(
  p_session_id TEXT,
  p_token_hash TEXT,
  p_agent_name TEXT,
  p_challenge_id TEXT,
  p_challenge_version BIGINT,
  p_total_amount BIGINT,
  p_max_amount_per_action BIGINT,
  p_allowed_targets TEXT[],
  p_allowance_profile JSONB,
  p_issuer_id TEXT,
  p_key_id TEXT,
  p_public_key TEXT,
  p_private_key_encrypted TEXT,
  p_expires_at TIMESTAMPTZ
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $arena_provision$
DECLARE
  v_id UUID;
  v_tenant_id UUID;
BEGIN
  IF p_session_id !~ '^arena_session_[0-9a-f]{32}$'
      OR p_token_hash !~ '^[0-9a-f]{64}$'
      OR length(btrim(p_agent_name)) NOT BETWEEN 1 AND 64
      OR length(p_challenge_id) NOT BETWEEN 1 AND 512
      OR p_challenge_id !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/+-]*$'
      OR p_challenge_version < 1
      OR p_total_amount < 1 OR p_max_amount_per_action < 1
      OR p_max_amount_per_action > p_total_amount
      OR cardinality(p_allowed_targets) NOT BETWEEN 1 AND 32
      OR pg_catalog.array_position(p_allowed_targets, NULL) IS NOT NULL
      OR EXISTS (SELECT 1 FROM unnest(p_allowed_targets) AS target
        WHERE length(target) NOT BETWEEN 1 AND 512
          OR target !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/+-]*$')
      OR cardinality(p_allowed_targets) <> (
        SELECT count(DISTINCT target) FROM unnest(p_allowed_targets) AS target
      )
      OR jsonb_typeof(p_allowance_profile) IS DISTINCT FROM 'object'
      OR length(p_issuer_id) NOT BETWEEN 1 AND 512
      OR p_issuer_id !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/+-]*$'
      OR length(p_key_id) NOT BETWEEN 1 AND 512
      OR p_key_id !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/+-]*$'
      OR p_public_key !~ '^[A-Za-z0-9_-]+$'
      OR p_private_key_encrypted NOT LIKE 'epenc:v1:%'
      OR p_expires_at <= clock_timestamp() THEN
    RETURN jsonb_build_object('ok', false, 'status', 400, 'reason', 'arena_session_invalid');
  END IF;

  IF (SELECT count(*) FROM jsonb_object_keys(p_allowance_profile)) <> 10
      OR p_allowance_profile->>'@version' IS DISTINCT FROM 'EP-ARENA-ALLOWANCE-v1'
      OR p_allowance_profile->>'session_id' IS DISTINCT FROM p_session_id
      OR p_allowance_profile->>'agent_name' IS DISTINCT FROM btrim(p_agent_name)
      OR p_allowance_profile->>'currency' IS DISTINCT FROM 'CREDITS'
      OR p_allowance_profile->>'total_amount' !~ '^[1-9][0-9]{0,18}$'
      OR p_allowance_profile->>'max_amount_per_action' !~ '^[1-9][0-9]{0,18}$'
      OR p_allowance_profile->'allowed_targets' IS DISTINCT FROM to_jsonb(p_allowed_targets)
      OR p_allowance_profile->>'issued_at' !~
        '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$'
      OR p_allowance_profile->>'expires_at' IS DISTINCT FROM
        pg_catalog.to_char(p_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
      OR p_allowance_profile->>'issued_at' >= p_allowance_profile->>'expires_at'
      OR p_allowance_profile->>'claim_boundary' IS DISTINCT FROM
        'synthetic_challenge_not_money_custody_settlement_identity_certification_or_production_authorization' THEN
    RETURN jsonb_build_object('ok', false, 'status', 400, 'reason', 'arena_allowance_profile_invalid');
  END IF;

  IF (p_allowance_profile->>'total_amount')::BIGINT <> p_total_amount
      OR (p_allowance_profile->>'max_amount_per_action')::BIGINT <> p_max_amount_per_action THEN
    RETURN jsonb_build_object('ok', false, 'status', 400, 'reason', 'arena_allowance_profile_mismatch');
  END IF;

  INSERT INTO public.arena_sessions (
    session_id, token_hash, agent_name, challenge_id, challenge_version,
    total_amount, remaining_amount, max_amount_per_action, allowed_targets,
    allowance_profile, issuer_id, key_id, public_key, private_key_encrypted,
    expires_at
  ) VALUES (
    p_session_id, p_token_hash, btrim(p_agent_name), p_challenge_id,
    p_challenge_version, p_total_amount, p_total_amount,
    p_max_amount_per_action, p_allowed_targets, p_allowance_profile,
    p_issuer_id, p_key_id, p_public_key, p_private_key_encrypted, p_expires_at
  ) RETURNING id, tenant_id INTO v_id, v_tenant_id;

  RETURN jsonb_build_object(
    'ok', true, 'session_row_id', v_id, 'tenant_id', v_tenant_id
  );
EXCEPTION WHEN unique_violation THEN
  RETURN jsonb_build_object('ok', false, 'status', 409, 'reason', 'arena_session_conflict');
END
$arena_provision$;

CREATE OR REPLACE FUNCTION public.attempt_arena_action(
  p_token_hash TEXT,
  p_session_id TEXT,
  p_attempt_nonce TEXT,
  p_operation_id TEXT,
  p_action JSONB,
  p_action_digest TEXT,
  p_caid TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $arena_attempt$
DECLARE
  v_session public.arena_sessions%ROWTYPE;
  v_existing public.arena_attempts%ROWTYPE;
  v_attempt_id TEXT;
  v_decision TEXT := 'allow';
  v_reason TEXT := NULL;
  v_amount BIGINT;
  v_remaining BIGINT;
  v_created_at TIMESTAMPTZ;
  v_attempt_count BIGINT;
BEGIN
  IF p_token_hash !~ '^[0-9a-f]{64}$'
     OR p_session_id !~ '^arena_session_[0-9a-f]{32}$'
     OR p_attempt_nonce !~ '^[A-Za-z0-9_-]{22,128}$'
     OR length(p_operation_id) NOT BETWEEN 1 AND 512
     OR p_operation_id !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/+-]*$'
     OR p_action_digest !~ '^sha256:[0-9a-f]{64}$'
     OR p_caid !~ '^caid:1:arena\.resource\.allocate\.1:jcs-sha256:[A-Za-z0-9_-]{43}$'
     OR jsonb_typeof(p_action) IS DISTINCT FROM 'object' THEN
    RETURN jsonb_build_object('ok', false, 'status', 400, 'reason', 'arena_request_invalid');
  END IF;

  SELECT * INTO v_session
  FROM public.arena_sessions
  WHERE session_id = p_session_id AND token_hash = p_token_hash
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'status', 404, 'reason', 'arena_session_not_found');
  END IF;

  SELECT * INTO v_existing
  FROM public.arena_attempts
  WHERE session_row_id = v_session.id AND operation_id = p_operation_id;

  IF FOUND THEN
    IF v_existing.action_digest <> p_action_digest
       OR v_existing.caid <> p_caid
       OR v_existing.action <> p_action THEN
      RETURN jsonb_build_object('ok', false, 'status', 409, 'reason', 'allowance_operation_equivocation');
    END IF;
    RETURN jsonb_build_object(
      'ok', true,
      'idempotent', true,
      'attempt_id', v_existing.attempt_id,
      'attempt_nonce', v_existing.attempt_nonce,
      'decision', v_existing.decision,
      'reason', v_existing.reason,
      'remaining_amount', v_existing.remaining_amount,
      'created_at', v_existing.created_at,
      'evidence_status', v_existing.evidence_status,
      'refusal_artifact', v_existing.refusal_artifact,
      'refusal_digest', v_existing.refusal_digest
    );
  END IF;

  SELECT * INTO v_existing
  FROM public.arena_attempts
  WHERE session_row_id = v_session.id AND attempt_nonce = p_attempt_nonce;

  IF FOUND THEN
    RETURN jsonb_build_object('ok', false, 'status', 409, 'reason', 'allowance_attempt_nonce_replay');
  END IF;

  SELECT count(*) INTO v_attempt_count
  FROM public.arena_attempts
  WHERE session_row_id = v_session.id;

  IF v_attempt_count >= 25 THEN
    RETURN jsonb_build_object('ok', false, 'status', 429, 'reason', 'arena_attempt_limit_exceeded');
  END IF;

  IF v_session.status <> 'active' OR clock_timestamp() >= v_session.expires_at THEN
    v_decision := 'refuse'; v_reason := 'allowance_expired';
  ELSIF (SELECT count(*) FROM jsonb_object_keys(p_action)) <> 6
      OR p_action->>'operation_id' IS DISTINCT FROM p_operation_id
      OR p_action->>'action_type' IS DISTINCT FROM 'arena.resource.allocate.1'
      OR length(p_action->>'purpose') NOT BETWEEN 1 AND 512
      OR p_action->>'purpose' !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/+-]*$'
      OR length(p_action->>'target') NOT BETWEEN 1 AND 512
      OR p_action->>'target' !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/+-]*$'
      OR p_action->>'amount' !~ '^[1-9][0-9]{0,17}$' THEN
    v_decision := 'refuse'; v_reason := 'allowance_action_shape_invalid';
  ELSIF p_action->>'currency' IS DISTINCT FROM v_session.currency THEN
    v_decision := 'refuse'; v_reason := 'allowance_currency_mismatch';
  ELSIF NOT (p_action->>'target' = ANY(v_session.allowed_targets)) THEN
    v_decision := 'refuse'; v_reason := 'allowance_target_not_allowed';
  ELSE
    v_amount := (p_action->>'amount')::BIGINT;
    IF v_amount > v_session.max_amount_per_action THEN
      v_decision := 'refuse'; v_reason := 'allowance_per_action_limit_exceeded';
    ELSIF v_amount > v_session.remaining_amount THEN
      v_decision := 'refuse'; v_reason := 'allowance_aggregate_limit_exceeded';
    ELSE
      UPDATE public.arena_sessions
      SET remaining_amount = remaining_amount - v_amount
      WHERE id = v_session.id AND remaining_amount >= v_amount
      RETURNING remaining_amount INTO v_remaining;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'arena allowance atomic debit conflicted';
      END IF;
    END IF;
  END IF;

  IF v_decision = 'refuse' THEN v_remaining := v_session.remaining_amount; END IF;
  v_attempt_id := 'arena_attempt_' || replace(gen_random_uuid()::text, '-', '');
  v_created_at := clock_timestamp();

  INSERT INTO public.arena_attempts (
    tenant_id, session_row_id, session_id, challenge_id, challenge_version,
    attempt_id, attempt_nonce, operation_id, action, action_digest, caid,
    decision, reason, remaining_amount, evidence_status, created_at
  ) VALUES (
    v_session.tenant_id, v_session.id, v_session.session_id,
    v_session.challenge_id, v_session.challenge_version,
    v_attempt_id, p_attempt_nonce, p_operation_id, p_action, p_action_digest, p_caid,
    v_decision, v_reason, v_remaining,
    CASE WHEN v_decision = 'refuse' THEN 'pending' ELSE 'not_applicable' END,
    v_created_at
  );

  RETURN jsonb_build_object(
    'ok', true,
    'idempotent', false,
    'attempt_id', v_attempt_id,
    'attempt_nonce', p_attempt_nonce,
    'decision', v_decision,
    'reason', v_reason,
    'remaining_amount', v_remaining,
    'created_at', v_created_at,
    'evidence_status', CASE WHEN v_decision = 'refuse' THEN 'pending' ELSE 'not_applicable' END
  );
END
$arena_attempt$;

CREATE OR REPLACE FUNCTION public.commit_arena_refusal(
  p_token_hash TEXT,
  p_attempt_id TEXT,
  p_refusal_artifact JSONB,
  p_refusal_digest TEXT
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $arena_refusal$
DECLARE
  v_attempt public.arena_attempts%ROWTYPE;
BEGIN
  SELECT attempt.* INTO v_attempt
  FROM public.arena_attempts AS attempt
  JOIN public.arena_sessions AS session ON session.id = attempt.session_row_id
  WHERE attempt.attempt_id = p_attempt_id AND session.token_hash = p_token_hash
  FOR UPDATE OF attempt;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'status', 404, 'reason', 'arena_attempt_not_found');
  END IF;
  IF v_attempt.decision <> 'refuse' THEN
    RETURN jsonb_build_object('ok', false, 'status', 409, 'reason', 'arena_attempt_not_refused');
  END IF;
  IF v_attempt.evidence_status = 'complete' THEN
    IF v_attempt.refusal_digest = p_refusal_digest AND v_attempt.refusal_artifact = p_refusal_artifact THEN
      RETURN jsonb_build_object('ok', true, 'idempotent', true);
    END IF;
    RETURN jsonb_build_object('ok', false, 'status', 409, 'reason', 'arena_refusal_equivocation');
  END IF;
  IF v_attempt.evidence_status <> 'pending'
      OR jsonb_typeof(p_refusal_artifact) IS DISTINCT FROM 'object'
      OR p_refusal_digest !~ '^sha256:[0-9a-f]{64}$' THEN
    RETURN jsonb_build_object('ok', false, 'status', 409, 'reason', 'arena_refusal_commit_invalid');
  END IF;
  UPDATE public.arena_attempts
  SET evidence_status = 'complete', refusal_artifact = p_refusal_artifact,
      refusal_digest = p_refusal_digest
  WHERE id = v_attempt.id;
  RETURN jsonb_build_object('ok', true, 'idempotent', false);
END
$arena_refusal$;

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
      'created_at', v_attempt.created_at
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

CREATE OR REPLACE FUNCTION public.prune_arena_sessions(
  p_before TIMESTAMPTZ
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $arena_prune$
DECLARE
  v_deleted BIGINT;
BEGIN
  IF p_before IS NULL OR p_before > clock_timestamp() THEN
    RETURN jsonb_build_object('ok', false, 'status', 400, 'reason', 'arena_prune_boundary_invalid');
  END IF;

  PERFORM pg_catalog.set_config('emilia.arena_prune', '1', true);
  WITH deleted AS (
    DELETE FROM public.arena_sessions AS session
    WHERE session.expires_at < p_before
      AND NOT EXISTS (
        SELECT 1
        FROM public.arena_shares AS share
        WHERE share.session_row_id = session.id
      )
    RETURNING session.id
  )
  SELECT count(*) INTO v_deleted FROM deleted;

  RETURN jsonb_build_object('ok', true, 'deleted_sessions', v_deleted);
END
$arena_prune$;

REVOKE ALL ON FUNCTION public.attempt_arena_action(TEXT, TEXT, TEXT, TEXT, JSONB, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.provision_arena_session(TEXT, TEXT, TEXT, TEXT, BIGINT, BIGINT, BIGINT, TEXT[], JSONB, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.commit_arena_refusal(TEXT, TEXT, JSONB, TEXT)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.publish_arena_refusal(TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.prune_arena_sessions(TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.attempt_arena_action(TEXT, TEXT, TEXT, TEXT, JSONB, TEXT, TEXT)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.provision_arena_session(TEXT, TEXT, TEXT, TEXT, BIGINT, BIGINT, BIGINT, TEXT[], JSONB, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.commit_arena_refusal(TEXT, TEXT, JSONB, TEXT)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.publish_arena_refusal(TEXT, TEXT)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.prune_arena_sessions(TIMESTAMPTZ)
  TO service_role;

COMMENT ON TABLE public.arena_sessions IS
  'Synthetic no-egress Arena allowances. Not money, custody, settlement, identity, or production authorization.';
COMMENT ON TABLE public.arena_shares IS
  'Explicitly published redacted projections; internal Arena rows remain private.';
