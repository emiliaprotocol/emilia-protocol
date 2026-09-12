-- SPDX-License-Identifier: Apache-2.0
-- Passwordless, email-verified accounts for EMILIA Works only. These accounts
-- map to inactive, unverified entity rows so existing Works ownership foreign
-- keys remain authoritative without creating a protocol API credential or a
-- public organization/agent claim.

CREATE TABLE public.works_accounts (
  account_id UUID PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
  owner_entity_id UUID NOT NULL UNIQUE
    REFERENCES public.entities(id) ON DELETE RESTRICT,
  email_digest TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (email_digest ~ '^hmac-sha256:[0-9a-f]{64}$'),
  display_name TEXT NOT NULL
    CHECK (pg_catalog.octet_length(display_name) BETWEEN 2 AND 200),
  email_verified_at TIMESTAMPTZ NOT NULL,
  consent_at TIMESTAMPTZ NOT NULL,
  email_notifications BOOLEAN NOT NULL DEFAULT FALSE,
  claims_verified BOOLEAN NOT NULL DEFAULT FALSE CHECK (claims_verified = FALSE),
  status TEXT COLLATE "C" NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('ACTIVE', 'DISABLED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  CHECK (email_verified_at >= consent_at)
);

CREATE TABLE public.works_account_email_challenges (
  challenge_id UUID PRIMARY KEY,
  email_digest TEXT COLLATE "C" NOT NULL
    CHECK (email_digest ~ '^hmac-sha256:[0-9a-f]{64}$'),
  client_digest TEXT COLLATE "C" NOT NULL
    CHECK (client_digest ~ '^hmac-sha256:[0-9a-f]{64}$'),
  code_digest TEXT COLLATE "C" NOT NULL
    CHECK (code_digest ~ '^hmac-sha256:[0-9a-f]{64}$'),
  mode TEXT COLLATE "C" NOT NULL CHECK (mode IN ('signup', 'login')),
  pending_display_name TEXT,
  consent BOOLEAN NOT NULL DEFAULT FALSE,
  email_notifications BOOLEAN NOT NULL DEFAULT FALSE,
  attempt_count SMALLINT NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 5),
  requested_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  delivery_confirmed_at TIMESTAMPTZ,
  consumed_at TIMESTAMPTZ,
  CHECK (expires_at > requested_at AND expires_at <= requested_at + INTERVAL '15 minutes'),
  CHECK (
    (mode = 'signup' AND pending_display_name IS NOT NULL AND consent = TRUE)
    OR (mode = 'login' AND pending_display_name IS NULL AND consent = FALSE)
  )
);

CREATE INDEX works_account_challenges_email_rate_idx
  ON public.works_account_email_challenges (email_digest, requested_at DESC);
CREATE INDEX works_account_challenges_client_rate_idx
  ON public.works_account_email_challenges (client_digest, requested_at DESC);

CREATE TABLE public.works_account_sessions (
  session_token_digest TEXT COLLATE "C" PRIMARY KEY
    CHECK (session_token_digest ~ '^sha256:[0-9a-f]{64}$'),
  account_id UUID NOT NULL REFERENCES public.works_accounts(account_id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '8 days'),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX works_account_sessions_account_idx
  ON public.works_account_sessions (account_id, created_at DESC);
CREATE INDEX works_account_sessions_active_expiry_idx
  ON public.works_account_sessions (expires_at)
  WHERE revoked_at IS NULL;

ALTER TABLE public.works_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_accounts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.works_account_email_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_account_email_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE public.works_account_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_account_sessions FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.works_accounts,
  public.works_account_email_challenges,
  public.works_account_sessions
  FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.works_accounts,
  public.works_account_email_challenges,
  public.works_account_sessions TO service_role;

CREATE POLICY works_accounts_service_only ON public.works_accounts
  FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY works_account_email_challenges_service_only
  ON public.works_account_email_challenges
  FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY works_account_sessions_service_only ON public.works_account_sessions
  FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

CREATE FUNCTION public.begin_works_account_email_challenge(
  p_challenge_id UUID,
  p_email_digest TEXT,
  p_client_digest TEXT,
  p_code_digest TEXT,
  p_mode TEXT,
  p_display_name TEXT,
  p_consent BOOLEAN,
  p_email_notifications BOOLEAN
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $begin_works_account_email_challenge$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_email_count INTEGER;
  v_client_count INTEGER;
BEGIN
  IF p_challenge_id IS NULL
    OR p_email_digest IS NULL
    OR p_email_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
    OR p_client_digest IS NULL
    OR p_client_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
    OR p_code_digest IS NULL
    OR p_code_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
    OR p_mode IS NULL
    OR p_mode NOT IN ('signup', 'login')
    OR (p_mode = 'signup' AND (
      p_display_name IS NULL
      OR pg_catalog.octet_length(p_display_name) NOT BETWEEN 2 AND 200
      OR p_consent IS DISTINCT FROM TRUE
    ))
    OR (p_mode = 'login' AND (p_display_name IS NOT NULL OR p_consent IS DISTINCT FROM FALSE))
  THEN
    RAISE EXCEPTION 'works account challenge input invalid' USING ERRCODE = '22023';
  END IF;

  -- Advisory locks serialize counters even when there is no prior row to lock.
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_email_digest, 0));
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_client_digest, 1));
  SELECT pg_catalog.count(*) INTO v_email_count
    FROM public.works_account_email_challenges
    WHERE email_digest = p_email_digest AND requested_at > v_now - INTERVAL '1 hour';
  SELECT pg_catalog.count(*) INTO v_client_count
    FROM public.works_account_email_challenges
    WHERE client_digest = p_client_digest AND requested_at > v_now - INTERVAL '1 hour';
  IF v_email_count >= 5 OR v_client_count >= 20 THEN
    RAISE EXCEPTION 'works account challenge rate limited' USING ERRCODE = 'WA001';
  END IF;

  INSERT INTO public.works_account_email_challenges (
    challenge_id, email_digest, client_digest, code_digest, mode,
    pending_display_name, consent, email_notifications, requested_at, expires_at
  ) VALUES (
    p_challenge_id, p_email_digest, p_client_digest, p_code_digest, p_mode,
    p_display_name, p_consent, COALESCE(p_email_notifications, FALSE), v_now,
    v_now + INTERVAL '10 minutes'
  );
  RETURN pg_catalog.jsonb_build_object('challenge_id', p_challenge_id);
END
$begin_works_account_email_challenge$;

CREATE FUNCTION public.mark_works_account_email_delivery(
  p_challenge_id UUID,
  p_code_digest TEXT,
  p_delivered BOOLEAN
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $mark_works_account_email_delivery$
DECLARE
  v_challenge public.works_account_email_challenges%ROWTYPE;
BEGIN
  SELECT * INTO v_challenge
  FROM public.works_account_email_challenges
  WHERE challenge_id = p_challenge_id AND code_digest = p_code_digest
  FOR UPDATE;
  IF NOT FOUND OR v_challenge.consumed_at IS NOT NULL THEN RETURN FALSE; END IF;
  IF p_delivered THEN
    UPDATE public.works_account_email_challenges
      SET delivery_confirmed_at = pg_catalog.transaction_timestamp()
      WHERE challenge_id = p_challenge_id;
  ELSE
    UPDATE public.works_account_email_challenges
      SET consumed_at = pg_catalog.transaction_timestamp()
      WHERE challenge_id = p_challenge_id;
  END IF;
  RETURN TRUE;
END
$mark_works_account_email_delivery$;

CREATE FUNCTION public.exchange_works_account_email_challenge(
  p_challenge_id UUID,
  p_email_digest TEXT,
  p_code_digest TEXT,
  p_session_token_digest TEXT,
  p_session_expires_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $exchange_works_account_email_challenge$
DECLARE
  v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
  v_challenge public.works_account_email_challenges%ROWTYPE;
  v_account public.works_accounts%ROWTYPE;
  v_entity_id UUID;
BEGIN
  IF p_challenge_id IS NULL
    OR p_email_digest IS NULL
    OR p_email_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
    OR p_code_digest IS NULL
    OR p_code_digest !~ '^hmac-sha256:[0-9a-f]{64}$'
    OR p_session_token_digest IS NULL
    OR p_session_token_digest !~ '^sha256:[0-9a-f]{64}$'
    OR p_session_expires_at IS NULL
    OR p_session_expires_at <= v_now
    OR p_session_expires_at > v_now + INTERVAL '8 days'
  THEN RAISE EXCEPTION 'works account exchange input invalid' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_challenge
  FROM public.works_account_email_challenges
  WHERE challenge_id = p_challenge_id
  FOR UPDATE;
  IF NOT FOUND
    OR v_challenge.consumed_at IS NOT NULL
    OR v_challenge.delivery_confirmed_at IS NULL
    OR v_challenge.expires_at <= v_now
    OR v_challenge.attempt_count >= 5
  THEN RETURN pg_catalog.jsonb_build_object('status', 'INVALID'); END IF;

  IF v_challenge.email_digest IS DISTINCT FROM p_email_digest
    OR v_challenge.code_digest IS DISTINCT FROM p_code_digest
  THEN
    UPDATE public.works_account_email_challenges SET
      attempt_count = attempt_count + 1,
      consumed_at = CASE WHEN attempt_count + 1 >= 5 THEN v_now ELSE consumed_at END
    WHERE challenge_id = p_challenge_id;
    RETURN pg_catalog.jsonb_build_object('status', 'INVALID');
  END IF;

  UPDATE public.works_account_email_challenges
    SET consumed_at = v_now
    WHERE challenge_id = p_challenge_id;

  -- Two valid signup challenges for the same email may be verified
  -- concurrently. Serialize identity creation by the keyed digest so they map
  -- to one durable account rather than racing the unique constraint.
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_email_digest, 2));
  SELECT * INTO v_account
  FROM public.works_accounts
  WHERE email_digest = p_email_digest
  FOR UPDATE;

  IF NOT FOUND THEN
    IF v_challenge.mode IS DISTINCT FROM 'signup' THEN
      RETURN pg_catalog.jsonb_build_object('status', 'INVALID');
    END IF;
    v_entity_id := extensions.gen_random_uuid();
    -- Some deployed installations retain the deprecated, non-null
    -- entities.api_key_hash column. Populate it with an unrecoverable random
    -- digest, never a bearer credential, while remaining compatible with
    -- clean schemas where migration 028 removed the column.
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'entities'
        AND column_name = 'api_key_hash'
    ) THEN
      EXECUTE $entity_with_legacy_hash$
        INSERT INTO public.entities (
          id, entity_id, owner_id, display_name, entity_type, description,
          capabilities, verified, status, organization_id, is_operator, api_key_hash
        ) VALUES ($1, $2, $3, $4, 'service_provider', $5, '[]'::JSONB,
          FALSE, 'inactive', $6, FALSE, $7)
      $entity_with_legacy_hash$
      USING v_entity_id,
        'works-account-' || pg_catalog.replace(v_entity_id::TEXT, '-', ''),
        'ep_works_owner_' || pg_catalog.replace(extensions.gen_random_uuid()::TEXT, '-', ''),
        v_challenge.pending_display_name,
        'Private EMILIA Works account. No organization or agent claim is verified.',
        '@org:works-account:' || pg_catalog.replace(extensions.gen_random_uuid()::TEXT, '-', ''),
        'sha256:' || pg_catalog.encode(extensions.gen_random_bytes(32), 'hex');
    ELSE
      INSERT INTO public.entities (
        id, entity_id, owner_id, display_name, entity_type, description,
        capabilities, verified, status, organization_id, is_operator
      ) VALUES (
        v_entity_id,
        'works-account-' || pg_catalog.replace(v_entity_id::TEXT, '-', ''),
        'ep_works_owner_' || pg_catalog.replace(extensions.gen_random_uuid()::TEXT, '-', ''),
        v_challenge.pending_display_name,
        'service_provider',
        'Private EMILIA Works account. No organization or agent claim is verified.',
        '[]'::JSONB,
        FALSE,
        'inactive',
        '@org:works-account:' || pg_catalog.replace(extensions.gen_random_uuid()::TEXT, '-', ''),
        FALSE
      );
    END IF;
    INSERT INTO public.works_accounts (
      owner_entity_id, email_digest, display_name, email_verified_at,
      consent_at, email_notifications
    ) VALUES (
      v_entity_id, p_email_digest, v_challenge.pending_display_name, v_now,
      v_now, v_challenge.email_notifications
    ) RETURNING * INTO v_account;
  END IF;

  IF v_account.status IS DISTINCT FROM 'ACTIVE' THEN
    RETURN pg_catalog.jsonb_build_object('status', 'INVALID');
  END IF;

  INSERT INTO public.works_account_sessions (
    session_token_digest, account_id, created_at, expires_at
  ) VALUES (p_session_token_digest, v_account.account_id, v_now, p_session_expires_at);

  RETURN pg_catalog.jsonb_build_object(
    'status', 'AUTHENTICATED',
    'account_id', v_account.account_id,
    'owner_entity_id', v_account.owner_entity_id,
    'display_name', v_account.display_name,
    'email_notifications', v_account.email_notifications
  );
END
$exchange_works_account_email_challenge$;

CREATE FUNCTION public.read_works_account_session(p_session_token_digest TEXT)
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $read_works_account_session$
  SELECT pg_catalog.jsonb_build_object(
    'account_id', account.account_id,
    'owner_entity_id', account.owner_entity_id,
    'display_name', account.display_name,
    'email_notifications', account.email_notifications
  )
  FROM public.works_account_sessions AS session
  JOIN public.works_accounts AS account USING (account_id)
  WHERE session.session_token_digest = p_session_token_digest
    AND session.revoked_at IS NULL
    AND session.expires_at > pg_catalog.transaction_timestamp()
    AND account.status = 'ACTIVE'
    AND account.email_verified_at IS NOT NULL
$read_works_account_session$;

CREATE FUNCTION public.revoke_works_account_session(p_session_token_digest TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
SET row_security = 'on'
AS $revoke_works_account_session$
BEGIN
  UPDATE public.works_account_sessions
    SET revoked_at = pg_catalog.transaction_timestamp()
    WHERE session_token_digest = p_session_token_digest
      AND revoked_at IS NULL;
  RETURN FOUND;
END
$revoke_works_account_session$;

REVOKE ALL ON FUNCTION public.begin_works_account_email_challenge(UUID, TEXT, TEXT, TEXT, TEXT, TEXT, BOOLEAN, BOOLEAN)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.mark_works_account_email_delivery(UUID, TEXT, BOOLEAN)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.exchange_works_account_email_challenge(UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.read_works_account_session(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.revoke_works_account_session(TEXT)
  FROM PUBLIC, anon, authenticated, service_role;

GRANT EXECUTE ON FUNCTION public.begin_works_account_email_challenge(UUID, TEXT, TEXT, TEXT, TEXT, TEXT, BOOLEAN, BOOLEAN) TO service_role;
GRANT EXECUTE ON FUNCTION public.mark_works_account_email_delivery(UUID, TEXT, BOOLEAN) TO service_role;
GRANT EXECUTE ON FUNCTION public.exchange_works_account_email_challenge(UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ) TO service_role;
GRANT EXECUTE ON FUNCTION public.read_works_account_session(TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.revoke_works_account_session(TEXT) TO service_role;

COMMENT ON TABLE public.works_accounts IS
  'Email-verified identities scoped only to EMILIA Works; no protocol API key or verified organization or agent claim.';
