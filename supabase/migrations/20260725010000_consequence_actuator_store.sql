-- SPDX-License-Identifier: Apache-2.0
-- Credential-owning consequence actuator one-time envelope store.
--
-- Runtime principals have EXECUTE on two narrow functions and no direct table
-- DML. The NOLOGIN owner is separate from tenant-bound executor principals.

GRANT USAGE, CREATE ON SCHEMA public TO consequence_actuator_store_owner;

CREATE SCHEMA IF NOT EXISTS consequence_actuator_private
  AUTHORIZATION consequence_actuator_store_owner;
REVOKE ALL ON SCHEMA consequence_actuator_private
  FROM PUBLIC, anon, authenticated, service_role;

CREATE TABLE consequence_actuator_private.tenant_principals (
  tenant_id TEXT NOT NULL
    CHECK (pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 256),
  principal_name NAME NOT NULL,
  PRIMARY KEY (tenant_id, principal_name)
);
ALTER TABLE consequence_actuator_private.tenant_principals
  OWNER TO consequence_actuator_store_owner;
ALTER TABLE consequence_actuator_private.tenant_principals
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE consequence_actuator_private.tenant_principals
  FORCE ROW LEVEL SECURITY;
CREATE POLICY consequence_actuator_principal_owner_all
  ON consequence_actuator_private.tenant_principals
  FOR ALL
  TO consequence_actuator_store_owner USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON consequence_actuator_private.tenant_principals
  FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;

CREATE TABLE public.consequence_actuator_envelopes (
  tenant_id TEXT NOT NULL
    CHECK (pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 256),
  attempt_id TEXT NOT NULL
    CHECK (pg_catalog.octet_length(attempt_id) BETWEEN 1 AND 256),
  action_digest TEXT NOT NULL
    CHECK (action_digest ~ '^sha256:[a-f0-9]{64}$'),
  caid TEXT NOT NULL
    CHECK (pg_catalog.octet_length(caid) BETWEEN 1 AND 512),
  provider_account_id TEXT NOT NULL
    CHECK (pg_catalog.octet_length(provider_account_id) BETWEEN 1 AND 256),
  target_digest TEXT NOT NULL
    CHECK (target_digest ~ '^sha256:[a-f0-9]{64}$'),
  operation TEXT NOT NULL
    CHECK (pg_catalog.octet_length(operation) BETWEEN 1 AND 256),
  idempotency_key TEXT NOT NULL
    CHECK (pg_catalog.octet_length(idempotency_key) BETWEEN 1 AND 256),
  nonce TEXT NOT NULL
    CHECK (
      pg_catalog.octet_length(nonce) BETWEEN 22 AND 128
      AND nonce ~ '^[A-Za-z0-9_-]+$'
    ),
  issued_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  envelope_digest TEXT NOT NULL
    CHECK (envelope_digest ~ '^sha256:[a-f0-9]{64}$'),
  state TEXT NOT NULL DEFAULT 'RESERVED'
    CHECK (state IN ('RESERVED', 'CONSUMED')),
  outcome TEXT
    CHECK (outcome IN ('COMMITTED', 'INDETERMINATE')),
  reserved_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  consumed_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, nonce),
  UNIQUE (tenant_id, provider_account_id, operation, idempotency_key),
  CHECK (expires_at > issued_at),
  CHECK (
    (state = 'RESERVED' AND outcome IS NULL AND consumed_at IS NULL)
    OR
    (state = 'CONSUMED' AND outcome IS NOT NULL AND consumed_at IS NOT NULL)
  )
);

ALTER TABLE public.consequence_actuator_envelopes OWNER TO consequence_actuator_store_owner;
ALTER TABLE public.consequence_actuator_envelopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.consequence_actuator_envelopes FORCE ROW LEVEL SECURITY;
CREATE POLICY consequence_actuator_envelope_owner_all
  ON public.consequence_actuator_envelopes
  FOR ALL
  TO consequence_actuator_store_owner USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON public.consequence_actuator_envelopes
  FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;

CREATE FUNCTION consequence_actuator_private.assert_tenant_principal(
  p_tenant_id TEXT
)
RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  IF p_tenant_id IS NULL
    OR pg_catalog.octet_length(p_tenant_id) NOT BETWEEN 1 AND 256
  THEN
    RAISE EXCEPTION 'tenant binding required' USING ERRCODE = '22023';
  END IF;
  IF NOT pg_catalog.pg_has_role(SESSION_USER, 'consequence_actuator_executor', 'MEMBER') THEN
    RAISE EXCEPTION 'consequence actuator executor role required'
      USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM consequence_actuator_private.tenant_principals AS principals
    WHERE principals.principal_name = SESSION_USER
      AND principals.tenant_id = p_tenant_id
  ) THEN
    RAISE EXCEPTION 'tenant principal binding required'
      USING ERRCODE = '42501';
  END IF;
END
$fn$;

CREATE FUNCTION consequence_actuator_private.reserve_envelope(
  p_tenant_id TEXT,
  p_attempt_id TEXT,
  p_action_digest TEXT,
  p_caid TEXT,
  p_provider_account_id TEXT,
  p_target_digest TEXT,
  p_operation TEXT,
  p_idempotency_key TEXT,
  p_nonce TEXT,
  p_issued_at TIMESTAMPTZ,
  p_expires_at TIMESTAMPTZ,
  p_envelope_digest TEXT
)
RETURNS TABLE(envelope_digest TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM consequence_actuator_private.assert_tenant_principal(p_tenant_id);
  IF p_attempt_id IS NULL
    OR pg_catalog.octet_length(p_attempt_id) NOT BETWEEN 1 AND 256
    OR p_action_digest IS NULL
    OR p_action_digest !~ '^sha256:[a-f0-9]{64}$'
    OR p_caid IS NULL
    OR pg_catalog.octet_length(p_caid) NOT BETWEEN 1 AND 512
    OR p_provider_account_id IS NULL
    OR pg_catalog.octet_length(p_provider_account_id) NOT BETWEEN 1 AND 256
    OR p_target_digest IS NULL
    OR p_target_digest !~ '^sha256:[a-f0-9]{64}$'
    OR p_operation IS NULL
    OR pg_catalog.octet_length(p_operation) NOT BETWEEN 1 AND 256
    OR p_idempotency_key IS NULL
    OR pg_catalog.octet_length(p_idempotency_key) NOT BETWEEN 1 AND 256
    OR p_nonce IS NULL
    OR pg_catalog.octet_length(p_nonce) NOT BETWEEN 22 AND 128
    OR p_nonce !~ '^[A-Za-z0-9_-]+$'
    OR p_envelope_digest IS NULL
    OR p_envelope_digest !~ '^sha256:[a-f0-9]{64}$'
  THEN
    RAISE EXCEPTION 'execution envelope binding is malformed or unbounded'
      USING ERRCODE = '22023';
  END IF;
  IF p_expires_at <= pg_catalog.clock_timestamp()
    OR p_issued_at > pg_catalog.clock_timestamp() + INTERVAL '30 seconds'
    OR p_expires_at - p_issued_at > INTERVAL '5 minutes'
  THEN
    RAISE EXCEPTION 'execution envelope is outside the freshness window'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  INSERT INTO public.consequence_actuator_envelopes (
    tenant_id,
    attempt_id,
    action_digest,
    caid,
    provider_account_id,
    target_digest,
    operation,
    idempotency_key,
    nonce,
    issued_at,
    expires_at,
    envelope_digest
  ) VALUES (
    p_tenant_id,
    p_attempt_id,
    p_action_digest,
    p_caid,
    p_provider_account_id,
    p_target_digest,
    p_operation,
    p_idempotency_key,
    p_nonce,
    p_issued_at,
    p_expires_at,
    p_envelope_digest
  )
  ON CONFLICT DO NOTHING
  RETURNING consequence_actuator_envelopes.envelope_digest;
END
$fn$;

CREATE FUNCTION consequence_actuator_private.consume_envelope(
  p_tenant_id TEXT,
  p_attempt_id TEXT,
  p_action_digest TEXT,
  p_caid TEXT,
  p_provider_account_id TEXT,
  p_target_digest TEXT,
  p_operation TEXT,
  p_idempotency_key TEXT,
  p_nonce TEXT,
  p_envelope_digest TEXT,
  p_outcome TEXT
)
RETURNS TABLE(envelope_digest TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM consequence_actuator_private.assert_tenant_principal(p_tenant_id);
  IF p_attempt_id IS NULL
    OR pg_catalog.octet_length(p_attempt_id) NOT BETWEEN 1 AND 256
    OR p_action_digest IS NULL
    OR p_action_digest !~ '^sha256:[a-f0-9]{64}$'
    OR p_caid IS NULL
    OR pg_catalog.octet_length(p_caid) NOT BETWEEN 1 AND 512
    OR p_provider_account_id IS NULL
    OR pg_catalog.octet_length(p_provider_account_id) NOT BETWEEN 1 AND 256
    OR p_target_digest IS NULL
    OR p_target_digest !~ '^sha256:[a-f0-9]{64}$'
    OR p_operation IS NULL
    OR pg_catalog.octet_length(p_operation) NOT BETWEEN 1 AND 256
    OR p_idempotency_key IS NULL
    OR pg_catalog.octet_length(p_idempotency_key) NOT BETWEEN 1 AND 256
    OR p_nonce IS NULL
    OR pg_catalog.octet_length(p_nonce) NOT BETWEEN 22 AND 128
    OR p_nonce !~ '^[A-Za-z0-9_-]+$'
    OR p_envelope_digest IS NULL
    OR p_envelope_digest !~ '^sha256:[a-f0-9]{64}$'
  THEN
    RAISE EXCEPTION 'execution envelope binding is malformed or unbounded'
      USING ERRCODE = '22023';
  END IF;
  IF p_outcome NOT IN ('COMMITTED', 'INDETERMINATE') THEN
    RAISE EXCEPTION 'invalid consequence outcome' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  UPDATE public.consequence_actuator_envelopes
  SET state = 'CONSUMED',
      outcome = p_outcome,
      consumed_at = pg_catalog.clock_timestamp()
  WHERE tenant_id = p_tenant_id
    AND attempt_id = p_attempt_id
    AND action_digest = p_action_digest
    AND caid = p_caid
    AND provider_account_id = p_provider_account_id
    AND target_digest = p_target_digest
    AND operation = p_operation
    AND idempotency_key = p_idempotency_key
    AND nonce = p_nonce
    AND envelope_digest = p_envelope_digest
    AND state = 'RESERVED'
  RETURNING consequence_actuator_envelopes.envelope_digest;
END
$fn$;

ALTER FUNCTION consequence_actuator_private.assert_tenant_principal(TEXT)
  OWNER TO consequence_actuator_store_owner;
ALTER FUNCTION consequence_actuator_private.reserve_envelope(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
  TIMESTAMPTZ, TIMESTAMPTZ, TEXT
) OWNER TO consequence_actuator_store_owner;
ALTER FUNCTION consequence_actuator_private.consume_envelope(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) OWNER TO consequence_actuator_store_owner;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA consequence_actuator_private
  FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;
GRANT USAGE ON SCHEMA consequence_actuator_private
  TO consequence_actuator_executor;
GRANT EXECUTE ON FUNCTION consequence_actuator_private.reserve_envelope(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
  TIMESTAMPTZ, TIMESTAMPTZ, TEXT
),
consequence_actuator_private.consume_envelope(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
)
TO consequence_actuator_executor;

COMMENT ON TABLE public.consequence_actuator_envelopes IS
  'RPC-only permanent replay fence for signed consequence execution envelopes.';
COMMENT ON TABLE consequence_actuator_private.tenant_principals IS
  'Deployment-provisioned mapping from tenant IDs to dedicated actuator database principals.';

REVOKE CREATE ON SCHEMA public FROM consequence_actuator_store_owner;
