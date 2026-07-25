-- SPDX-License-Identifier: Apache-2.0
-- Forward-only private terminal provider records for consequence actuators.
--
-- The dedicated, tenant-mapped consequence_actuator_executor service
-- principal can append one exact signed terminal provider record per execution
-- envelope and read it back only under the complete attempt binding. Client
-- roles and the generic Supabase service_role receive no table or RPC access.

SET ROLE consequence_actuator_store_owner;

CREATE TABLE consequence_actuator_private.provider_records (
  tenant_id TEXT NOT NULL
    CHECK (pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 256),
  provider_id TEXT NOT NULL
    CHECK (pg_catalog.octet_length(provider_id) BETWEEN 1 AND 256),
  provider_account_id TEXT NOT NULL
    CHECK (pg_catalog.octet_length(provider_account_id) BETWEEN 1 AND 256),
  environment TEXT NOT NULL
    CHECK (pg_catalog.octet_length(environment) BETWEEN 1 AND 256),
  request_digest TEXT NOT NULL
    CHECK (request_digest ~ '^sha256:[a-f0-9]{64}$'),
  attempt_id TEXT NOT NULL
    CHECK (pg_catalog.octet_length(attempt_id) BETWEEN 1 AND 256),
  operation_id TEXT NOT NULL
    CHECK (pg_catalog.octet_length(operation_id) BETWEEN 1 AND 256),
  caid TEXT NOT NULL
    CHECK (pg_catalog.octet_length(caid) BETWEEN 1 AND 512),
  action_digest TEXT NOT NULL
    CHECK (action_digest ~ '^sha256:[a-f0-9]{64}$'),
  target_digest TEXT NOT NULL
    CHECK (target_digest ~ '^sha256:[a-f0-9]{64}$'),
  operation TEXT NOT NULL
    CHECK (pg_catalog.octet_length(operation) BETWEEN 1 AND 256),
  nonce TEXT NOT NULL
    CHECK (
      pg_catalog.octet_length(nonce) BETWEEN 22 AND 128
      AND nonce ~ '^[A-Za-z0-9_-]+$'
    ),
  envelope_digest TEXT NOT NULL
    CHECK (envelope_digest ~ '^sha256:[a-f0-9]{64}$'),
  provider_attribution_digest TEXT NOT NULL
    CHECK (provider_attribution_digest ~ '^sha256:[a-f0-9]{64}$'),
  outcome TEXT NOT NULL
    CHECK (outcome IN ('COMMITTED', 'NOT_COMMITTED')),
  provider_record_digest TEXT NOT NULL
    CHECK (provider_record_digest ~ '^sha256:[a-f0-9]{64}$'),
  provider_record JSONB NOT NULL
    CHECK (pg_catalog.jsonb_typeof(provider_record) = 'object'),
  recorded_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (
    tenant_id, provider_id, provider_account_id, environment, attempt_id
  ),
  UNIQUE (tenant_id, nonce),
  UNIQUE (tenant_id, envelope_digest),
  UNIQUE (tenant_id, provider_record_digest),
  FOREIGN KEY (tenant_id, nonce)
    REFERENCES public.consequence_actuator_envelopes (tenant_id, nonce)
    ON DELETE RESTRICT
);

ALTER TABLE consequence_actuator_private.provider_records
  OWNER TO consequence_actuator_store_owner;
ALTER TABLE consequence_actuator_private.provider_records
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE consequence_actuator_private.provider_records
  FORCE ROW LEVEL SECURITY;
CREATE POLICY consequence_actuator_provider_record_owner_all
  ON consequence_actuator_private.provider_records
  FOR ALL
  TO consequence_actuator_store_owner
  USING (TRUE)
  WITH CHECK (TRUE);
REVOKE ALL ON consequence_actuator_private.provider_records
  FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;

CREATE FUNCTION consequence_actuator_private.reject_provider_record_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
BEGIN
  RAISE EXCEPTION 'consequence actuator provider records are immutable'
    USING ERRCODE = '55000';
END
$fn$;

ALTER FUNCTION consequence_actuator_private.reject_provider_record_mutation()
  OWNER TO consequence_actuator_store_owner;
REVOKE ALL ON FUNCTION
  consequence_actuator_private.reject_provider_record_mutation()
  FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;

CREATE TRIGGER consequence_actuator_provider_records_immutable
BEFORE UPDATE OR DELETE
ON consequence_actuator_private.provider_records
FOR EACH ROW
EXECUTE FUNCTION consequence_actuator_private.reject_provider_record_mutation();

CREATE FUNCTION consequence_actuator_private.record_provider_record(
  p_provider_record JSONB,
  p_provider_record_digest TEXT
)
RETURNS TABLE(provider_record_digest TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_payload JSONB;
  v_attribution JSONB;
  v_attribution_signature JSONB;
  v_binding JSONB;
  v_response JSONB;
  v_recorded_at TIMESTAMPTZ;
  v_inserted BIGINT;
BEGIN
  IF pg_catalog.jsonb_typeof(p_provider_record) IS DISTINCT FROM 'object'
    OR pg_catalog.pg_column_size(p_provider_record) > 1048576
    OR p_provider_record_digest IS NULL
    OR p_provider_record_digest !~ '^sha256:[a-f0-9]{64}$'
    OR (
      SELECT pg_catalog.count(*)
      FROM pg_catalog.jsonb_object_keys(p_provider_record)
    ) <> 3
    OR NOT (
      p_provider_record ? '@version'
      AND p_provider_record ? 'payload'
      AND p_provider_record ? 'signature'
    )
    OR p_provider_record ->> '@version'
      IS DISTINCT FROM 'EP-GITHUB-PROVIDER-ATTRIBUTION-RECORD-v2'
  THEN
    RAISE EXCEPTION 'provider record is malformed' USING ERRCODE = '22023';
  END IF;

  v_payload := p_provider_record -> 'payload';
  v_attribution := v_payload -> 'provider_attribution';
  v_attribution_signature := v_attribution -> 'signature';
  v_binding := v_attribution -> 'payload';
  v_response := v_payload -> 'provider_response';

  IF pg_catalog.jsonb_typeof(v_payload) IS DISTINCT FROM 'object'
    OR (
      SELECT pg_catalog.count(*)
      FROM pg_catalog.jsonb_object_keys(v_payload)
    ) <> 7
    OR NOT (
      v_payload ? '@version'
      AND v_payload ? 'outcome'
      AND v_payload ? 'provider_record_id'
      AND v_payload ? 'recorded_at'
      AND v_payload ? 'provider_response'
      AND v_payload ? 'provider_attribution'
      AND v_payload ? 'provider_attribution_digest'
    )
    OR v_payload ->> '@version'
      IS DISTINCT FROM 'EP-GITHUB-PROVIDER-ATTRIBUTION-RECORD-v2'
    OR v_payload ->> 'outcome' NOT IN ('COMMITTED', 'NOT_COMMITTED')
    OR v_payload ->> 'provider_record_id'
      !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$'
    OR v_payload ->> 'provider_attribution_digest'
      !~ '^sha256:[a-f0-9]{64}$'
    OR pg_catalog.jsonb_typeof(v_attribution) IS DISTINCT FROM 'object'
    OR (
      SELECT pg_catalog.count(*)
      FROM pg_catalog.jsonb_object_keys(v_attribution)
    ) <> 2
    OR NOT (v_attribution ? 'payload' AND v_attribution ? 'signature')
    OR pg_catalog.jsonb_typeof(v_attribution_signature)
      IS DISTINCT FROM 'object'
    OR (
      SELECT pg_catalog.count(*)
      FROM pg_catalog.jsonb_object_keys(v_attribution_signature)
    ) <> 3
    OR NOT (
      v_attribution_signature ? 'algorithm'
      AND v_attribution_signature ? 'key_id'
      AND v_attribution_signature ? 'value'
    )
    OR v_attribution_signature ->> 'algorithm'
      IS DISTINCT FROM 'Ed25519'
    OR v_attribution_signature ->> 'key_id'
      !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$'
    OR v_attribution_signature ->> 'value'
      !~ '^[A-Za-z0-9_-]{86}$'
    OR pg_catalog.jsonb_typeof(v_binding) IS DISTINCT FROM 'object'
    OR (
      SELECT pg_catalog.count(*)
      FROM pg_catalog.jsonb_object_keys(v_binding)
    ) <> 17
    OR NOT (
      v_binding ? '@version'
      AND v_binding ? 'issuer_id'
      AND v_binding ? 'tenant_id'
      AND v_binding ? 'provider_id'
      AND v_binding ? 'provider_account_id'
      AND v_binding ? 'environment'
      AND v_binding ? 'request_digest'
      AND v_binding ? 'attempt_id'
      AND v_binding ? 'operation_id'
      AND v_binding ? 'caid'
      AND v_binding ? 'action_digest'
      AND v_binding ? 'target_digest'
      AND v_binding ? 'operation'
      AND v_binding ? 'nonce'
      AND v_binding ? 'envelope_digest'
      AND v_binding ? 'effect_digest'
      AND v_binding ? 'issued_at'
    )
    OR v_binding ->> '@version'
      IS DISTINCT FROM 'EP-CONSEQUENCE-PROVIDER-ATTRIBUTION-v1'
    OR v_binding ->> 'tenant_id' IS NULL
    OR pg_catalog.octet_length(v_binding ->> 'tenant_id') NOT BETWEEN 1 AND 256
    OR v_binding ->> 'provider_id' IS DISTINCT FROM 'github'
    OR v_binding ->> 'provider_account_id' IS NULL
    OR pg_catalog.octet_length(v_binding ->> 'provider_account_id')
      NOT BETWEEN 1 AND 256
    OR v_binding ->> 'environment' IS NULL
    OR pg_catalog.octet_length(v_binding ->> 'environment') NOT BETWEEN 1 AND 256
    OR v_binding ->> 'request_digest' !~ '^sha256:[a-f0-9]{64}$'
    OR v_binding ->> 'attempt_id' IS NULL
    OR pg_catalog.octet_length(v_binding ->> 'attempt_id') NOT BETWEEN 1 AND 256
    OR v_binding ->> 'operation_id' IS NULL
    OR pg_catalog.octet_length(v_binding ->> 'operation_id') NOT BETWEEN 1 AND 256
    OR v_binding ->> 'caid' IS NULL
    OR pg_catalog.octet_length(v_binding ->> 'caid') NOT BETWEEN 1 AND 512
    OR v_binding ->> 'action_digest' !~ '^sha256:[a-f0-9]{64}$'
    OR v_binding ->> 'target_digest' !~ '^sha256:[a-f0-9]{64}$'
    OR v_binding ->> 'operation' IS NULL
    OR pg_catalog.octet_length(v_binding ->> 'operation') NOT BETWEEN 1 AND 256
    OR v_binding ->> 'envelope_digest' !~ '^sha256:[a-f0-9]{64}$'
    OR v_binding ->> 'effect_digest' !~ '^sha256:[a-f0-9]{64}$'
    OR v_binding ->> 'nonce' !~ '^[A-Za-z0-9_-]{22,128}$'
    OR pg_catalog.jsonb_typeof(v_response) IS DISTINCT FROM 'object'
    OR pg_catalog.jsonb_typeof(p_provider_record -> 'signature')
      IS DISTINCT FROM 'object'
    OR (
      SELECT pg_catalog.count(*)
      FROM pg_catalog.jsonb_object_keys(p_provider_record -> 'signature')
    ) <> 3
    OR p_provider_record -> 'signature' ->> 'algorithm'
      IS DISTINCT FROM 'Ed25519'
    OR p_provider_record -> 'signature' ->> 'key_id'
      !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$'
    OR p_provider_record -> 'signature' ->> 'value'
      !~ '^[A-Za-z0-9_-]{86}$'
  THEN
    RAISE EXCEPTION 'provider record binding is malformed'
      USING ERRCODE = '22023';
  END IF;

  BEGIN
    v_recorded_at := (v_payload ->> 'recorded_at')::TIMESTAMPTZ;
  EXCEPTION
    WHEN OTHERS THEN
      RAISE EXCEPTION 'provider record time is malformed'
        USING ERRCODE = '22023';
  END;

  IF (
      v_payload ->> 'outcome' = 'COMMITTED'
      AND (
        (SELECT pg_catalog.count(*)
         FROM pg_catalog.jsonb_object_keys(v_response)) <> 4
        OR NOT (
          v_response ? 'status'
          AND v_response ? 'number'
          AND v_response ? 'title'
          AND v_response ? 'body'
        )
        OR pg_catalog.jsonb_typeof(v_response -> 'status')
          IS DISTINCT FROM 'number'
        OR v_response ->> 'status' IS DISTINCT FROM '200'
        OR pg_catalog.jsonb_typeof(v_response -> 'number')
          IS DISTINCT FROM 'number'
        OR v_response ->> 'number' !~ '^[1-9][0-9]*$'
        OR pg_catalog.jsonb_typeof(v_response -> 'title')
          IS DISTINCT FROM 'string'
        OR pg_catalog.octet_length(v_response ->> 'title') > 1024
        OR pg_catalog.jsonb_typeof(v_response -> 'body')
          IS DISTINCT FROM 'string'
        OR pg_catalog.octet_length(v_response ->> 'body') > 524288
      )
    )
    OR (
      v_payload ->> 'outcome' = 'NOT_COMMITTED'
      AND (
        (SELECT pg_catalog.count(*)
         FROM pg_catalog.jsonb_object_keys(v_response)) <> 1
        OR NOT (v_response ? 'status')
        OR pg_catalog.jsonb_typeof(v_response -> 'status')
          IS DISTINCT FROM 'number'
        OR v_response ->> 'status' NOT IN ('401', '403', '404', '409', '422')
      )
    )
  THEN
    RAISE EXCEPTION 'provider response is malformed' USING ERRCODE = '22023';
  END IF;

  PERFORM consequence_actuator_private.assert_tenant_principal(
    v_binding ->> 'tenant_id'
  );

  IF NOT EXISTS (
    SELECT 1
    FROM public.consequence_actuator_envelopes AS envelopes
    WHERE envelopes.tenant_id = v_binding ->> 'tenant_id'
      AND envelopes.attempt_id = v_binding ->> 'attempt_id'
      AND envelopes.action_digest = v_binding ->> 'action_digest'
      AND envelopes.caid = v_binding ->> 'caid'
      AND envelopes.provider_account_id = v_binding ->> 'provider_account_id'
      AND envelopes.target_digest = v_binding ->> 'target_digest'
      AND envelopes.operation = v_binding ->> 'operation'
      AND envelopes.idempotency_key = v_binding ->> 'operation_id'
      AND envelopes.nonce = v_binding ->> 'nonce'
      AND envelopes.envelope_digest = v_binding ->> 'envelope_digest'
  ) THEN
    RAISE EXCEPTION 'provider record does not match its execution envelope'
      USING ERRCODE = '23503';
  END IF;

  INSERT INTO consequence_actuator_private.provider_records (
    tenant_id,
    provider_id,
    provider_account_id,
    environment,
    request_digest,
    attempt_id,
    operation_id,
    caid,
    action_digest,
    target_digest,
    operation,
    nonce,
    envelope_digest,
    provider_attribution_digest,
    outcome,
    provider_record_digest,
    provider_record,
    recorded_at
  ) VALUES (
    v_binding ->> 'tenant_id',
    v_binding ->> 'provider_id',
    v_binding ->> 'provider_account_id',
    v_binding ->> 'environment',
    v_binding ->> 'request_digest',
    v_binding ->> 'attempt_id',
    v_binding ->> 'operation_id',
    v_binding ->> 'caid',
    v_binding ->> 'action_digest',
    v_binding ->> 'target_digest',
    v_binding ->> 'operation',
    v_binding ->> 'nonce',
    v_binding ->> 'envelope_digest',
    v_payload ->> 'provider_attribution_digest',
    v_payload ->> 'outcome',
    p_provider_record_digest,
    p_provider_record,
    v_recorded_at
  )
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS v_inserted = ROW_COUNT;

  IF v_inserted = 1 THEN
    RETURN QUERY SELECT p_provider_record_digest;
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM consequence_actuator_private.provider_records AS records
    WHERE records.tenant_id = v_binding ->> 'tenant_id'
      AND records.provider_id = v_binding ->> 'provider_id'
      AND records.provider_account_id = v_binding ->> 'provider_account_id'
      AND records.environment = v_binding ->> 'environment'
      AND records.attempt_id = v_binding ->> 'attempt_id'
      AND records.provider_record_digest = p_provider_record_digest
      AND records.provider_record = p_provider_record
  ) THEN
    RETURN QUERY SELECT p_provider_record_digest;
    RETURN;
  END IF;

  RAISE EXCEPTION 'provider record conflict' USING ERRCODE = '23505';
END
$fn$;

CREATE FUNCTION consequence_actuator_private.read_provider_record(
  p_tenant_id TEXT,
  p_provider_id TEXT,
  p_provider_account_id TEXT,
  p_environment TEXT,
  p_request_digest TEXT,
  p_attempt_id TEXT,
  p_operation_id TEXT,
  p_caid TEXT,
  p_action_digest TEXT
)
RETURNS TABLE(provider_record JSONB, provider_record_digest TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
BEGIN
  PERFORM consequence_actuator_private.assert_tenant_principal(p_tenant_id);
  RETURN QUERY
  SELECT records.provider_record, records.provider_record_digest
  FROM consequence_actuator_private.provider_records AS records
  WHERE records.tenant_id = p_tenant_id
    AND records.provider_id = p_provider_id
    AND records.provider_account_id = p_provider_account_id
    AND records.environment = p_environment
    AND records.request_digest = p_request_digest
    AND records.attempt_id = p_attempt_id
    AND records.operation_id = p_operation_id
    AND records.caid = p_caid
    AND records.action_digest = p_action_digest;
END
$fn$;

ALTER FUNCTION consequence_actuator_private.record_provider_record(JSONB, TEXT)
  OWNER TO consequence_actuator_store_owner;
ALTER FUNCTION consequence_actuator_private.read_provider_record(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) OWNER TO consequence_actuator_store_owner;
REVOKE ALL ON FUNCTION
  consequence_actuator_private.record_provider_record(JSONB, TEXT)
  FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;
REVOKE ALL ON FUNCTION consequence_actuator_private.read_provider_record(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;
GRANT EXECUTE ON FUNCTION
  consequence_actuator_private.record_provider_record(JSONB, TEXT)
  TO consequence_actuator_executor;
GRANT EXECUTE ON FUNCTION consequence_actuator_private.read_provider_record(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) TO consequence_actuator_executor;

COMMENT ON TABLE consequence_actuator_private.provider_records IS
  'Private immutable exact terminal provider responses and signed attribution, append-only and tenant-bound to consequence actuator envelopes.';

-- Restore the migration role so the Supabase migration journal can advance.
SET ROLE postgres;
