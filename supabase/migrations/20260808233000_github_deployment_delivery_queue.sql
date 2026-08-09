-- SPDX-License-Identifier: Apache-2.0
-- Durable, tenant-bound inbox and leased work queue for authenticated GitHub
-- deployment-protection deliveries. Runtime principals receive RPC access only.

GRANT consequence_actuator_store_owner TO CURRENT_USER
  WITH INHERIT FALSE, SET TRUE;
SET ROLE consequence_actuator_store_owner;

CREATE TABLE consequence_actuator_private.github_deployment_deliveries (
  tenant_id TEXT NOT NULL
    CHECK (pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 256),
  delivery_id TEXT NOT NULL
    CHECK (
      pg_catalog.octet_length(delivery_id) BETWEEN 16 AND 128
      AND delivery_id ~ '^[A-Za-z0-9][A-Za-z0-9-]+$'
    ),
  request_digest TEXT NOT NULL
    CHECK (request_digest ~ '^sha256:[a-f0-9]{64}$'),
  body BYTEA NOT NULL
    CHECK (pg_catalog.octet_length(body) BETWEEN 1 AND 1048576),
  headers JSONB NOT NULL
    CHECK (
      pg_catalog.jsonb_typeof(headers) = 'object'
      AND pg_catalog.pg_column_size(headers) <= 32768
    ),
  state TEXT NOT NULL DEFAULT 'QUEUED'
    CHECK (state IN (
      'QUEUED', 'PROCESSING', 'APPROVED', 'REFUSED', 'INDETERMINATE'
    )),
  attempt_count INTEGER NOT NULL DEFAULT 0
    CHECK (attempt_count BETWEEN 0 AND 100),
  available_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  lease_owner TEXT
    CHECK (
      lease_owner IS NULL
      OR pg_catalog.octet_length(lease_owner) BETWEEN 1 AND 256
    ),
  lease_token TEXT
    CHECK (
      lease_token IS NULL
      OR pg_catalog.octet_length(lease_token) BETWEEN 1 AND 256
    ),
  lease_expires_at TIMESTAMPTZ,
  reason TEXT CHECK (
    reason IS NULL OR pg_catalog.octet_length(reason) BETWEEN 1 AND 512
  ),
  result JSONB CHECK (
    result IS NULL
    OR (
      pg_catalog.jsonb_typeof(result) = 'object'
      AND pg_catalog.pg_column_size(result) <= 131072
    )
  ),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY (tenant_id, delivery_id),
  CHECK (
    (state = 'PROCESSING'
      AND lease_owner IS NOT NULL
      AND lease_token IS NOT NULL
      AND lease_expires_at IS NOT NULL)
    OR
    (state <> 'PROCESSING'
      AND lease_owner IS NULL
      AND lease_token IS NULL
      AND lease_expires_at IS NULL)
  )
);

CREATE INDEX github_deployment_deliveries_due_idx
  ON consequence_actuator_private.github_deployment_deliveries (
    tenant_id, available_at, created_at
  )
  WHERE state = 'QUEUED';
CREATE INDEX github_deployment_deliveries_expired_lease_idx
  ON consequence_actuator_private.github_deployment_deliveries (
    tenant_id, lease_expires_at
  )
  WHERE state = 'PROCESSING';

ALTER TABLE consequence_actuator_private.github_deployment_deliveries
  OWNER TO consequence_actuator_store_owner;
ALTER TABLE consequence_actuator_private.github_deployment_deliveries
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE consequence_actuator_private.github_deployment_deliveries
  FORCE ROW LEVEL SECURITY;
CREATE POLICY consequence_actuator_github_delivery_owner_all
  ON consequence_actuator_private.github_deployment_deliveries
  FOR ALL TO consequence_actuator_store_owner
  USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON consequence_actuator_private.github_deployment_deliveries
  FROM PUBLIC, anon, authenticated, service_role,
    consequence_actuator_executor;

CREATE FUNCTION consequence_actuator_private.github_deployment_delivery_json(
  p_record consequence_actuator_private.github_deployment_deliveries
)
RETURNS JSONB
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
  SELECT pg_catalog.jsonb_build_object(
    'tenant_id', p_record.tenant_id,
    'delivery_id', p_record.delivery_id,
    'request_digest', p_record.request_digest,
    'body', pg_catalog.encode(p_record.body, 'base64'),
    'headers', p_record.headers,
    'state', p_record.state,
    'attempt_count', p_record.attempt_count,
    'available_at', p_record.available_at,
    'lease_owner', p_record.lease_owner,
    'lease_token', p_record.lease_token,
    'lease_expires_at', p_record.lease_expires_at,
    'reason', p_record.reason,
    'result', p_record.result,
    'created_at', p_record.created_at,
    'updated_at', p_record.updated_at
  )
$fn$;

CREATE FUNCTION consequence_actuator_private.enqueue_github_deployment_delivery(
  p_tenant_id TEXT,
  p_delivery_id TEXT,
  p_request_digest TEXT,
  p_body BYTEA,
  p_headers JSONB
)
RETURNS TABLE(outcome TEXT, delivery JSONB)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_record consequence_actuator_private.github_deployment_deliveries%ROWTYPE;
  v_inserted INTEGER;
BEGIN
  PERFORM consequence_actuator_private.assert_tenant_principal(p_tenant_id);
  IF p_delivery_id IS NULL
      OR pg_catalog.octet_length(p_delivery_id) NOT BETWEEN 16 AND 128
      OR p_delivery_id !~ '^[A-Za-z0-9][A-Za-z0-9-]+$'
      OR p_request_digest !~ '^sha256:[a-f0-9]{64}$'
      OR p_body IS NULL
      OR pg_catalog.octet_length(p_body) NOT BETWEEN 1 AND 1048576
      OR pg_catalog.jsonb_typeof(p_headers) <> 'object'
      OR pg_catalog.pg_column_size(p_headers) > 32768
  THEN
    RAISE EXCEPTION 'github deployment delivery invalid'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO consequence_actuator_private.github_deployment_deliveries (
    tenant_id, delivery_id, request_digest, body, headers
  ) VALUES (
    p_tenant_id, p_delivery_id, p_request_digest, p_body, p_headers
  ) ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS v_inserted = ROW_COUNT;

  SELECT * INTO STRICT v_record
  FROM consequence_actuator_private.github_deployment_deliveries AS queued
  WHERE queued.tenant_id = p_tenant_id
    AND queued.delivery_id = p_delivery_id;

  IF v_record.request_digest <> p_request_digest THEN
    RETURN QUERY SELECT 'CONFLICT'::TEXT,
      consequence_actuator_private.github_deployment_delivery_json(v_record);
    RETURN;
  END IF;
  RETURN QUERY SELECT
    CASE WHEN v_inserted = 1 THEN 'ENQUEUED'::TEXT ELSE 'DUPLICATE'::TEXT END,
    consequence_actuator_private.github_deployment_delivery_json(v_record);
END
$fn$;

CREATE FUNCTION consequence_actuator_private.claim_github_deployment_delivery(
  p_tenant_id TEXT,
  p_lease_owner TEXT,
  p_lease_token TEXT,
  p_lease_ms BIGINT
)
RETURNS TABLE(delivery JSONB)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_record consequence_actuator_private.github_deployment_deliveries%ROWTYPE;
BEGIN
  PERFORM consequence_actuator_private.assert_tenant_principal(p_tenant_id);
  IF p_lease_owner IS NULL
      OR pg_catalog.octet_length(p_lease_owner) NOT BETWEEN 1 AND 256
      OR p_lease_token IS NULL
      OR pg_catalog.octet_length(p_lease_token) NOT BETWEEN 1 AND 256
      OR p_lease_ms NOT BETWEEN 100 AND 300000
  THEN
    RAISE EXCEPTION 'github deployment lease invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_record
  FROM consequence_actuator_private.github_deployment_deliveries AS queued
  WHERE queued.tenant_id = p_tenant_id
    AND (
      (queued.state = 'QUEUED'
        AND queued.available_at <= pg_catalog.clock_timestamp())
      OR
      (queued.state = 'PROCESSING'
        AND queued.lease_expires_at <= pg_catalog.clock_timestamp())
    )
  ORDER BY queued.available_at, queued.created_at
  FOR UPDATE SKIP LOCKED
  LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;

  UPDATE consequence_actuator_private.github_deployment_deliveries AS queued
  SET state = 'PROCESSING',
      attempt_count = queued.attempt_count + 1,
      lease_owner = p_lease_owner,
      lease_token = p_lease_token,
      lease_expires_at = pg_catalog.clock_timestamp()
        + (p_lease_ms * INTERVAL '1 millisecond'),
      updated_at = pg_catalog.clock_timestamp()
  WHERE queued.tenant_id = v_record.tenant_id
    AND queued.delivery_id = v_record.delivery_id
  RETURNING * INTO STRICT v_record;

  RETURN QUERY SELECT
    consequence_actuator_private.github_deployment_delivery_json(v_record);
END
$fn$;

CREATE FUNCTION consequence_actuator_private.complete_github_deployment_delivery(
  p_tenant_id TEXT,
  p_delivery_id TEXT,
  p_request_digest TEXT,
  p_lease_token TEXT,
  p_state TEXT,
  p_reason TEXT,
  p_result JSONB
)
RETURNS TABLE(delivery JSONB)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_record consequence_actuator_private.github_deployment_deliveries%ROWTYPE;
BEGIN
  PERFORM consequence_actuator_private.assert_tenant_principal(p_tenant_id);
  IF p_state NOT IN ('APPROVED', 'REFUSED', 'INDETERMINATE')
      OR p_request_digest !~ '^sha256:[a-f0-9]{64}$'
      OR p_lease_token IS NULL
      OR pg_catalog.octet_length(p_lease_token) NOT BETWEEN 1 AND 256
      OR (p_reason IS NOT NULL AND pg_catalog.octet_length(p_reason) > 512)
      OR (p_result IS NOT NULL AND (
        pg_catalog.jsonb_typeof(p_result) <> 'object'
        OR pg_catalog.pg_column_size(p_result) > 131072
      ))
  THEN
    RAISE EXCEPTION 'github deployment completion invalid'
      USING ERRCODE = '22023';
  END IF;
  UPDATE consequence_actuator_private.github_deployment_deliveries AS queued
  SET state = p_state,
      reason = p_reason,
      result = p_result,
      lease_owner = NULL,
      lease_token = NULL,
      lease_expires_at = NULL,
      updated_at = pg_catalog.clock_timestamp()
  WHERE queued.tenant_id = p_tenant_id
    AND queued.delivery_id = p_delivery_id
    AND queued.request_digest = p_request_digest
    AND queued.state = 'PROCESSING'
    AND queued.lease_token = p_lease_token
  RETURNING * INTO v_record;
  IF NOT FOUND THEN RETURN; END IF;
  RETURN QUERY SELECT
    consequence_actuator_private.github_deployment_delivery_json(v_record);
END
$fn$;

CREATE FUNCTION consequence_actuator_private.retry_github_deployment_delivery(
  p_tenant_id TEXT,
  p_delivery_id TEXT,
  p_request_digest TEXT,
  p_lease_token TEXT,
  p_reason TEXT,
  p_delay_ms BIGINT
)
RETURNS TABLE(delivery JSONB)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_record consequence_actuator_private.github_deployment_deliveries%ROWTYPE;
BEGIN
  PERFORM consequence_actuator_private.assert_tenant_principal(p_tenant_id);
  IF p_delay_ms NOT BETWEEN 0 AND 3600000
      OR p_request_digest !~ '^sha256:[a-f0-9]{64}$'
      OR p_lease_token IS NULL
      OR pg_catalog.octet_length(p_lease_token) NOT BETWEEN 1 AND 256
      OR p_reason IS NULL
      OR pg_catalog.octet_length(p_reason) NOT BETWEEN 1 AND 512
  THEN
    RAISE EXCEPTION 'github deployment retry invalid'
      USING ERRCODE = '22023';
  END IF;
  UPDATE consequence_actuator_private.github_deployment_deliveries AS queued
  SET state = 'QUEUED',
      available_at = pg_catalog.clock_timestamp()
        + (p_delay_ms * INTERVAL '1 millisecond'),
      reason = p_reason,
      lease_owner = NULL,
      lease_token = NULL,
      lease_expires_at = NULL,
      updated_at = pg_catalog.clock_timestamp()
  WHERE queued.tenant_id = p_tenant_id
    AND queued.delivery_id = p_delivery_id
    AND queued.request_digest = p_request_digest
    AND queued.state = 'PROCESSING'
    AND queued.lease_token = p_lease_token
  RETURNING * INTO v_record;
  IF NOT FOUND THEN RETURN; END IF;
  RETURN QUERY SELECT
    consequence_actuator_private.github_deployment_delivery_json(v_record);
END
$fn$;

CREATE FUNCTION consequence_actuator_private.read_github_deployment_delivery(
  p_tenant_id TEXT,
  p_delivery_id TEXT
)
RETURNS TABLE(delivery JSONB)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
BEGIN
  PERFORM consequence_actuator_private.assert_tenant_principal(p_tenant_id);
  RETURN QUERY
  SELECT consequence_actuator_private.github_deployment_delivery_json(queued)
  FROM consequence_actuator_private.github_deployment_deliveries AS queued
  WHERE queued.tenant_id = p_tenant_id
    AND queued.delivery_id = p_delivery_id;
END
$fn$;

ALTER FUNCTION consequence_actuator_private.github_deployment_delivery_json(
  consequence_actuator_private.github_deployment_deliveries
) OWNER TO consequence_actuator_store_owner;
ALTER FUNCTION consequence_actuator_private.enqueue_github_deployment_delivery(
  TEXT, TEXT, TEXT, BYTEA, JSONB
) OWNER TO consequence_actuator_store_owner;
ALTER FUNCTION consequence_actuator_private.claim_github_deployment_delivery(
  TEXT, TEXT, TEXT, BIGINT
) OWNER TO consequence_actuator_store_owner;
ALTER FUNCTION consequence_actuator_private.complete_github_deployment_delivery(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB
) OWNER TO consequence_actuator_store_owner;
ALTER FUNCTION consequence_actuator_private.retry_github_deployment_delivery(
  TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT
) OWNER TO consequence_actuator_store_owner;
ALTER FUNCTION consequence_actuator_private.read_github_deployment_delivery(
  TEXT, TEXT
) OWNER TO consequence_actuator_store_owner;

REVOKE ALL ON FUNCTION consequence_actuator_private.github_deployment_delivery_json(
  consequence_actuator_private.github_deployment_deliveries
) FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;
REVOKE ALL ON FUNCTION consequence_actuator_private.enqueue_github_deployment_delivery(
  TEXT, TEXT, TEXT, BYTEA, JSONB
) FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;
REVOKE ALL ON FUNCTION consequence_actuator_private.claim_github_deployment_delivery(
  TEXT, TEXT, TEXT, BIGINT
) FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;
REVOKE ALL ON FUNCTION consequence_actuator_private.complete_github_deployment_delivery(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB
) FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;
REVOKE ALL ON FUNCTION consequence_actuator_private.retry_github_deployment_delivery(
  TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT
) FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;
REVOKE ALL ON FUNCTION consequence_actuator_private.read_github_deployment_delivery(
  TEXT, TEXT
) FROM PUBLIC, anon, authenticated, service_role, consequence_actuator_executor;

GRANT EXECUTE ON FUNCTION consequence_actuator_private.enqueue_github_deployment_delivery(
  TEXT, TEXT, TEXT, BYTEA, JSONB
) TO consequence_actuator_executor;
GRANT EXECUTE ON FUNCTION consequence_actuator_private.claim_github_deployment_delivery(
  TEXT, TEXT, TEXT, BIGINT
) TO consequence_actuator_executor;
GRANT EXECUTE ON FUNCTION consequence_actuator_private.complete_github_deployment_delivery(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, JSONB
) TO consequence_actuator_executor;
GRANT EXECUTE ON FUNCTION consequence_actuator_private.retry_github_deployment_delivery(
  TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT
) TO consequence_actuator_executor;
GRANT EXECUTE ON FUNCTION consequence_actuator_private.read_github_deployment_delivery(
  TEXT, TEXT
) TO consequence_actuator_executor;

COMMENT ON TABLE consequence_actuator_private.github_deployment_deliveries IS
  'Exact authenticated GitHub deployment-protection deliveries, durably queued before acknowledgement and leased to one worker at a time.';

RESET ROLE;
REVOKE consequence_actuator_store_owner FROM CURRENT_USER;
