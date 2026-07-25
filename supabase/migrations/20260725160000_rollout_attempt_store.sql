-- SPDX-License-Identifier: Apache-2.0
-- Forward-only durable rollout-attempt claim and terminal store.
--
-- A deployment-provisioned login must be a member of the dedicated NOLOGIN
-- rollout_attempt_executor role. The generic Supabase API roles, including
-- service_role, receive no schema, table, or function authority.

DO $roles$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname = 'rollout_attempt_store_owner'
  ) THEN
    CREATE ROLE rollout_attempt_store_owner NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname = 'rollout_attempt_executor'
  ) THEN
    CREATE ROLE rollout_attempt_executor NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

ALTER ROLE rollout_attempt_store_owner NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE rollout_attempt_executor NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

DO $role_separation$
BEGIN
  IF pg_catalog.pg_has_role(
      'rollout_attempt_executor',
      'rollout_attempt_store_owner',
      'MEMBER'
    )
    OR pg_catalog.pg_has_role(
      'rollout_attempt_store_owner',
      'rollout_attempt_executor',
      'MEMBER'
    )
  THEN
    RAISE EXCEPTION
      'rollout attempt owner and executor roles must be membership-disjoint'
      USING ERRCODE = '42501';
  END IF;
END
$role_separation$;

GRANT rollout_attempt_store_owner TO CURRENT_USER;

CREATE SCHEMA rollout_attempt_private
  AUTHORIZATION rollout_attempt_store_owner;
REVOKE ALL ON SCHEMA rollout_attempt_private
  FROM PUBLIC, anon, authenticated, service_role, rollout_attempt_executor;

GRANT USAGE ON SCHEMA extensions
  TO rollout_attempt_store_owner;
GRANT EXECUTE ON FUNCTION extensions.digest(BYTEA, TEXT)
  TO rollout_attempt_store_owner;

SET ROLE rollout_attempt_store_owner;

ALTER DEFAULT PRIVILEGES IN SCHEMA rollout_attempt_private
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA rollout_attempt_private
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE rollout_attempt_private.claims (
  claim_sha256 TEXT COLLATE "C" NOT NULL
    CHECK (claim_sha256 ~ '^[0-9a-f]{64}$'),
  authorization_id TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(authorization_id) BETWEEN 3 AND 256
      AND authorization_id ~ '^[A-Za-z0-9:_.@-]+$'
    ),
  rollout_nonce TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(rollout_nonce) BETWEEN 22 AND 128
      AND rollout_nonce ~ '^[A-Za-z0-9_-]+$'
    ),
  request_sha256 TEXT COLLATE "C" NOT NULL
    CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
  pre_resource_version TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(pre_resource_version) BETWEEN 1 AND 512
      AND pre_resource_version !~ '[[:space:]]'
    ),
  project_id TEXT COLLATE "C" NOT NULL
    CHECK (project_id ~ '^[a-z][a-z0-9-]{0,62}$'),
  region TEXT COLLATE "C" NOT NULL
    CHECK (region ~ '^[a-z][a-z0-9-]{0,62}$'),
  release_id TEXT COLLATE "C" NOT NULL
    CHECK (release_id ~ '^[a-z][a-z0-9-]{0,62}$'),
  transition TEXT COLLATE "C" NOT NULL
    CHECK (transition IN (
      'apply-decision-1',
      'apply-decision-10',
      'apply-decision-50',
      'apply-decision-100',
      'apply-actuator-100',
      'apply-rollback-actuator',
      'apply-rollback-decision'
    )),
  service TEXT COLLATE "C" NOT NULL
    CHECK (service ~ '^[a-z][a-z0-9-]{0,62}$'),
  config_sha256 TEXT COLLATE "C" NOT NULL
    CHECK (config_sha256 ~ '^[0-9a-f]{64}$'),
  deployer_principal TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(deployer_principal) BETWEEN 1 AND 512
      AND deployer_principal ~
        '^serviceAccount:[^@[:space:],]+@[^@[:space:],]+[.]iam[.]gserviceaccount[.]com$'
    ),
  workflow_ref TEXT COLLATE "C" NOT NULL
    CHECK (
      workflow_ref =
        'emiliaprotocol/emilia-protocol/.github/workflows/consequence-control-deploy.yml@refs/heads/main'
    ),
  workflow_sha TEXT COLLATE "C" NOT NULL
    CHECK (workflow_sha ~ '^[0-9a-f]{40}$'),
  wif_provider TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(wif_provider) BETWEEN 1 AND 512
      AND wif_provider ~
        '^projects/[1-9][0-9]*/locations/global/workloadIdentityPools/[a-z][a-z0-9-]{3,31}/providers/[a-z][a-z0-9-]{3,31}$'
    ),
  claim_payload JSONB NOT NULL
    CHECK (
      pg_catalog.jsonb_typeof(claim_payload) = 'object'
      AND pg_catalog.pg_column_size(claim_payload) <= 32768
    ),
  claimed_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY (claim_sha256),
  UNIQUE (authorization_id),
  UNIQUE (rollout_nonce),
  UNIQUE (authorization_id, rollout_nonce, request_sha256, pre_resource_version)
);

CREATE TABLE rollout_attempt_private.terminals (
  claim_sha256 TEXT COLLATE "C" NOT NULL,
  terminal_operation TEXT COLLATE "C" NOT NULL
    CHECK (terminal_operation IN ('complete', 'reconcile')),
  outcome TEXT COLLATE "C" NOT NULL
    CHECK (outcome IN ('applied', 'not-applied', 'indeterminate')),
  status TEXT COLLATE "C" NOT NULL
    CHECK (status IN ('completed', 'applied', 'not-applied', 'indeterminate')),
  final_resource_version TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(final_resource_version) BETWEEN 1 AND 512
      AND final_resource_version !~ '[[:space:]]'
    ),
  terminal_payload JSONB NOT NULL
    CHECK (
      pg_catalog.jsonb_typeof(terminal_payload) = 'object'
      AND pg_catalog.pg_column_size(terminal_payload) <= 65536
    ),
  terminal_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY (claim_sha256),
  FOREIGN KEY (claim_sha256)
    REFERENCES rollout_attempt_private.claims (claim_sha256)
    ON DELETE RESTRICT,
  CHECK (
    (
      terminal_operation = 'complete'
      AND outcome = 'applied'
      AND status = 'completed'
    )
    OR
    (
      terminal_operation = 'reconcile'
      AND status = outcome
    )
  )
);

ALTER TABLE rollout_attempt_private.claims
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE rollout_attempt_private.claims
  FORCE ROW LEVEL SECURITY;
ALTER TABLE rollout_attempt_private.terminals
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE rollout_attempt_private.terminals
  FORCE ROW LEVEL SECURITY;

CREATE POLICY rollout_attempt_claim_owner_all
  ON rollout_attempt_private.claims
  FOR ALL
  TO rollout_attempt_store_owner
  USING (TRUE)
  WITH CHECK (TRUE);
CREATE POLICY rollout_attempt_terminal_owner_all
  ON rollout_attempt_private.terminals
  FOR ALL
  TO rollout_attempt_store_owner
  USING (TRUE)
  WITH CHECK (TRUE);

REVOKE ALL ON rollout_attempt_private.claims
  FROM PUBLIC, anon, authenticated, service_role, rollout_attempt_executor;
REVOKE ALL ON rollout_attempt_private.terminals
  FROM PUBLIC, anon, authenticated, service_role, rollout_attempt_executor;

CREATE FUNCTION rollout_attempt_private.reject_append_only_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
BEGIN
  RAISE EXCEPTION 'rollout attempt records are append-only'
    USING ERRCODE = '55000';
END
$fn$;

CREATE TRIGGER rollout_attempt_claims_no_update_delete
BEFORE UPDATE OR DELETE
ON rollout_attempt_private.claims
FOR EACH ROW
EXECUTE FUNCTION rollout_attempt_private.reject_append_only_mutation();

CREATE TRIGGER rollout_attempt_claims_no_truncate
BEFORE TRUNCATE
ON rollout_attempt_private.claims
FOR EACH STATEMENT
EXECUTE FUNCTION rollout_attempt_private.reject_append_only_mutation();

CREATE TRIGGER rollout_attempt_terminals_no_update_delete
BEFORE UPDATE OR DELETE
ON rollout_attempt_private.terminals
FOR EACH ROW
EXECUTE FUNCTION rollout_attempt_private.reject_append_only_mutation();

CREATE TRIGGER rollout_attempt_terminals_no_truncate
BEFORE TRUNCATE
ON rollout_attempt_private.terminals
FOR EACH STATEMENT
EXECUTE FUNCTION rollout_attempt_private.reject_append_only_mutation();

CREATE FUNCTION rollout_attempt_private.assert_executor()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
BEGIN
  IF SESSION_USER IN ('anon', 'authenticated', 'service_role')
    OR NOT pg_catalog.pg_has_role(SESSION_USER, 'rollout_attempt_executor', 'MEMBER')
    OR pg_catalog.pg_has_role(
      SESSION_USER,
      'rollout_attempt_store_owner',
      'MEMBER'
    )
    OR EXISTS (
      SELECT 1
      FROM pg_catalog.pg_roles AS inherited_role
      WHERE pg_catalog.pg_has_role(
        SESSION_USER,
        inherited_role.oid,
        'MEMBER'
      )
        AND (
          inherited_role.rolsuper
          OR inherited_role.rolcreatedb
          OR inherited_role.rolcreaterole
          OR inherited_role.rolreplication
          OR inherited_role.rolbypassrls
        )
    )
  THEN
    RAISE EXCEPTION
      'dedicated least-privilege rollout attempt executor is required'
      USING ERRCODE = '42501';
  END IF;
END
$fn$;

CREATE FUNCTION rollout_attempt_private.validate_claim(p_claim JSONB)
RETURNS TEXT
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_canonical_key TEXT;
  v_expected_sha256 TEXT;
BEGIN
  IF p_claim IS NULL
    OR pg_catalog.jsonb_typeof(p_claim) IS DISTINCT FROM 'object'
    OR pg_catalog.pg_column_size(p_claim) > 32768
    OR (
      SELECT pg_catalog.count(*)
      FROM pg_catalog.jsonb_object_keys(p_claim)
    ) <> 16
    OR NOT (
      p_claim ? 'schema'
      AND p_claim ? 'claim_sha256'
      AND p_claim ? 'authorization_id'
      AND p_claim ? 'rollout_nonce'
      AND p_claim ? 'request_sha256'
      AND p_claim ? 'pre_resource_version'
      AND p_claim ? 'project_id'
      AND p_claim ? 'region'
      AND p_claim ? 'release_id'
      AND p_claim ? 'transition'
      AND p_claim ? 'service'
      AND p_claim ? 'config_sha256'
      AND p_claim ? 'deployer_principal'
      AND p_claim ? 'workflow_ref'
      AND p_claim ? 'workflow_sha'
      AND p_claim ? 'wif_provider'
    )
    OR EXISTS (
      SELECT 1
      FROM pg_catalog.jsonb_each(p_claim) AS member
      WHERE pg_catalog.jsonb_typeof(member.value) IS DISTINCT FROM 'string'
    )
  THEN
    RAISE EXCEPTION 'rollout attempt claim must have the exact JSON shape'
      USING ERRCODE = '22023';
  END IF;

  IF p_claim ->> 'schema'
      IS DISTINCT FROM 'emilia-deployment-attempt-claim.v1'
    OR p_claim ->> 'claim_sha256' !~ '^[0-9a-f]{64}$'
    OR pg_catalog.octet_length(p_claim ->> 'authorization_id')
      NOT BETWEEN 3 AND 256
    OR p_claim ->> 'authorization_id' !~ '^[A-Za-z0-9:_.@-]+$'
    OR pg_catalog.octet_length(p_claim ->> 'rollout_nonce')
      NOT BETWEEN 22 AND 128
    OR p_claim ->> 'rollout_nonce' !~ '^[A-Za-z0-9_-]+$'
    OR p_claim ->> 'request_sha256' !~ '^[0-9a-f]{64}$'
    OR pg_catalog.octet_length(p_claim ->> 'pre_resource_version')
      NOT BETWEEN 1 AND 512
    OR p_claim ->> 'pre_resource_version' ~ '[[:space:]]'
    OR p_claim ->> 'project_id' !~ '^[a-z][a-z0-9-]{0,62}$'
    OR p_claim ->> 'region' !~ '^[a-z][a-z0-9-]{0,62}$'
    OR p_claim ->> 'release_id' !~ '^[a-z][a-z0-9-]{0,62}$'
    OR p_claim ->> 'transition' NOT IN (
      'apply-decision-1',
      'apply-decision-10',
      'apply-decision-50',
      'apply-decision-100',
      'apply-actuator-100',
      'apply-rollback-actuator',
      'apply-rollback-decision'
    )
    OR p_claim ->> 'service' !~ '^[a-z][a-z0-9-]{0,62}$'
    OR p_claim ->> 'config_sha256' !~ '^[0-9a-f]{64}$'
    OR pg_catalog.octet_length(p_claim ->> 'deployer_principal')
      NOT BETWEEN 1 AND 512
    OR p_claim ->> 'deployer_principal' !~
      '^serviceAccount:[^@[:space:],]+@[^@[:space:],]+[.]iam[.]gserviceaccount[.]com$'
    OR p_claim ->> 'workflow_ref' IS DISTINCT FROM
      'emiliaprotocol/emilia-protocol/.github/workflows/consequence-control-deploy.yml@refs/heads/main'
    OR p_claim ->> 'workflow_sha' !~ '^[0-9a-f]{40}$'
    OR pg_catalog.octet_length(p_claim ->> 'wif_provider')
      NOT BETWEEN 1 AND 512
    OR p_claim ->> 'wif_provider' !~
      '^projects/[1-9][0-9]*/locations/global/workloadIdentityPools/[a-z][a-z0-9-]{3,31}/providers/[a-z][a-z0-9-]{3,31}$'
  THEN
    RAISE EXCEPTION 'rollout attempt claim binding is malformed'
      USING ERRCODE = '22023';
  END IF;

  v_canonical_key :=
    '{"authorization_id":'
    || pg_catalog.to_jsonb(p_claim ->> 'authorization_id')::TEXT
    || ',"pre_resource_version":'
    || pg_catalog.to_jsonb(p_claim ->> 'pre_resource_version')::TEXT
    || ',"request_sha256":'
    || pg_catalog.to_jsonb(p_claim ->> 'request_sha256')::TEXT
    || ',"rollout_nonce":'
    || pg_catalog.to_jsonb(p_claim ->> 'rollout_nonce')::TEXT
    || '}';
  v_expected_sha256 := pg_catalog.encode(
    extensions.digest(
      pg_catalog.convert_to(
        'EMILIA-DEPLOYMENT-ATTEMPT-CLAIM-V1',
        'UTF8'
      )
      || pg_catalog.decode('00', 'hex')
      || pg_catalog.convert_to(v_canonical_key, 'UTF8'),
      'sha256'
    ),
    'hex'
  );
  IF p_claim ->> 'claim_sha256' IS DISTINCT FROM v_expected_sha256 THEN
    RAISE EXCEPTION 'claim digest does not match exact claim key'
      USING ERRCODE = '22023';
  END IF;
  RETURN v_expected_sha256;
END
$fn$;

CREATE FUNCTION rollout_attempt_private.apply_operation(
  p_operation TEXT,
  p_payload TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_payload JSONB;
  v_claim JSONB;
  v_claim_sha256 TEXT;
  v_outcome TEXT;
  v_status TEXT;
  v_final_resource_version TEXT;
  v_inserted BIGINT;
BEGIN
  PERFORM rollout_attempt_private.assert_executor();

  IF p_operation NOT IN ('claim', 'complete', 'reconcile') THEN
    RAISE EXCEPTION 'rollout attempt operation is unsupported'
      USING ERRCODE = '22023';
  END IF;
  IF p_payload IS NULL
    OR pg_catalog.octet_length(p_payload) NOT BETWEEN 1 AND 65536
  THEN
    RAISE EXCEPTION 'rollout attempt operation JSON is unbounded'
      USING ERRCODE = '22023';
  END IF;
  BEGIN
    v_payload := p_payload::JSONB;
  EXCEPTION
    WHEN OTHERS THEN
      RAISE EXCEPTION 'rollout attempt operation JSON is invalid'
        USING ERRCODE = '22023';
  END;

  IF p_operation = 'claim' THEN
    v_claim := v_payload;
    v_claim_sha256 :=
      rollout_attempt_private.validate_claim(v_claim);
    BEGIN
      INSERT INTO rollout_attempt_private.claims (
        claim_sha256,
        authorization_id,
        rollout_nonce,
        request_sha256,
        pre_resource_version,
        project_id,
        region,
        release_id,
        transition,
        service,
        config_sha256,
        deployer_principal,
        workflow_ref,
        workflow_sha,
        wif_provider,
        claim_payload
      ) VALUES (
        v_claim_sha256,
        v_claim ->> 'authorization_id',
        v_claim ->> 'rollout_nonce',
        v_claim ->> 'request_sha256',
        v_claim ->> 'pre_resource_version',
        v_claim ->> 'project_id',
        v_claim ->> 'region',
        v_claim ->> 'release_id',
        v_claim ->> 'transition',
        v_claim ->> 'service',
        v_claim ->> 'config_sha256',
        v_claim ->> 'deployer_principal',
        v_claim ->> 'workflow_ref',
        v_claim ->> 'workflow_sha',
        v_claim ->> 'wif_provider',
        v_claim
      );
    EXCEPTION
      WHEN unique_violation THEN
        RAISE EXCEPTION 'duplicate rollout attempt claim key or digest'
          USING ERRCODE = '23505';
    END;

    RETURN pg_catalog.jsonb_build_object(
      'schema', 'emilia-deployment-attempt-store-response.v1',
      'operation', 'claim',
      'status', 'claimed',
      'claim_sha256', v_claim_sha256,
      'final_resource_version', NULL
    );
  END IF;

  IF pg_catalog.jsonb_typeof(v_payload) IS DISTINCT FROM 'object'
    OR (
      SELECT pg_catalog.count(*)
      FROM pg_catalog.jsonb_object_keys(v_payload)
    ) <> 5
    OR NOT (
      v_payload ? 'schema'
      AND v_payload ? 'operation'
      AND v_payload ? 'claim'
      AND v_payload ? 'outcome'
      AND v_payload ? 'final_resource_version'
    )
    OR pg_catalog.jsonb_typeof(v_payload -> 'schema')
      IS DISTINCT FROM 'string'
    OR pg_catalog.jsonb_typeof(v_payload -> 'operation')
      IS DISTINCT FROM 'string'
    OR pg_catalog.jsonb_typeof(v_payload -> 'claim')
      IS DISTINCT FROM 'object'
    OR pg_catalog.jsonb_typeof(v_payload -> 'outcome')
      IS DISTINCT FROM 'string'
    OR pg_catalog.jsonb_typeof(v_payload -> 'final_resource_version')
      IS DISTINCT FROM 'string'
    OR v_payload ->> 'schema' IS DISTINCT FROM
      'emilia-deployment-attempt-store-operation.v1'
    OR v_payload ->> 'operation' IS DISTINCT FROM p_operation
  THEN
    RAISE EXCEPTION 'terminal operation must have the exact JSON shape'
      USING ERRCODE = '22023';
  END IF;

  v_claim := v_payload -> 'claim';
  v_claim_sha256 := rollout_attempt_private.validate_claim(v_claim);
  v_outcome := v_payload ->> 'outcome';
  v_final_resource_version :=
    v_payload ->> 'final_resource_version';
  IF pg_catalog.octet_length(v_final_resource_version)
      NOT BETWEEN 1 AND 512
    OR v_final_resource_version ~ '[[:space:]]'
    OR (
      p_operation = 'complete'
      AND v_outcome IS DISTINCT FROM 'applied'
    )
    OR (
      p_operation = 'reconcile'
      AND v_outcome NOT IN ('applied', 'not-applied', 'indeterminate')
    )
  THEN
    RAISE EXCEPTION 'terminal outcome is malformed'
      USING ERRCODE = '22023';
  END IF;
  v_status := CASE
    WHEN p_operation = 'complete' THEN 'completed'
    ELSE v_outcome
  END;

  BEGIN
    INSERT INTO rollout_attempt_private.terminals (
      claim_sha256,
      terminal_operation,
      outcome,
      status,
      final_resource_version,
      terminal_payload
    )
    SELECT
      v_claim_sha256,
      p_operation,
      v_outcome,
      v_status,
      v_final_resource_version,
      v_payload
    FROM rollout_attempt_private.claims AS claims
    WHERE claims.claim_sha256 = v_claim_sha256
      AND claims.claim_payload = v_claim;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
  EXCEPTION
    WHEN unique_violation THEN
      RAISE EXCEPTION
        'attempt is unclaimed, already terminal, or claim binding mismatched'
        USING ERRCODE = '23505';
  END;
  IF v_inserted <> 1 THEN
    RAISE EXCEPTION
      'attempt is unclaimed, already terminal, or claim binding mismatched'
      USING ERRCODE = '55000';
  END IF;

  RETURN pg_catalog.jsonb_build_object(
    'schema', 'emilia-deployment-attempt-store-response.v1',
    'operation', p_operation,
    'status', v_status,
    'claim_sha256', v_claim_sha256,
    'final_resource_version', v_final_resource_version
  );
END
$fn$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rollout_attempt_private
  FROM PUBLIC, anon, authenticated, service_role, rollout_attempt_executor;
GRANT USAGE ON SCHEMA rollout_attempt_private
  TO rollout_attempt_executor;
GRANT EXECUTE ON FUNCTION rollout_attempt_private.apply_operation(TEXT, TEXT)
  TO rollout_attempt_executor;

COMMENT ON TABLE rollout_attempt_private.claims IS
  'Append-only rollout authorization attempt claims with exact digest and replay-key uniqueness.';
COMMENT ON TABLE rollout_attempt_private.terminals IS
  'Append-only one-terminal compare-and-set records bound to the exact claimed JSON and final Cloud Run resourceVersion.';

RESET ROLE;

COMMENT ON ROLE rollout_attempt_executor IS
  'NOLOGIN group role for the dedicated rollout attempt-store database login; no Supabase API role membership is permitted.';

REVOKE rollout_attempt_executor
  FROM anon, authenticated, service_role;
REVOKE rollout_attempt_store_owner
  FROM anon, authenticated, service_role;
REVOKE rollout_attempt_store_owner FROM CURRENT_USER;
