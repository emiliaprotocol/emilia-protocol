-- SPDX-License-Identifier: Apache-2.0
-- Durable Proposal-to-Effect consequence-attempt custody.
--
-- Executor and recovery authority are separate NOLOGIN group roles. Deployment
-- owners must provision each least-privilege login in tenant_principals and
-- grant only the matching group role; service_role has no RPC authority.

CREATE SCHEMA IF NOT EXISTS proposal_to_effect_private;
REVOKE ALL ON SCHEMA proposal_to_effect_private FROM PUBLIC;

DO $roles$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'proposal_to_effect_executor'
  ) THEN
    CREATE ROLE proposal_to_effect_executor NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'proposal_to_effect_recovery'
  ) THEN
    CREATE ROLE proposal_to_effect_recovery NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

CREATE TABLE IF NOT EXISTS proposal_to_effect_private.tenant_principals (
  principal_name NAME NOT NULL,
  tenant_id TEXT COLLATE "C" NOT NULL
    CHECK (tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  can_execute BOOLEAN NOT NULL DEFAULT FALSE,
  can_recover BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY (principal_name, tenant_id),
  CHECK (can_execute OR can_recover)
);

CREATE TABLE IF NOT EXISTS proposal_to_effect_private.consequence_attempts (
  tenant_id TEXT COLLATE "C" NOT NULL
    CHECK (tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  provider_id TEXT COLLATE "C" NOT NULL
    CHECK (provider_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  provider_account_id TEXT COLLATE "C" NOT NULL
    CHECK (provider_account_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  environment TEXT COLLATE "C" NOT NULL
    CHECK (environment ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  attempt_id TEXT COLLATE "C" NOT NULL
    CHECK (attempt_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  operation_digest TEXT COLLATE "C" NOT NULL
    CHECK (operation_digest ~ '^sha256:[a-f0-9]{64}$'),
  request_digest TEXT COLLATE "C" NOT NULL
    CHECK (request_digest ~ '^sha256:[a-f0-9]{64}$'),
  action_digest TEXT COLLATE "C" NOT NULL
    CHECK (action_digest ~ '^sha256:[a-f0-9]{64}$'),
  config_digest TEXT COLLATE "C" NOT NULL
    CHECK (config_digest ~ '^sha256:[a-f0-9]{64}$'),
  attempt_digest TEXT COLLATE "C" NOT NULL
    CHECK (attempt_digest ~ '^sha256:[a-f0-9]{64}$'),
  owner_digest TEXT COLLATE "C" NOT NULL UNIQUE
    CHECK (owner_digest ~ '^sha256:[a-f0-9]{64}$'),
  owner_generation BIGINT NOT NULL DEFAULT 0 CHECK (owner_generation >= 0),
  state TEXT COLLATE "C" NOT NULL DEFAULT 'RESERVED'
    CHECK (state IN (
      'RESERVED', 'INVOKING', 'INDETERMINATE',
      'COMMITTED', 'RELEASED', 'ESCALATED'
    )),
  evidence_digest TEXT COLLATE "C"
    CHECK (evidence_digest IS NULL OR evidence_digest ~ '^sha256:[a-f0-9]{64}$'),
  evidence_binding_digest TEXT COLLATE "C"
    CHECK (
      evidence_binding_digest IS NULL
      OR evidence_binding_digest ~ '^sha256:[a-f0-9]{64}$'
    ),
  last_heartbeat_at TIMESTAMPTZ NOT NULL,
  lease_expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (
    tenant_id, provider_id, provider_account_id, environment, attempt_id
  ),
  UNIQUE (
    tenant_id, provider_id, provider_account_id, environment, operation_digest
  ),
  UNIQUE (
    tenant_id, provider_id, provider_account_id, environment, request_digest
  ),
  UNIQUE (
    tenant_id, provider_id, provider_account_id, environment, attempt_digest
  ),
  UNIQUE (
    tenant_id, provider_id, provider_account_id, environment,
    attempt_id, attempt_digest
  ),
  CHECK (
    (evidence_digest IS NULL AND evidence_binding_digest IS NULL)
    OR
    (evidence_digest IS NOT NULL AND evidence_binding_digest IS NOT NULL)
  ),
  CHECK (created_at <= updated_at),
  CHECK (created_at <= last_heartbeat_at),
  CHECK (last_heartbeat_at < lease_expires_at)
);

CREATE TABLE IF NOT EXISTS proposal_to_effect_private.provider_evidence (
  tenant_id TEXT COLLATE "C" NOT NULL,
  provider_id TEXT COLLATE "C" NOT NULL,
  provider_account_id TEXT COLLATE "C" NOT NULL,
  environment TEXT COLLATE "C" NOT NULL,
  attempt_id TEXT COLLATE "C" NOT NULL,
  attempt_digest TEXT COLLATE "C" NOT NULL
    CHECK (attempt_digest ~ '^sha256:[a-f0-9]{64}$'),
  operation_id TEXT COLLATE "C" NOT NULL
    CHECK (operation_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  caid TEXT COLLATE "C" NOT NULL
    CHECK (caid ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  action_digest TEXT COLLATE "C" NOT NULL
    CHECK (action_digest ~ '^sha256:[a-f0-9]{64}$'),
  evidence_id TEXT COLLATE "C" NOT NULL
    CHECK (evidence_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$'),
  observed_at TIMESTAMPTZ NOT NULL,
  outcome TEXT COLLATE "C" NOT NULL
    CHECK (outcome IN ('COMMITTED', 'NOT_COMMITTED', 'ESCALATED')),
  evidence_digest TEXT COLLATE "C" NOT NULL
    CHECK (evidence_digest ~ '^sha256:[a-f0-9]{64}$'),
  evidence_binding_digest TEXT COLLATE "C" NOT NULL
    CHECK (evidence_binding_digest ~ '^sha256:[a-f0-9]{64}$'),
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY (
    tenant_id, provider_id, provider_account_id, environment, evidence_digest
  ),
  UNIQUE (
    tenant_id, provider_id, provider_account_id, environment, evidence_id
  ),
  UNIQUE (
    tenant_id, provider_id, provider_account_id, environment,
    evidence_binding_digest
  ),
  FOREIGN KEY (
    tenant_id, provider_id, provider_account_id, environment,
    attempt_id, attempt_digest
  ) REFERENCES proposal_to_effect_private.consequence_attempts (
    tenant_id, provider_id, provider_account_id, environment,
    attempt_id, attempt_digest
  ) ON DELETE RESTRICT
);

ALTER TABLE proposal_to_effect_private.tenant_principals
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposal_to_effect_private.tenant_principals
  FORCE ROW LEVEL SECURITY;
ALTER TABLE proposal_to_effect_private.consequence_attempts
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposal_to_effect_private.consequence_attempts
  FORCE ROW LEVEL SECURITY;
ALTER TABLE proposal_to_effect_private.provider_evidence
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposal_to_effect_private.provider_evidence
  FORCE ROW LEVEL SECURITY;

DO $ddl$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_policies
    WHERE schemaname = 'proposal_to_effect_private'
      AND tablename = 'tenant_principals'
      AND policyname = 'proposal_to_effect_principals_owner_only'
  ) THEN
    CREATE POLICY proposal_to_effect_principals_owner_only
      ON proposal_to_effect_private.tenant_principals
      USING (
        CURRENT_USER = (
          SELECT tableowner
          FROM pg_catalog.pg_tables
          WHERE schemaname = 'proposal_to_effect_private'
            AND tablename = 'tenant_principals'
        )
      )
      WITH CHECK (
        CURRENT_USER = (
          SELECT tableowner
          FROM pg_catalog.pg_tables
          WHERE schemaname = 'proposal_to_effect_private'
            AND tablename = 'tenant_principals'
        )
      );
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_policies
    WHERE schemaname = 'proposal_to_effect_private'
      AND tablename = 'consequence_attempts'
      AND policyname = 'proposal_to_effect_owner_only'
  ) THEN
    CREATE POLICY proposal_to_effect_owner_only
      ON proposal_to_effect_private.consequence_attempts
      USING (
        CURRENT_USER = (
          SELECT tableowner
          FROM pg_catalog.pg_tables
          WHERE schemaname = 'proposal_to_effect_private'
            AND tablename = 'consequence_attempts'
        )
      )
      WITH CHECK (
        CURRENT_USER = (
          SELECT tableowner
          FROM pg_catalog.pg_tables
          WHERE schemaname = 'proposal_to_effect_private'
            AND tablename = 'consequence_attempts'
        )
      );
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_policies
    WHERE schemaname = 'proposal_to_effect_private'
      AND tablename = 'provider_evidence'
      AND policyname = 'proposal_to_effect_evidence_owner_only'
  ) THEN
    CREATE POLICY proposal_to_effect_evidence_owner_only
      ON proposal_to_effect_private.provider_evidence
      USING (
        CURRENT_USER = (
          SELECT tableowner
          FROM pg_catalog.pg_tables
          WHERE schemaname = 'proposal_to_effect_private'
            AND tablename = 'provider_evidence'
        )
      )
      WITH CHECK (
        CURRENT_USER = (
          SELECT tableowner
          FROM pg_catalog.pg_tables
          WHERE schemaname = 'proposal_to_effect_private'
            AND tablename = 'provider_evidence'
        )
      );
  END IF;
END
$ddl$;

REVOKE ALL ON TABLE proposal_to_effect_private.tenant_principals FROM PUBLIC;
REVOKE ALL ON TABLE proposal_to_effect_private.consequence_attempts FROM PUBLIC;
REVOKE ALL ON TABLE proposal_to_effect_private.provider_evidence FROM PUBLIC;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.assert_tenant_principal(
  p_tenant_id TEXT,
  p_recovery BOOLEAN
)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_role_ok BOOLEAN;
  v_binding_ok BOOLEAN;
BEGIN
  v_role_ok := CASE
    WHEN p_recovery IS TRUE THEN pg_catalog.pg_has_role(
      SESSION_USER, 'proposal_to_effect_recovery', 'MEMBER'
    )
    WHEN p_recovery IS FALSE THEN pg_catalog.pg_has_role(
      SESSION_USER, 'proposal_to_effect_executor', 'MEMBER'
    )
    ELSE pg_catalog.pg_has_role(
      SESSION_USER, 'proposal_to_effect_executor', 'MEMBER'
    ) OR pg_catalog.pg_has_role(
      SESSION_USER, 'proposal_to_effect_recovery', 'MEMBER'
    )
  END;
  SELECT EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.tenant_principals AS principals
    WHERE principals.principal_name = SESSION_USER
      AND principals.tenant_id = p_tenant_id
      AND CASE
        WHEN p_recovery IS TRUE THEN principals.can_recover
        WHEN p_recovery IS FALSE THEN principals.can_execute
        ELSE principals.can_execute OR principals.can_recover
      END
  ) INTO v_binding_ok;
  IF v_role_ok IS NOT TRUE OR v_binding_ok IS NOT TRUE THEN
    RAISE EXCEPTION 'PTE_TENANT_PRINCIPAL_REFUSED'
      USING ERRCODE = '42501';
  END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.guard_attempt_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $fn$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'PTE_ATTEMPT_DELETE_REFUSED';
  END IF;
  IF OLD.state IN ('COMMITTED', 'RELEASED', 'ESCALATED') THEN
    RAISE EXCEPTION 'PTE_TERMINAL_ATTEMPT_IMMUTABLE';
  END IF;
  IF ROW(
    NEW.tenant_id, NEW.provider_id, NEW.provider_account_id, NEW.environment,
    NEW.attempt_id, NEW.operation_digest, NEW.request_digest,
    NEW.action_digest, NEW.config_digest, NEW.attempt_digest, NEW.created_at
  ) IS DISTINCT FROM ROW(
    OLD.tenant_id, OLD.provider_id, OLD.provider_account_id, OLD.environment,
    OLD.attempt_id, OLD.operation_digest, OLD.request_digest,
    OLD.action_digest, OLD.config_digest, OLD.attempt_digest, OLD.created_at
  ) THEN
    RAISE EXCEPTION 'PTE_ATTEMPT_BINDING_IMMUTABLE';
  END IF;
  IF NEW.updated_at < OLD.updated_at
     OR NEW.last_heartbeat_at < OLD.last_heartbeat_at
     OR NEW.lease_expires_at < OLD.lease_expires_at
     OR NEW.last_heartbeat_at >= NEW.lease_expires_at THEN
    RAISE EXCEPTION 'PTE_LEASE_REWIND_REFUSED';
  END IF;

  IF NEW.owner_generation = OLD.owner_generation THEN
    IF NEW.owner_digest IS DISTINCT FROM OLD.owner_digest OR NOT (
      (OLD.state = NEW.state)
      OR
      (OLD.state = 'RESERVED' AND NEW.state = 'INVOKING')
      OR (OLD.state = 'INVOKING' AND NEW.state = 'INDETERMINATE')
      OR (
        OLD.state = 'INDETERMINATE'
        AND NEW.state IN ('COMMITTED', 'RELEASED', 'ESCALATED')
      )
    ) THEN
      RAISE EXCEPTION 'PTE_ATTEMPT_TRANSITION_REFUSED';
    END IF;
    IF ROW(NEW.evidence_digest, NEW.evidence_binding_digest)
       IS DISTINCT FROM ROW(OLD.evidence_digest, OLD.evidence_binding_digest)
       AND NOT (
         OLD.state = 'INDETERMINATE'
         AND NEW.state IN ('COMMITTED', 'RELEASED', 'ESCALATED')
         AND OLD.evidence_digest IS NULL
         AND OLD.evidence_binding_digest IS NULL
         AND NEW.evidence_digest IS NOT NULL
         AND NEW.evidence_binding_digest IS NOT NULL
       ) THEN
      RAISE EXCEPTION 'PTE_ATTEMPT_EVIDENCE_REBIND_REFUSED';
    END IF;
  ELSIF NEW.owner_generation = OLD.owner_generation + 1 THEN
    IF NEW.owner_digest IS NOT DISTINCT FROM OLD.owner_digest
       OR ROW(NEW.evidence_digest, NEW.evidence_binding_digest)
          IS DISTINCT FROM ROW(OLD.evidence_digest, OLD.evidence_binding_digest)
       OR NOT (
         (OLD.state = 'RESERVED' AND NEW.state = 'RESERVED')
         OR (OLD.state = 'INVOKING' AND NEW.state = 'INDETERMINATE')
         OR (OLD.state = 'INDETERMINATE' AND NEW.state = 'INDETERMINATE')
       ) THEN
      RAISE EXCEPTION 'PTE_ATTEMPT_RECOVERY_REFUSED';
    END IF;
  ELSE
    RAISE EXCEPTION 'PTE_OWNER_GENERATION_REFUSED';
  END IF;
  RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS proposal_to_effect_attempt_guard
  ON proposal_to_effect_private.consequence_attempts;
CREATE TRIGGER proposal_to_effect_attempt_guard
BEFORE UPDATE OR DELETE ON proposal_to_effect_private.consequence_attempts
FOR EACH ROW EXECUTE FUNCTION proposal_to_effect_private.guard_attempt_mutation();

CREATE OR REPLACE FUNCTION proposal_to_effect_private.guard_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $fn$
BEGIN
  RAISE EXCEPTION 'PTE_PROVIDER_EVIDENCE_IMMUTABLE';
END
$fn$;

DROP TRIGGER IF EXISTS proposal_to_effect_evidence_guard
  ON proposal_to_effect_private.provider_evidence;
CREATE TRIGGER proposal_to_effect_evidence_guard
BEFORE UPDATE OR DELETE ON proposal_to_effect_private.provider_evidence
FOR EACH ROW EXECUTE FUNCTION proposal_to_effect_private.guard_evidence_mutation();

CREATE OR REPLACE FUNCTION proposal_to_effect_private.reserve_attempt(
  p_tenant_id TEXT,
  p_provider_id TEXT,
  p_provider_account_id TEXT,
  p_environment TEXT,
  p_attempt_id TEXT,
  p_operation_digest TEXT,
  p_request_digest TEXT,
  p_action_digest TEXT,
  p_config_digest TEXT,
  p_attempt_digest TEXT,
  p_owner_digest TEXT,
  p_lease_seconds INTEGER
)
RETURNS TABLE(applied BOOLEAN, reason TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_count BIGINT;
  v_now TIMESTAMPTZ;
BEGIN
  PERFORM proposal_to_effect_private.assert_tenant_principal(p_tenant_id, FALSE);
  IF p_lease_seconds < 1 OR p_lease_seconds > 300 THEN
    RAISE EXCEPTION 'PTE_LEASE_DURATION_REFUSED'
      USING ERRCODE = '22023';
  END IF;
  v_now := pg_catalog.clock_timestamp();
  INSERT INTO proposal_to_effect_private.consequence_attempts (
    tenant_id, provider_id, provider_account_id, environment, attempt_id,
    operation_digest, request_digest, action_digest, config_digest,
    attempt_digest, owner_digest, last_heartbeat_at, lease_expires_at,
    created_at, updated_at
  ) VALUES (
    p_tenant_id, p_provider_id, p_provider_account_id, p_environment, p_attempt_id,
    p_operation_digest, p_request_digest, p_action_digest, p_config_digest,
    p_attempt_digest, p_owner_digest, v_now,
    v_now + pg_catalog.make_interval(secs => p_lease_seconds),
    v_now, v_now
  )
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  IF v_count = 1 THEN
    RETURN QUERY SELECT TRUE, NULL::TEXT;
  ELSIF EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.consequence_attempts
    WHERE tenant_id = p_tenant_id
      AND provider_id = p_provider_id
      AND provider_account_id = p_provider_account_id
      AND environment = p_environment
      AND attempt_id = p_attempt_id
      AND operation_digest = p_operation_digest
      AND request_digest = p_request_digest
      AND action_digest = p_action_digest
      AND config_digest = p_config_digest
      AND attempt_digest = p_attempt_digest
      AND owner_digest = p_owner_digest
      AND owner_generation = 0
      AND state = 'RESERVED'
  ) THEN
    -- idempotent_reservation: the original COMMIT may have succeeded.
    RETURN QUERY SELECT TRUE, NULL::TEXT;
  ELSIF EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.consequence_attempts
    WHERE tenant_id = p_tenant_id
      AND provider_id = p_provider_id
      AND provider_account_id = p_provider_account_id
      AND environment = p_environment
      AND attempt_id = p_attempt_id
  ) THEN
    RETURN QUERY SELECT FALSE, 'attempt_exists'::TEXT;
  ELSE
    RETURN QUERY SELECT FALSE, 'binding_conflict'::TEXT;
  END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.transition_attempt(
  p_tenant_id TEXT,
  p_attempt_id TEXT,
  p_owner_digest TEXT,
  p_expected_state TEXT,
  p_next_state TEXT,
  p_lease_seconds INTEGER
)
RETURNS TABLE(applied BOOLEAN, reason TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_count BIGINT;
  v_now TIMESTAMPTZ;
BEGIN
  PERFORM proposal_to_effect_private.assert_tenant_principal(p_tenant_id, FALSE);
  IF p_lease_seconds < 1 OR p_lease_seconds > 300 THEN
    RAISE EXCEPTION 'PTE_LEASE_DURATION_REFUSED'
      USING ERRCODE = '22023';
  END IF;
  v_now := pg_catalog.clock_timestamp();
  UPDATE proposal_to_effect_private.consequence_attempts
  SET state = p_next_state,
      last_heartbeat_at = v_now,
      lease_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds),
      updated_at = v_now
  WHERE tenant_id = p_tenant_id
    AND attempt_id = p_attempt_id
    AND owner_digest = p_owner_digest
    AND state = p_expected_state
    AND (
      (p_expected_state = 'RESERVED' AND p_next_state = 'INVOKING')
      OR (p_expected_state = 'INVOKING' AND p_next_state = 'INDETERMINATE')
      OR (
        p_expected_state = 'INDETERMINATE'
        AND p_next_state IN ('COMMITTED', 'RELEASED', 'ESCALATED')
      )
    );
  GET DIAGNOSTICS v_count = ROW_COUNT;
  IF v_count = 1 THEN
    RETURN QUERY SELECT TRUE, NULL::TEXT;
  ELSIF EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.consequence_attempts
    WHERE tenant_id = p_tenant_id
      AND attempt_id = p_attempt_id
      AND owner_digest = p_owner_digest
      AND state = p_next_state
  ) THEN
    -- idempotent_transition: retry after an ambiguous COMMIT.
    RETURN QUERY SELECT TRUE, NULL::TEXT;
  ELSE
    RETURN QUERY SELECT FALSE, NULL::TEXT;
  END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.heartbeat_attempt(
  p_tenant_id TEXT,
  p_attempt_id TEXT,
  p_owner_digest TEXT,
  p_lease_seconds INTEGER
)
RETURNS TABLE(applied BOOLEAN, reason TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_count BIGINT;
  v_now TIMESTAMPTZ;
BEGIN
  PERFORM proposal_to_effect_private.assert_tenant_principal(p_tenant_id, FALSE);
  IF p_lease_seconds < 1 OR p_lease_seconds > 300 THEN
    RAISE EXCEPTION 'PTE_LEASE_DURATION_REFUSED'
      USING ERRCODE = '22023';
  END IF;
  v_now := pg_catalog.clock_timestamp();
  UPDATE proposal_to_effect_private.consequence_attempts
  SET last_heartbeat_at = v_now,
      lease_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds),
      updated_at = v_now
  WHERE tenant_id = p_tenant_id
    AND attempt_id = p_attempt_id
    AND owner_digest = p_owner_digest
    AND state IN ('RESERVED', 'INVOKING', 'INDETERMINATE');
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN QUERY SELECT v_count = 1, NULL::TEXT;
END
$fn$;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.reconcile_attempt(
  p_tenant_id TEXT,
  p_provider_id TEXT,
  p_provider_account_id TEXT,
  p_environment TEXT,
  p_attempt_id TEXT,
  p_owner_digest TEXT,
  p_operation_digest TEXT,
  p_request_digest TEXT,
  p_action_digest TEXT,
  p_config_digest TEXT,
  p_attempt_digest TEXT,
  p_operation_id TEXT,
  p_caid TEXT,
  p_next_state TEXT,
  p_evidence_id TEXT,
  p_observed_at TIMESTAMPTZ,
  p_outcome TEXT,
  p_evidence_digest TEXT,
  p_evidence_binding_digest TEXT
)
RETURNS TABLE(applied BOOLEAN, reason TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_attempt_digest TEXT;
BEGIN
  PERFORM proposal_to_effect_private.assert_tenant_principal(p_tenant_id, FALSE);
  IF NOT (
    (p_outcome = 'COMMITTED' AND p_next_state = 'COMMITTED')
    OR (p_outcome = 'NOT_COMMITTED' AND p_next_state = 'RELEASED')
    OR (p_outcome = 'ESCALATED' AND p_next_state = 'ESCALATED')
  ) THEN
    RETURN QUERY SELECT FALSE, NULL::TEXT;
    RETURN;
  END IF;
  BEGIN
    UPDATE proposal_to_effect_private.consequence_attempts
    SET state = p_next_state,
        evidence_digest = p_evidence_digest,
        evidence_binding_digest = p_evidence_binding_digest,
        updated_at = pg_catalog.clock_timestamp()
    WHERE tenant_id = p_tenant_id
      AND provider_id = p_provider_id
      AND provider_account_id = p_provider_account_id
      AND environment = p_environment
      AND attempt_id = p_attempt_id
      AND owner_digest = p_owner_digest
      AND operation_digest = p_operation_digest
      AND request_digest = p_request_digest
      AND action_digest = p_action_digest
      AND config_digest = p_config_digest
      AND attempt_digest = p_attempt_digest
      AND state = 'INDETERMINATE'
    RETURNING attempt_digest INTO v_attempt_digest;
    IF v_attempt_digest IS NOT NULL THEN
      INSERT INTO proposal_to_effect_private.provider_evidence (
        tenant_id, provider_id, provider_account_id, environment,
        attempt_id, attempt_digest, operation_id, caid, action_digest,
        evidence_id, observed_at, outcome,
        evidence_digest, evidence_binding_digest
      ) VALUES (
        p_tenant_id, p_provider_id, p_provider_account_id, p_environment,
        p_attempt_id, p_attempt_digest, p_operation_id, p_caid, p_action_digest,
        p_evidence_id, p_observed_at, p_outcome,
        p_evidence_digest, p_evidence_binding_digest
      );
      RETURN QUERY SELECT TRUE, NULL::TEXT;
      RETURN;
    END IF;
  EXCEPTION
    WHEN unique_violation OR foreign_key_violation OR check_violation THEN
      v_attempt_digest := NULL;
  END;
  IF EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.consequence_attempts AS attempts
    JOIN proposal_to_effect_private.provider_evidence AS evidence
      USING (
        tenant_id, provider_id, provider_account_id, environment,
        attempt_id, attempt_digest
      )
    WHERE attempts.tenant_id = p_tenant_id
      AND attempts.provider_id = p_provider_id
      AND attempts.provider_account_id = p_provider_account_id
      AND attempts.environment = p_environment
      AND attempts.attempt_id = p_attempt_id
      AND attempts.owner_digest = p_owner_digest
      AND attempts.operation_digest = p_operation_digest
      AND attempts.request_digest = p_request_digest
      AND attempts.action_digest = p_action_digest
      AND attempts.config_digest = p_config_digest
      AND attempts.attempt_digest = p_attempt_digest
      AND attempts.state = p_next_state
      AND attempts.evidence_digest = p_evidence_digest
      AND attempts.evidence_binding_digest = p_evidence_binding_digest
      AND evidence.operation_id = p_operation_id
      AND evidence.caid = p_caid
      AND evidence.action_digest = p_action_digest
      AND evidence.evidence_id = p_evidence_id
      AND evidence.observed_at = p_observed_at
      AND evidence.outcome = p_outcome
      AND evidence.evidence_digest = p_evidence_digest
      AND evidence.evidence_binding_digest = p_evidence_binding_digest
  ) THEN
    -- idempotent_reconciliation: retry after an ambiguous COMMIT.
    RETURN QUERY SELECT TRUE, NULL::TEXT;
  ELSE
    RETURN QUERY SELECT FALSE, NULL::TEXT;
  END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.read_attempt(
  p_tenant_id TEXT,
  p_provider_id TEXT,
  p_provider_account_id TEXT,
  p_environment TEXT,
  p_attempt_id TEXT,
  p_request_digest TEXT
)
RETURNS TABLE(
  tenant_id TEXT,
  provider_id TEXT,
  provider_account_id TEXT,
  environment TEXT,
  attempt_id TEXT,
  operation_digest TEXT,
  request_digest TEXT,
  action_digest TEXT,
  config_digest TEXT,
  attempt_digest TEXT,
  state TEXT,
  evidence_digest TEXT,
  owner_generation BIGINT,
  last_heartbeat_at TEXT,
  lease_expires_at TEXT,
  lease_stale BOOLEAN
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $fn$
BEGIN
  PERFORM proposal_to_effect_private.assert_tenant_principal(p_tenant_id, NULL);
  RETURN QUERY SELECT
    attempts.tenant_id,
    attempts.provider_id,
    attempts.provider_account_id,
    attempts.environment,
    attempts.attempt_id,
    attempts.operation_digest,
    attempts.request_digest,
    attempts.action_digest,
    attempts.config_digest,
    attempts.attempt_digest,
    attempts.state,
    attempts.evidence_digest,
    attempts.owner_generation,
    pg_catalog.to_char(
      attempts.last_heartbeat_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
    ),
    pg_catalog.to_char(
      attempts.lease_expires_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
    ),
    attempts.lease_expires_at <= pg_catalog.clock_timestamp()
  FROM proposal_to_effect_private.consequence_attempts AS attempts
  WHERE attempts.tenant_id = p_tenant_id
    AND attempts.provider_id = p_provider_id
    AND attempts.provider_account_id = p_provider_account_id
    AND attempts.environment = p_environment
    AND attempts.attempt_id = p_attempt_id
    AND attempts.request_digest = p_request_digest;
END
$fn$;

CREATE OR REPLACE FUNCTION proposal_to_effect_private.recover_attempt(
  p_tenant_id TEXT,
  p_provider_id TEXT,
  p_provider_account_id TEXT,
  p_environment TEXT,
  p_attempt_id TEXT,
  p_request_digest TEXT,
  p_attempt_digest TEXT,
  p_owner_generation BIGINT,
  p_expected_state TEXT,
  p_expected_lease_expires_at TIMESTAMPTZ,
  p_next_owner_digest TEXT,
  p_lease_seconds INTEGER
)
RETURNS TABLE(applied BOOLEAN, reason TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_count BIGINT;
  v_now TIMESTAMPTZ;
BEGIN
  PERFORM proposal_to_effect_private.assert_tenant_principal(p_tenant_id, TRUE);
  IF p_lease_seconds < 1 OR p_lease_seconds > 300 THEN
    RAISE EXCEPTION 'PTE_LEASE_DURATION_REFUSED'
      USING ERRCODE = '22023';
  END IF;
  v_now := pg_catalog.clock_timestamp();
  UPDATE proposal_to_effect_private.consequence_attempts
  SET owner_digest = p_next_owner_digest,
      owner_generation = owner_generation + 1,
      state = CASE
        WHEN state = 'RESERVED' THEN 'RESERVED'
        ELSE 'INDETERMINATE'
      END,
      last_heartbeat_at = v_now,
      lease_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds),
      updated_at = v_now
  WHERE tenant_id = p_tenant_id
    AND provider_id = p_provider_id
    AND provider_account_id = p_provider_account_id
    AND environment = p_environment
    AND attempt_id = p_attempt_id
    AND request_digest = p_request_digest
    AND attempt_digest = p_attempt_digest
    AND owner_generation = p_owner_generation
    AND state = p_expected_state
    AND state IN ('RESERVED', 'INVOKING', 'INDETERMINATE')
    AND lease_expires_at = p_expected_lease_expires_at
    AND lease_expires_at <= pg_catalog.clock_timestamp();
  GET DIAGNOSTICS v_count = ROW_COUNT;
  IF v_count = 1 THEN
    RETURN QUERY SELECT TRUE, NULL::TEXT;
  ELSIF EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.consequence_attempts
    WHERE tenant_id = p_tenant_id
      AND provider_id = p_provider_id
      AND provider_account_id = p_provider_account_id
      AND environment = p_environment
      AND attempt_id = p_attempt_id
      AND request_digest = p_request_digest
      AND attempt_digest = p_attempt_digest
      AND owner_generation = p_owner_generation + 1
      AND owner_digest = p_next_owner_digest
      AND state = CASE
        WHEN p_expected_state = 'RESERVED' THEN 'RESERVED'
        ELSE 'INDETERMINATE'
      END
  ) THEN
    -- idempotent_recovery: retry after an ambiguous COMMIT.
    RETURN QUERY SELECT TRUE, NULL::TEXT;
  ELSIF EXISTS (
    SELECT 1
    FROM proposal_to_effect_private.consequence_attempts
    WHERE tenant_id = p_tenant_id
      AND provider_id = p_provider_id
      AND provider_account_id = p_provider_account_id
      AND environment = p_environment
      AND attempt_id = p_attempt_id
      AND request_digest = p_request_digest
      AND attempt_digest = p_attempt_digest
      AND owner_generation = p_owner_generation
      AND state = p_expected_state
      AND lease_expires_at = p_expected_lease_expires_at
      AND lease_expires_at > pg_catalog.clock_timestamp()
  ) THEN
    RETURN QUERY SELECT FALSE, 'attempt_not_stale'::TEXT;
  ELSE
    RETURN QUERY SELECT FALSE, 'recovery_conflict'::TEXT;
  END IF;
END
$fn$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA proposal_to_effect_private FROM PUBLIC;

GRANT USAGE ON SCHEMA proposal_to_effect_private
  TO proposal_to_effect_executor, proposal_to_effect_recovery;
GRANT EXECUTE ON FUNCTION proposal_to_effect_private.reserve_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER
) TO proposal_to_effect_executor;
GRANT EXECUTE ON FUNCTION proposal_to_effect_private.transition_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER
) TO proposal_to_effect_executor;
GRANT EXECUTE ON FUNCTION proposal_to_effect_private.heartbeat_attempt(
  TEXT, TEXT, TEXT, INTEGER
) TO proposal_to_effect_executor;
GRANT EXECUTE ON FUNCTION proposal_to_effect_private.reconcile_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
  TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT, TEXT, TEXT
) TO proposal_to_effect_executor;
GRANT EXECUTE ON FUNCTION proposal_to_effect_private.read_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
) TO proposal_to_effect_executor, proposal_to_effect_recovery;
GRANT EXECUTE ON FUNCTION proposal_to_effect_private.recover_attempt(
  TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TIMESTAMPTZ,
  TEXT, INTEGER
) TO proposal_to_effect_recovery;

-- Supabase defaults are explicitly removed. Only the dedicated executor and
-- recovery roles granted by the governed DDL can call this private API.
REVOKE ALL ON SCHEMA proposal_to_effect_private
  FROM anon, authenticated, PUBLIC, service_role;
REVOKE ALL ON ALL TABLES IN SCHEMA proposal_to_effect_private
  FROM anon, authenticated, PUBLIC, service_role;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA proposal_to_effect_private
  FROM anon, authenticated, PUBLIC, service_role;
REVOKE EXECUTE ON FUNCTION proposal_to_effect_private.assert_tenant_principal(TEXT, BOOLEAN)
  FROM anon, authenticated, PUBLIC, service_role;
REVOKE EXECUTE ON FUNCTION proposal_to_effect_private.guard_attempt_mutation()
  FROM anon, authenticated, PUBLIC, service_role;
REVOKE EXECUTE ON FUNCTION proposal_to_effect_private.guard_evidence_mutation()
  FROM anon, authenticated, PUBLIC, service_role;

COMMENT ON TABLE proposal_to_effect_private.tenant_principals IS
  'Owner-provisioned database-login to tenant bindings; executor and recovery authority remain separate.';
COMMENT ON TABLE proposal_to_effect_private.consequence_attempts IS
  'Owner-fenced durable consequence attempts with heartbeat leases, immutable bindings, and terminal outcomes.';
COMMENT ON TABLE proposal_to_effect_private.provider_evidence IS
  'Immutable authenticated provider evidence bound to exact operation, CAID, action, request, and consequence attempt.';

