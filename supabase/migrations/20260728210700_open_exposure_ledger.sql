-- SPDX-License-Identifier: Apache-2.0
-- Durable Open Exposure Ledger v1.
--
-- Dedicated tenant-mapped service principals receive only the RPCs for their
-- custody role. Generic Supabase API roles, including service_role, receive no
-- schema, table, sequence, or function authority.

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ep_open_exposure_store_owner') THEN
    CREATE ROLE ep_open_exposure_store_owner NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ep_open_exposure_origin') THEN
    CREATE ROLE ep_open_exposure_origin NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ep_open_exposure_executor') THEN
    CREATE ROLE ep_open_exposure_executor NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ep_open_exposure_reconciler') THEN
    CREATE ROLE ep_open_exposure_reconciler NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ep_open_exposure_policy_admin') THEN
    CREATE ROLE ep_open_exposure_policy_admin NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ep_open_exposure_reader') THEN
    CREATE ROLE ep_open_exposure_reader NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

ALTER ROLE ep_open_exposure_store_owner NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE ep_open_exposure_origin NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE ep_open_exposure_executor NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE ep_open_exposure_reconciler NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE ep_open_exposure_policy_admin NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE ep_open_exposure_reader NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

DO $role_separation$
DECLARE
  v_left NAME;
  v_right NAME;
BEGIN
  FOREACH v_left IN ARRAY ARRAY[
    'ep_open_exposure_origin'::NAME,
    'ep_open_exposure_executor'::NAME,
    'ep_open_exposure_reconciler'::NAME
  ]
  LOOP
    FOREACH v_right IN ARRAY ARRAY[
      'ep_open_exposure_origin'::NAME,
      'ep_open_exposure_executor'::NAME,
      'ep_open_exposure_reconciler'::NAME
    ]
    LOOP
      IF v_left < v_right AND EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS left_membership
        JOIN pg_catalog.pg_roles AS left_role
          ON left_role.oid = left_membership.roleid
        JOIN pg_catalog.pg_auth_members AS right_membership
          ON right_membership.member = left_membership.member
        JOIN pg_catalog.pg_roles AS right_role
          ON right_role.oid = right_membership.roleid
        WHERE left_role.rolname = v_left
          AND right_role.rolname = v_right
          AND (left_membership.inherit_option OR left_membership.set_option)
          AND (right_membership.inherit_option OR right_membership.set_option)
      ) THEN
        RAISE EXCEPTION 'open exposure custody roles must be membership-disjoint'
          USING ERRCODE = '42501';
      END IF;
    END LOOP;
  END LOOP;
END
$role_separation$;

GRANT ep_open_exposure_store_owner TO CURRENT_USER
  WITH INHERIT FALSE, SET TRUE;

CREATE SCHEMA open_exposure_private
  AUTHORIZATION ep_open_exposure_store_owner;
REVOKE ALL ON SCHEMA open_exposure_private
  FROM PUBLIC, anon, authenticated, service_role,
    ep_open_exposure_origin, ep_open_exposure_executor,
    ep_open_exposure_reconciler, ep_open_exposure_policy_admin,
    ep_open_exposure_reader;

GRANT USAGE ON SCHEMA extensions TO ep_open_exposure_store_owner;
GRANT EXECUTE ON FUNCTION extensions.digest(BYTEA, TEXT)
  TO ep_open_exposure_store_owner;
GRANT EXECUTE ON FUNCTION extensions.gen_random_bytes(INTEGER)
  TO ep_open_exposure_store_owner;

SET ROLE ep_open_exposure_store_owner;

ALTER DEFAULT PRIVILEGES IN SCHEMA open_exposure_private
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA open_exposure_private
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE open_exposure_private.tenant_principals (
  principal_name NAME NOT NULL,
  tenant_id TEXT COLLATE "C" NOT NULL
    CHECK (pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 512),
  authority_kind TEXT COLLATE "C" NOT NULL
    CHECK (authority_kind IN (
      'POLICY_ADMIN', 'ORIGIN', 'EXECUTOR', 'RECONCILER', 'READER'
    )),
  authority_id TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(authority_id) BETWEEN 1 AND 512
      AND authority_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]*$'
    ),
  PRIMARY KEY (principal_name, tenant_id, authority_kind),
  UNIQUE (tenant_id, authority_kind, authority_id)
);

CREATE TABLE open_exposure_private.ceilings (
  tenant_id TEXT COLLATE "C" NOT NULL
    CHECK (pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 512),
  ceiling_id TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(ceiling_id) BETWEEN 1 AND 512
      AND ceiling_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]*$'
    ),
  scope TEXT COLLATE "C" NOT NULL
    CHECK (scope IN ('TENANT', 'PROGRAM', 'COUNTERPARTY', 'ACTION_CLASS')),
  scope_value TEXT COLLATE "C" NOT NULL
    CHECK (pg_catalog.octet_length(scope_value) BETWEEN 1 AND 512),
  currency TEXT COLLATE "C" NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  window_start TIMESTAMPTZ NOT NULL,
  window_end TIMESTAMPTZ NOT NULL,
  limit_minor BIGINT NOT NULL CHECK (limit_minor >= 0),
  policy_digest TEXT COLLATE "C" NOT NULL
    CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
  ceiling_digest TEXT COLLATE "C" NOT NULL
    CHECK (ceiling_digest ~ '^sha256:[0-9a-f]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  PRIMARY KEY (tenant_id, ceiling_id),
  UNIQUE (
    tenant_id, scope, scope_value, currency, window_start, window_end
  ),
  CHECK (window_start < window_end),
  CHECK (
    (scope = 'TENANT' AND scope_value = '*')
    OR (scope <> 'TENANT' AND scope_value <> '*')
  )
);

CREATE TABLE open_exposure_private.exposures (
  tenant_id TEXT COLLATE "C" NOT NULL
    CHECK (pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 512),
  exposure_id TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(exposure_id) BETWEEN 1 AND 512
      AND exposure_id ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]*$'
    ),
  operation_token_digest TEXT COLLATE "C" NOT NULL
    CHECK (operation_token_digest ~ '^sha256:[0-9a-f]{64}$'),
  reservation_digest TEXT COLLATE "C" NOT NULL
    CHECK (reservation_digest ~ '^sha256:[0-9a-f]{64}$'),
  program_id TEXT COLLATE "C" NOT NULL
    CHECK (pg_catalog.octet_length(program_id) BETWEEN 1 AND 512),
  program_version TEXT COLLATE "C" NOT NULL
    CHECK (
      pg_catalog.octet_length(program_version) BETWEEN 1 AND 512
      AND program_version ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]*$'
    ),
  program_source_digest TEXT COLLATE "C" NOT NULL
    CHECK (program_source_digest ~ '^sha256:[0-9a-f]{64}$'),
  program_digest TEXT COLLATE "C" NOT NULL
    CHECK (program_digest ~ '^sha256:[0-9a-f]{64}$'),
  caid TEXT COLLATE "C" NOT NULL
    CHECK (
      caid ~ '^caid:1:[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
    ),
  action_digest TEXT COLLATE "C" NOT NULL
    CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  admission_snapshot_digest TEXT COLLATE "C" NOT NULL
    CHECK (admission_snapshot_digest ~ '^sha256:[0-9a-f]{64}$'),
  authorization_digest TEXT COLLATE "C" NOT NULL
    CHECK (authorization_digest ~ '^sha256:[0-9a-f]{64}$'),
  authorization_expires_at TIMESTAMPTZ NOT NULL,
  counterparty_id TEXT COLLATE "C" NOT NULL
    CHECK (pg_catalog.octet_length(counterparty_id) BETWEEN 1 AND 512),
  action_class TEXT COLLATE "C" NOT NULL
    CHECK (pg_catalog.octet_length(action_class) BETWEEN 1 AND 512),
  amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
  currency TEXT COLLATE "C" NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  window_start TIMESTAMPTZ NOT NULL,
  window_end TIMESTAMPTZ NOT NULL,
  reserved_at TIMESTAMPTZ NOT NULL,
  invoke_by TIMESTAMPTZ NOT NULL,
  reconcile_by TIMESTAMPTZ NOT NULL,
  origin_authority_id TEXT COLLATE "C" NOT NULL,
  executor_authority_id TEXT COLLATE "C" NOT NULL,
  reconciliation_authority_id TEXT COLLATE "C" NOT NULL,
  reservation_evidence_digest TEXT COLLATE "C" NOT NULL
    CHECK (reservation_evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
  ceiling_digests TEXT[] NOT NULL,
  revision BIGINT NOT NULL CHECK (revision >= 0),
  status TEXT COLLATE "C" NOT NULL CHECK (status IN (
    'RESERVED', 'INVOKING', 'INDETERMINATE',
    'CLOSED_COMMITTED', 'CLOSED_PROVEN_NOT_COMMITTED'
  )),
  invoked_at TIMESTAMPTZ,
  invocation_permit_digest TEXT COLLATE "C"
    CHECK (
      invocation_permit_digest IS NULL
      OR invocation_permit_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
  indeterminate_evidence_digest TEXT COLLATE "C"
    CHECK (
      indeterminate_evidence_digest IS NULL
      OR indeterminate_evidence_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
  reconciliation_outcome TEXT COLLATE "C"
    CHECK (reconciliation_outcome IN (
      'COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'
    )),
  reconciliation_evidence_digest TEXT COLLATE "C"
    CHECK (
      reconciliation_evidence_digest IS NULL
      OR reconciliation_evidence_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
  last_changed_at TIMESTAMPTZ NOT NULL,
  predecessor_record_digest TEXT COLLATE "C"
    CHECK (
      predecessor_record_digest IS NULL
      OR predecessor_record_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
  record_digest TEXT COLLATE "C" NOT NULL
    CHECK (record_digest ~ '^sha256:[0-9a-f]{64}$'),
  PRIMARY KEY (tenant_id, exposure_id),
  UNIQUE (tenant_id, operation_token_digest),
  CHECK (window_start < window_end),
  CHECK (reserved_at >= window_start AND reserved_at < window_end),
  CHECK (reserved_at <= invoke_by AND invoke_by <= reconcile_by),
  CHECK (invoke_by <= window_end),
  CHECK (reserved_at <= authorization_expires_at),
  CHECK (invoke_by <= authorization_expires_at),
  CHECK (origin_authority_id <> executor_authority_id),
  CHECK (reconciliation_authority_id <> origin_authority_id),
  CHECK (reconciliation_authority_id <> executor_authority_id),
  CHECK (pg_catalog.array_length(ceiling_digests, 1) = 4),
  CHECK ((invoked_at IS NULL) = (invocation_permit_digest IS NULL)),
  CHECK (
    (status = 'RESERVED' AND invocation_permit_digest IS NULL)
    OR (status IN ('INVOKING', 'INDETERMINATE', 'CLOSED_COMMITTED')
      AND invocation_permit_digest IS NOT NULL)
    OR status = 'CLOSED_PROVEN_NOT_COMMITTED'
  ),
  CHECK (
    (status IN ('RESERVED', 'INVOKING')
      AND reconciliation_outcome IS NULL
      AND reconciliation_evidence_digest IS NULL)
    OR (status = 'INDETERMINATE'
      AND indeterminate_evidence_digest IS NOT NULL
      AND (
        (reconciliation_outcome IS NULL AND reconciliation_evidence_digest IS NULL)
        OR (reconciliation_outcome = 'INDETERMINATE'
          AND reconciliation_evidence_digest IS NOT NULL)
      ))
    OR (status = 'CLOSED_COMMITTED'
      AND reconciliation_outcome = 'COMMITTED'
      AND reconciliation_evidence_digest IS NOT NULL)
    OR (status = 'CLOSED_PROVEN_NOT_COMMITTED'
      AND reconciliation_outcome = 'PROVEN_NOT_COMMITTED'
      AND reconciliation_evidence_digest IS NOT NULL)
  )
);

CREATE TABLE open_exposure_private.history (
  tenant_id TEXT COLLATE "C" NOT NULL,
  exposure_id TEXT COLLATE "C" NOT NULL,
  sequence BIGINT NOT NULL CHECK (sequence >= 0),
  event TEXT COLLATE "C" NOT NULL CHECK (event IN (
    'RESERVED', 'INVOKING', 'INDETERMINATE',
    'RECONCILED_INDETERMINATE', 'CLOSED_COMMITTED',
    'CLOSED_PROVEN_NOT_COMMITTED'
  )),
  program_version TEXT COLLATE "C" NOT NULL,
  program_source_digest TEXT COLLATE "C" NOT NULL
    CHECK (program_source_digest ~ '^sha256:[0-9a-f]{64}$'),
  program_digest TEXT COLLATE "C" NOT NULL
    CHECK (program_digest ~ '^sha256:[0-9a-f]{64}$'),
  caid TEXT COLLATE "C" NOT NULL,
  action_digest TEXT COLLATE "C" NOT NULL
    CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  admission_snapshot_digest TEXT COLLATE "C" NOT NULL
    CHECK (admission_snapshot_digest ~ '^sha256:[0-9a-f]{64}$'),
  authorization_digest TEXT COLLATE "C" NOT NULL
    CHECK (authorization_digest ~ '^sha256:[0-9a-f]{64}$'),
  authorization_expires_at TIMESTAMPTZ NOT NULL,
  invocation_permit_digest TEXT COLLATE "C"
    CHECK (
      invocation_permit_digest IS NULL
      OR invocation_permit_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
  record_digest TEXT COLLATE "C" NOT NULL
    CHECK (record_digest ~ '^sha256:[0-9a-f]{64}$'),
  evidence_digest TEXT COLLATE "C" NOT NULL
    CHECK (evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
  recorded_at TIMESTAMPTZ NOT NULL,
  predecessor_entry_digest TEXT COLLATE "C"
    CHECK (
      predecessor_entry_digest IS NULL
      OR predecessor_entry_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
  entry_digest TEXT COLLATE "C" NOT NULL
    CHECK (entry_digest ~ '^sha256:[0-9a-f]{64}$'),
  PRIMARY KEY (tenant_id, exposure_id, sequence),
  UNIQUE (tenant_id, entry_digest),
  FOREIGN KEY (tenant_id, exposure_id)
    REFERENCES open_exposure_private.exposures (tenant_id, exposure_id)
    ON DELETE RESTRICT,
  CHECK (
    (sequence = 0 AND predecessor_entry_digest IS NULL)
    OR (sequence > 0 AND predecessor_entry_digest IS NOT NULL)
  )
);

CREATE TABLE open_exposure_private.reconciliation_tokens (
  tenant_id TEXT COLLATE "C" NOT NULL,
  reconciliation_token_digest TEXT COLLATE "C" NOT NULL
    CHECK (reconciliation_token_digest ~ '^sha256:[0-9a-f]{64}$'),
  request_digest TEXT COLLATE "C" NOT NULL
    CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
  exposure_id TEXT COLLATE "C" NOT NULL,
  response_record JSONB NOT NULL
    CHECK (
      pg_catalog.jsonb_typeof(response_record) = 'object'
      AND pg_catalog.pg_column_size(response_record) <= 131072
    ),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  PRIMARY KEY (tenant_id, reconciliation_token_digest),
  FOREIGN KEY (tenant_id, exposure_id)
    REFERENCES open_exposure_private.exposures (tenant_id, exposure_id)
    ON DELETE RESTRICT
);

CREATE UNIQUE INDEX open_exposure_ceiling_scope_idx
  ON open_exposure_private.ceilings (
    tenant_id, currency, window_start, window_end, scope, scope_value
  );
CREATE INDEX open_exposure_open_aggregate_idx
  ON open_exposure_private.exposures (
    tenant_id, currency, window_start, window_end,
    program_id, counterparty_id, action_class
  ) INCLUDE (amount_minor)
  WHERE status IN ('RESERVED', 'INVOKING', 'INDETERMINATE');
CREATE INDEX open_exposure_aging_idx
  ON open_exposure_private.exposures (
    tenant_id, status, reserved_at, exposure_id
  ) WHERE status IN ('RESERVED', 'INVOKING', 'INDETERMINATE');
CREATE INDEX open_exposure_deadline_idx
  ON open_exposure_private.exposures (
    tenant_id, status, invoke_by, reconcile_by, exposure_id
  ) WHERE status IN ('RESERVED', 'INVOKING', 'INDETERMINATE');
CREATE INDEX open_exposure_history_read_idx
  ON open_exposure_private.history (tenant_id, exposure_id, sequence);

ALTER TABLE open_exposure_private.tenant_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_exposure_private.tenant_principals FORCE ROW LEVEL SECURITY;
ALTER TABLE open_exposure_private.ceilings ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_exposure_private.ceilings FORCE ROW LEVEL SECURITY;
ALTER TABLE open_exposure_private.exposures ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_exposure_private.exposures FORCE ROW LEVEL SECURITY;
ALTER TABLE open_exposure_private.history ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_exposure_private.history FORCE ROW LEVEL SECURITY;
ALTER TABLE open_exposure_private.reconciliation_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_exposure_private.reconciliation_tokens FORCE ROW LEVEL SECURITY;

CREATE POLICY open_exposure_principals_owner_only
  ON open_exposure_private.tenant_principals
  TO ep_open_exposure_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY open_exposure_ceilings_owner_only
  ON open_exposure_private.ceilings
  TO ep_open_exposure_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY open_exposure_rows_owner_only
  ON open_exposure_private.exposures
  TO ep_open_exposure_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY open_exposure_history_owner_only
  ON open_exposure_private.history
  TO ep_open_exposure_store_owner USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY open_exposure_reconciliation_tokens_owner_only
  ON open_exposure_private.reconciliation_tokens
  TO ep_open_exposure_store_owner USING (TRUE) WITH CHECK (TRUE);

CREATE FUNCTION open_exposure_private.sha256(
  p_domain TEXT,
  p_value JSONB
)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
  SELECT 'sha256:' || pg_catalog.encode(
    extensions.digest(
      pg_catalog.convert_to(p_domain, 'UTF8')
        || pg_catalog.decode('00', 'hex')
        || pg_catalog.convert_to(p_value::TEXT, 'UTF8'),
      'sha256'
    ),
    'hex'
  );
$fn$;

CREATE FUNCTION open_exposure_private.iso(p_value TIMESTAMPTZ)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
  SELECT pg_catalog.to_char(
    p_value AT TIME ZONE 'UTC',
    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
  );
$fn$;

CREATE FUNCTION open_exposure_private.assert_principal(
  p_tenant_id TEXT,
  p_authority_kind TEXT,
  p_authority_id TEXT,
  p_expected_kind TEXT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_role NAME;
BEGIN
  IF p_tenant_id IS NULL
    OR pg_catalog.octet_length(p_tenant_id) NOT BETWEEN 1 AND 512
    OR p_authority_kind NOT IN (
      'POLICY_ADMIN', 'ORIGIN', 'EXECUTOR', 'RECONCILER', 'READER'
    )
    OR p_authority_id IS NULL
    OR pg_catalog.octet_length(p_authority_id) NOT BETWEEN 1 AND 512
    OR (p_expected_kind IS NOT NULL AND p_authority_kind <> p_expected_kind)
  THEN
    RAISE EXCEPTION 'OPEN_EXPOSURE_AUTHORITY_REFUSED' USING ERRCODE = '42501';
  END IF;

  v_role := CASE p_authority_kind
    WHEN 'POLICY_ADMIN' THEN 'ep_open_exposure_policy_admin'::NAME
    WHEN 'ORIGIN' THEN 'ep_open_exposure_origin'::NAME
    WHEN 'EXECUTOR' THEN 'ep_open_exposure_executor'::NAME
    WHEN 'RECONCILER' THEN 'ep_open_exposure_reconciler'::NAME
    WHEN 'READER' THEN 'ep_open_exposure_reader'::NAME
  END;

  IF SESSION_USER IN ('anon', 'authenticated', 'service_role')
    OR pg_catalog.pg_has_role(SESSION_USER, 'ep_open_exposure_store_owner', 'USAGE')
    OR pg_catalog.pg_has_role(SESSION_USER, 'ep_open_exposure_store_owner', 'SET')
    OR NOT (
      pg_catalog.pg_has_role(SESSION_USER, v_role, 'USAGE')
      OR pg_catalog.pg_has_role(SESSION_USER, v_role, 'SET')
    )
    OR EXISTS (
      SELECT 1
      FROM pg_catalog.pg_roles AS inherited_role
      WHERE (
        pg_catalog.pg_has_role(SESSION_USER, inherited_role.oid, 'USAGE')
        OR pg_catalog.pg_has_role(SESSION_USER, inherited_role.oid, 'SET')
      )
      AND (
        inherited_role.rolsuper
        OR inherited_role.rolcreatedb
        OR inherited_role.rolcreaterole
        OR inherited_role.rolreplication
        OR inherited_role.rolbypassrls
      )
    )
    OR NOT EXISTS (
      SELECT 1
      FROM open_exposure_private.tenant_principals AS principals
      WHERE principals.principal_name = SESSION_USER
        AND principals.tenant_id = p_tenant_id
        AND principals.authority_kind = p_authority_kind
        AND principals.authority_id = p_authority_id
    )
  THEN
    RAISE EXCEPTION 'OPEN_EXPOSURE_AUTHORITY_REFUSED' USING ERRCODE = '42501';
  END IF;
END
$fn$;

CREATE FUNCTION open_exposure_private.principal_separation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $fn$
BEGIN
  IF NEW.authority_kind IN ('ORIGIN', 'EXECUTOR', 'RECONCILER')
    AND EXISTS (
      SELECT 1
      FROM open_exposure_private.tenant_principals AS existing
      WHERE existing.principal_name = NEW.principal_name
        AND existing.tenant_id = NEW.tenant_id
        AND existing.authority_kind IN ('ORIGIN', 'EXECUTOR', 'RECONCILER')
        AND existing.authority_kind <> NEW.authority_kind
    )
  THEN
    RAISE EXCEPTION 'open exposure custody principals must be distinct'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER open_exposure_principal_separation_trigger
BEFORE INSERT OR UPDATE ON open_exposure_private.tenant_principals
FOR EACH ROW EXECUTE FUNCTION open_exposure_private.principal_separation_guard();

CREATE FUNCTION open_exposure_private.immutable_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $fn$
BEGIN
  RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME
    USING ERRCODE = 'check_violation';
END
$fn$;

CREATE TRIGGER open_exposure_ceilings_immutable_trigger
BEFORE UPDATE OR DELETE ON open_exposure_private.ceilings
FOR EACH ROW EXECUTE FUNCTION open_exposure_private.immutable_guard();
CREATE TRIGGER open_exposure_history_immutable_trigger
BEFORE UPDATE OR DELETE ON open_exposure_private.history
FOR EACH ROW EXECUTE FUNCTION open_exposure_private.immutable_guard();
CREATE TRIGGER open_exposure_reconciliation_tokens_immutable_trigger
BEFORE UPDATE OR DELETE ON open_exposure_private.reconciliation_tokens
FOR EACH ROW EXECUTE FUNCTION open_exposure_private.immutable_guard();

CREATE FUNCTION open_exposure_private.exposure_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $fn$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'open exposure records cannot be deleted'
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
    OR OLD.exposure_id IS DISTINCT FROM NEW.exposure_id
    OR OLD.operation_token_digest IS DISTINCT FROM NEW.operation_token_digest
    OR OLD.reservation_digest IS DISTINCT FROM NEW.reservation_digest
    OR OLD.program_id IS DISTINCT FROM NEW.program_id
    OR OLD.program_version IS DISTINCT FROM NEW.program_version
    OR OLD.program_source_digest IS DISTINCT FROM NEW.program_source_digest
    OR OLD.program_digest IS DISTINCT FROM NEW.program_digest
    OR OLD.caid IS DISTINCT FROM NEW.caid
    OR OLD.action_digest IS DISTINCT FROM NEW.action_digest
    OR OLD.admission_snapshot_digest IS DISTINCT FROM NEW.admission_snapshot_digest
    OR OLD.authorization_digest IS DISTINCT FROM NEW.authorization_digest
    OR OLD.authorization_expires_at IS DISTINCT FROM NEW.authorization_expires_at
    OR OLD.counterparty_id IS DISTINCT FROM NEW.counterparty_id
    OR OLD.action_class IS DISTINCT FROM NEW.action_class
    OR OLD.amount_minor IS DISTINCT FROM NEW.amount_minor
    OR OLD.currency IS DISTINCT FROM NEW.currency
    OR OLD.window_start IS DISTINCT FROM NEW.window_start
    OR OLD.window_end IS DISTINCT FROM NEW.window_end
    OR OLD.reserved_at IS DISTINCT FROM NEW.reserved_at
    OR OLD.invoke_by IS DISTINCT FROM NEW.invoke_by
    OR OLD.reconcile_by IS DISTINCT FROM NEW.reconcile_by
    OR OLD.origin_authority_id IS DISTINCT FROM NEW.origin_authority_id
    OR OLD.executor_authority_id IS DISTINCT FROM NEW.executor_authority_id
    OR OLD.reconciliation_authority_id IS DISTINCT FROM NEW.reconciliation_authority_id
    OR OLD.reservation_evidence_digest IS DISTINCT FROM NEW.reservation_evidence_digest
    OR OLD.ceiling_digests IS DISTINCT FROM NEW.ceiling_digests
  THEN
    RAISE EXCEPTION 'open exposure reservation fields are immutable'
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.invocation_permit_digest IS DISTINCT FROM NEW.invocation_permit_digest
    AND NOT (
      OLD.status = 'RESERVED'
      AND NEW.status = 'INVOKING'
      AND OLD.invocation_permit_digest IS NULL
      AND NEW.invocation_permit_digest IS NOT NULL
    )
  THEN
    RAISE EXCEPTION 'open exposure invocation permit digest is immutable'
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.revision = 0
    AND NEW.revision = 0
    AND OLD.record_digest = 'sha256:' || pg_catalog.repeat('0', 64)
    AND NEW.record_digest <> OLD.record_digest
    AND OLD.status IS NOT DISTINCT FROM NEW.status
    AND OLD.invoked_at IS NOT DISTINCT FROM NEW.invoked_at
    AND OLD.invocation_permit_digest IS NOT DISTINCT FROM NEW.invocation_permit_digest
    AND OLD.indeterminate_evidence_digest IS NOT DISTINCT FROM NEW.indeterminate_evidence_digest
    AND OLD.reconciliation_outcome IS NOT DISTINCT FROM NEW.reconciliation_outcome
    AND OLD.reconciliation_evidence_digest IS NOT DISTINCT FROM NEW.reconciliation_evidence_digest
    AND OLD.last_changed_at IS NOT DISTINCT FROM NEW.last_changed_at
    AND NEW.predecessor_record_digest IS NULL
  THEN
    RETURN NEW;
  END IF;
  IF NEW.revision <> OLD.revision + 1
    OR NEW.predecessor_record_digest IS DISTINCT FROM OLD.record_digest
    OR NEW.record_digest = OLD.record_digest
  THEN
    RAISE EXCEPTION 'open exposure revision chain is invalid'
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status IN ('CLOSED_COMMITTED', 'CLOSED_PROVEN_NOT_COMMITTED')
    OR (OLD.status = 'RESERVED' AND NEW.status NOT IN (
      'INVOKING', 'CLOSED_PROVEN_NOT_COMMITTED'
    ))
    OR (OLD.status = 'INVOKING' AND NEW.status NOT IN (
      'INDETERMINATE', 'CLOSED_COMMITTED', 'CLOSED_PROVEN_NOT_COMMITTED'
    ))
    OR (OLD.status = 'INDETERMINATE' AND NEW.status NOT IN (
      'INDETERMINATE', 'CLOSED_COMMITTED', 'CLOSED_PROVEN_NOT_COMMITTED'
    ))
  THEN
    RAISE EXCEPTION 'open exposure transition is invalid'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER open_exposure_record_guard_trigger
BEFORE UPDATE OR DELETE ON open_exposure_private.exposures
FOR EACH ROW EXECUTE FUNCTION open_exposure_private.exposure_guard();

CREATE FUNCTION open_exposure_private.record_json(
  p_record open_exposure_private.exposures
)
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
  SELECT pg_catalog.jsonb_build_object(
    'version', 'EP-OPEN-EXPOSURE-LEDGER-v1',
    'tenant_id', p_record.tenant_id,
    'exposure_id', p_record.exposure_id,
    'operation_token_digest', p_record.operation_token_digest,
    'reservation_digest', p_record.reservation_digest,
    'program_id', p_record.program_id,
    'program_version', p_record.program_version,
    'program_source_digest', p_record.program_source_digest,
    'program_digest', p_record.program_digest,
    'caid', p_record.caid,
    'action_digest', p_record.action_digest,
    'admission_snapshot_digest', p_record.admission_snapshot_digest,
    'authorization_digest', p_record.authorization_digest,
    'authorization_expires_at', open_exposure_private.iso(
      p_record.authorization_expires_at
    ),
    'counterparty_id', p_record.counterparty_id,
    'action_class', p_record.action_class,
    'amount_minor', p_record.amount_minor::TEXT,
    'currency', p_record.currency,
    'window_start', open_exposure_private.iso(p_record.window_start),
    'window_end', open_exposure_private.iso(p_record.window_end),
    'reserved_at', open_exposure_private.iso(p_record.reserved_at),
    'invoke_by', open_exposure_private.iso(p_record.invoke_by),
    'reconcile_by', open_exposure_private.iso(p_record.reconcile_by),
    'origin_authority_id', p_record.origin_authority_id,
    'executor_authority_id', p_record.executor_authority_id,
    'reconciliation_authority_id', p_record.reconciliation_authority_id,
    'reservation_evidence_digest', p_record.reservation_evidence_digest,
    'ceiling_digests', pg_catalog.to_jsonb(p_record.ceiling_digests),
    'revision', p_record.revision,
    'status', p_record.status,
    'invoked_at', CASE WHEN p_record.invoked_at IS NULL THEN NULL
      ELSE open_exposure_private.iso(p_record.invoked_at) END,
    'invocation_permit_digest', p_record.invocation_permit_digest,
    'indeterminate_evidence_digest', p_record.indeterminate_evidence_digest,
    'reconciliation_outcome', p_record.reconciliation_outcome,
    'reconciliation_evidence_digest', p_record.reconciliation_evidence_digest,
    'last_changed_at', open_exposure_private.iso(p_record.last_changed_at),
    'predecessor_record_digest', p_record.predecessor_record_digest,
    'record_digest', p_record.record_digest
  );
$fn$;

CREATE FUNCTION open_exposure_private.ceiling_json(
  p_ceiling open_exposure_private.ceilings
)
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
  SELECT pg_catalog.jsonb_build_object(
    'version', 'EP-OPEN-EXPOSURE-LEDGER-v1',
    'tenant_id', p_ceiling.tenant_id,
    'ceiling_id', p_ceiling.ceiling_id,
    'scope', p_ceiling.scope,
    'scope_value', p_ceiling.scope_value,
    'currency', p_ceiling.currency,
    'window_start', open_exposure_private.iso(p_ceiling.window_start),
    'window_end', open_exposure_private.iso(p_ceiling.window_end),
    'limit_minor', p_ceiling.limit_minor::TEXT,
    'policy_digest', p_ceiling.policy_digest,
    'ceiling_digest', p_ceiling.ceiling_digest
  );
$fn$;

CREATE FUNCTION open_exposure_private.record_digest(
  p_record open_exposure_private.exposures
)
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
  SELECT open_exposure_private.sha256(
    'EP-OPEN-EXPOSURE-RECORD-SQL-v1',
    open_exposure_private.record_json(p_record) - 'record_digest'
  );
$fn$;

CREATE FUNCTION open_exposure_private.append_history(
  p_record open_exposure_private.exposures,
  p_event TEXT,
  p_evidence_digest TEXT,
  p_recorded_at TIMESTAMPTZ
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_sequence BIGINT;
  v_predecessor TEXT;
  v_entry_digest TEXT;
  v_body JSONB;
BEGIN
  SELECT history.sequence + 1, history.entry_digest
  INTO v_sequence, v_predecessor
  FROM open_exposure_private.history AS history
  WHERE history.tenant_id = p_record.tenant_id
    AND history.exposure_id = p_record.exposure_id
  ORDER BY history.sequence DESC
  LIMIT 1;
  IF NOT FOUND THEN
    v_sequence := 0;
    v_predecessor := NULL;
  END IF;
  v_body := pg_catalog.jsonb_build_object(
    'version', 'EP-OPEN-EXPOSURE-HISTORY-v1',
    'tenant_id', p_record.tenant_id,
    'exposure_id', p_record.exposure_id,
    'sequence', v_sequence,
    'event', p_event,
    'program_version', p_record.program_version,
    'program_source_digest', p_record.program_source_digest,
    'program_digest', p_record.program_digest,
    'caid', p_record.caid,
    'action_digest', p_record.action_digest,
    'admission_snapshot_digest', p_record.admission_snapshot_digest,
    'authorization_digest', p_record.authorization_digest,
    'authorization_expires_at', open_exposure_private.iso(
      p_record.authorization_expires_at
    ),
    'invocation_permit_digest', p_record.invocation_permit_digest,
    'record_digest', p_record.record_digest,
    'evidence_digest', p_evidence_digest,
    'recorded_at', open_exposure_private.iso(p_recorded_at),
    'predecessor_entry_digest', v_predecessor
  );
  v_entry_digest := open_exposure_private.sha256(
    'EP-OPEN-EXPOSURE-HISTORY-SQL-v1', v_body
  );
  INSERT INTO open_exposure_private.history (
    tenant_id, exposure_id, sequence, event,
    program_version, program_source_digest, program_digest, caid,
    action_digest, admission_snapshot_digest, authorization_digest,
    authorization_expires_at, invocation_permit_digest, record_digest,
    evidence_digest, recorded_at, predecessor_entry_digest, entry_digest
  ) VALUES (
    p_record.tenant_id, p_record.exposure_id, v_sequence, p_event,
    p_record.program_version, p_record.program_source_digest,
    p_record.program_digest, p_record.caid, p_record.action_digest,
    p_record.admission_snapshot_digest, p_record.authorization_digest,
    p_record.authorization_expires_at, p_record.invocation_permit_digest,
    p_record.record_digest, p_evidence_digest, p_recorded_at,
    v_predecessor, v_entry_digest
  );
END
$fn$;

CREATE FUNCTION open_exposure_private.register_ceiling(p_payload JSONB)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_row open_exposure_private.ceilings%ROWTYPE;
  v_digest TEXT;
  v_inserted BOOLEAN;
BEGIN
  PERFORM open_exposure_private.assert_principal(
    p_payload ->> 'tenant_id', p_payload ->> 'authority_kind',
    p_payload ->> 'authority_id', 'POLICY_ADMIN'
  );
  IF p_payload ->> 'version' <> 'EP-OPEN-EXPOSURE-LEDGER-v1'
    OR p_payload ->> 'scope' NOT IN ('TENANT', 'PROGRAM', 'COUNTERPARTY', 'ACTION_CLASS')
    OR p_payload ->> 'currency' !~ '^[A-Z]{3}$'
    OR p_payload ->> 'policy_digest' !~ '^sha256:[0-9a-f]{64}$'
    OR (p_payload ->> 'limit_minor') !~ '^(0|[1-9][0-9]{0,18})$'
  THEN
    RAISE EXCEPTION 'open exposure ceiling payload is invalid' USING ERRCODE = '22023';
  END IF;
  v_digest := open_exposure_private.sha256(
    'EP-OPEN-EXPOSURE-CEILING-SQL-v1', p_payload - 'ceiling_digest'
  );
  INSERT INTO open_exposure_private.ceilings (
    tenant_id, ceiling_id, scope, scope_value, currency,
    window_start, window_end, limit_minor, policy_digest, ceiling_digest
  ) VALUES (
    p_payload ->> 'tenant_id', p_payload ->> 'ceiling_id',
    p_payload ->> 'scope', p_payload ->> 'scope_value',
    p_payload ->> 'currency', (p_payload ->> 'window_start')::TIMESTAMPTZ,
    (p_payload ->> 'window_end')::TIMESTAMPTZ,
    (p_payload ->> 'limit_minor')::BIGINT,
    p_payload ->> 'policy_digest', v_digest
  ) ON CONFLICT DO NOTHING
  RETURNING * INTO v_row;
  v_inserted := FOUND;

  IF NOT v_inserted THEN
    SELECT ceilings.* INTO v_row
    FROM open_exposure_private.ceilings AS ceilings
    WHERE ceilings.tenant_id = p_payload ->> 'tenant_id'
      AND (
        ceilings.ceiling_id = p_payload ->> 'ceiling_id'
        OR (
          ceilings.scope = p_payload ->> 'scope'
          AND ceilings.scope_value = p_payload ->> 'scope_value'
          AND ceilings.currency = p_payload ->> 'currency'
          AND ceilings.window_start = (p_payload ->> 'window_start')::TIMESTAMPTZ
          AND ceilings.window_end = (p_payload ->> 'window_end')::TIMESTAMPTZ
        )
      )
    ORDER BY (ceilings.ceiling_id = p_payload ->> 'ceiling_id') DESC
    LIMIT 1;
    IF NOT FOUND THEN
      RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'ceiling_scope_conflict');
    END IF;
    IF v_row.ceiling_id <> p_payload ->> 'ceiling_id' THEN
      RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'ceiling_scope_conflict');
    END IF;
    IF v_row.scope <> p_payload ->> 'scope'
      OR v_row.scope_value <> p_payload ->> 'scope_value'
      OR v_row.currency <> p_payload ->> 'currency'
      OR v_row.window_start <> (p_payload ->> 'window_start')::TIMESTAMPTZ
      OR v_row.window_end <> (p_payload ->> 'window_end')::TIMESTAMPTZ
      OR v_row.limit_minor <> (p_payload ->> 'limit_minor')::BIGINT
      OR v_row.policy_digest <> p_payload ->> 'policy_digest'
    THEN
      RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'ceiling_id_conflict');
    END IF;
  END IF;
  RETURN pg_catalog.jsonb_build_object(
    'ok', TRUE, 'replayed', NOT v_inserted,
    'ceiling', open_exposure_private.ceiling_json(v_row)
  );
END
$fn$;

CREATE FUNCTION open_exposure_private.reserve(p_payload JSONB)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_existing open_exposure_private.exposures%ROWTYPE;
  v_record open_exposure_private.exposures%ROWTYPE;
  v_ceiling open_exposure_private.ceilings%ROWTYPE;
  v_ceiling_count INTEGER := 0;
  v_ceiling_digests TEXT[] := ARRAY[]::TEXT[];
  v_used NUMERIC := 0;
  v_amount BIGINT;
  v_reservation_digest TEXT;
  v_record_digest TEXT;
BEGIN
  PERFORM open_exposure_private.assert_principal(
    p_payload ->> 'tenant_id', p_payload ->> 'authority_kind',
    p_payload ->> 'authority_id', 'ORIGIN'
  );
  IF p_payload ->> 'version' <> 'EP-OPEN-EXPOSURE-LEDGER-v1'
    OR p_payload ->> 'authority_id' <> p_payload ->> 'origin_authority_id'
    OR p_payload ->> 'operation_token_digest' !~ '^sha256:[0-9a-f]{64}$'
    OR p_payload ->> 'reservation_evidence_digest' !~ '^sha256:[0-9a-f]{64}$'
    OR pg_catalog.octet_length(p_payload ->> 'program_version') NOT BETWEEN 1 AND 512
    OR p_payload ->> 'program_version' !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]*$'
    OR p_payload ->> 'program_source_digest' !~ '^sha256:[0-9a-f]{64}$'
    OR p_payload ->> 'program_digest' !~ '^sha256:[0-9a-f]{64}$'
    OR p_payload ->> 'caid'
      !~ '^caid:1:[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
    OR p_payload ->> 'action_digest' !~ '^sha256:[0-9a-f]{64}$'
    OR p_payload ->> 'admission_snapshot_digest' !~ '^sha256:[0-9a-f]{64}$'
    OR p_payload ->> 'authorization_digest' !~ '^sha256:[0-9a-f]{64}$'
    OR (p_payload ->> 'amount_minor') !~ '^[1-9][0-9]{0,18}$'
    OR p_payload ->> 'currency' !~ '^[A-Z]{3}$'
    OR p_payload ->> 'origin_authority_id' = p_payload ->> 'executor_authority_id'
    OR p_payload ->> 'reconciliation_authority_id' = p_payload ->> 'origin_authority_id'
    OR p_payload ->> 'reconciliation_authority_id' = p_payload ->> 'executor_authority_id'
    OR open_exposure_private.iso((p_payload ->> 'window_start')::TIMESTAMPTZ)
      <> p_payload ->> 'window_start'
    OR open_exposure_private.iso((p_payload ->> 'window_end')::TIMESTAMPTZ)
      <> p_payload ->> 'window_end'
    OR open_exposure_private.iso((p_payload ->> 'reserved_at')::TIMESTAMPTZ)
      <> p_payload ->> 'reserved_at'
    OR open_exposure_private.iso((p_payload ->> 'invoke_by')::TIMESTAMPTZ)
      <> p_payload ->> 'invoke_by'
    OR open_exposure_private.iso((p_payload ->> 'reconcile_by')::TIMESTAMPTZ)
      <> p_payload ->> 'reconcile_by'
    OR open_exposure_private.iso(
      (p_payload ->> 'authorization_expires_at')::TIMESTAMPTZ
    ) <> p_payload ->> 'authorization_expires_at'
    OR (p_payload ->> 'invoke_by')::TIMESTAMPTZ
      > (p_payload ->> 'window_end')::TIMESTAMPTZ
    OR (p_payload ->> 'invoke_by')::TIMESTAMPTZ
      > (p_payload ->> 'authorization_expires_at')::TIMESTAMPTZ
  THEN
    RAISE EXCEPTION 'open exposure reservation payload is invalid' USING ERRCODE = '22023';
  END IF;
  v_amount := (p_payload ->> 'amount_minor')::BIGINT;
  v_reservation_digest := open_exposure_private.sha256(
    'EP-OPEN-EXPOSURE-RESERVATION-SQL-v1', p_payload - 'reservation_digest'
  );

  SELECT exposures.* INTO v_existing
  FROM open_exposure_private.exposures AS exposures
  WHERE exposures.tenant_id = p_payload ->> 'tenant_id'
    AND exposures.operation_token_digest = p_payload ->> 'operation_token_digest';
  IF FOUND THEN
    RETURN CASE WHEN v_existing.reservation_digest = v_reservation_digest
      THEN pg_catalog.jsonb_build_object(
        'ok', TRUE, 'replayed', TRUE,
        'record', open_exposure_private.record_json(v_existing)
      )
      ELSE pg_catalog.jsonb_build_object(
        'ok', FALSE, 'reason', 'operation_token_conflict'
      ) END;
  END IF;

  FOR v_ceiling IN
    SELECT ceilings.*
    FROM open_exposure_private.ceilings AS ceilings
    WHERE ceilings.tenant_id = p_payload ->> 'tenant_id'
      AND ceilings.currency = p_payload ->> 'currency'
      AND ceilings.window_start = (p_payload ->> 'window_start')::TIMESTAMPTZ
      AND ceilings.window_end = (p_payload ->> 'window_end')::TIMESTAMPTZ
      AND (
        (ceilings.scope = 'TENANT' AND ceilings.scope_value = '*')
        OR (ceilings.scope = 'PROGRAM' AND ceilings.scope_value = p_payload ->> 'program_id')
        OR (ceilings.scope = 'COUNTERPARTY' AND ceilings.scope_value = p_payload ->> 'counterparty_id')
        OR (ceilings.scope = 'ACTION_CLASS' AND ceilings.scope_value = p_payload ->> 'action_class')
      )
    ORDER BY ceilings.scope, ceilings.scope_value
    FOR UPDATE
  LOOP
    v_ceiling_count := v_ceiling_count + 1;
    v_ceiling_digests := pg_catalog.array_append(v_ceiling_digests, v_ceiling.ceiling_digest);
    SELECT COALESCE(SUM(exposures.amount_minor), 0) INTO v_used
    FROM open_exposure_private.exposures AS exposures
    WHERE exposures.tenant_id = v_ceiling.tenant_id
      AND exposures.currency = v_ceiling.currency
      AND exposures.window_start = v_ceiling.window_start
      AND exposures.window_end = v_ceiling.window_end
      AND exposures.status IN ('RESERVED', 'INVOKING', 'INDETERMINATE')
      AND CASE v_ceiling.scope
        WHEN 'TENANT' THEN TRUE
        WHEN 'PROGRAM' THEN exposures.program_id = v_ceiling.scope_value
        WHEN 'COUNTERPARTY' THEN exposures.counterparty_id = v_ceiling.scope_value
        WHEN 'ACTION_CLASS' THEN exposures.action_class = v_ceiling.scope_value
        ELSE FALSE
      END;
    IF v_used > v_ceiling.limit_minor
      OR v_amount::NUMERIC > v_ceiling.limit_minor::NUMERIC - v_used
    THEN
      RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'ceiling_exceeded');
    END IF;
  END LOOP;
  IF v_ceiling_count <> 4 THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'ceiling_not_configured');
  END IF;

  SELECT exposures.* INTO v_existing
  FROM open_exposure_private.exposures AS exposures
  WHERE exposures.tenant_id = p_payload ->> 'tenant_id'
    AND exposures.operation_token_digest = p_payload ->> 'operation_token_digest';
  IF FOUND THEN
    RETURN CASE WHEN v_existing.reservation_digest = v_reservation_digest
      THEN pg_catalog.jsonb_build_object(
        'ok', TRUE, 'replayed', TRUE,
        'record', open_exposure_private.record_json(v_existing)
      )
      ELSE pg_catalog.jsonb_build_object(
        'ok', FALSE, 'reason', 'operation_token_conflict'
      ) END;
  END IF;
  IF EXISTS (
    SELECT 1 FROM open_exposure_private.exposures AS exposures
    WHERE exposures.tenant_id = p_payload ->> 'tenant_id'
      AND exposures.exposure_id = p_payload ->> 'exposure_id'
  ) THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'exposure_exists');
  END IF;

  INSERT INTO open_exposure_private.exposures (
    tenant_id, exposure_id, operation_token_digest, reservation_digest,
    program_id, program_version, program_source_digest, program_digest,
    caid, action_digest, admission_snapshot_digest, authorization_digest,
    authorization_expires_at, counterparty_id, action_class, amount_minor, currency,
    window_start, window_end, reserved_at, invoke_by, reconcile_by,
    origin_authority_id, executor_authority_id, reconciliation_authority_id,
    reservation_evidence_digest, ceiling_digests, revision, status,
    invoked_at, invocation_permit_digest, indeterminate_evidence_digest, reconciliation_outcome,
    reconciliation_evidence_digest, last_changed_at,
    predecessor_record_digest, record_digest
  ) VALUES (
    p_payload ->> 'tenant_id', p_payload ->> 'exposure_id',
    p_payload ->> 'operation_token_digest', v_reservation_digest,
    p_payload ->> 'program_id', p_payload ->> 'program_version',
    p_payload ->> 'program_source_digest', p_payload ->> 'program_digest',
    p_payload ->> 'caid', p_payload ->> 'action_digest',
    p_payload ->> 'admission_snapshot_digest',
    p_payload ->> 'authorization_digest',
    (p_payload ->> 'authorization_expires_at')::TIMESTAMPTZ,
    p_payload ->> 'counterparty_id',
    p_payload ->> 'action_class', v_amount, p_payload ->> 'currency',
    (p_payload ->> 'window_start')::TIMESTAMPTZ,
    (p_payload ->> 'window_end')::TIMESTAMPTZ,
    (p_payload ->> 'reserved_at')::TIMESTAMPTZ,
    (p_payload ->> 'invoke_by')::TIMESTAMPTZ,
    (p_payload ->> 'reconcile_by')::TIMESTAMPTZ,
    p_payload ->> 'origin_authority_id', p_payload ->> 'executor_authority_id',
    p_payload ->> 'reconciliation_authority_id',
    p_payload ->> 'reservation_evidence_digest',
    (SELECT pg_catalog.array_agg(value ORDER BY value COLLATE "C")
      FROM pg_catalog.unnest(v_ceiling_digests) AS value),
    0, 'RESERVED', NULL, NULL, NULL, NULL, NULL,
    (p_payload ->> 'reserved_at')::TIMESTAMPTZ, NULL,
    'sha256:' || pg_catalog.repeat('0', 64)
  ) RETURNING * INTO v_record;
  v_record_digest := open_exposure_private.record_digest(v_record);
  UPDATE open_exposure_private.exposures
  SET record_digest = v_record_digest
  WHERE tenant_id = v_record.tenant_id AND exposure_id = v_record.exposure_id
  RETURNING * INTO v_record;
  PERFORM open_exposure_private.append_history(
    v_record, 'RESERVED', v_record.reservation_evidence_digest, v_record.reserved_at
  );
  RETURN pg_catalog.jsonb_build_object(
    'ok', TRUE, 'replayed', FALSE,
    'record', open_exposure_private.record_json(v_record)
  );
END
$fn$;

CREATE FUNCTION open_exposure_private.begin_invocation(p_payload JSONB)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_record open_exposure_private.exposures%ROWTYPE;
  v_invoked_at TIMESTAMPTZ;
  v_invocation_permit TEXT;
  v_invocation_permit_digest TEXT;
BEGIN
  PERFORM open_exposure_private.assert_principal(
    p_payload ->> 'tenant_id', p_payload ->> 'authority_kind',
    p_payload ->> 'authority_id', 'EXECUTOR'
  );
  IF pg_catalog.octet_length(p_payload ->> 'program_version') NOT BETWEEN 1 AND 512
    OR p_payload ->> 'program_version' !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]*$'
    OR p_payload ->> 'program_source_digest' !~ '^sha256:[0-9a-f]{64}$'
    OR p_payload ->> 'program_digest' !~ '^sha256:[0-9a-f]{64}$'
    OR p_payload ->> 'caid'
      !~ '^caid:1:[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
    OR p_payload ->> 'action_digest' !~ '^sha256:[0-9a-f]{64}$'
    OR p_payload ->> 'admission_snapshot_digest' !~ '^sha256:[0-9a-f]{64}$'
    OR p_payload ->> 'authorization_digest' !~ '^sha256:[0-9a-f]{64}$'
    OR open_exposure_private.iso(
      (p_payload ->> 'authorization_expires_at')::TIMESTAMPTZ
    ) <> p_payload ->> 'authorization_expires_at'
  THEN
    RAISE EXCEPTION 'open exposure invocation binding is invalid'
      USING ERRCODE = '22023';
  END IF;
  v_invoked_at := pg_catalog.transaction_timestamp();
  SELECT exposures.* INTO v_record
  FROM open_exposure_private.exposures AS exposures
  WHERE exposures.tenant_id = p_payload ->> 'tenant_id'
    AND exposures.exposure_id = p_payload ->> 'exposure_id'
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'exposure_not_found');
  END IF;
  IF v_record.executor_authority_id <> p_payload ->> 'authority_id' THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'wrong_authority');
  END IF;
  IF v_record.operation_token_digest <> p_payload ->> 'operation_token_digest' THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'operation_token_conflict');
  END IF;
  IF v_record.program_version <> p_payload ->> 'program_version'
    OR v_record.program_source_digest <> p_payload ->> 'program_source_digest'
    OR v_record.program_digest <> p_payload ->> 'program_digest'
    OR v_record.caid <> p_payload ->> 'caid'
    OR v_record.action_digest <> p_payload ->> 'action_digest'
    OR v_record.admission_snapshot_digest <> p_payload ->> 'admission_snapshot_digest'
    OR v_record.authorization_digest <> p_payload ->> 'authorization_digest'
    OR v_record.authorization_expires_at
      <> (p_payload ->> 'authorization_expires_at')::TIMESTAMPTZ
  THEN
    RETURN pg_catalog.jsonb_build_object(
      'ok', FALSE, 'reason', 'immutable_binding_conflict'
    );
  END IF;
  IF v_record.status IN ('INVOKING', 'INDETERMINATE') THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'reconciliation_required');
  END IF;
  IF v_record.status IN ('CLOSED_COMMITTED', 'CLOSED_PROVEN_NOT_COMMITTED') THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'already_closed');
  END IF;
  IF v_record.status <> 'RESERVED'
    OR v_invoked_at < v_record.reserved_at
  THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'state_conflict');
  END IF;
  IF v_invoked_at > v_record.invoke_by
    OR v_invoked_at > v_record.authorization_expires_at
  THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'invocation_expired');
  END IF;

  v_invocation_permit := 'open-exposure-invoke:v1:'
    || pg_catalog.encode(extensions.gen_random_bytes(32), 'hex');
  v_invocation_permit_digest := open_exposure_private.sha256(
    'EP-OPEN-EXPOSURE-INVOCATION-PERMIT-SQL-v1',
    pg_catalog.jsonb_build_object(
      'permit', v_invocation_permit,
      'tenant_id', v_record.tenant_id,
      'exposure_id', v_record.exposure_id,
      'operation_token_digest', v_record.operation_token_digest,
      'reservation_digest', v_record.reservation_digest,
      'program_version', v_record.program_version,
      'program_source_digest', v_record.program_source_digest,
      'program_digest', v_record.program_digest,
      'caid', v_record.caid,
      'action_digest', v_record.action_digest,
      'admission_snapshot_digest', v_record.admission_snapshot_digest,
      'authorization_digest', v_record.authorization_digest,
      'authorization_expires_at', open_exposure_private.iso(
        v_record.authorization_expires_at
      )
    )
  );

  UPDATE open_exposure_private.exposures AS exposures
  SET revision = exposures.revision + 1,
    status = 'INVOKING', invoked_at = v_invoked_at,
    invocation_permit_digest = v_invocation_permit_digest,
    last_changed_at = v_invoked_at,
    predecessor_record_digest = exposures.record_digest,
    record_digest = open_exposure_private.sha256(
      'EP-OPEN-EXPOSURE-TRANSITION-SQL-v1',
      open_exposure_private.record_json(exposures)
        || pg_catalog.jsonb_build_object(
          'next_revision', exposures.revision + 1,
          'next_status', 'INVOKING',
          'invocation_permit_digest', v_invocation_permit_digest,
          'changed_at', open_exposure_private.iso(v_invoked_at)
        )
    )
  WHERE exposures.tenant_id = v_record.tenant_id
    AND exposures.exposure_id = v_record.exposure_id
  RETURNING * INTO v_record;
  PERFORM open_exposure_private.append_history(
    v_record, 'INVOKING', v_record.reservation_evidence_digest, v_invoked_at
  );
  RETURN pg_catalog.jsonb_build_object(
    'ok', TRUE, 'replayed', FALSE,
    'invocation_permit', v_invocation_permit,
    'record', open_exposure_private.record_json(v_record)
  );
END
$fn$;

CREATE FUNCTION open_exposure_private.mark_indeterminate(p_payload JSONB)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_record open_exposure_private.exposures%ROWTYPE;
  v_observed_at TIMESTAMPTZ;
  v_evidence_digest TEXT;
BEGIN
  PERFORM open_exposure_private.assert_principal(
    p_payload ->> 'tenant_id', p_payload ->> 'authority_kind',
    p_payload ->> 'authority_id', 'EXECUTOR'
  );
  v_observed_at := (p_payload ->> 'observed_at')::TIMESTAMPTZ;
  v_evidence_digest := p_payload ->> 'evidence_digest';
  IF v_evidence_digest !~ '^sha256:[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'indeterminate evidence digest is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT exposures.* INTO v_record
  FROM open_exposure_private.exposures AS exposures
  WHERE exposures.tenant_id = p_payload ->> 'tenant_id'
    AND exposures.exposure_id = p_payload ->> 'exposure_id'
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'exposure_not_found');
  END IF;
  IF v_record.executor_authority_id <> p_payload ->> 'authority_id' THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'wrong_authority');
  END IF;
  IF v_record.operation_token_digest <> p_payload ->> 'operation_token_digest' THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'operation_token_conflict');
  END IF;
  IF v_record.status = 'INDETERMINATE' THEN
    RETURN CASE WHEN v_record.indeterminate_evidence_digest = v_evidence_digest
        AND v_record.last_changed_at = v_observed_at
      THEN pg_catalog.jsonb_build_object(
        'ok', TRUE, 'replayed', TRUE,
        'record', open_exposure_private.record_json(v_record)
      )
      ELSE pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'state_conflict') END;
  END IF;
  IF v_record.status IN ('CLOSED_COMMITTED', 'CLOSED_PROVEN_NOT_COMMITTED') THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'already_closed');
  END IF;
  IF v_record.status <> 'INVOKING'
    OR v_observed_at < v_record.invoked_at
  THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'state_conflict');
  END IF;

  UPDATE open_exposure_private.exposures AS exposures
  SET revision = exposures.revision + 1,
    status = 'INDETERMINATE',
    indeterminate_evidence_digest = v_evidence_digest,
    last_changed_at = v_observed_at,
    predecessor_record_digest = exposures.record_digest,
    record_digest = open_exposure_private.sha256(
      'EP-OPEN-EXPOSURE-TRANSITION-SQL-v1',
      open_exposure_private.record_json(exposures)
        || pg_catalog.jsonb_build_object(
          'next_revision', exposures.revision + 1,
          'next_status', 'INDETERMINATE',
          'evidence_digest', v_evidence_digest,
          'changed_at', open_exposure_private.iso(v_observed_at)
        )
    )
  WHERE exposures.tenant_id = v_record.tenant_id
    AND exposures.exposure_id = v_record.exposure_id
  RETURNING * INTO v_record;
  PERFORM open_exposure_private.append_history(
    v_record, 'INDETERMINATE', v_evidence_digest, v_observed_at
  );
  RETURN pg_catalog.jsonb_build_object(
    'ok', TRUE, 'replayed', FALSE,
    'record', open_exposure_private.record_json(v_record)
  );
END
$fn$;

CREATE FUNCTION open_exposure_private.reconcile(p_payload JSONB)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_record open_exposure_private.exposures%ROWTYPE;
  v_prior open_exposure_private.reconciliation_tokens%ROWTYPE;
  v_observed_at TIMESTAMPTZ;
  v_outcome TEXT;
  v_status TEXT;
  v_event TEXT;
  v_request_digest TEXT;
  v_token_digest TEXT;
  v_evidence_digest TEXT;
BEGIN
  PERFORM open_exposure_private.assert_principal(
    p_payload ->> 'tenant_id', p_payload ->> 'authority_kind',
    p_payload ->> 'authority_id', 'RECONCILER'
  );
  v_token_digest := p_payload ->> 'reconciliation_token_digest';
  v_evidence_digest := p_payload ->> 'evidence_digest';
  v_outcome := p_payload ->> 'outcome';
  v_observed_at := (p_payload ->> 'observed_at')::TIMESTAMPTZ;
  IF v_token_digest !~ '^sha256:[0-9a-f]{64}$'
    OR v_evidence_digest !~ '^sha256:[0-9a-f]{64}$'
    OR v_outcome NOT IN ('COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE')
  THEN
    RAISE EXCEPTION 'open exposure reconciliation payload is invalid'
      USING ERRCODE = '22023';
  END IF;
  v_request_digest := open_exposure_private.sha256(
    'EP-OPEN-EXPOSURE-RECONCILIATION-SQL-v1', p_payload - 'request_digest'
  );
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      (p_payload ->> 'tenant_id') || ':' || v_token_digest,
      19790521
    )
  );
  SELECT tokens.* INTO v_prior
  FROM open_exposure_private.reconciliation_tokens AS tokens
  WHERE tokens.tenant_id = p_payload ->> 'tenant_id'
    AND tokens.reconciliation_token_digest = v_token_digest;
  IF FOUND THEN
    RETURN CASE WHEN v_prior.request_digest = v_request_digest
      THEN pg_catalog.jsonb_build_object(
        'ok', TRUE, 'replayed', TRUE, 'record', v_prior.response_record
      )
      ELSE pg_catalog.jsonb_build_object(
        'ok', FALSE, 'reason', 'reconciliation_token_conflict'
      ) END;
  END IF;

  SELECT exposures.* INTO v_record
  FROM open_exposure_private.exposures AS exposures
  WHERE exposures.tenant_id = p_payload ->> 'tenant_id'
    AND exposures.exposure_id = p_payload ->> 'exposure_id'
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'exposure_not_found');
  END IF;
  IF v_record.reconciliation_authority_id <> p_payload ->> 'authority_id' THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'wrong_authority');
  END IF;
  IF v_record.operation_token_digest <> p_payload ->> 'operation_token_digest' THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'operation_token_conflict');
  END IF;
  IF v_record.status IN ('CLOSED_COMMITTED', 'CLOSED_PROVEN_NOT_COMMITTED') THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'already_closed');
  END IF;
  IF v_observed_at < v_record.last_changed_at
    OR (v_outcome IN ('COMMITTED', 'INDETERMINATE') AND v_record.status = 'RESERVED')
  THEN
    RETURN pg_catalog.jsonb_build_object('ok', FALSE, 'reason', 'state_conflict');
  END IF;
  v_status := CASE v_outcome
    WHEN 'COMMITTED' THEN 'CLOSED_COMMITTED'
    WHEN 'PROVEN_NOT_COMMITTED' THEN 'CLOSED_PROVEN_NOT_COMMITTED'
    ELSE 'INDETERMINATE'
  END;
  v_event := CASE v_outcome
    WHEN 'COMMITTED' THEN 'CLOSED_COMMITTED'
    WHEN 'PROVEN_NOT_COMMITTED' THEN 'CLOSED_PROVEN_NOT_COMMITTED'
    ELSE 'RECONCILED_INDETERMINATE'
  END;

  UPDATE open_exposure_private.exposures AS exposures
  SET revision = exposures.revision + 1,
    status = v_status,
    indeterminate_evidence_digest = CASE WHEN v_outcome = 'INDETERMINATE'
      THEN v_evidence_digest ELSE exposures.indeterminate_evidence_digest END,
    reconciliation_outcome = v_outcome,
    reconciliation_evidence_digest = v_evidence_digest,
    last_changed_at = v_observed_at,
    predecessor_record_digest = exposures.record_digest,
    record_digest = open_exposure_private.sha256(
      'EP-OPEN-EXPOSURE-TRANSITION-SQL-v1',
      open_exposure_private.record_json(exposures)
        || pg_catalog.jsonb_build_object(
          'next_revision', exposures.revision + 1,
          'next_status', v_status,
          'outcome', v_outcome,
          'evidence_digest', v_evidence_digest,
          'changed_at', open_exposure_private.iso(v_observed_at)
        )
    )
  WHERE exposures.tenant_id = v_record.tenant_id
    AND exposures.exposure_id = v_record.exposure_id
  RETURNING * INTO v_record;
  PERFORM open_exposure_private.append_history(
    v_record, v_event, v_evidence_digest, v_observed_at
  );
  INSERT INTO open_exposure_private.reconciliation_tokens (
    tenant_id, reconciliation_token_digest, request_digest,
    exposure_id, response_record
  ) VALUES (
    v_record.tenant_id, v_token_digest, v_request_digest,
    v_record.exposure_id, open_exposure_private.record_json(v_record)
  );
  RETURN pg_catalog.jsonb_build_object(
    'ok', TRUE, 'replayed', FALSE,
    'record', open_exposure_private.record_json(v_record)
  );
END
$fn$;

CREATE FUNCTION open_exposure_private.read_exposure(p_payload JSONB)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_record open_exposure_private.exposures%ROWTYPE;
BEGIN
  PERFORM open_exposure_private.assert_principal(
    p_payload ->> 'tenant_id', p_payload ->> 'authority_kind',
    p_payload ->> 'authority_id', 'READER'
  );
  SELECT exposures.* INTO v_record
  FROM open_exposure_private.exposures AS exposures
  WHERE exposures.tenant_id = p_payload ->> 'tenant_id'
    AND exposures.exposure_id = p_payload ->> 'exposure_id';
  RETURN pg_catalog.jsonb_build_object(
    'ok', TRUE,
    'record', CASE WHEN FOUND THEN open_exposure_private.record_json(v_record) ELSE NULL END
  );
END
$fn$;

CREATE FUNCTION open_exposure_private.read_history(p_payload JSONB)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_entries JSONB;
BEGIN
  PERFORM open_exposure_private.assert_principal(
    p_payload ->> 'tenant_id', p_payload ->> 'authority_kind',
    p_payload ->> 'authority_id', 'READER'
  );
  SELECT COALESCE(
    pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object(
        'version', 'EP-OPEN-EXPOSURE-HISTORY-v1',
        'tenant_id', history.tenant_id,
        'exposure_id', history.exposure_id,
        'sequence', history.sequence,
        'event', history.event,
        'program_version', history.program_version,
        'program_source_digest', history.program_source_digest,
        'program_digest', history.program_digest,
        'caid', history.caid,
        'action_digest', history.action_digest,
        'admission_snapshot_digest', history.admission_snapshot_digest,
        'authorization_digest', history.authorization_digest,
        'authorization_expires_at', open_exposure_private.iso(
          history.authorization_expires_at
        ),
        'invocation_permit_digest', history.invocation_permit_digest,
        'record_digest', history.record_digest,
        'evidence_digest', history.evidence_digest,
        'recorded_at', open_exposure_private.iso(history.recorded_at),
        'predecessor_entry_digest', history.predecessor_entry_digest,
        'entry_digest', history.entry_digest
      ) ORDER BY history.sequence
    ),
    '[]'::JSONB
  ) INTO v_entries
  FROM open_exposure_private.history AS history
  WHERE history.tenant_id = p_payload ->> 'tenant_id'
    AND history.exposure_id = p_payload ->> 'exposure_id';
  RETURN pg_catalog.jsonb_build_object('ok', TRUE, 'entries', v_entries);
END
$fn$;

CREATE FUNCTION open_exposure_private.sum_open(p_payload JSONB)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_result JSONB;
BEGIN
  PERFORM open_exposure_private.assert_principal(
    p_payload ->> 'tenant_id', p_payload ->> 'authority_kind',
    p_payload ->> 'authority_id', 'READER'
  );
  WITH selected AS MATERIALIZED (
    SELECT exposures.*
    FROM open_exposure_private.exposures AS exposures
    WHERE exposures.tenant_id = p_payload ->> 'tenant_id'
      AND exposures.currency = p_payload ->> 'currency'
      AND exposures.window_start = (p_payload ->> 'window_start')::TIMESTAMPTZ
      AND exposures.window_end = (p_payload ->> 'window_end')::TIMESTAMPTZ
      AND exposures.status IN ('RESERVED', 'INVOKING', 'INDETERMINATE')
      AND ((p_payload ->> 'program_id') IS NULL
        OR exposures.program_id = p_payload ->> 'program_id')
      AND ((p_payload ->> 'counterparty_id') IS NULL
        OR exposures.counterparty_id = p_payload ->> 'counterparty_id')
      AND ((p_payload ->> 'action_class') IS NULL
        OR exposures.action_class = p_payload ->> 'action_class')
  ), program_totals AS (
    SELECT program_id AS key, SUM(amount_minor) AS total FROM selected GROUP BY program_id
  ), counterparty_totals AS (
    SELECT counterparty_id AS key, SUM(amount_minor) AS total FROM selected GROUP BY counterparty_id
  ), action_totals AS (
    SELECT action_class AS key, SUM(amount_minor) AS total FROM selected GROUP BY action_class
  ), status_totals AS (
    SELECT status AS key, SUM(amount_minor) AS total FROM selected GROUP BY status
  )
  SELECT pg_catalog.jsonb_build_object(
    'ok', TRUE,
    'total_minor', COALESCE((SELECT SUM(amount_minor) FROM selected), 0)::TEXT,
    'by_program', COALESCE((SELECT pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object('key', key, 'amount_minor', total::TEXT)
      ORDER BY key COLLATE "C") FROM program_totals), '[]'::JSONB),
    'by_counterparty', COALESCE((SELECT pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object('key', key, 'amount_minor', total::TEXT)
      ORDER BY key COLLATE "C") FROM counterparty_totals), '[]'::JSONB),
    'by_action_class', COALESCE((SELECT pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object('key', key, 'amount_minor', total::TEXT)
      ORDER BY key COLLATE "C") FROM action_totals), '[]'::JSONB),
    'by_status', COALESCE((SELECT pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object('key', key, 'amount_minor', total::TEXT)
      ORDER BY key COLLATE "C") FROM status_totals), '[]'::JSONB)
  ) INTO v_result;
  RETURN v_result;
END
$fn$;

CREATE FUNCTION open_exposure_private.list_aging(p_payload JSONB)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_records JSONB;
  v_limit INTEGER;
  v_minimum_age BIGINT;
BEGIN
  PERFORM open_exposure_private.assert_principal(
    p_payload ->> 'tenant_id', p_payload ->> 'authority_kind',
    p_payload ->> 'authority_id', 'READER'
  );
  v_limit := (p_payload ->> 'limit')::INTEGER;
  v_minimum_age := (p_payload ->> 'minimum_age_ms')::BIGINT;
  IF v_limit NOT BETWEEN 1 AND 10000 OR v_minimum_age < 0 THEN
    RAISE EXCEPTION 'open exposure aging query is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT COALESCE(pg_catalog.jsonb_agg(rows.record_json ORDER BY rows.reserved_at, rows.exposure_id), '[]'::JSONB)
  INTO v_records
  FROM (
    SELECT exposures.reserved_at, exposures.exposure_id,
      open_exposure_private.record_json(exposures) AS record_json
    FROM open_exposure_private.exposures AS exposures
    WHERE exposures.tenant_id = p_payload ->> 'tenant_id'
      AND exposures.status IN ('RESERVED', 'INVOKING', 'INDETERMINATE')
      AND exposures.reserved_at <= (p_payload ->> 'as_of')::TIMESTAMPTZ
        - (v_minimum_age * INTERVAL '1 millisecond')
    ORDER BY exposures.reserved_at, exposures.exposure_id
    LIMIT v_limit
  ) AS rows;
  RETURN pg_catalog.jsonb_build_object('ok', TRUE, 'records', v_records);
END
$fn$;

CREATE FUNCTION open_exposure_private.list_deadlines(p_payload JSONB)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
  v_records JSONB;
  v_limit INTEGER;
BEGIN
  PERFORM open_exposure_private.assert_principal(
    p_payload ->> 'tenant_id', p_payload ->> 'authority_kind',
    p_payload ->> 'authority_id', 'READER'
  );
  v_limit := (p_payload ->> 'limit')::INTEGER;
  IF v_limit NOT BETWEEN 1 AND 10000 THEN
    RAISE EXCEPTION 'open exposure deadline query is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT COALESCE(pg_catalog.jsonb_agg(rows.record_json ORDER BY rows.deadline, rows.exposure_id), '[]'::JSONB)
  INTO v_records
  FROM (
    SELECT exposures.exposure_id,
      CASE WHEN exposures.status = 'RESERVED'
        THEN exposures.invoke_by ELSE exposures.reconcile_by END AS deadline,
      open_exposure_private.record_json(exposures) AS record_json
    FROM open_exposure_private.exposures AS exposures
    WHERE exposures.tenant_id = p_payload ->> 'tenant_id'
      AND exposures.status IN ('RESERVED', 'INVOKING', 'INDETERMINATE')
      AND CASE WHEN exposures.status = 'RESERVED'
        THEN exposures.invoke_by ELSE exposures.reconcile_by END
        <= (p_payload ->> 'due_at_or_before')::TIMESTAMPTZ
    ORDER BY deadline, exposures.exposure_id
    LIMIT v_limit
  ) AS rows;
  RETURN pg_catalog.jsonb_build_object('ok', TRUE, 'records', v_records);
END
$fn$;

REVOKE ALL ON ALL TABLES IN SCHEMA open_exposure_private
  FROM PUBLIC, anon, authenticated, service_role,
    ep_open_exposure_origin, ep_open_exposure_executor,
    ep_open_exposure_reconciler, ep_open_exposure_policy_admin,
    ep_open_exposure_reader;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA open_exposure_private
  FROM PUBLIC, anon, authenticated, service_role,
    ep_open_exposure_origin, ep_open_exposure_executor,
    ep_open_exposure_reconciler, ep_open_exposure_policy_admin,
    ep_open_exposure_reader;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA open_exposure_private
  FROM PUBLIC, anon, authenticated, service_role,
    ep_open_exposure_origin, ep_open_exposure_executor,
    ep_open_exposure_reconciler, ep_open_exposure_policy_admin,
    ep_open_exposure_reader;

GRANT USAGE ON SCHEMA open_exposure_private
  TO ep_open_exposure_origin, ep_open_exposure_executor,
    ep_open_exposure_reconciler, ep_open_exposure_policy_admin,
    ep_open_exposure_reader;
GRANT EXECUTE ON FUNCTION open_exposure_private.register_ceiling(JSONB)
  TO ep_open_exposure_policy_admin;
GRANT EXECUTE ON FUNCTION open_exposure_private.reserve(JSONB)
  TO ep_open_exposure_origin;
GRANT EXECUTE ON FUNCTION open_exposure_private.begin_invocation(JSONB),
  open_exposure_private.mark_indeterminate(JSONB)
  TO ep_open_exposure_executor;
GRANT EXECUTE ON FUNCTION open_exposure_private.reconcile(JSONB)
  TO ep_open_exposure_reconciler;
GRANT EXECUTE ON FUNCTION open_exposure_private.read_exposure(JSONB),
  open_exposure_private.read_history(JSONB),
  open_exposure_private.sum_open(JSONB),
  open_exposure_private.list_aging(JSONB),
  open_exposure_private.list_deadlines(JSONB)
  TO ep_open_exposure_reader;

RESET ROLE;
REVOKE ep_open_exposure_store_owner FROM CURRENT_USER;
