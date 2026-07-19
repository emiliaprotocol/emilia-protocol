-- SPDX-License-Identifier: Apache-2.0
-- EMILIA Gate Postgres evidence runtime (EP-GATE-PG-EVIDENCE-v1).
--
-- Run this migration as a non-runtime owner with CREATE EXTENSION, CREATEROLE,
-- and CREATE privileges. Grant emilia_gate_evidence_runtime to each login used
-- by Gate, then bind each login to exact evidence and binary witness stream
-- scopes with grant_runtime_scope() and grant_network_witness_scope(). Runtime
-- reads are RLS-filtered and each write function authorizes session_user.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'emilia_gate_evidence_runtime') THEN
    CREATE ROLE emilia_gate_evidence_runtime
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
END
$role$;

DO $role_safety$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM pg_catalog.pg_roles
      WHERE rolname = 'emilia_gate_evidence_runtime'
        AND (
          rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole
          OR rolreplication OR rolbypassrls
        )
  ) THEN
    RAISE EXCEPTION 'emilia_gate_evidence_runtime has unsafe privileged attributes'
      USING ERRCODE = '42501';
  END IF;
END
$role_safety$;

ALTER ROLE emilia_gate_evidence_runtime NOLOGIN NOINHERIT;

CREATE SCHEMA IF NOT EXISTS emilia_gate_evidence;
REVOKE ALL ON SCHEMA emilia_gate_evidence FROM PUBLIC;
REVOKE CREATE ON SCHEMA emilia_gate_evidence FROM emilia_gate_evidence_runtime;
GRANT USAGE ON SCHEMA emilia_gate_evidence TO emilia_gate_evidence_runtime;

CREATE TABLE IF NOT EXISTS emilia_gate_evidence.heads (
  tenant_id  TEXT NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 256),
  gate_id    TEXT NOT NULL CHECK (char_length(gate_id) BETWEEN 1 AND 256),
  stream_id  TEXT NOT NULL CHECK (char_length(stream_id) BETWEEN 1 AND 256),
  head_seq   BIGINT NOT NULL DEFAULT -1,
  head_hash  TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, gate_id, stream_id),
  CONSTRAINT evidence_head_shape CHECK (
    (head_seq = -1 AND head_hash IS NULL)
    OR (head_seq BETWEEN 0 AND 9007199254740991 AND head_hash ~ '^[0-9a-f]{64}$')
  )
);

CREATE TABLE IF NOT EXISTS emilia_gate_evidence.records (
  tenant_id  TEXT NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 256),
  gate_id    TEXT NOT NULL CHECK (char_length(gate_id) BETWEEN 1 AND 256),
  stream_id  TEXT NOT NULL CHECK (char_length(stream_id) BETWEEN 1 AND 256),
  seq        BIGINT NOT NULL CHECK (seq BETWEEN 0 AND 9007199254740991),
  record_id  TEXT NOT NULL CHECK (char_length(record_id) BETWEEN 16 AND 256),
  prev_hash  TEXT NOT NULL CHECK (prev_hash = 'genesis' OR prev_hash ~ '^[0-9a-f]{64}$'),
  hash       TEXT NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
  record     JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, gate_id, stream_id, seq),
  UNIQUE (tenant_id, gate_id, stream_id, record_id),
  UNIQUE (tenant_id, gate_id, stream_id, hash),
  FOREIGN KEY (tenant_id, gate_id, stream_id)
    REFERENCES emilia_gate_evidence.heads (tenant_id, gate_id, stream_id)
    ON DELETE RESTRICT,
  CONSTRAINT evidence_record_seq_match CHECK (
    jsonb_typeof(record -> 'seq') = 'number'
    AND (record ->> 'seq')::numeric = seq
  ),
  CONSTRAINT evidence_record_id_match CHECK (record ->> 'record_id' = record_id),
  CONSTRAINT evidence_record_prev_match CHECK (record ->> 'prev_hash' = prev_hash),
  CONSTRAINT evidence_record_hash_match CHECK (record ->> 'hash' = hash)
);

CREATE TABLE IF NOT EXISTS emilia_gate_evidence.runtime_scope_grants (
  login_role NAME NOT NULL,
  tenant_id  TEXT NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 256),
  gate_id    TEXT NOT NULL CHECK (char_length(gate_id) BETWEEN 1 AND 256),
  stream_id  TEXT NOT NULL CHECK (char_length(stream_id) BETWEEN 1 AND 256),
  granted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (login_role, tenant_id, gate_id, stream_id)
);

CREATE TABLE IF NOT EXISTS emilia_gate_evidence.network_witness_scope_grants (
  login_role NAME NOT NULL,
  tenant_id  TEXT NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 256),
  gate_id    TEXT NOT NULL CHECK (char_length(gate_id) BETWEEN 1 AND 256),
  stream_key BYTEA NOT NULL CHECK (octet_length(stream_key) BETWEEN 1 AND 1024),
  granted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (login_role, tenant_id, gate_id, stream_key)
);

CREATE TABLE IF NOT EXISTS emilia_gate_evidence.network_witness_checkpoints (
  tenant_id        TEXT NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 256),
  gate_id          TEXT NOT NULL CHECK (char_length(gate_id) BETWEEN 1 AND 256),
  stream_key       BYTEA NOT NULL CHECK (octet_length(stream_key) BETWEEN 1 AND 1024),
  sequence         BIGINT NOT NULL CHECK (sequence BETWEEN 0 AND 9007199254740991),
  statement_digest TEXT NOT NULL CHECK (statement_digest ~ '^sha256:[0-9a-f]{64}$'),
  equivocated      BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, gate_id, stream_key)
);

ALTER TABLE emilia_gate_evidence.network_witness_checkpoints
  ADD COLUMN IF NOT EXISTS equivocated BOOLEAN NOT NULL DEFAULT FALSE;

-- Re-running the migration cannot leave the runtime role as an object owner;
-- ownership bypasses ordinary table ACLs in Postgres.
ALTER SCHEMA emilia_gate_evidence OWNER TO CURRENT_USER;
ALTER TABLE emilia_gate_evidence.heads OWNER TO CURRENT_USER;
ALTER TABLE emilia_gate_evidence.records OWNER TO CURRENT_USER;
ALTER TABLE emilia_gate_evidence.runtime_scope_grants OWNER TO CURRENT_USER;
ALTER TABLE emilia_gate_evidence.network_witness_scope_grants OWNER TO CURRENT_USER;
ALTER TABLE emilia_gate_evidence.network_witness_checkpoints OWNER TO CURRENT_USER;

CREATE OR REPLACE FUNCTION emilia_gate_evidence.reject_record_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  RAISE EXCEPTION 'EMILIA evidence records are append-only'
    USING ERRCODE = '55000';
END
$function$;

ALTER FUNCTION emilia_gate_evidence.reject_record_mutation() OWNER TO CURRENT_USER;

DROP TRIGGER IF EXISTS evidence_records_are_immutable ON emilia_gate_evidence.records;
CREATE TRIGGER evidence_records_are_immutable
  BEFORE UPDATE OR DELETE OR TRUNCATE ON emilia_gate_evidence.records
  FOR EACH STATEMENT EXECUTE FUNCTION emilia_gate_evidence.reject_record_mutation();

CREATE OR REPLACE FUNCTION emilia_gate_evidence.runtime_scope_authorized(
  p_tenant_id TEXT,
  p_gate_id TEXT,
  p_stream_id TEXT
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
  SELECT EXISTS (
    SELECT 1
      FROM emilia_gate_evidence.runtime_scope_grants AS g
      JOIN pg_catalog.pg_roles AS r ON r.rolname = g.login_role
      WHERE g.login_role = session_user
        AND g.tenant_id = p_tenant_id
        AND g.gate_id = p_gate_id
        AND g.stream_id = p_stream_id
        AND r.rolcanlogin
        AND NOT r.rolsuper
        AND NOT r.rolbypassrls
        AND pg_catalog.pg_has_role(
          session_user,
          'emilia_gate_evidence_runtime',
          'MEMBER'
        )
  )
$function$;

CREATE OR REPLACE FUNCTION emilia_gate_evidence.grant_runtime_scope(
  p_login_role NAME,
  p_tenant_id TEXT,
  p_gate_id TEXT,
  p_stream_id TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
  v_role pg_catalog.pg_roles%ROWTYPE;
BEGIN
  IF p_tenant_id IS NULL OR char_length(p_tenant_id) NOT BETWEEN 1 AND 256
     OR p_gate_id IS NULL OR char_length(p_gate_id) NOT BETWEEN 1 AND 256
     OR p_stream_id IS NULL OR char_length(p_stream_id) NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION 'invalid EMILIA evidence scope' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_role
    FROM pg_catalog.pg_roles
    WHERE rolname = p_login_role;
  IF NOT FOUND OR NOT v_role.rolcanlogin THEN
    RAISE EXCEPTION 'EMILIA evidence scope requires an existing login role'
      USING ERRCODE = '22023';
  END IF;
  IF v_role.rolsuper OR v_role.rolbypassrls THEN
    RAISE EXCEPTION 'EMILIA runtime login must not bypass row security'
      USING ERRCODE = '42501';
  END IF;
  IF NOT pg_catalog.pg_has_role(
    p_login_role,
    'emilia_gate_evidence_runtime',
    'MEMBER'
  ) THEN
    RAISE EXCEPTION 'EMILIA runtime login must be a member of emilia_gate_evidence_runtime'
      USING ERRCODE = '42501';
  END IF;

  INSERT INTO emilia_gate_evidence.runtime_scope_grants (
    login_role, tenant_id, gate_id, stream_id
  ) VALUES (
    p_login_role, p_tenant_id, p_gate_id, p_stream_id
  ) ON CONFLICT DO NOTHING;
END
$function$;

CREATE OR REPLACE FUNCTION emilia_gate_evidence.revoke_runtime_scope(
  p_login_role NAME,
  p_tenant_id TEXT,
  p_gate_id TEXT,
  p_stream_id TEXT
)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
  WITH deleted AS (
    DELETE FROM emilia_gate_evidence.runtime_scope_grants
      WHERE login_role = p_login_role
        AND tenant_id = p_tenant_id
        AND gate_id = p_gate_id
        AND stream_id = p_stream_id
      RETURNING 1
  )
  SELECT EXISTS (SELECT 1 FROM deleted)
$function$;

CREATE OR REPLACE FUNCTION emilia_gate_evidence.network_witness_scope_authorized(
  p_tenant_id TEXT,
  p_gate_id TEXT,
  p_stream_key BYTEA
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
  SELECT EXISTS (
    SELECT 1
      FROM emilia_gate_evidence.network_witness_scope_grants AS g
      JOIN pg_catalog.pg_roles AS r ON r.rolname = g.login_role
      WHERE g.login_role = session_user
        AND g.tenant_id = p_tenant_id
        AND g.gate_id = p_gate_id
        AND g.stream_key = p_stream_key
        AND r.rolcanlogin
        AND NOT r.rolsuper
        AND NOT r.rolbypassrls
        AND pg_catalog.pg_has_role(
          session_user,
          'emilia_gate_evidence_runtime',
          'MEMBER'
        )
  )
$function$;

CREATE OR REPLACE FUNCTION emilia_gate_evidence.grant_network_witness_scope(
  p_login_role NAME,
  p_tenant_id TEXT,
  p_gate_id TEXT,
  p_stream_key BYTEA
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
  v_role pg_catalog.pg_roles%ROWTYPE;
BEGIN
  IF p_tenant_id IS NULL OR char_length(p_tenant_id) NOT BETWEEN 1 AND 256
     OR p_gate_id IS NULL OR char_length(p_gate_id) NOT BETWEEN 1 AND 256
     OR p_stream_key IS NULL OR octet_length(p_stream_key) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'invalid EMILIA network-witness scope' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_role
    FROM pg_catalog.pg_roles
    WHERE rolname = p_login_role;
  IF NOT FOUND OR NOT v_role.rolcanlogin THEN
    RAISE EXCEPTION 'EMILIA network-witness scope requires an existing login role'
      USING ERRCODE = '22023';
  END IF;
  IF v_role.rolsuper OR v_role.rolbypassrls THEN
    RAISE EXCEPTION 'EMILIA runtime login must not bypass row security'
      USING ERRCODE = '42501';
  END IF;
  IF NOT pg_catalog.pg_has_role(
    p_login_role,
    'emilia_gate_evidence_runtime',
    'MEMBER'
  ) THEN
    RAISE EXCEPTION 'EMILIA runtime login must be a member of emilia_gate_evidence_runtime'
      USING ERRCODE = '42501';
  END IF;

  INSERT INTO emilia_gate_evidence.network_witness_scope_grants (
    login_role, tenant_id, gate_id, stream_key
  ) VALUES (
    p_login_role, p_tenant_id, p_gate_id, p_stream_key
  ) ON CONFLICT DO NOTHING;
END
$function$;

CREATE OR REPLACE FUNCTION emilia_gate_evidence.revoke_network_witness_scope(
  p_login_role NAME,
  p_tenant_id TEXT,
  p_gate_id TEXT,
  p_stream_key BYTEA
)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
  WITH deleted AS (
    DELETE FROM emilia_gate_evidence.network_witness_scope_grants
      WHERE login_role = p_login_role
        AND tenant_id = p_tenant_id
        AND gate_id = p_gate_id
        AND stream_key = p_stream_key
      RETURNING 1
  )
  SELECT EXISTS (SELECT 1 FROM deleted)
$function$;

CREATE OR REPLACE FUNCTION emilia_gate_evidence.advance_network_witness_checkpoint(
  p_tenant_id TEXT,
  p_gate_id TEXT,
  p_stream_key BYTEA,
  p_sequence BIGINT,
  p_statement_digest TEXT
)
RETURNS TABLE (accepted BOOLEAN, reason TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
  v_current_digest TEXT;
  v_current_sequence BIGINT;
  v_equivocated BOOLEAN;
  v_inserted INTEGER;
BEGIN
  IF p_tenant_id IS NULL OR char_length(p_tenant_id) NOT BETWEEN 1 AND 256
     OR p_gate_id IS NULL OR char_length(p_gate_id) NOT BETWEEN 1 AND 256
     OR p_stream_key IS NULL OR octet_length(p_stream_key) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'invalid EMILIA network-witness scope' USING ERRCODE = '22023';
  END IF;
  IF NOT emilia_gate_evidence.network_witness_scope_authorized(
    p_tenant_id,
    p_gate_id,
    p_stream_key
  ) THEN
    RAISE EXCEPTION 'EMILIA network-witness scope is not authorized for session login %', session_user
      USING ERRCODE = '42501';
  END IF;
  IF p_sequence IS NULL OR p_sequence < 0 OR p_sequence > 9007199254740991 THEN
    RAISE EXCEPTION 'invalid EMILIA network-witness sequence' USING ERRCODE = '22003';
  END IF;
  IF p_statement_digest IS NULL
     OR p_statement_digest !~ '^sha256:[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid EMILIA network-witness statement digest'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO emilia_gate_evidence.network_witness_checkpoints (
    tenant_id, gate_id, stream_key, sequence, statement_digest
  ) VALUES (
    p_tenant_id, p_gate_id, p_stream_key, p_sequence, p_statement_digest
  ) ON CONFLICT (tenant_id, gate_id, stream_key) DO NOTHING;
  GET DIAGNOSTICS v_inserted = ROW_COUNT;
  IF v_inserted = 1 THEN
    RETURN QUERY SELECT TRUE, NULL::TEXT;
    RETURN;
  END IF;

  SELECT checkpoint.sequence, checkpoint.statement_digest, checkpoint.equivocated
    INTO STRICT v_current_sequence, v_current_digest, v_equivocated
    FROM emilia_gate_evidence.network_witness_checkpoints AS checkpoint
    WHERE checkpoint.tenant_id = p_tenant_id
      AND checkpoint.gate_id = p_gate_id
      AND checkpoint.stream_key = p_stream_key
    FOR UPDATE;

  IF v_equivocated THEN
    RETURN QUERY SELECT FALSE, 'sequence_equivocation'::TEXT;
    RETURN;
  END IF;

  IF p_sequence < v_current_sequence THEN
    RETURN QUERY SELECT FALSE, 'sequence_rollback'::TEXT;
    RETURN;
  END IF;
  IF p_sequence = v_current_sequence THEN
    IF p_statement_digest = v_current_digest THEN
      RETURN QUERY SELECT FALSE, 'statement_replay'::TEXT;
    ELSE
      UPDATE emilia_gate_evidence.network_witness_checkpoints
        SET equivocated = TRUE,
            updated_at = clock_timestamp()
        WHERE tenant_id = p_tenant_id
          AND gate_id = p_gate_id
          AND stream_key = p_stream_key
          AND sequence = v_current_sequence
          AND statement_digest = v_current_digest
          AND equivocated = FALSE;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'EMILIA network-witness equivocation fence was lost'
          USING ERRCODE = '40001';
      END IF;
      RETURN QUERY SELECT FALSE, 'sequence_equivocation'::TEXT;
    END IF;
    RETURN;
  END IF;

  UPDATE emilia_gate_evidence.network_witness_checkpoints
    SET sequence = p_sequence,
        statement_digest = p_statement_digest,
        updated_at = clock_timestamp()
    WHERE tenant_id = p_tenant_id
      AND gate_id = p_gate_id
      AND stream_key = p_stream_key
      AND sequence = v_current_sequence
      AND statement_digest = v_current_digest
      AND equivocated = FALSE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'EMILIA network-witness checkpoint fence was lost'
      USING ERRCODE = '40001';
  END IF;

  RETURN QUERY SELECT TRUE, NULL::TEXT;
END
$function$;

ALTER FUNCTION emilia_gate_evidence.runtime_scope_authorized(TEXT, TEXT, TEXT)
  OWNER TO CURRENT_USER;
ALTER FUNCTION emilia_gate_evidence.grant_runtime_scope(NAME, TEXT, TEXT, TEXT)
  OWNER TO CURRENT_USER;
ALTER FUNCTION emilia_gate_evidence.revoke_runtime_scope(NAME, TEXT, TEXT, TEXT)
  OWNER TO CURRENT_USER;
ALTER FUNCTION emilia_gate_evidence.network_witness_scope_authorized(TEXT, TEXT, BYTEA)
  OWNER TO CURRENT_USER;
ALTER FUNCTION emilia_gate_evidence.grant_network_witness_scope(NAME, TEXT, TEXT, BYTEA)
  OWNER TO CURRENT_USER;
ALTER FUNCTION emilia_gate_evidence.revoke_network_witness_scope(NAME, TEXT, TEXT, BYTEA)
  OWNER TO CURRENT_USER;
ALTER FUNCTION emilia_gate_evidence.advance_network_witness_checkpoint(TEXT, TEXT, BYTEA, BIGINT, TEXT)
  OWNER TO CURRENT_USER;

CREATE OR REPLACE FUNCTION emilia_gate_evidence.append_record(
  p_tenant_id TEXT,
  p_gate_id TEXT,
  p_stream_id TEXT,
  p_expected_head_hash TEXT,
  p_record JSONB,
  p_canonical_body TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
  v_body JSONB;
  v_head_hash TEXT;
  v_head_seq BIGINT;
  v_hash TEXT;
  v_prev_hash TEXT;
  v_record_id TEXT;
  v_seq BIGINT;
  v_updated INTEGER;
BEGIN
  IF p_tenant_id IS NULL OR char_length(p_tenant_id) NOT BETWEEN 1 AND 256
     OR p_gate_id IS NULL OR char_length(p_gate_id) NOT BETWEEN 1 AND 256
     OR p_stream_id IS NULL OR char_length(p_stream_id) NOT BETWEEN 1 AND 256 THEN
    RAISE EXCEPTION 'invalid EMILIA evidence scope' USING ERRCODE = '22023';
  END IF;
  IF NOT emilia_gate_evidence.runtime_scope_authorized(
    p_tenant_id,
    p_gate_id,
    p_stream_id
  ) THEN
    RAISE EXCEPTION 'EMILIA evidence scope is not authorized for session login %', session_user
      USING ERRCODE = '42501';
  END IF;
  IF p_expected_head_hash IS NOT NULL AND p_expected_head_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid expected EMILIA evidence head' USING ERRCODE = '22023';
  END IF;
  IF p_record IS NULL OR jsonb_typeof(p_record) <> 'object'
     OR p_canonical_body IS NULL
     OR octet_length(p_canonical_body) > 8388608
     OR jsonb_typeof(p_record -> 'seq') <> 'number'
     OR coalesce(p_record ->> 'seq', '') !~ '^(0|[1-9][0-9]*)$'
     OR char_length(coalesce(p_record ->> 'record_id', '')) NOT BETWEEN 16 AND 256
     OR coalesce(p_record ->> 'prev_hash', '') !~ '^(genesis|[0-9a-f]{64})$'
     OR coalesce(p_record ->> 'hash', '') !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid EMILIA evidence record' USING ERRCODE = '22023';
  END IF;

  BEGIN
    v_body := p_canonical_body::jsonb;
    v_seq := (p_record ->> 'seq')::bigint;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid EMILIA canonical evidence body' USING ERRCODE = '22023';
  END;
  IF v_seq < 0 OR v_seq > 9007199254740991 THEN
    RAISE EXCEPTION 'EMILIA evidence sequence is outside the safe-integer range'
      USING ERRCODE = '22003';
  END IF;

  v_record_id := p_record ->> 'record_id';
  v_prev_hash := p_record ->> 'prev_hash';
  v_hash := p_record ->> 'hash';
  IF v_body IS DISTINCT FROM (p_record - 'hash')
     OR encode(public.digest(convert_to(p_canonical_body, 'UTF8'), 'sha256'), 'hex')
        IS DISTINCT FROM v_hash THEN
    RAISE EXCEPTION 'EMILIA evidence canonical hash mismatch' USING ERRCODE = '23514';
  END IF;

  INSERT INTO emilia_gate_evidence.heads (tenant_id, gate_id, stream_id)
    VALUES (p_tenant_id, p_gate_id, p_stream_id)
    ON CONFLICT (tenant_id, gate_id, stream_id) DO NOTHING;

  SELECT h.head_seq, h.head_hash
    INTO STRICT v_head_seq, v_head_hash
    FROM emilia_gate_evidence.heads h
    WHERE h.tenant_id = p_tenant_id
      AND h.gate_id = p_gate_id
      AND h.stream_id = p_stream_id
    FOR UPDATE;

  -- A false return means ordinary optimistic contention. Every malformed or
  -- indeterminate condition raises, so callers cannot mistake it for a retry.
  IF p_expected_head_hash IS DISTINCT FROM v_head_hash THEN
    RETURN FALSE;
  END IF;
  IF v_seq <> v_head_seq + 1
     OR v_prev_hash <> coalesce(v_head_hash, 'genesis') THEN
    RAISE EXCEPTION 'EMILIA evidence record does not extend the locked head'
      USING ERRCODE = '23514';
  END IF;

  INSERT INTO emilia_gate_evidence.records (
    tenant_id, gate_id, stream_id, seq, record_id, prev_hash, hash, record
  ) VALUES (
    p_tenant_id, p_gate_id, p_stream_id, v_seq, v_record_id, v_prev_hash, v_hash, p_record
  );

  UPDATE emilia_gate_evidence.heads
    SET head_seq = v_seq, head_hash = v_hash, updated_at = clock_timestamp()
    WHERE tenant_id = p_tenant_id
      AND gate_id = p_gate_id
      AND stream_id = p_stream_id
      AND head_seq = v_head_seq
      AND head_hash IS NOT DISTINCT FROM v_head_hash;
  GET DIAGNOSTICS v_updated = ROW_COUNT;
  IF v_updated <> 1 THEN
    RAISE EXCEPTION 'EMILIA evidence head fence was lost' USING ERRCODE = '40001';
  END IF;

  RETURN TRUE;
END
$function$;

ALTER FUNCTION emilia_gate_evidence.append_record(TEXT, TEXT, TEXT, TEXT, JSONB, TEXT)
  OWNER TO CURRENT_USER;

ALTER TABLE emilia_gate_evidence.heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE emilia_gate_evidence.heads FORCE ROW LEVEL SECURITY;
ALTER TABLE emilia_gate_evidence.records ENABLE ROW LEVEL SECURITY;
ALTER TABLE emilia_gate_evidence.records FORCE ROW LEVEL SECURITY;
ALTER TABLE emilia_gate_evidence.network_witness_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE emilia_gate_evidence.network_witness_checkpoints FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS evidence_heads_runtime_read ON emilia_gate_evidence.heads;
CREATE POLICY evidence_heads_runtime_read
  ON emilia_gate_evidence.heads
  FOR SELECT
  TO emilia_gate_evidence_runtime
  USING (emilia_gate_evidence.runtime_scope_authorized(tenant_id, gate_id, stream_id));

DROP POLICY IF EXISTS evidence_records_runtime_read ON emilia_gate_evidence.records;
CREATE POLICY evidence_records_runtime_read
  ON emilia_gate_evidence.records
  FOR SELECT
  TO emilia_gate_evidence_runtime
  USING (emilia_gate_evidence.runtime_scope_authorized(tenant_id, gate_id, stream_id));

DROP POLICY IF EXISTS network_witness_runtime_read
  ON emilia_gate_evidence.network_witness_checkpoints;
CREATE POLICY network_witness_runtime_read
  ON emilia_gate_evidence.network_witness_checkpoints
  FOR SELECT
  TO emilia_gate_evidence_runtime
  USING (emilia_gate_evidence.network_witness_scope_authorized(tenant_id, gate_id, stream_key));

-- FORCE RLS applies to the table owner too. Give only the current migration
-- owner an all-rows policy so SECURITY DEFINER append can perform its fenced
-- write after validating session_user. Re-runs replace stale owner policies.
DROP POLICY IF EXISTS evidence_heads_owner_all ON emilia_gate_evidence.heads;
DROP POLICY IF EXISTS evidence_records_owner_all ON emilia_gate_evidence.records;
DROP POLICY IF EXISTS network_witness_owner_all
  ON emilia_gate_evidence.network_witness_checkpoints;
DO $policies$
BEGIN
  EXECUTE format(
    'CREATE POLICY evidence_heads_owner_all ON emilia_gate_evidence.heads FOR ALL TO %I USING (true) WITH CHECK (true)',
    current_user
  );
  EXECUTE format(
    'CREATE POLICY evidence_records_owner_all ON emilia_gate_evidence.records FOR ALL TO %I USING (true) WITH CHECK (true)',
    current_user
  );
  EXECUTE format(
    'CREATE POLICY network_witness_owner_all ON emilia_gate_evidence.network_witness_checkpoints FOR ALL TO %I USING (true) WITH CHECK (true)',
    current_user
  );
END
$policies$;

REVOKE ALL ON TABLE
  emilia_gate_evidence.records,
  emilia_gate_evidence.heads,
  emilia_gate_evidence.runtime_scope_grants,
  emilia_gate_evidence.network_witness_scope_grants,
  emilia_gate_evidence.network_witness_checkpoints
  FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON emilia_gate_evidence.records, emilia_gate_evidence.heads
  FROM emilia_gate_evidence_runtime;
REVOKE ALL ON TABLE emilia_gate_evidence.runtime_scope_grants
  FROM emilia_gate_evidence_runtime;
REVOKE ALL ON TABLE emilia_gate_evidence.network_witness_scope_grants
  FROM emilia_gate_evidence_runtime;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON emilia_gate_evidence.network_witness_checkpoints
  FROM emilia_gate_evidence_runtime;
GRANT SELECT ON emilia_gate_evidence.records, emilia_gate_evidence.heads
  TO emilia_gate_evidence_runtime;
GRANT SELECT ON emilia_gate_evidence.network_witness_checkpoints
  TO emilia_gate_evidence_runtime;

REVOKE ALL ON FUNCTION emilia_gate_evidence.reject_record_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION emilia_gate_evidence.reject_record_mutation()
  FROM emilia_gate_evidence_runtime;
REVOKE ALL ON FUNCTION emilia_gate_evidence.runtime_scope_authorized(TEXT, TEXT, TEXT)
  FROM PUBLIC, emilia_gate_evidence_runtime;
GRANT EXECUTE ON FUNCTION emilia_gate_evidence.runtime_scope_authorized(TEXT, TEXT, TEXT)
  TO emilia_gate_evidence_runtime;
REVOKE ALL ON FUNCTION emilia_gate_evidence.grant_runtime_scope(NAME, TEXT, TEXT, TEXT)
  FROM PUBLIC, emilia_gate_evidence_runtime;
REVOKE ALL ON FUNCTION emilia_gate_evidence.revoke_runtime_scope(NAME, TEXT, TEXT, TEXT)
  FROM PUBLIC, emilia_gate_evidence_runtime;
REVOKE ALL ON FUNCTION emilia_gate_evidence.network_witness_scope_authorized(TEXT, TEXT, BYTEA)
  FROM PUBLIC, emilia_gate_evidence_runtime;
GRANT EXECUTE ON FUNCTION emilia_gate_evidence.network_witness_scope_authorized(TEXT, TEXT, BYTEA)
  TO emilia_gate_evidence_runtime;
REVOKE ALL ON FUNCTION emilia_gate_evidence.grant_network_witness_scope(NAME, TEXT, TEXT, BYTEA)
  FROM PUBLIC, emilia_gate_evidence_runtime;
REVOKE ALL ON FUNCTION emilia_gate_evidence.revoke_network_witness_scope(NAME, TEXT, TEXT, BYTEA)
  FROM PUBLIC, emilia_gate_evidence_runtime;
REVOKE ALL ON FUNCTION emilia_gate_evidence.advance_network_witness_checkpoint(TEXT, TEXT, BYTEA, BIGINT, TEXT)
  FROM PUBLIC, emilia_gate_evidence_runtime;
GRANT EXECUTE ON FUNCTION emilia_gate_evidence.advance_network_witness_checkpoint(TEXT, TEXT, BYTEA, BIGINT, TEXT)
  TO emilia_gate_evidence_runtime;
REVOKE ALL ON FUNCTION emilia_gate_evidence.append_record(TEXT, TEXT, TEXT, TEXT, JSONB, TEXT)
  FROM PUBLIC, emilia_gate_evidence_runtime;
GRANT EXECUTE ON FUNCTION emilia_gate_evidence.append_record(TEXT, TEXT, TEXT, TEXT, JSONB, TEXT)
  TO emilia_gate_evidence_runtime;

COMMENT ON FUNCTION emilia_gate_evidence.append_record(TEXT, TEXT, TEXT, TEXT, JSONB, TEXT)
  IS 'Authorize session_user, then atomically compare-and-append canonical EMILIA evidence under a scoped head row lock.';
COMMENT ON FUNCTION emilia_gate_evidence.grant_runtime_scope(NAME, TEXT, TEXT, TEXT)
  IS 'Bind one non-bypass runtime login to one exact tenant/gate/stream evidence scope.';
COMMENT ON FUNCTION emilia_gate_evidence.grant_network_witness_scope(NAME, TEXT, TEXT, BYTEA)
  IS 'Bind one non-bypass runtime login to one exact tenant/gate/binary witness stream scope.';
COMMENT ON TABLE emilia_gate_evidence.runtime_scope_grants
  IS 'Owner-managed bindings from runtime login roles to exact textual evidence scopes.';
COMMENT ON TABLE emilia_gate_evidence.network_witness_scope_grants
  IS 'Owner-managed bindings from runtime login roles to exact binary network-witness stream keys.';
COMMENT ON FUNCTION emilia_gate_evidence.advance_network_witness_checkpoint(TEXT, TEXT, BYTEA, BIGINT, TEXT)
  IS 'Atomically advance a scoped witness checkpoint or distinguish replay, rollback, and same-sequence equivocation.';
COMMENT ON TABLE emilia_gate_evidence.network_witness_checkpoints
  IS 'Latest tenant/gate/stream network-witness sequence and statement digest; a checkpoint, not complete observation history.';
COMMENT ON TABLE emilia_gate_evidence.records
  IS 'Immutable tenant/gate/stream-scoped EMILIA evidence records.';

COMMIT;
