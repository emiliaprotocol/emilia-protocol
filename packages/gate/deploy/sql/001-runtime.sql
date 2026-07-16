-- SPDX-License-Identifier: Apache-2.0
-- EMILIA Gate Postgres evidence runtime (EP-GATE-PG-EVIDENCE-v1).
--
-- Run this migration as a non-runtime owner with CREATE EXTENSION, CREATEROLE,
-- and CREATE privileges. Grant emilia_gate_evidence_runtime to the login used
-- by Gate after installation. The runtime role can read evidence and execute
-- the append function, but cannot mutate either table directly.

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

ALTER ROLE emilia_gate_evidence_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;

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

-- Re-running the migration cannot leave the runtime role as an object owner;
-- ownership bypasses ordinary table ACLs in Postgres.
ALTER SCHEMA emilia_gate_evidence OWNER TO CURRENT_USER;
ALTER TABLE emilia_gate_evidence.heads OWNER TO CURRENT_USER;
ALTER TABLE emilia_gate_evidence.records OWNER TO CURRENT_USER;

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

REVOKE ALL ON TABLE emilia_gate_evidence.records, emilia_gate_evidence.heads FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON emilia_gate_evidence.records, emilia_gate_evidence.heads
  FROM emilia_gate_evidence_runtime;
GRANT SELECT ON emilia_gate_evidence.records, emilia_gate_evidence.heads
  TO emilia_gate_evidence_runtime;

REVOKE ALL ON FUNCTION emilia_gate_evidence.reject_record_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION emilia_gate_evidence.reject_record_mutation()
  FROM emilia_gate_evidence_runtime;
REVOKE ALL ON FUNCTION emilia_gate_evidence.append_record(TEXT, TEXT, TEXT, TEXT, JSONB, TEXT)
  FROM PUBLIC, emilia_gate_evidence_runtime;
GRANT EXECUTE ON FUNCTION emilia_gate_evidence.append_record(TEXT, TEXT, TEXT, TEXT, JSONB, TEXT)
  TO emilia_gate_evidence_runtime;

COMMENT ON FUNCTION emilia_gate_evidence.append_record(TEXT, TEXT, TEXT, TEXT, JSONB, TEXT)
  IS 'Atomically compare-and-append canonical EMILIA evidence under a scoped head row lock.';
COMMENT ON TABLE emilia_gate_evidence.records
  IS 'Immutable tenant/gate/stream-scoped EMILIA evidence records.';

COMMIT;
