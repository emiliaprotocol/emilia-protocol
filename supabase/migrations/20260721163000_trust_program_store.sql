-- SPDX-License-Identifier: Apache-2.0
-- Durable, RPC-only state custody for EP-GATE-TRUST-PROGRAM-PROFILE-v1.

CREATE SCHEMA IF NOT EXISTS trust_program_private;

REVOKE ALL ON SCHEMA trust_program_private
  FROM PUBLIC, anon, authenticated, service_role;
GRANT USAGE ON SCHEMA trust_program_private TO service_role;

CREATE TABLE trust_program_private.store_root (
  root_id SMALLINT PRIMARY KEY CHECK (root_id = 1)
);

INSERT INTO trust_program_private.store_root (root_id) VALUES (1);

CREATE TABLE trust_program_private.instances (
  instance_id TEXT PRIMARY KEY
    CHECK (instance_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  revision BIGINT NOT NULL CHECK (revision >= 0 AND revision <= 9007199254740991),
  state_json TEXT NOT NULL CHECK (octet_length(state_json) <= 4194304),
  state_digest TEXT NOT NULL CHECK (state_digest ~ '^sha256:[0-9a-f]{64}$'),
  updated_at TEXT NOT NULL
);

CREATE TABLE trust_program_private.events (
  instance_id TEXT NOT NULL
    REFERENCES trust_program_private.instances(instance_id) ON DELETE RESTRICT,
  revision BIGINT NOT NULL CHECK (revision >= 0 AND revision <= 9007199254740991),
  previous_revision BIGINT NULL,
  event_kind TEXT NOT NULL CHECK (event_kind IN ('create', 'cas', 'invalidate')),
  state_json TEXT NOT NULL CHECK (octet_length(state_json) <= 4194304),
  state_digest TEXT NOT NULL CHECK (state_digest ~ '^sha256:[0-9a-f]{64}$'),
  reason TEXT NULL,
  recorded_at TEXT NOT NULL,
  PRIMARY KEY (instance_id, revision),
  CHECK (
    (event_kind = 'create' AND revision = 0 AND previous_revision IS NULL)
    OR (
      event_kind IN ('cas', 'invalidate')
      AND previous_revision = revision - 1
    )
  ),
  CHECK (
    (event_kind = 'invalidate' AND reason IS NOT NULL AND length(reason) BETWEEN 1 AND 256)
    OR (event_kind <> 'invalidate' AND reason IS NULL)
  )
);

ALTER TABLE trust_program_private.store_root ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust_program_private.store_root FORCE ROW LEVEL SECURITY;
ALTER TABLE trust_program_private.instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust_program_private.instances FORCE ROW LEVEL SECURITY;
ALTER TABLE trust_program_private.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust_program_private.events FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE trust_program_private.store_root
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE trust_program_private.instances
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE trust_program_private.events
  FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION trust_program_private.validate_state(
  p_instance_id pg_catalog.text,
  p_revision pg_catalog.int8,
  p_state_json pg_catalog.text,
  p_state_digest pg_catalog.text,
  p_event_at pg_catalog.text
)
RETURNS pg_catalog.jsonb
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_state pg_catalog.jsonb;
BEGIN
  IF p_instance_id IS NULL
     OR p_instance_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
     OR p_revision IS NULL
     OR p_revision < 0
     OR p_revision > 9007199254740991
     OR p_state_json IS NULL
     OR pg_catalog.octet_length(p_state_json) > 4194304
     OR p_state_digest IS NULL
     OR p_state_digest !~ '^sha256:[0-9a-f]{64}$'
     OR p_state_digest IS DISTINCT FROM (
       'sha256:' || pg_catalog.encode(
         extensions.digest(pg_catalog.convert_to(p_state_json, 'UTF8'), 'sha256'),
         'hex'
       )
     )
     OR p_event_at IS NULL
     OR p_event_at !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$'
     OR NOT pg_catalog.pg_input_is_valid(p_event_at, 'timestamp with time zone')
  THEN
    RAISE EXCEPTION 'TP_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;

  BEGIN
    v_state := p_state_json::pg_catalog.jsonb;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'TP_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END;

  IF pg_catalog.jsonb_typeof(v_state) IS DISTINCT FROM 'object'
     OR v_state ->> 'instance_id' IS DISTINCT FROM p_instance_id
     OR NOT pg_catalog.pg_input_is_valid(v_state ->> 'revision', 'bigint')
     OR (v_state ->> 'revision')::pg_catalog.int8 IS DISTINCT FROM p_revision
     OR v_state ->> 'updated_at' IS DISTINCT FROM p_event_at
  THEN
    RAISE EXCEPTION 'TP_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;

  RETURN v_state;
END;
$$;

CREATE OR REPLACE FUNCTION trust_program_private.reject_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  RAISE EXCEPTION 'TP_EVENT_IMMUTABLE' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER trust_program_events_immutable
  BEFORE UPDATE OR DELETE ON trust_program_private.events
  FOR EACH ROW
  EXECUTE FUNCTION trust_program_private.reject_event_mutation();

CREATE OR REPLACE FUNCTION trust_program_private.trust_program_create(
  p_instance_id pg_catalog.text,
  p_state_json pg_catalog.text,
  p_state_digest pg_catalog.text,
  p_event_at pg_catalog.text
)
RETURNS TABLE (
  ok pg_catalog.bool,
  reason pg_catalog.text,
  instance_id pg_catalog.text,
  revision pg_catalog.int8,
  state_json pg_catalog.text,
  state_digest pg_catalog.text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_state pg_catalog.jsonb;
  v_inserted pg_catalog.bool := false;
BEGIN
  v_state := trust_program_private.validate_state(
    p_instance_id, 0, p_state_json, p_state_digest, p_event_at
  );

  IF v_state ->> 'status' IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'TP_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;

  PERFORM 1
  FROM trust_program_private.store_root AS r
  WHERE r.root_id = 1
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'TP_STORE_CORRUPT' USING ERRCODE = '55000';
  END IF;

  INSERT INTO trust_program_private.instances AS i (
    instance_id, revision, state_json, state_digest, updated_at
  ) VALUES (
    p_instance_id, 0, p_state_json, p_state_digest, p_event_at
  )
  ON CONFLICT ON CONSTRAINT instances_pkey DO NOTHING
  RETURNING true INTO v_inserted;

  IF v_inserted IS DISTINCT FROM true THEN
    RETURN QUERY SELECT false, 'instance_exists'::pg_catalog.text,
      p_instance_id, NULL::pg_catalog.int8, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  INSERT INTO trust_program_private.events (
    instance_id, revision, previous_revision, event_kind,
    state_json, state_digest, reason, recorded_at
  ) VALUES (
    p_instance_id, 0, NULL, 'create',
    p_state_json, p_state_digest, NULL, p_event_at
  );

  RETURN QUERY SELECT true, NULL::pg_catalog.text,
    p_instance_id, 0::pg_catalog.int8, p_state_json, p_state_digest;
END;
$$;

CREATE OR REPLACE FUNCTION trust_program_private.trust_program_get(
  p_instance_id pg_catalog.text
)
RETURNS TABLE (
  ok pg_catalog.bool,
  reason pg_catalog.text,
  instance_id pg_catalog.text,
  revision pg_catalog.int8,
  state_json pg_catalog.text,
  state_digest pg_catalog.text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_instance trust_program_private.instances%ROWTYPE;
BEGIN
  IF p_instance_id IS NULL
     OR p_instance_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  THEN
    RAISE EXCEPTION 'TP_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;

  SELECT i.* INTO v_instance
  FROM trust_program_private.instances AS i
  WHERE i.instance_id = p_instance_id;

  IF NOT FOUND THEN
    RETURN QUERY SELECT false, 'instance_not_found'::pg_catalog.text,
      p_instance_id, NULL::pg_catalog.int8, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  PERFORM trust_program_private.validate_state(
    v_instance.instance_id,
    v_instance.revision,
    v_instance.state_json,
    v_instance.state_digest,
    v_instance.updated_at
  );

  IF NOT EXISTS (
    SELECT 1
    FROM trust_program_private.events AS e
    WHERE e.instance_id = v_instance.instance_id
      AND e.revision = v_instance.revision
      AND e.state_json = v_instance.state_json
      AND e.state_digest = v_instance.state_digest
      AND e.recorded_at = v_instance.updated_at
  ) THEN
    RAISE EXCEPTION 'TP_STORE_CORRUPT' USING ERRCODE = '55000';
  END IF;

  RETURN QUERY SELECT true, NULL::pg_catalog.text,
    v_instance.instance_id, v_instance.revision,
    v_instance.state_json, v_instance.state_digest;
END;
$$;

CREATE OR REPLACE FUNCTION trust_program_private.trust_program_compare_and_swap(
  p_instance_id pg_catalog.text,
  p_expected_revision pg_catalog.int8,
  p_next_revision pg_catalog.int8,
  p_state_json pg_catalog.text,
  p_state_digest pg_catalog.text,
  p_event_at pg_catalog.text
)
RETURNS TABLE (
  ok pg_catalog.bool,
  reason pg_catalog.text,
  instance_id pg_catalog.text,
  revision pg_catalog.int8,
  state_json pg_catalog.text,
  state_digest pg_catalog.text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_current trust_program_private.instances%ROWTYPE;
  v_current_state pg_catalog.jsonb;
  v_next_state pg_catalog.jsonb;
BEGIN
  IF p_expected_revision IS NULL
     OR p_expected_revision < 0
     OR p_expected_revision >= 9007199254740991
     OR p_next_revision IS DISTINCT FROM p_expected_revision + 1
  THEN
    RAISE EXCEPTION 'TP_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;

  v_next_state := trust_program_private.validate_state(
    p_instance_id, p_next_revision, p_state_json, p_state_digest, p_event_at
  );

  PERFORM 1
  FROM trust_program_private.store_root AS r
  WHERE r.root_id = 1
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'TP_STORE_CORRUPT' USING ERRCODE = '55000';
  END IF;

  SELECT i.* INTO v_current
  FROM trust_program_private.instances AS i
  WHERE i.instance_id = p_instance_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN QUERY SELECT false, 'instance_not_found'::pg_catalog.text,
      p_instance_id, NULL::pg_catalog.int8, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  v_current_state := trust_program_private.validate_state(
    v_current.instance_id,
    v_current.revision,
    v_current.state_json,
    v_current.state_digest,
    v_current.updated_at
  );

  IF NOT EXISTS (
    SELECT 1
    FROM trust_program_private.events AS e
    WHERE e.instance_id = v_current.instance_id
      AND e.revision = v_current.revision
      AND e.state_json = v_current.state_json
      AND e.state_digest = v_current.state_digest
      AND e.recorded_at = v_current.updated_at
  ) THEN
    RAISE EXCEPTION 'TP_STORE_CORRUPT' USING ERRCODE = '55000';
  END IF;

  IF v_current.revision IS DISTINCT FROM p_expected_revision THEN
    RETURN QUERY SELECT false, 'revision_conflict'::pg_catalog.text,
      p_instance_id, NULL::pg_catalog.int8, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  IF p_event_at::pg_catalog.timestamptz < v_current.updated_at::pg_catalog.timestamptz THEN
    RETURN QUERY SELECT false, 'clock_regression'::pg_catalog.text,
      p_instance_id, NULL::pg_catalog.int8, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  IF v_next_state ->> 'version' IS DISTINCT FROM v_current_state ->> 'version'
     OR v_next_state ->> 'instance_id' IS DISTINCT FROM v_current_state ->> 'instance_id'
     OR v_next_state ->> 'program_id' IS DISTINCT FROM v_current_state ->> 'program_id'
     OR v_next_state ->> 'program_version' IS DISTINCT FROM v_current_state ->> 'program_version'
     OR v_next_state ->> 'program_digest' IS DISTINCT FROM v_current_state ->> 'program_digest'
     OR v_next_state ->> 'root_caid' IS DISTINCT FROM v_current_state ->> 'root_caid'
     OR v_next_state ->> 'action_digest' IS DISTINCT FROM v_current_state ->> 'action_digest'
     OR v_next_state ->> 'created_at' IS DISTINCT FROM v_current_state ->> 'created_at'
  THEN
    RAISE EXCEPTION 'TP_STATE_BINDING_CHANGED' USING ERRCODE = '22023';
  END IF;

  UPDATE trust_program_private.instances AS i
  SET revision = p_next_revision,
      state_json = p_state_json,
      state_digest = p_state_digest,
      updated_at = p_event_at
  WHERE i.instance_id = p_instance_id;

  INSERT INTO trust_program_private.events (
    instance_id, revision, previous_revision, event_kind,
    state_json, state_digest, reason, recorded_at
  ) VALUES (
    p_instance_id, p_next_revision, p_expected_revision, 'cas',
    p_state_json, p_state_digest, NULL, p_event_at
  );

  RETURN QUERY SELECT true, NULL::pg_catalog.text,
    p_instance_id, p_next_revision, p_state_json, p_state_digest;
END;
$$;

CREATE OR REPLACE FUNCTION trust_program_private.trust_program_invalidate(
  p_instance_id pg_catalog.text,
  p_expected_revision pg_catalog.int8,
  p_reason pg_catalog.text,
  p_at pg_catalog.text,
  p_state_json pg_catalog.text,
  p_state_digest pg_catalog.text
)
RETURNS TABLE (
  ok pg_catalog.bool,
  reason pg_catalog.text,
  instance_id pg_catalog.text,
  revision pg_catalog.int8,
  state_json pg_catalog.text,
  state_digest pg_catalog.text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_current trust_program_private.instances%ROWTYPE;
  v_current_state pg_catalog.jsonb;
  v_next_state pg_catalog.jsonb;
  v_expected_state pg_catalog.jsonb;
  v_stages pg_catalog.jsonb;
  v_execution pg_catalog.jsonb;
  v_next_revision pg_catalog.int8;
BEGIN
  IF p_expected_revision IS NULL
     OR p_expected_revision < 0
     OR p_expected_revision >= 9007199254740991
     OR p_reason IS NULL
     OR pg_catalog.length(p_reason) NOT BETWEEN 1 AND 256
  THEN
    RAISE EXCEPTION 'TP_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;
  v_next_revision := p_expected_revision + 1;
  v_next_state := trust_program_private.validate_state(
    p_instance_id, v_next_revision, p_state_json, p_state_digest, p_at
  );

  PERFORM 1
  FROM trust_program_private.store_root AS r
  WHERE r.root_id = 1
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'TP_STORE_CORRUPT' USING ERRCODE = '55000';
  END IF;

  SELECT i.* INTO v_current
  FROM trust_program_private.instances AS i
  WHERE i.instance_id = p_instance_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN QUERY SELECT false, 'instance_not_found'::pg_catalog.text,
      p_instance_id, NULL::pg_catalog.int8, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  v_current_state := trust_program_private.validate_state(
    v_current.instance_id,
    v_current.revision,
    v_current.state_json,
    v_current.state_digest,
    v_current.updated_at
  );

  IF NOT EXISTS (
    SELECT 1
    FROM trust_program_private.events AS e
    WHERE e.instance_id = v_current.instance_id
      AND e.revision = v_current.revision
      AND e.state_json = v_current.state_json
      AND e.state_digest = v_current.state_digest
      AND e.recorded_at = v_current.updated_at
  ) THEN
    RAISE EXCEPTION 'TP_STORE_CORRUPT' USING ERRCODE = '55000';
  END IF;

  IF v_current.revision IS DISTINCT FROM p_expected_revision THEN
    RETURN QUERY SELECT false, 'revision_conflict'::pg_catalog.text,
      p_instance_id, NULL::pg_catalog.int8, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;
  IF p_at::pg_catalog.timestamptz < v_current.updated_at::pg_catalog.timestamptz THEN
    RETURN QUERY SELECT false, 'clock_regression'::pg_catalog.text,
      p_instance_id, NULL::pg_catalog.int8, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;
  IF v_current_state ->> 'status' IS NOT DISTINCT FROM 'invalidated' THEN
    RETURN QUERY SELECT false, 'program_instance_invalidated'::pg_catalog.text,
      p_instance_id, NULL::pg_catalog.int8, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  IF pg_catalog.jsonb_typeof(v_current_state -> 'stages') IS DISTINCT FROM 'object'
     OR pg_catalog.jsonb_typeof(v_current_state -> 'execution') IS DISTINCT FROM 'object'
     OR EXISTS (
       SELECT 1
       FROM pg_catalog.jsonb_each(v_current_state -> 'stages') AS stage(key, value)
       WHERE pg_catalog.jsonb_typeof(stage.value) IS DISTINCT FROM 'object'
     )
  THEN
    RAISE EXCEPTION 'TP_STORE_CORRUPT' USING ERRCODE = '55000';
  END IF;

  SELECT COALESCE(
    pg_catalog.jsonb_object_agg(
      stage.key,
      stage.value || pg_catalog.jsonb_build_object('status', 'invalidated')
    ),
    '{}'::pg_catalog.jsonb
  )
  INTO v_stages
  FROM pg_catalog.jsonb_each(v_current_state -> 'stages') AS stage(key, value);

  v_execution := v_current_state -> 'execution';
  IF v_execution ->> 'status' IN ('locked', 'ready') THEN
    v_execution := v_execution || pg_catalog.jsonb_build_object('status', 'invalidated');
  END IF;

  v_expected_state := v_current_state
    || pg_catalog.jsonb_build_object(
      'status', 'invalidated',
      'invalidation_reason', p_reason,
      'revision', v_next_revision,
      'updated_at', p_at,
      'stages', v_stages,
      'execution', v_execution
    );

  IF v_next_state IS DISTINCT FROM v_expected_state THEN
    RAISE EXCEPTION 'TP_INVALIDATION_TRANSITION_INVALID' USING ERRCODE = '22023';
  END IF;

  UPDATE trust_program_private.instances AS i
  SET revision = v_next_revision,
      state_json = p_state_json,
      state_digest = p_state_digest,
      updated_at = p_at
  WHERE i.instance_id = p_instance_id;

  INSERT INTO trust_program_private.events (
    instance_id, revision, previous_revision, event_kind,
    state_json, state_digest, reason, recorded_at
  ) VALUES (
    p_instance_id, v_next_revision, p_expected_revision, 'invalidate',
    p_state_json, p_state_digest, p_reason, p_at
  );

  RETURN QUERY SELECT true, NULL::pg_catalog.text,
    p_instance_id, v_next_revision, p_state_json, p_state_digest;
END;
$$;

REVOKE ALL ON FUNCTION trust_program_private.validate_state(
  pg_catalog.text, pg_catalog.int8, pg_catalog.text, pg_catalog.text, pg_catalog.text
) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION trust_program_private.reject_event_mutation()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION trust_program_private.trust_program_create(
  pg_catalog.text, pg_catalog.text, pg_catalog.text, pg_catalog.text
) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION trust_program_private.trust_program_get(pg_catalog.text)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION trust_program_private.trust_program_compare_and_swap(
  pg_catalog.text, pg_catalog.int8, pg_catalog.int8,
  pg_catalog.text, pg_catalog.text, pg_catalog.text
) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION trust_program_private.trust_program_invalidate(
  pg_catalog.text, pg_catalog.int8, pg_catalog.text,
  pg_catalog.text, pg_catalog.text, pg_catalog.text
) FROM PUBLIC, anon, authenticated, service_role;

GRANT EXECUTE ON FUNCTION trust_program_private.trust_program_create(
  pg_catalog.text, pg_catalog.text, pg_catalog.text, pg_catalog.text
) TO service_role;
GRANT EXECUTE ON FUNCTION trust_program_private.trust_program_get(pg_catalog.text)
  TO service_role;
GRANT EXECUTE ON FUNCTION trust_program_private.trust_program_compare_and_swap(
  pg_catalog.text, pg_catalog.int8, pg_catalog.int8,
  pg_catalog.text, pg_catalog.text, pg_catalog.text
) TO service_role;
GRANT EXECUTE ON FUNCTION trust_program_private.trust_program_invalidate(
  pg_catalog.text, pg_catalog.int8, pg_catalog.text,
  pg_catalog.text, pg_catalog.text, pg_catalog.text
) TO service_role;
