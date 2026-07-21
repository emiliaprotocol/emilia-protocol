-- SPDX-License-Identifier: Apache-2.0
-- Durable, tenant-aware, RPC-only custody for EP-GATE-REMEDY-PROGRAM-PROFILE-v1.

CREATE SCHEMA IF NOT EXISTS remedy_program_private;

REVOKE ALL ON SCHEMA remedy_program_private
  FROM PUBLIC, anon, authenticated, service_role;
GRANT USAGE ON SCHEMA remedy_program_private TO service_role;

CREATE TABLE remedy_program_private.store_root (
  root_id SMALLINT PRIMARY KEY CHECK (root_id = 1)
);

INSERT INTO remedy_program_private.store_root (root_id) VALUES (1);

CREATE TABLE remedy_program_private.instances (
  tenant_id TEXT NOT NULL
    CHECK (
      octet_length(tenant_id) BETWEEN 1 AND 512
      AND tenant_id !~ '[[:cntrl:]]'
    ),
  instance_id TEXT NOT NULL
    CHECK (instance_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'),
  revision BIGINT NOT NULL CHECK (revision BETWEEN 0 AND 9007199254740991),
  state_json TEXT NOT NULL CHECK (octet_length(state_json) <= 4194304),
  state_digest TEXT NOT NULL CHECK (state_digest ~ '^sha256:[0-9a-f]{64}$'),
  event_at TEXT NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, instance_id)
);

CREATE TABLE remedy_program_private.events (
  tenant_id TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  revision BIGINT NOT NULL CHECK (revision BETWEEN 0 AND 9007199254740991),
  previous_revision BIGINT NULL,
  event_kind TEXT NOT NULL CHECK (event_kind IN ('create', 'cas')),
  state_json TEXT NOT NULL CHECK (octet_length(state_json) <= 4194304),
  state_digest TEXT NOT NULL CHECK (state_digest ~ '^sha256:[0-9a-f]{64}$'),
  event_at TEXT NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, instance_id, revision),
  FOREIGN KEY (tenant_id, instance_id)
    REFERENCES remedy_program_private.instances(tenant_id, instance_id) ON DELETE RESTRICT,
  CHECK (
    (event_kind = 'create' AND revision = 0 AND previous_revision IS NULL)
    OR (
      event_kind = 'cas'
      AND revision > 0
      AND previous_revision = revision - 1
    )
  )
);

CREATE TABLE remedy_program_private.evidence_id_consumptions (
  tenant_id TEXT NOT NULL,
  evidence_id TEXT NOT NULL
    CHECK (evidence_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'),
  instance_id TEXT NOT NULL,
  revision BIGINT NOT NULL CHECK (revision BETWEEN 0 AND 9007199254740991),
  recorded_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, evidence_id),
  FOREIGN KEY (tenant_id, instance_id, revision)
    REFERENCES remedy_program_private.events(tenant_id, instance_id, revision) ON DELETE RESTRICT
);

CREATE TABLE remedy_program_private.evidence_digest_consumptions (
  tenant_id TEXT NOT NULL,
  evidence_digest TEXT NOT NULL
    CHECK (evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
  instance_id TEXT NOT NULL,
  revision BIGINT NOT NULL CHECK (revision BETWEEN 0 AND 9007199254740991),
  recorded_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, evidence_digest),
  FOREIGN KEY (tenant_id, instance_id, revision)
    REFERENCES remedy_program_private.events(tenant_id, instance_id, revision) ON DELETE RESTRICT
);

CREATE TABLE remedy_program_private.remedy_authorizations (
  tenant_id TEXT NOT NULL,
  remedy_operation_id TEXT NOT NULL
    CHECK (remedy_operation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'),
  remedy_action_digest TEXT NOT NULL
    CHECK (remedy_action_digest ~ '^sha256:[0-9a-f]{64}$'),
  remedy_caid TEXT NOT NULL
    CHECK (
      octet_length(remedy_caid) BETWEEN 1 AND 1024
      AND remedy_caid !~ '[[:cntrl:]]'
    ),
  instance_id TEXT NOT NULL,
  revision BIGINT NOT NULL CHECK (revision BETWEEN 0 AND 9007199254740991),
  recorded_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, remedy_operation_id),
  UNIQUE (tenant_id, remedy_action_digest),
  UNIQUE (tenant_id, remedy_caid),
  FOREIGN KEY (tenant_id, instance_id, revision)
    REFERENCES remedy_program_private.events(tenant_id, instance_id, revision) ON DELETE RESTRICT
);

ALTER TABLE remedy_program_private.store_root ENABLE ROW LEVEL SECURITY;
ALTER TABLE remedy_program_private.store_root FORCE ROW LEVEL SECURITY;
ALTER TABLE remedy_program_private.instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE remedy_program_private.instances FORCE ROW LEVEL SECURITY;
ALTER TABLE remedy_program_private.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE remedy_program_private.events FORCE ROW LEVEL SECURITY;
ALTER TABLE remedy_program_private.evidence_id_consumptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE remedy_program_private.evidence_id_consumptions FORCE ROW LEVEL SECURITY;
ALTER TABLE remedy_program_private.evidence_digest_consumptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE remedy_program_private.evidence_digest_consumptions FORCE ROW LEVEL SECURITY;
ALTER TABLE remedy_program_private.remedy_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE remedy_program_private.remedy_authorizations FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE remedy_program_private.store_root
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE remedy_program_private.instances
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE remedy_program_private.events
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE remedy_program_private.evidence_id_consumptions
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE remedy_program_private.evidence_digest_consumptions
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE remedy_program_private.remedy_authorizations
  FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION remedy_program_private.validate_state(
  p_tenant_id pg_catalog.text,
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
  IF p_tenant_id IS NULL
     OR pg_catalog.octet_length(p_tenant_id) NOT BETWEEN 1 AND 512
     OR p_tenant_id ~ '[[:cntrl:]]'
     OR p_instance_id IS NULL
     OR p_instance_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'
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
    RAISE EXCEPTION 'RP_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;

  BEGIN
    v_state := p_state_json::pg_catalog.jsonb;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'RP_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END;

  IF pg_catalog.jsonb_typeof(v_state) IS DISTINCT FROM 'object'
     OR v_state ->> 'tenant_id' IS DISTINCT FROM p_tenant_id
     OR v_state ->> 'instance_id' IS DISTINCT FROM p_instance_id
     OR NOT pg_catalog.pg_input_is_valid(v_state ->> 'revision', 'bigint')
     OR (v_state ->> 'revision')::pg_catalog.int8 IS DISTINCT FROM p_revision
     OR v_state ->> 'updated_at' IS DISTINCT FROM p_event_at
     OR pg_catalog.jsonb_typeof(v_state -> 'used_evidence_ids') IS DISTINCT FROM 'array'
     OR pg_catalog.jsonb_typeof(v_state -> 'used_evidence_digests') IS DISTINCT FROM 'array'
     OR pg_catalog.jsonb_typeof(v_state -> 'remedies') IS DISTINCT FROM 'array'
     OR (
       pg_catalog.jsonb_typeof(v_state -> 'active_remedy') IS DISTINCT FROM 'object'
       AND pg_catalog.jsonb_typeof(v_state -> 'active_remedy') IS DISTINCT FROM 'null'
     )
     OR EXISTS (
       SELECT 1
       FROM pg_catalog.jsonb_array_elements(v_state -> 'used_evidence_ids') AS item(value)
       WHERE pg_catalog.jsonb_typeof(item.value) IS DISTINCT FROM 'string'
          OR item.value #>> '{}' !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'
     )
     OR EXISTS (
       SELECT 1
       FROM pg_catalog.jsonb_array_elements(v_state -> 'used_evidence_digests') AS item(value)
       WHERE pg_catalog.jsonb_typeof(item.value) IS DISTINCT FROM 'string'
          OR item.value #>> '{}' !~ '^sha256:[0-9a-f]{64}$'
     )
     OR EXISTS (
       SELECT 1
       FROM (
         SELECT item.value AS attempt
         FROM pg_catalog.jsonb_array_elements(v_state -> 'remedies') AS item(value)
         UNION ALL
         SELECT v_state -> 'active_remedy'
         WHERE pg_catalog.jsonb_typeof(v_state -> 'active_remedy') = 'object'
       ) AS attempts
       WHERE pg_catalog.jsonb_typeof(attempts.attempt) IS DISTINCT FROM 'object'
          OR attempts.attempt ->> 'remedy_operation_id' IS NULL
          OR attempts.attempt ->> 'remedy_operation_id'
               !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'
          OR attempts.attempt ->> 'remedy_action_digest' IS NULL
          OR attempts.attempt ->> 'remedy_action_digest' !~ '^sha256:[0-9a-f]{64}$'
          OR attempts.attempt ->> 'remedy_caid' IS NULL
          OR pg_catalog.octet_length(attempts.attempt ->> 'remedy_caid') NOT BETWEEN 1 AND 1024
          OR attempts.attempt ->> 'remedy_caid' ~ '[[:cntrl:]]'
     )
  THEN
    RAISE EXCEPTION 'RP_STATE_BINDING_INVALID' USING ERRCODE = '22023';
  END IF;

  RETURN v_state;
END;
$$;

CREATE OR REPLACE FUNCTION remedy_program_private.state_attempts(
  p_state pg_catalog.jsonb
)
RETURNS TABLE (
  remedy_operation_id pg_catalog.text,
  remedy_action_digest pg_catalog.text,
  remedy_caid pg_catalog.text
)
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT
    attempts.attempt ->> 'remedy_operation_id',
    attempts.attempt ->> 'remedy_action_digest',
    attempts.attempt ->> 'remedy_caid'
  FROM (
    SELECT item.value AS attempt
    FROM pg_catalog.jsonb_array_elements(p_state -> 'remedies') AS item(value)
    UNION ALL
    SELECT p_state -> 'active_remedy'
    WHERE pg_catalog.jsonb_typeof(p_state -> 'active_remedy') = 'object'
  ) AS attempts;
$$;

CREATE OR REPLACE FUNCTION remedy_program_private.reject_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  RAISE EXCEPTION 'RP_EVENT_IMMUTABLE' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER remedy_program_events_immutable
  BEFORE UPDATE OR DELETE ON remedy_program_private.events
  FOR EACH ROW
  EXECUTE FUNCTION remedy_program_private.reject_event_mutation();

CREATE TRIGGER remedy_program_evidence_ids_immutable
  BEFORE UPDATE OR DELETE ON remedy_program_private.evidence_id_consumptions
  FOR EACH ROW
  EXECUTE FUNCTION remedy_program_private.reject_event_mutation();

CREATE TRIGGER remedy_program_evidence_digests_immutable
  BEFORE UPDATE OR DELETE ON remedy_program_private.evidence_digest_consumptions
  FOR EACH ROW
  EXECUTE FUNCTION remedy_program_private.reject_event_mutation();

CREATE TRIGGER remedy_program_authorizations_immutable
  BEFORE UPDATE OR DELETE ON remedy_program_private.remedy_authorizations
  FOR EACH ROW
  EXECUTE FUNCTION remedy_program_private.reject_event_mutation();

CREATE OR REPLACE FUNCTION remedy_program_private.remedy_program_create(
  p_tenant_id pg_catalog.text,
  p_instance_id pg_catalog.text,
  p_state_json pg_catalog.text,
  p_state_digest pg_catalog.text,
  p_event_at pg_catalog.text
)
RETURNS TABLE (
  ok pg_catalog.bool,
  reason pg_catalog.text,
  tenant_id pg_catalog.text,
  instance_id pg_catalog.text,
  revision pg_catalog.int8,
  state_json pg_catalog.text,
  state_digest pg_catalog.text,
  recorded_at pg_catalog.text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_state pg_catalog.jsonb;
  v_recorded_at pg_catalog.timestamptz;
  v_inserted pg_catalog.bool := false;
BEGIN
  v_state := remedy_program_private.validate_state(
    p_tenant_id, p_instance_id, 0, p_state_json, p_state_digest, p_event_at
  );

  PERFORM 1
  FROM remedy_program_private.store_root AS r
  WHERE r.root_id = 1
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RP_STORE_CORRUPT' USING ERRCODE = '55000';
  END IF;

  v_recorded_at := pg_catalog.clock_timestamp();
  IF p_event_at::pg_catalog.timestamptz
       > v_recorded_at + pg_catalog.make_interval(mins => 5)
  THEN
    RETURN QUERY SELECT false, 'clock_forward_skew'::pg_catalog.text,
      p_tenant_id, p_instance_id, NULL::pg_catalog.int8,
      NULL::pg_catalog.text, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM remedy_program_private.instances AS i
    WHERE i.tenant_id = p_tenant_id
      AND i.instance_id = p_instance_id
  ) THEN
    RETURN QUERY SELECT false, 'instance_exists'::pg_catalog.text,
      p_tenant_id, p_instance_id, NULL::pg_catalog.int8,
      NULL::pg_catalog.text, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  IF (
    SELECT pg_catalog.count(*) IS DISTINCT FROM pg_catalog.count(DISTINCT value)
    FROM pg_catalog.jsonb_array_elements_text(v_state -> 'used_evidence_ids') AS ids(value)
  ) OR (
    SELECT pg_catalog.count(*) IS DISTINCT FROM pg_catalog.count(DISTINCT value)
    FROM pg_catalog.jsonb_array_elements_text(v_state -> 'used_evidence_digests') AS digests(value)
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements_text(v_state -> 'used_evidence_ids') AS ids(value)
    JOIN remedy_program_private.evidence_id_consumptions AS consumed
      ON consumed.tenant_id = p_tenant_id
     AND consumed.evidence_id = ids.value
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements_text(v_state -> 'used_evidence_digests') AS digests(value)
    JOIN remedy_program_private.evidence_digest_consumptions AS consumed
      ON consumed.tenant_id = p_tenant_id
     AND consumed.evidence_digest = digests.value
  ) THEN
    RETURN QUERY SELECT false, 'evidence_replayed'::pg_catalog.text,
      p_tenant_id, p_instance_id, NULL::pg_catalog.int8,
      NULL::pg_catalog.text, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM remedy_program_private.state_attempts(v_state) AS attempts
    GROUP BY attempts.remedy_operation_id
    HAVING pg_catalog.count(*) > 1
  ) OR EXISTS (
    SELECT 1
    FROM remedy_program_private.state_attempts(v_state) AS attempts
    GROUP BY attempts.remedy_action_digest
    HAVING pg_catalog.count(*) > 1
  ) OR EXISTS (
    SELECT 1
    FROM remedy_program_private.state_attempts(v_state) AS attempts
    GROUP BY attempts.remedy_caid
    HAVING pg_catalog.count(*) > 1
  ) OR EXISTS (
    SELECT 1
    FROM remedy_program_private.state_attempts(v_state) AS attempts
    JOIN remedy_program_private.remedy_authorizations AS consumed
      ON consumed.tenant_id = p_tenant_id
     AND (
       consumed.remedy_operation_id = attempts.remedy_operation_id
       OR consumed.remedy_action_digest = attempts.remedy_action_digest
       OR consumed.remedy_caid = attempts.remedy_caid
     )
  ) THEN
    RETURN QUERY SELECT false, 'remedy_operation_replayed'::pg_catalog.text,
      p_tenant_id, p_instance_id, NULL::pg_catalog.int8,
      NULL::pg_catalog.text, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  INSERT INTO remedy_program_private.instances AS i (
    tenant_id, instance_id, revision, state_json, state_digest, event_at, recorded_at
  ) VALUES (
    p_tenant_id, p_instance_id, 0, p_state_json, p_state_digest,
    p_event_at, v_recorded_at
  )
  ON CONFLICT ON CONSTRAINT instances_pkey DO NOTHING
  RETURNING true INTO v_inserted;

  IF v_inserted IS DISTINCT FROM true THEN
    RETURN QUERY SELECT false, 'instance_exists'::pg_catalog.text,
      p_tenant_id, p_instance_id, NULL::pg_catalog.int8,
      NULL::pg_catalog.text, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  INSERT INTO remedy_program_private.events (
    tenant_id, instance_id, revision, previous_revision, event_kind,
    state_json, state_digest, event_at, recorded_at
  ) VALUES (
    p_tenant_id, p_instance_id, 0, NULL, 'create',
    p_state_json, p_state_digest, p_event_at, v_recorded_at
  );

  INSERT INTO remedy_program_private.evidence_id_consumptions (
    tenant_id, evidence_id, instance_id, revision, recorded_at
  )
  SELECT p_tenant_id, ids.value, p_instance_id, 0, v_recorded_at
  FROM pg_catalog.jsonb_array_elements_text(v_state -> 'used_evidence_ids') AS ids(value);

  INSERT INTO remedy_program_private.evidence_digest_consumptions (
    tenant_id, evidence_digest, instance_id, revision, recorded_at
  )
  SELECT p_tenant_id, digests.value, p_instance_id, 0, v_recorded_at
  FROM pg_catalog.jsonb_array_elements_text(v_state -> 'used_evidence_digests') AS digests(value);

  INSERT INTO remedy_program_private.remedy_authorizations (
    tenant_id, remedy_operation_id, remedy_action_digest, remedy_caid,
    instance_id, revision, recorded_at
  )
  SELECT p_tenant_id,
    attempts.remedy_operation_id,
    attempts.remedy_action_digest,
    attempts.remedy_caid,
    p_instance_id,
    0,
    v_recorded_at
  FROM remedy_program_private.state_attempts(v_state) AS attempts;

  RETURN QUERY SELECT true, NULL::pg_catalog.text,
    p_tenant_id, p_instance_id, 0::pg_catalog.int8,
    p_state_json, p_state_digest,
    pg_catalog.to_char(
      v_recorded_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    );
END;
$$;

CREATE OR REPLACE FUNCTION remedy_program_private.remedy_program_get(
  p_tenant_id pg_catalog.text,
  p_instance_id pg_catalog.text
)
RETURNS TABLE (
  ok pg_catalog.bool,
  reason pg_catalog.text,
  tenant_id pg_catalog.text,
  instance_id pg_catalog.text,
  revision pg_catalog.int8,
  state_json pg_catalog.text,
  state_digest pg_catalog.text,
  recorded_at pg_catalog.text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_instance remedy_program_private.instances%ROWTYPE;
  v_state pg_catalog.jsonb;
BEGIN
  IF p_tenant_id IS NULL
     OR pg_catalog.octet_length(p_tenant_id) NOT BETWEEN 1 AND 512
     OR p_tenant_id ~ '[[:cntrl:]]'
     OR p_instance_id IS NULL
     OR p_instance_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'
  THEN
    RAISE EXCEPTION 'RP_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;

  SELECT i.* INTO v_instance
  FROM remedy_program_private.instances AS i
  WHERE i.tenant_id = p_tenant_id
    AND i.instance_id = p_instance_id;

  IF NOT FOUND THEN
    RETURN QUERY SELECT false, 'instance_not_found'::pg_catalog.text,
      p_tenant_id, p_instance_id, NULL::pg_catalog.int8,
      NULL::pg_catalog.text, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  v_state := remedy_program_private.validate_state(
    v_instance.tenant_id,
    v_instance.instance_id,
    v_instance.revision,
    v_instance.state_json,
    v_instance.state_digest,
    v_instance.event_at
  );

  IF NOT EXISTS (
    SELECT 1
    FROM remedy_program_private.events AS e
    WHERE e.tenant_id = v_instance.tenant_id
      AND e.instance_id = v_instance.instance_id
      AND e.revision = v_instance.revision
      AND e.state_json = v_instance.state_json
      AND e.state_digest = v_instance.state_digest
      AND e.event_at = v_instance.event_at
      AND e.recorded_at = v_instance.recorded_at
  ) THEN
    RAISE EXCEPTION 'RP_STORE_CORRUPT' USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements_text(v_state -> 'used_evidence_ids') AS ids(value)
    WHERE NOT EXISTS (
      SELECT 1
      FROM remedy_program_private.evidence_id_consumptions AS consumed
      WHERE consumed.tenant_id = v_instance.tenant_id
        AND consumed.evidence_id = ids.value
        AND consumed.instance_id = v_instance.instance_id
        AND consumed.revision <= v_instance.revision
    )
  ) OR EXISTS (
    SELECT 1
    FROM remedy_program_private.evidence_id_consumptions AS consumed
    WHERE consumed.tenant_id = v_instance.tenant_id
      AND consumed.instance_id = v_instance.instance_id
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements_text(v_state -> 'used_evidence_ids') AS ids(value)
        WHERE ids.value = consumed.evidence_id
      )
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements_text(v_state -> 'used_evidence_digests') AS digests(value)
    WHERE NOT EXISTS (
      SELECT 1
      FROM remedy_program_private.evidence_digest_consumptions AS consumed
      WHERE consumed.tenant_id = v_instance.tenant_id
        AND consumed.evidence_digest = digests.value
        AND consumed.instance_id = v_instance.instance_id
        AND consumed.revision <= v_instance.revision
    )
  ) OR EXISTS (
    SELECT 1
    FROM remedy_program_private.evidence_digest_consumptions AS consumed
    WHERE consumed.tenant_id = v_instance.tenant_id
      AND consumed.instance_id = v_instance.instance_id
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements_text(v_state -> 'used_evidence_digests') AS digests(value)
        WHERE digests.value = consumed.evidence_digest
      )
  ) OR EXISTS (
    SELECT 1
    FROM remedy_program_private.state_attempts(v_state) AS attempts
    WHERE NOT EXISTS (
      SELECT 1
      FROM remedy_program_private.remedy_authorizations AS consumed
      WHERE consumed.tenant_id = v_instance.tenant_id
        AND consumed.instance_id = v_instance.instance_id
        AND consumed.remedy_operation_id = attempts.remedy_operation_id
        AND consumed.remedy_action_digest = attempts.remedy_action_digest
        AND consumed.remedy_caid = attempts.remedy_caid
        AND consumed.revision <= v_instance.revision
    )
  ) OR EXISTS (
    SELECT 1
    FROM remedy_program_private.remedy_authorizations AS consumed
    WHERE consumed.tenant_id = v_instance.tenant_id
      AND consumed.instance_id = v_instance.instance_id
      AND NOT EXISTS (
        SELECT 1
        FROM remedy_program_private.state_attempts(v_state) AS attempts
        WHERE attempts.remedy_operation_id = consumed.remedy_operation_id
          AND attempts.remedy_action_digest = consumed.remedy_action_digest
          AND attempts.remedy_caid = consumed.remedy_caid
      )
  ) THEN
    RAISE EXCEPTION 'RP_RESERVATION_LEDGER_CORRUPT' USING ERRCODE = '55000';
  END IF;

  RETURN QUERY SELECT true, NULL::pg_catalog.text,
    v_instance.tenant_id, v_instance.instance_id, v_instance.revision,
    v_instance.state_json, v_instance.state_digest,
    pg_catalog.to_char(
      v_instance.recorded_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    );
END;
$$;

CREATE OR REPLACE FUNCTION remedy_program_private.remedy_program_compare_and_swap(
  p_tenant_id pg_catalog.text,
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
  tenant_id pg_catalog.text,
  instance_id pg_catalog.text,
  revision pg_catalog.int8,
  state_json pg_catalog.text,
  state_digest pg_catalog.text,
  recorded_at pg_catalog.text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_current remedy_program_private.instances%ROWTYPE;
  v_current_state pg_catalog.jsonb;
  v_next_state pg_catalog.jsonb;
  v_recorded_at pg_catalog.timestamptz;
BEGIN
  IF p_expected_revision IS NULL
     OR p_expected_revision < 0
     OR p_expected_revision >= 9007199254740991
     OR p_next_revision IS DISTINCT FROM p_expected_revision + 1
  THEN
    RAISE EXCEPTION 'RP_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;

  v_next_state := remedy_program_private.validate_state(
    p_tenant_id, p_instance_id, p_next_revision,
    p_state_json, p_state_digest, p_event_at
  );

  PERFORM 1
  FROM remedy_program_private.store_root AS r
  WHERE r.root_id = 1
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RP_STORE_CORRUPT' USING ERRCODE = '55000';
  END IF;

  SELECT i.* INTO v_current
  FROM remedy_program_private.instances AS i
  WHERE i.tenant_id = p_tenant_id
    AND i.instance_id = p_instance_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN QUERY SELECT false, 'instance_not_found'::pg_catalog.text,
      p_tenant_id, p_instance_id, NULL::pg_catalog.int8,
      NULL::pg_catalog.text, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  v_current_state := remedy_program_private.validate_state(
    v_current.tenant_id,
    v_current.instance_id,
    v_current.revision,
    v_current.state_json,
    v_current.state_digest,
    v_current.event_at
  );

  IF NOT EXISTS (
    SELECT 1
    FROM remedy_program_private.events AS e
    WHERE e.tenant_id = v_current.tenant_id
      AND e.instance_id = v_current.instance_id
      AND e.revision = v_current.revision
      AND e.state_json = v_current.state_json
      AND e.state_digest = v_current.state_digest
      AND e.event_at = v_current.event_at
      AND e.recorded_at = v_current.recorded_at
  ) THEN
    RAISE EXCEPTION 'RP_STORE_CORRUPT' USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements_text(v_current_state -> 'used_evidence_ids') AS ids(value)
    WHERE NOT EXISTS (
      SELECT 1
      FROM remedy_program_private.evidence_id_consumptions AS consumed
      WHERE consumed.tenant_id = v_current.tenant_id
        AND consumed.evidence_id = ids.value
        AND consumed.instance_id = v_current.instance_id
        AND consumed.revision <= v_current.revision
    )
  ) OR EXISTS (
    SELECT 1
    FROM remedy_program_private.evidence_id_consumptions AS consumed
    WHERE consumed.tenant_id = v_current.tenant_id
      AND consumed.instance_id = v_current.instance_id
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements_text(v_current_state -> 'used_evidence_ids') AS ids(value)
        WHERE ids.value = consumed.evidence_id
      )
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements_text(v_current_state -> 'used_evidence_digests') AS digests(value)
    WHERE NOT EXISTS (
      SELECT 1
      FROM remedy_program_private.evidence_digest_consumptions AS consumed
      WHERE consumed.tenant_id = v_current.tenant_id
        AND consumed.evidence_digest = digests.value
        AND consumed.instance_id = v_current.instance_id
        AND consumed.revision <= v_current.revision
    )
  ) OR EXISTS (
    SELECT 1
    FROM remedy_program_private.evidence_digest_consumptions AS consumed
    WHERE consumed.tenant_id = v_current.tenant_id
      AND consumed.instance_id = v_current.instance_id
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements_text(v_current_state -> 'used_evidence_digests') AS digests(value)
        WHERE digests.value = consumed.evidence_digest
      )
  ) OR EXISTS (
    SELECT 1
    FROM remedy_program_private.state_attempts(v_current_state) AS attempts
    WHERE NOT EXISTS (
      SELECT 1
      FROM remedy_program_private.remedy_authorizations AS consumed
      WHERE consumed.tenant_id = v_current.tenant_id
        AND consumed.instance_id = v_current.instance_id
        AND consumed.remedy_operation_id = attempts.remedy_operation_id
        AND consumed.remedy_action_digest = attempts.remedy_action_digest
        AND consumed.remedy_caid = attempts.remedy_caid
        AND consumed.revision <= v_current.revision
    )
  ) OR EXISTS (
    SELECT 1
    FROM remedy_program_private.remedy_authorizations AS consumed
    WHERE consumed.tenant_id = v_current.tenant_id
      AND consumed.instance_id = v_current.instance_id
      AND NOT EXISTS (
        SELECT 1
        FROM remedy_program_private.state_attempts(v_current_state) AS attempts
        WHERE attempts.remedy_operation_id = consumed.remedy_operation_id
          AND attempts.remedy_action_digest = consumed.remedy_action_digest
          AND attempts.remedy_caid = consumed.remedy_caid
      )
  ) THEN
    RAISE EXCEPTION 'RP_RESERVATION_LEDGER_CORRUPT' USING ERRCODE = '55000';
  END IF;

  IF v_current.revision IS DISTINCT FROM p_expected_revision THEN
    RETURN QUERY SELECT false, 'revision_conflict'::pg_catalog.text,
      p_tenant_id, p_instance_id, NULL::pg_catalog.int8,
      NULL::pg_catalog.text, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  v_recorded_at := pg_catalog.clock_timestamp();
  IF v_recorded_at < v_current.recorded_at THEN
    RAISE EXCEPTION 'RP_DB_CLOCK_REGRESSION' USING ERRCODE = '55000';
  END IF;
  IF p_event_at::pg_catalog.timestamptz < v_current.event_at::pg_catalog.timestamptz THEN
    RETURN QUERY SELECT false, 'clock_regression'::pg_catalog.text,
      p_tenant_id, p_instance_id, NULL::pg_catalog.int8,
      NULL::pg_catalog.text, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;
  IF p_event_at::pg_catalog.timestamptz
       > v_recorded_at + pg_catalog.make_interval(mins => 5)
  THEN
    RETURN QUERY SELECT false, 'clock_forward_skew'::pg_catalog.text,
      p_tenant_id, p_instance_id, NULL::pg_catalog.int8,
      NULL::pg_catalog.text, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements_text(v_current_state -> 'used_evidence_ids') AS current_ids(value)
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_catalog.jsonb_array_elements_text(v_next_state -> 'used_evidence_ids') AS next_ids(value)
      WHERE next_ids.value = current_ids.value
    )
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements_text(v_current_state -> 'used_evidence_digests') AS current_digests(value)
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_catalog.jsonb_array_elements_text(v_next_state -> 'used_evidence_digests') AS next_digests(value)
      WHERE next_digests.value = current_digests.value
    )
  ) THEN
    RAISE EXCEPTION 'RP_CONSUMPTION_REMOVED' USING ERRCODE = '22023';
  END IF;

  IF (
    SELECT pg_catalog.count(*) IS DISTINCT FROM pg_catalog.count(DISTINCT value)
    FROM pg_catalog.jsonb_array_elements_text(v_next_state -> 'used_evidence_ids') AS ids(value)
  ) OR (
    SELECT pg_catalog.count(*) IS DISTINCT FROM pg_catalog.count(DISTINCT value)
    FROM pg_catalog.jsonb_array_elements_text(v_next_state -> 'used_evidence_digests') AS digests(value)
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements_text(v_next_state -> 'used_evidence_ids') AS next_ids(value)
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_catalog.jsonb_array_elements_text(v_current_state -> 'used_evidence_ids') AS current_ids(value)
      WHERE current_ids.value = next_ids.value
    )
      AND EXISTS (
        SELECT 1
        FROM remedy_program_private.evidence_id_consumptions AS consumed
        WHERE consumed.tenant_id = p_tenant_id
          AND consumed.evidence_id = next_ids.value
      )
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements_text(v_next_state -> 'used_evidence_digests') AS next_digests(value)
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_catalog.jsonb_array_elements_text(v_current_state -> 'used_evidence_digests') AS current_digests(value)
      WHERE current_digests.value = next_digests.value
    )
      AND EXISTS (
        SELECT 1
        FROM remedy_program_private.evidence_digest_consumptions AS consumed
        WHERE consumed.tenant_id = p_tenant_id
          AND consumed.evidence_digest = next_digests.value
      )
  ) THEN
    RETURN QUERY SELECT false, 'evidence_replayed'::pg_catalog.text,
      p_tenant_id, p_instance_id, NULL::pg_catalog.int8,
      NULL::pg_catalog.text, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM remedy_program_private.state_attempts(v_current_state) AS current_attempts
    WHERE NOT EXISTS (
      SELECT 1
      FROM remedy_program_private.state_attempts(v_next_state) AS next_attempts
      WHERE next_attempts.remedy_operation_id = current_attempts.remedy_operation_id
        AND next_attempts.remedy_action_digest = current_attempts.remedy_action_digest
        AND next_attempts.remedy_caid = current_attempts.remedy_caid
    )
  ) THEN
    RAISE EXCEPTION 'RP_REMEDY_AUTHORIZATION_REMOVED' USING ERRCODE = '22023';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM remedy_program_private.state_attempts(v_next_state) AS attempts
    GROUP BY attempts.remedy_operation_id
    HAVING pg_catalog.count(*) > 1
  ) OR EXISTS (
    SELECT 1
    FROM remedy_program_private.state_attempts(v_next_state) AS attempts
    GROUP BY attempts.remedy_action_digest
    HAVING pg_catalog.count(*) > 1
  ) OR EXISTS (
    SELECT 1
    FROM remedy_program_private.state_attempts(v_next_state) AS attempts
    GROUP BY attempts.remedy_caid
    HAVING pg_catalog.count(*) > 1
  ) OR EXISTS (
    SELECT 1
    FROM remedy_program_private.state_attempts(v_next_state) AS next_attempts
    WHERE NOT EXISTS (
      SELECT 1
      FROM remedy_program_private.state_attempts(v_current_state) AS current_attempts
      WHERE current_attempts.remedy_operation_id = next_attempts.remedy_operation_id
    )
      AND EXISTS (
        SELECT 1
        FROM remedy_program_private.remedy_authorizations AS consumed
        WHERE consumed.tenant_id = p_tenant_id
          AND (
            consumed.remedy_operation_id = next_attempts.remedy_operation_id
            OR consumed.remedy_action_digest = next_attempts.remedy_action_digest
            OR consumed.remedy_caid = next_attempts.remedy_caid
          )
      )
  ) THEN
    RETURN QUERY SELECT false, 'remedy_operation_replayed'::pg_catalog.text,
      p_tenant_id, p_instance_id, NULL::pg_catalog.int8,
      NULL::pg_catalog.text, NULL::pg_catalog.text, NULL::pg_catalog.text;
    RETURN;
  END IF;

  IF v_next_state ->> 'tenant_id' IS DISTINCT FROM v_current_state ->> 'tenant_id'
     OR v_next_state ->> 'instance_id' IS DISTINCT FROM v_current_state ->> 'instance_id'
     OR v_next_state ->> 'version' IS DISTINCT FROM v_current_state ->> 'version'
     OR v_next_state ->> 'created_at' IS DISTINCT FROM v_current_state ->> 'created_at'
     OR v_next_state ->> 'environment' IS DISTINCT FROM v_current_state ->> 'environment'
     OR v_next_state ->> 'audience' IS DISTINCT FROM v_current_state ->> 'audience'
     OR v_next_state -> 'original' IS DISTINCT FROM v_current_state -> 'original'
     OR v_next_state ->> 'remedy_profile_digest'
          IS DISTINCT FROM v_current_state ->> 'remedy_profile_digest'
     OR v_next_state ->> 'destination_binding_digest'
          IS DISTINCT FROM v_current_state ->> 'destination_binding_digest'
     OR v_next_state ->> 'max_remedy_units'
          IS DISTINCT FROM v_current_state ->> 'max_remedy_units'
     OR v_next_state ->> 'unit' IS DISTINCT FROM v_current_state ->> 'unit'
     OR v_next_state ->> 'create_request_digest'
          IS DISTINCT FROM v_current_state ->> 'create_request_digest'
  THEN
    RAISE EXCEPTION 'RP_STATE_BINDING_CHANGED' USING ERRCODE = '22023';
  END IF;

  -- Facts already recorded by the remedy lifecycle are append-only.  A
  -- service-role caller may advance an active attempt, but it may not rewrite
  -- the original effect, a completed attempt, or a previously accepted
  -- revocation/dispute/reconciliation/resolution statement.
  IF (
    pg_catalog.jsonb_typeof(v_current_state -> 'revocation') <> 'null'
    AND v_next_state -> 'revocation' IS DISTINCT FROM v_current_state -> 'revocation'
  ) OR (
    pg_catalog.jsonb_typeof(v_current_state -> 'dispute') <> 'null'
    AND v_next_state -> 'dispute' IS DISTINCT FROM v_current_state -> 'dispute'
  ) OR (
    pg_catalog.jsonb_typeof(v_current_state -> 'original_reconciliation') <> 'null'
    AND v_next_state -> 'original_reconciliation'
          IS DISTINCT FROM v_current_state -> 'original_reconciliation'
  ) OR (
    pg_catalog.jsonb_typeof(v_current_state -> 'resolution') <> 'null'
    AND v_next_state -> 'resolution' IS DISTINCT FROM v_current_state -> 'resolution'
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements(v_current_state -> 'remedies') AS old_attempt(value)
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_catalog.jsonb_array_elements(v_next_state -> 'remedies') AS next_attempt(value)
      WHERE next_attempt.value = old_attempt.value
    )
  ) THEN
    RAISE EXCEPTION 'RP_RECORDED_FACT_CHANGED' USING ERRCODE = '22023';
  END IF;

  IF (v_next_state ->> 'remedied_units')::pg_catalog.int8
       < (v_current_state ->> 'remedied_units')::pg_catalog.int8
     OR (v_next_state ->> 'remaining_units')::pg_catalog.int8
       > (v_current_state ->> 'remaining_units')::pg_catalog.int8
  THEN
    RAISE EXCEPTION 'RP_REMEDY_ACCOUNTING_REGRESSION' USING ERRCODE = '22023';
  END IF;

  UPDATE remedy_program_private.instances AS i
  SET revision = p_next_revision,
      state_json = p_state_json,
      state_digest = p_state_digest,
      event_at = p_event_at,
      recorded_at = v_recorded_at
  WHERE i.tenant_id = p_tenant_id
    AND i.instance_id = p_instance_id;

  INSERT INTO remedy_program_private.events (
    tenant_id, instance_id, revision, previous_revision, event_kind,
    state_json, state_digest, event_at, recorded_at
  ) VALUES (
    p_tenant_id, p_instance_id, p_next_revision, p_expected_revision, 'cas',
    p_state_json, p_state_digest, p_event_at, v_recorded_at
  );

  INSERT INTO remedy_program_private.evidence_id_consumptions (
    tenant_id, evidence_id, instance_id, revision, recorded_at
  )
  SELECT p_tenant_id, next_ids.value, p_instance_id, p_next_revision, v_recorded_at
  FROM pg_catalog.jsonb_array_elements_text(v_next_state -> 'used_evidence_ids') AS next_ids(value)
  WHERE NOT EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements_text(v_current_state -> 'used_evidence_ids') AS current_ids(value)
    WHERE current_ids.value = next_ids.value
  );

  INSERT INTO remedy_program_private.evidence_digest_consumptions (
    tenant_id, evidence_digest, instance_id, revision, recorded_at
  )
  SELECT p_tenant_id, next_digests.value, p_instance_id, p_next_revision, v_recorded_at
  FROM pg_catalog.jsonb_array_elements_text(v_next_state -> 'used_evidence_digests') AS next_digests(value)
  WHERE NOT EXISTS (
    SELECT 1
    FROM pg_catalog.jsonb_array_elements_text(v_current_state -> 'used_evidence_digests') AS current_digests(value)
    WHERE current_digests.value = next_digests.value
  );

  INSERT INTO remedy_program_private.remedy_authorizations (
    tenant_id, remedy_operation_id, remedy_action_digest, remedy_caid,
    instance_id, revision, recorded_at
  )
  SELECT p_tenant_id,
    next_attempts.remedy_operation_id,
    next_attempts.remedy_action_digest,
    next_attempts.remedy_caid,
    p_instance_id,
    p_next_revision,
    v_recorded_at
  FROM remedy_program_private.state_attempts(v_next_state) AS next_attempts
  WHERE NOT EXISTS (
    SELECT 1
    FROM remedy_program_private.state_attempts(v_current_state) AS current_attempts
    WHERE current_attempts.remedy_operation_id = next_attempts.remedy_operation_id
  );

  RETURN QUERY SELECT true, NULL::pg_catalog.text,
    p_tenant_id, p_instance_id, p_next_revision,
    p_state_json, p_state_digest,
    pg_catalog.to_char(
      v_recorded_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    );
END;
$$;

REVOKE ALL ON FUNCTION remedy_program_private.validate_state(
  pg_catalog.text, pg_catalog.text, pg_catalog.int8,
  pg_catalog.text, pg_catalog.text, pg_catalog.text
) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION remedy_program_private.state_attempts(pg_catalog.jsonb)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION remedy_program_private.reject_event_mutation()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION remedy_program_private.remedy_program_create(
  pg_catalog.text, pg_catalog.text, pg_catalog.text,
  pg_catalog.text, pg_catalog.text
) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION remedy_program_private.remedy_program_get(
  pg_catalog.text, pg_catalog.text
) FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION remedy_program_private.remedy_program_compare_and_swap(
  pg_catalog.text, pg_catalog.text, pg_catalog.int8, pg_catalog.int8,
  pg_catalog.text, pg_catalog.text, pg_catalog.text
) FROM PUBLIC, anon, authenticated, service_role;

GRANT EXECUTE ON FUNCTION remedy_program_private.remedy_program_create(
  pg_catalog.text, pg_catalog.text, pg_catalog.text,
  pg_catalog.text, pg_catalog.text
) TO service_role;
GRANT EXECUTE ON FUNCTION remedy_program_private.remedy_program_get(
  pg_catalog.text, pg_catalog.text
) TO service_role;
GRANT EXECUTE ON FUNCTION remedy_program_private.remedy_program_compare_and_swap(
  pg_catalog.text, pg_catalog.text, pg_catalog.int8, pg_catalog.int8,
  pg_catalog.text, pg_catalog.text, pg_catalog.text
) TO service_role;
