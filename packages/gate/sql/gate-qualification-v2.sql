-- SPDX-License-Identifier: Apache-2.0
-- Gate Qualification v2: single-tenant, deployment-bound local_atomic store.
--
-- Concurrency contract:
--   * each public RPC below is one transaction statement;
--   * rows are locked in deployment -> admission -> operation -> resource-key
--     -> protected-request -> candidate/runtime -> evidence -> status -> lease order;
--   * permanent UNIQUE keys fence admission_id, operation_id, and live resources;
--   * the TypeScript adapter retries SQLSTATE 40001 and 40P01 with unchanged
--     capability digests (default: three retries after the first attempt).
--
-- This schema intentionally has no tenant/principal map and no presenter-chosen
-- tenant session setting.  One singleton binding makes the database a domain
-- for exactly one tenant and one deployment.  Deployment operators must grant
-- EXECUTE on the public RPC functions to the dedicated runtime role; table
-- privileges are not required because those RPCs are SECURITY DEFINER.

-- Keep all function creation and privilege changes in one transaction.  New
-- SECURITY DEFINER functions are therefore never visible with PostgreSQL's
-- default PUBLIC EXECUTE privilege, and CREATE OR REPLACE preserves any
-- explicit runtime-role grants made by the deployment owner.
BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS public.ep_gate_deployment_binding (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  deployment_id text NOT NULL UNIQUE,
  tenant_id text NOT NULL UNIQUE,
  trust_epoch bigint NOT NULL CHECK (trust_epoch >= 0),
  trust_configuration_digest text NOT NULL CHECK (trust_configuration_digest ~ '^sha256:[0-9a-f]{64}$'),
  configuration_epoch bigint NOT NULL CHECK (configuration_epoch >= 0),
  configuration_digest text NOT NULL CHECK (configuration_digest ~ '^sha256:[0-9a-f]{64}$'),
  runtime_measurement_digest text NOT NULL CHECK (runtime_measurement_digest ~ '^sha256:[0-9a-f]{64}$'),
  candidate_match text NOT NULL CHECK (candidate_match IN ('EXACT_MATCH', 'MISMATCH', 'STALE', 'UNPINNABLE')),
  currentness_observed_at timestamptz NOT NULL,
  maximum_observation_age_ms bigint NOT NULL DEFAULT 5000
    CHECK (maximum_observation_age_ms BETWEEN 1 AND 300000)
);

-- Safe for an existing v2 installation: old bindings acquire the conservative
-- five-second TypeScript default, while operators can lower it before the next invocation.
ALTER TABLE public.ep_gate_deployment_binding
  ADD COLUMN IF NOT EXISTS maximum_observation_age_ms bigint
  NOT NULL DEFAULT 5000 CHECK (maximum_observation_age_ms BETWEEN 1 AND 300000);

CREATE TABLE IF NOT EXISTS public.ep_gate_candidate_runtime_heads (
  deployment_id text PRIMARY KEY REFERENCES public.ep_gate_deployment_binding(deployment_id),
  candidate_manifest_digest text NOT NULL CHECK (candidate_manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
  runtime_measurement_digest text NOT NULL CHECK (runtime_measurement_digest ~ '^sha256:[0-9a-f]{64}$'),
  candidate_match text NOT NULL CHECK (candidate_match IN ('EXACT_MATCH', 'MISMATCH', 'STALE', 'UNPINNABLE')),
  observed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS public.ep_gate_protected_request_heads (
  deployment_id text NOT NULL REFERENCES public.ep_gate_deployment_binding(deployment_id),
  operation_id text NOT NULL,
  caid text NOT NULL,
  action_digest text NOT NULL CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  effect_request_digest text NOT NULL CHECK (effect_request_digest ~ '^sha256:[0-9a-f]{64}$'),
  provider_id text NOT NULL,
  provider_account_id text NOT NULL,
  provider_environment text NOT NULL,
  executor_adapter_digest text NOT NULL CHECK (executor_adapter_digest ~ '^sha256:[0-9a-f]{64}$'),
  idempotency_key text NOT NULL,
  observed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (deployment_id, operation_id)
);

-- The trusted currentness writer publishes one independently versioned head
-- for every control-bearing input.  Invocation joins by role, subject, and
-- verifier and then binds all remaining immutable input fields.
CREATE TABLE IF NOT EXISTS public.ep_gate_evidence_heads (
  deployment_id text NOT NULL REFERENCES public.ep_gate_deployment_binding(deployment_id),
  role text NOT NULL CHECK (role IN ('aeb', 'aec', 'local_policy', 'authorization')),
  subject text NOT NULL,
  verifier_id text NOT NULL,
  artifact_type text NOT NULL,
  payload_digest text NOT NULL CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
  profile_digest text NOT NULL CHECK (profile_digest ~ '^sha256:[0-9a-f]{64}$'),
  trust_configuration_digest text NOT NULL CHECK (trust_configuration_digest ~ '^sha256:[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (deployment_id, role, subject, verifier_id)
);

CREATE TABLE IF NOT EXISTS public.ep_gate_qualification_status_heads (
  deployment_id text NOT NULL REFERENCES public.ep_gate_deployment_binding(deployment_id),
  authority_id text NOT NULL,
  sequence bigint NOT NULL CHECK (sequence >= 0),
  head_payload_digest text NOT NULL CHECK (head_payload_digest ~ '^sha256:[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (deployment_id, authority_id)
);

CREATE TABLE IF NOT EXISTS public.ep_gate_external_leases (
  deployment_id text NOT NULL REFERENCES public.ep_gate_deployment_binding(deployment_id),
  resource_id text NOT NULL,
  digest text NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (deployment_id, resource_id)
);

-- Durable, deployment-local compare-and-advance heads. A trusted enrollment or
-- recovery path provisions the authenticated baseline before admission. The
-- head advances atomically with a successful reservation; release, expiry, and
-- reconciliation never lower it. WebAuthn counters may skip, but a committed
-- observed value must never be reusable or move backwards.
CREATE TABLE IF NOT EXISTS public.ep_gate_monotonic_counters (
  deployment_id text NOT NULL REFERENCES public.ep_gate_deployment_binding(deployment_id),
  tenant_id text NOT NULL,
  resource_id text NOT NULL,
  current_value bigint NOT NULL CHECK (current_value BETWEEN 0 AND 4294967295),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (deployment_id, resource_id)
);

CREATE TABLE IF NOT EXISTS public.ep_gate_admission_snapshots (
  deployment_id text NOT NULL REFERENCES public.ep_gate_deployment_binding(deployment_id),
  tenant_id text NOT NULL,
  snapshot_digest text NOT NULL CHECK (snapshot_digest ~ '^sha256:[0-9a-f]{64}$'),
  admission_id text NOT NULL,
  operation_id text NOT NULL,
  snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (deployment_id, snapshot_digest),
  UNIQUE (deployment_id, admission_id)
);

CREATE TABLE IF NOT EXISTS public.ep_gate_admission_records (
  deployment_id text NOT NULL REFERENCES public.ep_gate_deployment_binding(deployment_id),
  tenant_id text NOT NULL,
  admission_id text NOT NULL,
  operation_id text NOT NULL,
  snapshot_digest text NOT NULL,
  revision bigint NOT NULL CHECK (revision >= 0),
  owner_digest text NOT NULL CHECK (owner_digest ~ '^sha256:[0-9a-f]{64}$'),
  record_json jsonb NOT NULL CHECK (jsonb_typeof(record_json) = 'object'),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (deployment_id, admission_id),
  FOREIGN KEY (deployment_id, snapshot_digest)
    REFERENCES public.ep_gate_admission_snapshots(deployment_id, snapshot_digest)
);

CREATE TABLE IF NOT EXISTS public.ep_gate_operation_heads (
  deployment_id text NOT NULL REFERENCES public.ep_gate_deployment_binding(deployment_id),
  tenant_id text NOT NULL,
  operation_id text NOT NULL,
  admission_id text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (deployment_id, operation_id),
  UNIQUE (deployment_id, admission_id),
  FOREIGN KEY (deployment_id, admission_id)
    REFERENCES public.ep_gate_admission_records(deployment_id, admission_id)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE IF NOT EXISTS public.ep_gate_resource_fences (
  deployment_id text NOT NULL REFERENCES public.ep_gate_deployment_binding(deployment_id),
  tenant_id text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('replay', 'capability', 'budget', 'qualification_use', 'provider_operation', 'external_lease')),
  resource_id text NOT NULL,
  reservation_id text NOT NULL,
  digest text NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
  expires_at timestamptz NOT NULL,
  admission_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('RESERVED', 'CONSUMED')),
  PRIMARY KEY (deployment_id, kind, resource_id),
  FOREIGN KEY (deployment_id, admission_id)
    REFERENCES public.ep_gate_admission_records(deployment_id, admission_id)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX IF NOT EXISTS ep_gate_resource_fences_admission_idx
  ON public.ep_gate_resource_fences (deployment_id, admission_id, kind, resource_id);

CREATE TABLE IF NOT EXISTS public.ep_gate_admission_journal (
  deployment_id text NOT NULL REFERENCES public.ep_gate_deployment_binding(deployment_id),
  tenant_id text NOT NULL,
  admission_id text NOT NULL,
  operation_id text NOT NULL,
  sequence bigint NOT NULL CHECK (sequence >= 0),
  event text NOT NULL CHECK (event IN (
    'RESERVED', 'RELEASED', 'EXPIRED', 'SUPERSEDED', 'INVOKING',
    'RECOVERED_INDETERMINATE', 'PROVIDER_OUTCOME', 'EFFECT_RELATION'
  )),
  record_digest text NOT NULL CHECK (record_digest ~ '^sha256:[0-9a-f]{64}$'),
  predecessor_digest text CHECK (predecessor_digest IS NULL OR predecessor_digest ~ '^sha256:[0-9a-f]{64}$'),
  entry_digest text NOT NULL CHECK (entry_digest ~ '^sha256:[0-9a-f]{64}$'),
  entry_json jsonb NOT NULL CHECK (jsonb_typeof(entry_json) = 'object'),
  recorded_at timestamptz NOT NULL,
  PRIMARY KEY (deployment_id, admission_id, sequence),
  UNIQUE (deployment_id, entry_digest),
  FOREIGN KEY (deployment_id, admission_id)
    REFERENCES public.ep_gate_admission_records(deployment_id, admission_id)
    DEFERRABLE INITIALLY DEFERRED
);

REVOKE ALL ON TABLE public.ep_gate_deployment_binding FROM PUBLIC;
REVOKE ALL ON TABLE public.ep_gate_candidate_runtime_heads FROM PUBLIC;
REVOKE ALL ON TABLE public.ep_gate_protected_request_heads FROM PUBLIC;
REVOKE ALL ON TABLE public.ep_gate_evidence_heads FROM PUBLIC;
REVOKE ALL ON TABLE public.ep_gate_qualification_status_heads FROM PUBLIC;
REVOKE ALL ON TABLE public.ep_gate_external_leases FROM PUBLIC;
REVOKE ALL ON TABLE public.ep_gate_monotonic_counters FROM PUBLIC;
REVOKE ALL ON TABLE public.ep_gate_admission_snapshots FROM PUBLIC;
REVOKE ALL ON TABLE public.ep_gate_admission_records FROM PUBLIC;
REVOKE ALL ON TABLE public.ep_gate_operation_heads FROM PUBLIC;
REVOKE ALL ON TABLE public.ep_gate_resource_fences FROM PUBLIC;
REVOKE ALL ON TABLE public.ep_gate_admission_journal FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.ep_gate_refuse_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION 'Gate Qualification v2 history is append-only';
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_guard_operation_head()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Gate Qualification v2 operation heads are permanent';
  END IF;
  IF OLD.deployment_id <> NEW.deployment_id
     OR OLD.tenant_id <> NEW.tenant_id
     OR OLD.operation_id <> NEW.operation_id
     OR OLD.created_at <> NEW.created_at THEN
    RAISE EXCEPTION 'Gate Qualification v2 operation identity is immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_guard_deployment_binding()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Gate deployment binding is permanent';
  END IF;
  IF OLD.singleton <> NEW.singleton
     OR OLD.deployment_id <> NEW.deployment_id
     OR OLD.tenant_id <> NEW.tenant_id THEN
    RAISE EXCEPTION 'Gate deployment and tenant binding are immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_guard_resource_consumption()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF OLD.state = 'CONSUMED' THEN
    IF TG_OP = 'DELETE' THEN
      RAISE EXCEPTION 'consumed Gate resources are permanent';
    END IF;
    IF NEW.state <> 'CONSUMED'
       OR NEW.admission_id <> OLD.admission_id
       OR NEW.digest <> OLD.digest
       OR NEW.reservation_id <> OLD.reservation_id
       OR NEW.expires_at <> OLD.expires_at THEN
      RAISE EXCEPTION 'consumed Gate resources cannot be released or transferred';
    END IF;
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_guard_consumed_record()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF OLD.record_json->>'execution_right' = 'CONSUMED'
     AND NEW.record_json->>'execution_right' <> 'CONSUMED' THEN
    RAISE EXCEPTION 'consumed Gate execution authority cannot be restored';
  END IF;
  RETURN NEW;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'ep_gate_snapshots_append_only') THEN
    CREATE TRIGGER ep_gate_snapshots_append_only
      BEFORE UPDATE OR DELETE ON public.ep_gate_admission_snapshots
      FOR EACH ROW EXECUTE FUNCTION public.ep_gate_refuse_history_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'ep_gate_journal_append_only') THEN
    CREATE TRIGGER ep_gate_journal_append_only
      BEFORE UPDATE OR DELETE ON public.ep_gate_admission_journal
      FOR EACH ROW EXECUTE FUNCTION public.ep_gate_refuse_history_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'ep_gate_operation_head_permanent') THEN
    CREATE TRIGGER ep_gate_operation_head_permanent
      BEFORE UPDATE OR DELETE ON public.ep_gate_operation_heads
      FOR EACH ROW EXECUTE FUNCTION public.ep_gate_guard_operation_head();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'ep_gate_deployment_binding_permanent') THEN
    CREATE TRIGGER ep_gate_deployment_binding_permanent
      BEFORE UPDATE OR DELETE ON public.ep_gate_deployment_binding
      FOR EACH ROW EXECUTE FUNCTION public.ep_gate_guard_deployment_binding();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'ep_gate_resource_consumption_permanent') THEN
    CREATE TRIGGER ep_gate_resource_consumption_permanent
      BEFORE UPDATE OR DELETE ON public.ep_gate_resource_fences
      FOR EACH ROW EXECUTE FUNCTION public.ep_gate_guard_resource_consumption();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'ep_gate_record_consumption_permanent') THEN
    CREATE TRIGGER ep_gate_record_consumption_permanent
      BEFORE UPDATE ON public.ep_gate_admission_records
      FOR EACH ROW EXECUTE FUNCTION public.ep_gate_guard_consumed_record();
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_iso(p_value timestamptz)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT to_char(p_value AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_canonical_json(p_value jsonb)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_type text := jsonb_typeof(p_value);
  v_result text;
BEGIN
  IF v_type IN ('null', 'boolean', 'number', 'string') THEN
    RETURN p_value::text;
  ELSIF v_type = 'array' THEN
    SELECT '[' || COALESCE(string_agg(public.ep_gate_canonical_json(item), ',' ORDER BY ordinal), '') || ']'
      INTO v_result
      FROM jsonb_array_elements(p_value) WITH ORDINALITY AS values_(item, ordinal);
    RETURN v_result;
  ELSIF v_type = 'object' THEN
    SELECT '{' || COALESCE(string_agg(to_jsonb(key_name)::text || ':' || public.ep_gate_canonical_json(item), ',' ORDER BY key_name COLLATE "C"), '') || '}'
      INTO v_result
      FROM jsonb_each(p_value) AS values_(key_name, item);
    RETURN v_result;
  END IF;
  RAISE EXCEPTION 'unsupported JSON value';
END;
$$;

-- pgcrypto may already be installed in a deployment-owned schema (for
-- example, `extensions`).  CREATE EXTENSION IF NOT EXISTS does not relocate an
-- existing extension, so an unqualified digest() call would make installation
-- order observable and can fail despite pgcrypto being present.  Resolve the
-- extension's trusted catalog namespace once and bake the qualified function
-- name into the immutable hash helper.
DO $ep_gate_hash_install$
DECLARE v_pgcrypto_schema text;
BEGIN
  SELECT namespaces.nspname
    INTO STRICT v_pgcrypto_schema
    FROM pg_catalog.pg_extension AS extensions
    JOIN pg_catalog.pg_namespace AS namespaces
      ON namespaces.oid = extensions.extnamespace
   WHERE extensions.extname = 'pgcrypto';

  EXECUTE pg_catalog.format($function$
    CREATE OR REPLACE FUNCTION public.ep_gate_hash(p_domain text, p_value jsonb)
    RETURNS text
    LANGUAGE sql
    IMMUTABLE
    STRICT
    SET search_path = pg_catalog, public
    AS $body$
      SELECT 'sha256:' || pg_catalog.encode(
        %I.digest(
          pg_catalog.convert_to(p_domain, 'UTF8')
            || pg_catalog.decode('00', 'hex')
            || pg_catalog.convert_to(public.ep_gate_canonical_json(p_value), 'UTF8'),
          'sha256'::text
        ),
        'hex'
      )
    $body$
  $function$, v_pgcrypto_schema);
END
$ep_gate_hash_install$;

CREATE OR REPLACE FUNCTION public.ep_gate_jsonb_has_exact_keys(
  p_value jsonb,
  p_expected text[]
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
DECLARE
  v_actual text[];
  v_expected text[];
BEGIN
  IF jsonb_typeof(p_value) <> 'object' THEN RETURN false; END IF;
  SELECT COALESCE(array_agg(key_name ORDER BY key_name COLLATE "C"), ARRAY[]::text[])
    INTO v_actual FROM jsonb_object_keys(p_value) AS keys_(key_name);
  SELECT COALESCE(array_agg(key_name ORDER BY key_name COLLATE "C"), ARRAY[]::text[])
    INTO v_expected FROM unnest(p_expected) AS keys_(key_name);
  RETURN v_actual = v_expected;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_jsonb_is_identifier(p_value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT CASE WHEN jsonb_typeof(p_value) = 'string' THEN
    (p_value #>> '{}') ~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]*$'
      AND octet_length(p_value #>> '{}') <= 512
  ELSE false END
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_jsonb_is_digest(p_value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT jsonb_typeof(p_value) = 'string'
    AND (p_value #>> '{}') ~ '^sha256:[0-9a-f]{64}$'
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_jsonb_is_safe_nonnegative_integer(p_value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT CASE WHEN jsonb_typeof(p_value) = 'number'
                    AND (p_value #>> '{}') ~ '^(0|[1-9][0-9]*)$'
    THEN (p_value #>> '{}')::numeric <= 9007199254740991
    ELSE false
  END
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_jsonb_is_digest_array(
  p_value jsonb,
  p_maximum integer
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
DECLARE
  v_sorted jsonb;
BEGIN
  IF jsonb_typeof(p_value) <> 'array'
     OR jsonb_array_length(p_value) NOT BETWEEN 1 AND p_maximum THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1 FROM jsonb_array_elements(p_value) AS values_(item)
    WHERE jsonb_typeof(item) <> 'string'
       OR (item #>> '{}') !~ '^sha256:[0-9a-f]{64}$'
  ) OR (SELECT count(DISTINCT item) FROM jsonb_array_elements(p_value) AS values_(item))
       <> jsonb_array_length(p_value) THEN
    RETURN false;
  END IF;
  SELECT jsonb_agg(item ORDER BY (item #>> '{}') COLLATE "C") INTO v_sorted
    FROM jsonb_array_elements(p_value) AS values_(item);
  RETURN p_value = v_sorted;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_refusal(p_reason text)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT jsonb_build_object('ok', false, 'reason', p_reason)
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_assert_binding(p_deployment_id text, p_tenant_id text)
RETURNS public.ep_gate_deployment_binding
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_binding public.ep_gate_deployment_binding%ROWTYPE;
BEGIN
  SELECT * INTO v_binding
    FROM public.ep_gate_deployment_binding
    WHERE singleton
    FOR SHARE;
  IF NOT FOUND
     OR v_binding.deployment_id <> p_deployment_id
     OR v_binding.tenant_id <> p_tenant_id THEN
    RAISE EXCEPTION 'Gate deployment binding mismatch';
  END IF;
  RETURN v_binding;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_assert_snapshot(
  p_deployment_id text,
  p_tenant_id text,
  p_snapshot jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_body jsonb;
  v_custody jsonb;
  v_status jsonb;
  v_provider jsonb;
  v_inputs jsonb;
  v_input jsonb;
  v_resources jsonb;
  v_resource jsonb;
  v_relation jsonb;
  v_admitted timestamptz;
  v_expires timestamptz;
  v_count bigint;
  v_sorted jsonb;
  v_payloads jsonb;
BEGIN
  IF public.ep_gate_jsonb_has_exact_keys(
       p_snapshot, ARRAY['body', 'snapshot_digest']
     ) IS NOT TRUE
     OR jsonb_typeof(p_snapshot->'body') <> 'object' THEN
    RAISE EXCEPTION 'invalid admission snapshot';
  END IF;
  v_body := p_snapshot->'body';

  IF public.ep_gate_jsonb_has_exact_keys(v_body, ARRAY[
       '@version', 'tenant_id', 'admission_id', 'operation_id',
       'candidate_manifest_digest', 'runtime_measurement_digest',
       'candidate_custody', 'assignment_digest', 'qualification_policy_digest',
       'test_result_payload_digests',
       'agent_evaluation_evidence_payload_digests',
       'qualification_statement_payload_digest', 'qualification_status',
       'caid', 'action_digest', 'effect_request_digest', 'provider',
       'executor_adapter_digest', 'idempotency_key',
       'authorization_policy_digest', 'trust_epoch',
       'trust_configuration_digest', 'configuration_epoch',
       'configuration_digest', 'inputs', 'resource_reservations',
       'admitted_at', 'expires_at', 'supersedes_admission_id', 'remedy_for'
     ]) IS NOT TRUE THEN
    RAISE EXCEPTION 'admission snapshot body must be closed';
  END IF;

  IF v_body->>'@version' <> 'EP-GATE-ADMISSION-SNAPSHOT-v2'
     OR v_body->>'tenant_id' <> p_tenant_id
     OR public.ep_gate_jsonb_is_identifier(v_body->'tenant_id') IS NOT TRUE
     OR public.ep_gate_jsonb_is_identifier(v_body->'admission_id') IS NOT TRUE
     OR public.ep_gate_jsonb_is_identifier(v_body->'operation_id') IS NOT TRUE
     OR public.ep_gate_jsonb_is_identifier(v_body->'idempotency_key') IS NOT TRUE
     OR public.ep_gate_jsonb_is_digest(p_snapshot->'snapshot_digest') IS NOT TRUE
     OR public.ep_gate_jsonb_is_digest(v_body->'candidate_manifest_digest') IS NOT TRUE
     OR public.ep_gate_jsonb_is_digest(v_body->'runtime_measurement_digest') IS NOT TRUE
     OR public.ep_gate_jsonb_is_digest(v_body->'assignment_digest') IS NOT TRUE
     OR public.ep_gate_jsonb_is_digest(v_body->'qualification_policy_digest') IS NOT TRUE
     OR public.ep_gate_jsonb_is_digest(v_body->'qualification_statement_payload_digest') IS NOT TRUE
     OR public.ep_gate_jsonb_is_digest(v_body->'action_digest') IS NOT TRUE
     OR public.ep_gate_jsonb_is_digest(v_body->'effect_request_digest') IS NOT TRUE
     OR public.ep_gate_jsonb_is_digest(v_body->'executor_adapter_digest') IS NOT TRUE
     OR public.ep_gate_jsonb_is_digest(v_body->'authorization_policy_digest') IS NOT TRUE
     OR public.ep_gate_jsonb_is_digest(v_body->'trust_configuration_digest') IS NOT TRUE
     OR public.ep_gate_jsonb_is_digest(v_body->'configuration_digest') IS NOT TRUE
     OR public.ep_gate_jsonb_is_safe_nonnegative_integer(v_body->'trust_epoch') IS NOT TRUE
     OR public.ep_gate_jsonb_is_safe_nonnegative_integer(v_body->'configuration_epoch') IS NOT TRUE
     OR jsonb_typeof(v_body->'caid') <> 'string'
     OR (v_body->>'caid') !~ '^caid:1:[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
     OR public.ep_gate_hash('EP-GATE-ADMISSION-SNAPSHOT-v2:DIGEST', v_body) <> p_snapshot->>'snapshot_digest' THEN
    RAISE EXCEPTION 'admission snapshot identity or digest mismatch';
  END IF;

  IF jsonb_typeof(v_body->'admitted_at') <> 'string'
     OR jsonb_typeof(v_body->'expires_at') <> 'string'
     OR (v_body->>'admitted_at') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
     OR (v_body->>'expires_at') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$' THEN
    RAISE EXCEPTION 'invalid admission timestamps';
  END IF;
  v_admitted := (v_body->>'admitted_at')::timestamptz;
  v_expires := (v_body->>'expires_at')::timestamptz;
  IF v_expires <= v_admitted THEN
    RAISE EXCEPTION 'invalid admission expiry';
  END IF;

  v_custody := v_body->'candidate_custody';
  IF public.ep_gate_jsonb_has_exact_keys(v_custody, ARRAY[
       'request_construction', 'mutation_credential_custody',
       'enforcement_placement', 'evidence_digest'
     ]) IS NOT TRUE
     OR v_custody->>'request_construction' <> 'EXECUTOR_ADAPTER'
     OR v_custody->>'mutation_credential_custody' <> 'EXECUTOR_ADAPTER'
     OR v_custody->>'enforcement_placement' NOT IN ('SYSTEM_OF_RECORD', 'ACTUATOR', 'MIDDLEWARE')
     OR public.ep_gate_jsonb_is_digest(v_custody->'evidence_digest') IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid candidate custody binding';
  END IF;

  v_status := v_body->'qualification_status';
  IF public.ep_gate_jsonb_has_exact_keys(v_status, ARRAY[
       'authority_id', 'sequence', 'head_payload_digest', 'observed_at', 'expires_at'
     ]) IS NOT TRUE
     OR public.ep_gate_jsonb_is_identifier(v_status->'authority_id') IS NOT TRUE
     OR public.ep_gate_jsonb_is_safe_nonnegative_integer(v_status->'sequence') IS NOT TRUE
     OR public.ep_gate_jsonb_is_digest(v_status->'head_payload_digest') IS NOT TRUE
     OR jsonb_typeof(v_status->'observed_at') <> 'string'
     OR jsonb_typeof(v_status->'expires_at') <> 'string'
     OR (v_status->>'observed_at') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
     OR (v_status->>'expires_at') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
     OR (v_status->>'expires_at')::timestamptz <= v_admitted
     OR v_expires > (v_status->>'expires_at')::timestamptz THEN
    RAISE EXCEPTION 'invalid qualification status binding';
  END IF;

  v_provider := v_body->'provider';
  IF public.ep_gate_jsonb_has_exact_keys(
       v_provider, ARRAY['provider_id', 'account_id', 'environment']
     ) IS NOT TRUE
     OR public.ep_gate_jsonb_is_identifier(v_provider->'provider_id') IS NOT TRUE
     OR public.ep_gate_jsonb_is_identifier(v_provider->'account_id') IS NOT TRUE
     OR public.ep_gate_jsonb_is_identifier(v_provider->'environment') IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid provider binding';
  END IF;

  IF public.ep_gate_jsonb_is_digest_array(v_body->'test_result_payload_digests', 64) IS NOT TRUE
     OR public.ep_gate_jsonb_is_digest_array(
       v_body->'agent_evaluation_evidence_payload_digests', 32
     ) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid admission digest lists';
  END IF;

  v_inputs := v_body->'inputs';
  IF jsonb_typeof(v_inputs) <> 'array' THEN
    RAISE EXCEPTION 'invalid admission inputs';
  END IF;
  IF jsonb_array_length(v_inputs) NOT BETWEEN 10 AND 128 THEN
    RAISE EXCEPTION 'invalid admission input cardinality';
  END IF;
  FOR v_input IN SELECT item FROM jsonb_array_elements(v_inputs) AS values_(item) LOOP
    IF public.ep_gate_jsonb_has_exact_keys(v_input, ARRAY[
         'role', 'artifact_type', 'subject', 'payload_digest', 'profile_digest',
         'verifier_id', 'trust_configuration_digest', 'valid_until'
       ]) IS NOT TRUE
       OR jsonb_typeof(v_input->'role') <> 'string'
       OR v_input->>'role' NOT IN (
         'candidate_manifest', 'runtime_measurement', 'test_result',
         'agent_evaluation_evidence', 'qualification_statement',
         'qualification_status', 'aeb', 'aec', 'local_policy', 'authorization'
       )
       OR public.ep_gate_jsonb_is_identifier(v_input->'artifact_type') IS NOT TRUE
       OR public.ep_gate_jsonb_is_identifier(v_input->'subject') IS NOT TRUE
       OR public.ep_gate_jsonb_is_identifier(v_input->'verifier_id') IS NOT TRUE
       OR public.ep_gate_jsonb_is_digest(v_input->'payload_digest') IS NOT TRUE
       OR public.ep_gate_jsonb_is_digest(v_input->'profile_digest') IS NOT TRUE
       OR public.ep_gate_jsonb_is_digest(v_input->'trust_configuration_digest') IS NOT TRUE
       OR jsonb_typeof(v_input->'valid_until') <> 'string'
       OR (v_input->>'valid_until') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
       OR (v_input->>'valid_until')::timestamptz <= v_admitted
       OR v_expires > (v_input->>'valid_until')::timestamptz THEN
      RAISE EXCEPTION 'invalid admission input';
    END IF;
  END LOOP;
  IF (SELECT count(DISTINCT item) FROM jsonb_array_elements(v_inputs) AS values_(item))
       <> jsonb_array_length(v_inputs)
     OR EXISTS (
       SELECT 1
       FROM (VALUES
         ('candidate_manifest'), ('runtime_measurement'),
         ('qualification_statement'), ('qualification_status'),
         ('aeb'), ('aec'), ('local_policy'), ('authorization')
       ) AS required(role)
       WHERE (SELECT count(*) FROM jsonb_array_elements(v_inputs) AS values_(item)
              WHERE item->>'role' = required.role) <> 1
     )
     OR EXISTS (
       SELECT 1
       FROM (VALUES ('test_result'), ('agent_evaluation_evidence')) AS required(role)
       WHERE (SELECT count(*) FROM jsonb_array_elements(v_inputs) AS values_(item)
              WHERE item->>'role' = required.role) < 1
     ) THEN
    RAISE EXCEPTION 'missing, duplicate, or malformed admission input role';
  END IF;
  SELECT jsonb_agg(item ORDER BY
      CASE item->>'role'
        WHEN 'candidate_manifest' THEN 0 WHEN 'runtime_measurement' THEN 1
        WHEN 'test_result' THEN 2 WHEN 'agent_evaluation_evidence' THEN 3
        WHEN 'qualification_statement' THEN 4 WHEN 'qualification_status' THEN 5
        WHEN 'aeb' THEN 6 WHEN 'aec' THEN 7 WHEN 'local_policy' THEN 8
        WHEN 'authorization' THEN 9 ELSE 99 END,
      public.ep_gate_canonical_json(item) COLLATE "C")
    INTO v_sorted FROM jsonb_array_elements(v_inputs) AS values_(item);
  IF v_inputs <> v_sorted THEN
    RAISE EXCEPTION 'admission inputs are not canonical';
  END IF;

  IF (SELECT item->>'payload_digest' FROM jsonb_array_elements(v_inputs) AS values_(item)
      WHERE item->>'role' = 'candidate_manifest')
       IS DISTINCT FROM v_body->>'candidate_manifest_digest'
     OR (SELECT item->>'payload_digest' FROM jsonb_array_elements(v_inputs) AS values_(item)
         WHERE item->>'role' = 'runtime_measurement')
       IS DISTINCT FROM v_body->>'runtime_measurement_digest'
     OR (SELECT item->>'payload_digest' FROM jsonb_array_elements(v_inputs) AS values_(item)
         WHERE item->>'role' = 'qualification_statement')
       IS DISTINCT FROM v_body->>'qualification_statement_payload_digest'
     OR (SELECT item->>'payload_digest' FROM jsonb_array_elements(v_inputs) AS values_(item)
         WHERE item->>'role' = 'qualification_status')
       IS DISTINCT FROM v_status->>'head_payload_digest' THEN
    RAISE EXCEPTION 'singleton admission input binding mismatch';
  END IF;
  SELECT jsonb_agg(item->'payload_digest' ORDER BY (item->>'payload_digest') COLLATE "C")
    INTO v_payloads FROM jsonb_array_elements(v_inputs) AS values_(item)
    WHERE item->>'role' = 'test_result';
  IF v_payloads IS DISTINCT FROM v_body->'test_result_payload_digests' THEN
    RAISE EXCEPTION 'test result input binding mismatch';
  END IF;
  SELECT jsonb_agg(item->'payload_digest' ORDER BY (item->>'payload_digest') COLLATE "C")
    INTO v_payloads FROM jsonb_array_elements(v_inputs) AS values_(item)
    WHERE item->>'role' = 'agent_evaluation_evidence';
  IF v_payloads IS DISTINCT FROM v_body->'agent_evaluation_evidence_payload_digests' THEN
    RAISE EXCEPTION 'agent evidence input binding mismatch';
  END IF;

  v_resources := v_body->'resource_reservations';
  IF jsonb_typeof(v_resources) <> 'array' THEN
    RAISE EXCEPTION 'invalid admission resources';
  END IF;
  IF jsonb_array_length(v_resources) NOT BETWEEN 1 AND 64 THEN
    RAISE EXCEPTION 'invalid admission resource cardinality';
  END IF;
  FOR v_resource IN SELECT item FROM jsonb_array_elements(v_resources) AS values_(item) LOOP
    IF ((v_resource->>'kind' = 'monotonic_counter' AND
         public.ep_gate_jsonb_has_exact_keys(v_resource, ARRAY[
           'kind', 'resource_id', 'reservation_id', 'digest', 'expires_at',
           'expected_value', 'next_value'
         ]) IS NOT TRUE)
        OR (v_resource->>'kind' <> 'monotonic_counter' AND
         public.ep_gate_jsonb_has_exact_keys(v_resource, ARRAY[
           'kind', 'resource_id', 'reservation_id', 'digest', 'expires_at'
         ]) IS NOT TRUE))
       OR jsonb_typeof(v_resource->'kind') <> 'string'
       OR v_resource->>'kind' NOT IN (
         'replay', 'capability', 'budget', 'qualification_use',
         'provider_operation', 'external_lease', 'monotonic_counter'
       )
       OR public.ep_gate_jsonb_is_identifier(v_resource->'resource_id') IS NOT TRUE
       OR public.ep_gate_jsonb_is_identifier(v_resource->'reservation_id') IS NOT TRUE
       OR public.ep_gate_jsonb_is_digest(v_resource->'digest') IS NOT TRUE
       OR jsonb_typeof(v_resource->'expires_at') <> 'string'
       OR (v_resource->>'expires_at') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
       OR (v_resource->>'expires_at')::timestamptz <= v_admitted
       OR v_expires > (v_resource->>'expires_at')::timestamptz
       OR (v_resource->>'kind' = 'monotonic_counter' AND (
         public.ep_gate_jsonb_is_safe_nonnegative_integer(v_resource->'expected_value') IS NOT TRUE
         OR public.ep_gate_jsonb_is_safe_nonnegative_integer(v_resource->'next_value') IS NOT TRUE
         OR (v_resource->>'next_value')::numeric <= (v_resource->>'expected_value')::numeric
         OR (v_resource->>'next_value')::numeric > 4294967295
       )) THEN
      RAISE EXCEPTION 'invalid admission resource';
    END IF;
  END LOOP;
  SELECT count(*) INTO v_count
    FROM (
      SELECT resource->>'kind', resource->>'resource_id'
      FROM jsonb_array_elements(v_resources) AS values_(resource)
      GROUP BY resource->>'kind', resource->>'resource_id'
    ) unique_resources;
  IF v_count <> jsonb_array_length(v_resources) THEN
    RAISE EXCEPTION 'invalid or duplicate admission resource';
  END IF;
  SELECT jsonb_agg(item ORDER BY (item->>'kind') COLLATE "C", (item->>'resource_id') COLLATE "C")
    INTO v_sorted FROM jsonb_array_elements(v_resources) AS values_(item);
  IF v_resources <> v_sorted THEN
    RAISE EXCEPTION 'admission resources are not canonical';
  END IF;
  IF (SELECT count(*) FROM jsonb_array_elements(v_resources) AS values_(item)
      WHERE item->>'kind' = 'provider_operation'
        AND item->>'resource_id' = v_body->>'operation_id') <> 1
     OR EXISTS (
       SELECT 1 FROM jsonb_array_elements(v_resources) AS values_(item)
       WHERE item->>'kind' = 'provider_operation'
         AND item->>'resource_id' <> v_body->>'operation_id'
     ) THEN
    RAISE EXCEPTION 'provider operation resource binding mismatch';
  END IF;

  IF jsonb_typeof(v_body->'supersedes_admission_id') NOT IN ('null', 'string')
     OR (jsonb_typeof(v_body->'supersedes_admission_id') = 'string'
         AND public.ep_gate_jsonb_is_identifier(v_body->'supersedes_admission_id') IS NOT TRUE) THEN
    RAISE EXCEPTION 'invalid supersession relation';
  END IF;
  v_relation := v_body->'remedy_for';
  IF jsonb_typeof(v_relation) = 'object' THEN
    IF public.ep_gate_jsonb_has_exact_keys(v_relation, ARRAY[
         'tenant_id', 'admission_id', 'operation_id', 'snapshot_digest'
       ]) IS NOT TRUE
       OR public.ep_gate_jsonb_is_identifier(v_relation->'tenant_id') IS NOT TRUE
       OR public.ep_gate_jsonb_is_identifier(v_relation->'admission_id') IS NOT TRUE
       OR public.ep_gate_jsonb_is_identifier(v_relation->'operation_id') IS NOT TRUE
       OR public.ep_gate_jsonb_is_digest(v_relation->'snapshot_digest') IS NOT TRUE
       OR v_relation->>'admission_id' = v_body->>'admission_id'
       OR v_relation->>'operation_id' = v_body->>'operation_id' THEN
      RAISE EXCEPTION 'invalid remedy relation';
    END IF;
  ELSIF jsonb_typeof(v_relation) <> 'null' THEN
    RAISE EXCEPTION 'invalid remedy relation';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_expected_resources(p_snapshot jsonb, p_state text)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT jsonb_agg(resource || jsonb_build_object('state', p_state)
                   ORDER BY resource->>'kind', resource->>'resource_id')
  FROM jsonb_array_elements(p_snapshot->'body'->'resource_reservations') AS values_(resource)
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_finalize_record(p_body jsonb)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public
AS $$
  SELECT p_body || jsonb_build_object(
    'record_digest', public.ep_gate_hash('EP-GATE-ADMISSION-RECORD-v2:DIGEST', p_body)
  )
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_assert_record(p_record jsonb)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF p_record->>'@version' <> 'EP-GATE-ADMISSION-RECORD-v2'
     OR COALESCE(p_record->>'record_digest', '') !~ '^sha256:[0-9a-f]{64}$'
     OR public.ep_gate_hash(
       'EP-GATE-ADMISSION-RECORD-v2:DIGEST',
       p_record - 'record_digest'
     ) <> p_record->>'record_digest' THEN
    RAISE EXCEPTION 'admission record digest mismatch';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_make_journal_entry(
  p_record jsonb,
  p_event text,
  p_predecessor_digest text,
  p_recorded_at text
)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_body jsonb;
BEGIN
  v_body := jsonb_build_object(
    '@version', 'EP-GATE-ADMISSION-JOURNAL-v2',
    'tenant_id', p_record->>'tenant_id',
    'admission_id', p_record->>'admission_id',
    'operation_id', p_record->>'operation_id',
    'sequence', (p_record->>'revision')::bigint,
    'event', p_event,
    'snapshot_digest', p_record->>'snapshot_digest',
    'record_digest', p_record->>'record_digest',
    'predecessor_digest', to_jsonb(p_predecessor_digest),
    'recorded_at', p_recorded_at
  );
  RETURN v_body || jsonb_build_object(
    'entry_digest', public.ep_gate_hash('EP-GATE-ADMISSION-JOURNAL-v2:DIGEST', v_body)
  );
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_load_admission_locked(
  p_deployment_id text,
  p_tenant_id text,
  p_admission_id text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_record_row public.ep_gate_admission_records%ROWTYPE;
  v_snapshot jsonb;
  v_journal_count bigint;
  v_head_admission text;
BEGIN
  SELECT * INTO v_record_row
    FROM public.ep_gate_admission_records
    WHERE deployment_id = p_deployment_id AND admission_id = p_admission_id
    FOR UPDATE;
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF v_record_row.tenant_id <> p_tenant_id
     OR v_record_row.record_json->>'tenant_id' <> p_tenant_id
     OR v_record_row.record_json->>'admission_id' <> p_admission_id
     OR (v_record_row.record_json->>'revision')::bigint <> v_record_row.revision
     OR v_record_row.record_json->>'owner_digest' <> v_record_row.owner_digest
     OR v_record_row.record_json->>'operation_id' <> v_record_row.operation_id
     OR v_record_row.record_json->>'snapshot_digest' <> v_record_row.snapshot_digest THEN
    RAISE EXCEPTION 'admission record columns do not match the record head';
  END IF;
  PERFORM public.ep_gate_assert_record(v_record_row.record_json);
  SELECT snapshot_json INTO STRICT v_snapshot
    FROM public.ep_gate_admission_snapshots
    WHERE deployment_id = p_deployment_id AND snapshot_digest = v_record_row.snapshot_digest;
  PERFORM public.ep_gate_assert_snapshot(p_deployment_id, p_tenant_id, v_snapshot);
  IF v_snapshot->'body'->>'admission_id' <> p_admission_id
     OR v_snapshot->'body'->>'operation_id' <> v_record_row.operation_id THEN
    RAISE EXCEPTION 'admission record and snapshot identity mismatch';
  END IF;
  SELECT count(*) INTO v_journal_count
    FROM public.ep_gate_admission_journal
    WHERE deployment_id = p_deployment_id AND admission_id = p_admission_id;
  IF v_journal_count <> v_record_row.revision + 1
     OR NOT EXISTS (
       SELECT 1 FROM public.ep_gate_admission_journal
       WHERE deployment_id = p_deployment_id
         AND admission_id = p_admission_id
         AND sequence = v_record_row.revision
         AND record_digest = v_record_row.record_json->>'record_digest'
     ) THEN
    RAISE EXCEPTION 'admission record and journal head mismatch';
  END IF;
  SELECT admission_id INTO v_head_admission
    FROM public.ep_gate_operation_heads
    WHERE deployment_id = p_deployment_id AND operation_id = v_record_row.operation_id
    FOR UPDATE;
  IF v_record_row.record_json->>'state' <> 'SUPERSEDED'
     AND v_head_admission IS DISTINCT FROM p_admission_id THEN
    RAISE EXCEPTION 'admission is not the permanent operation head';
  END IF;
  RETURN v_record_row.record_json;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_insert_record_and_journal(
  p_deployment_id text,
  p_record_body jsonb,
  p_event text,
  p_recorded_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_record jsonb := public.ep_gate_finalize_record(p_record_body);
  v_at text := public.ep_gate_iso(p_recorded_at);
  v_entry jsonb;
BEGIN
  IF (v_record->>'revision')::bigint <> 0 THEN
    RAISE EXCEPTION 'initial admission revision must be zero';
  END IF;
  v_entry := public.ep_gate_make_journal_entry(v_record, p_event, NULL, v_at);
  INSERT INTO public.ep_gate_admission_records (
    deployment_id, tenant_id, admission_id, operation_id, snapshot_digest,
    revision, owner_digest, record_json, updated_at
  ) VALUES (
    p_deployment_id, v_record->>'tenant_id', v_record->>'admission_id',
    v_record->>'operation_id', v_record->>'snapshot_digest', 0,
    v_record->>'owner_digest', v_record, p_recorded_at
  );
  INSERT INTO public.ep_gate_admission_journal (
    deployment_id, tenant_id, admission_id, operation_id, sequence, event,
    record_digest, predecessor_digest, entry_digest, entry_json, recorded_at
  ) VALUES (
    p_deployment_id, v_record->>'tenant_id', v_record->>'admission_id',
    v_record->>'operation_id', 0, p_event, v_record->>'record_digest', NULL,
    v_entry->>'entry_digest', v_entry, p_recorded_at
  );
  RETURN v_record;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_apply_transition(
  p_deployment_id text,
  p_current jsonb,
  p_changes jsonb,
  p_event text,
  p_recorded_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_previous_entry_digest text;
  v_body jsonb;
  v_record jsonb;
  v_entry jsonb;
  v_at text := public.ep_gate_iso(p_recorded_at);
  v_revision bigint := (p_current->>'revision')::bigint + 1;
BEGIN
  PERFORM public.ep_gate_assert_record(p_current);
  SELECT entry_digest INTO STRICT v_previous_entry_digest
    FROM public.ep_gate_admission_journal
    WHERE deployment_id = p_deployment_id
      AND admission_id = p_current->>'admission_id'
      AND sequence = (p_current->>'revision')::bigint
      AND record_digest = p_current->>'record_digest';
  v_body := (p_current - 'record_digest') || p_changes || jsonb_build_object(
    'revision', v_revision,
    'updated_at', v_at,
    'predecessor_record_digest', p_current->>'record_digest'
  );
  v_record := public.ep_gate_finalize_record(v_body);
  v_entry := public.ep_gate_make_journal_entry(v_record, p_event, v_previous_entry_digest, v_at);
  UPDATE public.ep_gate_admission_records
    SET revision = v_revision,
        owner_digest = v_record->>'owner_digest',
        record_json = v_record,
        updated_at = p_recorded_at
    WHERE deployment_id = p_deployment_id
      AND admission_id = p_current->>'admission_id'
      AND revision = (p_current->>'revision')::bigint
      AND record_json = p_current;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'admission CAS changed while locked';
  END IF;
  INSERT INTO public.ep_gate_admission_journal (
    deployment_id, tenant_id, admission_id, operation_id, sequence, event,
    record_digest, predecessor_digest, entry_digest, entry_json, recorded_at
  ) VALUES (
    p_deployment_id, v_record->>'tenant_id', v_record->>'admission_id',
    v_record->>'operation_id', v_revision, p_event, v_record->>'record_digest',
    v_previous_entry_digest, v_entry->>'entry_digest', v_entry, p_recorded_at
  );
  RETURN v_record;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_resources_exact(
  p_deployment_id text,
  p_admission_id text,
  p_snapshot jsonb,
  p_state text
)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $$
  SELECT
    (SELECT count(*) FROM public.ep_gate_resource_fences f
       WHERE f.deployment_id = p_deployment_id AND f.admission_id = p_admission_id)
      = (SELECT count(*) FROM jsonb_array_elements(
           p_snapshot->'body'->'resource_reservations'
         ) AS values_(resource)
         WHERE resource->>'kind' <> 'monotonic_counter')
    AND NOT EXISTS (
      SELECT 1
      FROM jsonb_array_elements(p_snapshot->'body'->'resource_reservations') AS values_(resource)
      LEFT JOIN public.ep_gate_resource_fences f
        ON f.deployment_id = p_deployment_id
       AND f.kind = resource->>'kind'
       AND f.resource_id = resource->>'resource_id'
       AND f.admission_id = p_admission_id
      WHERE resource->>'kind' <> 'monotonic_counter'
        AND (f.resource_id IS NULL
         OR f.reservation_id <> resource->>'reservation_id'
         OR f.digest <> resource->>'digest'
         OR f.expires_at <> (resource->>'expires_at')::timestamptz
         OR f.state <> p_state)
    )
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_advance_monotonic_counters(
  p_deployment_id text,
  p_tenant_id text,
  p_body jsonb,
  p_recorded_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_resource jsonb;
  v_rows bigint;
BEGIN
  FOR v_resource IN
    SELECT resource
    FROM jsonb_array_elements(p_body->'resource_reservations') AS values_(resource)
    WHERE resource->>'kind' = 'monotonic_counter'
    ORDER BY resource->>'resource_id'
  LOOP
    UPDATE public.ep_gate_monotonic_counters
      SET current_value = (v_resource->>'next_value')::bigint,
          updated_at = p_recorded_at
      WHERE deployment_id = p_deployment_id
        AND tenant_id = p_tenant_id
        AND resource_id = v_resource->>'resource_id'
        AND current_value = (v_resource->>'expected_value')::bigint;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows <> 1 THEN
      RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'monotonic counter conflict';
    END IF;
  END LOOP;
END;
$$;

-- Operator-only bootstrap for an authenticated WebAuthn enrollment or recovery
-- ceremony. Runtime admission roles should receive no EXECUTE grant on this
-- function. Re-provisioning an existing resource is always refused so a stale
-- or attacker-selected baseline cannot replace the durable head.
CREATE OR REPLACE FUNCTION public.ep_gate_provision_monotonic_counter(
  p_deployment_id text,
  p_tenant_id text,
  p_resource_id text,
  p_initial_value bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM public.ep_gate_assert_binding(p_deployment_id, p_tenant_id);
  IF public.ep_gate_jsonb_is_identifier(to_jsonb(p_resource_id)) IS NOT TRUE
     OR p_initial_value IS NULL
     OR p_initial_value < 0
     OR p_initial_value > 4294967295 THEN
    RAISE EXCEPTION 'invalid monotonic counter enrollment';
  END IF;
  BEGIN
    INSERT INTO public.ep_gate_monotonic_counters (
      deployment_id, tenant_id, resource_id, current_value, updated_at
    ) VALUES (
      p_deployment_id, p_tenant_id, p_resource_id, p_initial_value,
      clock_timestamp()
    );
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION USING ERRCODE = '23505',
      MESSAGE = 'monotonic counter already provisioned';
  END;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_initial_record(
  p_snapshot jsonb,
  p_owner_digest text,
  p_recorded_at timestamptz
)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog, public
AS $$
  SELECT jsonb_build_object(
    '@version', 'EP-GATE-ADMISSION-RECORD-v2',
    'tenant_id', p_snapshot->'body'->>'tenant_id',
    'admission_id', p_snapshot->'body'->>'admission_id',
    'operation_id', p_snapshot->'body'->>'operation_id',
    'snapshot_digest', p_snapshot->>'snapshot_digest',
    'revision', 0,
    'state', 'RESERVED',
    'execution_right', 'RESERVED',
    'provider_attempt', 'NOT_ENTERED',
    'owner_digest', p_owner_digest,
    'invocation_token_digest', NULL,
    'provider_outcome', NULL,
    'effect_relation', NULL,
    'resources', public.ep_gate_expected_resources(p_snapshot, 'RESERVED'),
    'superseded_by_admission_id', NULL,
    'refusal_reason', NULL,
    'invocation_started_at', NULL,
    'created_at', public.ep_gate_iso(p_recorded_at),
    'updated_at', public.ep_gate_iso(p_recorded_at),
    'predecessor_record_digest', NULL
  )
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_admission_reserve(
  p_deployment_id text,
  p_tenant_id text,
  p_snapshot jsonb,
  p_owner_digest text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_body jsonb;
  v_now timestamptz;
  v_record jsonb;
  v_target record;
BEGIN
  PERFORM public.ep_gate_assert_binding(p_deployment_id, p_tenant_id);
  PERFORM public.ep_gate_assert_snapshot(p_deployment_id, p_tenant_id, p_snapshot);
  IF p_owner_digest !~ '^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'invalid owner digest'; END IF;
  v_body := p_snapshot->'body';
  IF v_body->'supersedes_admission_id' <> 'null'::jsonb THEN
    RETURN public.ep_gate_refusal('relation_conflict');
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.ep_gate_admission_records
    WHERE deployment_id = p_deployment_id AND admission_id = v_body->>'admission_id'
  ) THEN RETURN public.ep_gate_refusal('admission_exists'); END IF;
  IF EXISTS (
    SELECT 1 FROM public.ep_gate_operation_heads
    WHERE deployment_id = p_deployment_id AND operation_id = v_body->>'operation_id'
  ) THEN RETURN public.ep_gate_refusal('operation_exists'); END IF;
  v_now := clock_timestamp();
  IF (v_body->>'expires_at')::timestamptz <= v_now THEN
    RETURN public.ep_gate_refusal('admission_expired');
  END IF;
  IF v_body->'remedy_for' <> 'null'::jsonb THEN
    SELECT r.record_json, s.snapshot_json INTO v_target
      FROM public.ep_gate_admission_records r
      JOIN public.ep_gate_admission_snapshots s
        ON s.deployment_id = r.deployment_id AND s.snapshot_digest = r.snapshot_digest
      WHERE r.deployment_id = p_deployment_id
        AND r.tenant_id = v_body->'remedy_for'->>'tenant_id'
        AND r.admission_id = v_body->'remedy_for'->>'admission_id'
        AND r.snapshot_digest = v_body->'remedy_for'->>'snapshot_digest';
    IF NOT FOUND THEN RETURN public.ep_gate_refusal('relation_not_found'); END IF;
    IF v_target.record_json->>'state' NOT IN ('INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED')
       OR v_target.snapshot_json->'body'->>'operation_id' = v_body->>'operation_id'
       OR v_target.snapshot_json->'body'->>'caid' = v_body->>'caid' THEN
      RETURN public.ep_gate_refusal('relation_conflict');
    END IF;
  END IF;

  BEGIN
    PERFORM public.ep_gate_advance_monotonic_counters(
      p_deployment_id, p_tenant_id, v_body, v_now
    );
    INSERT INTO public.ep_gate_operation_heads (
      deployment_id, tenant_id, operation_id, admission_id, created_at, updated_at
    ) VALUES (
      p_deployment_id, p_tenant_id, v_body->>'operation_id', v_body->>'admission_id', v_now, v_now
    );
    INSERT INTO public.ep_gate_admission_snapshots (
      deployment_id, tenant_id, snapshot_digest, admission_id, operation_id, snapshot_json, created_at
    ) VALUES (
      p_deployment_id, p_tenant_id, p_snapshot->>'snapshot_digest', v_body->>'admission_id',
      v_body->>'operation_id', p_snapshot, v_now
    );
    v_record := public.ep_gate_insert_record_and_journal(
      p_deployment_id,
      public.ep_gate_initial_record(p_snapshot, p_owner_digest, v_now),
      'RESERVED',
      v_now
    );
    INSERT INTO public.ep_gate_resource_fences (
      deployment_id, tenant_id, kind, resource_id, reservation_id, digest,
      expires_at, admission_id, state
    )
    SELECT p_deployment_id, p_tenant_id, resource->>'kind', resource->>'resource_id',
      resource->>'reservation_id', resource->>'digest', (resource->>'expires_at')::timestamptz,
      v_body->>'admission_id', 'RESERVED'
    FROM jsonb_array_elements(v_body->'resource_reservations') AS values_(resource)
    WHERE resource->>'kind' <> 'monotonic_counter'
    ORDER BY resource->>'kind', resource->>'resource_id';
  EXCEPTION WHEN unique_violation THEN
    IF EXISTS (SELECT 1 FROM public.ep_gate_admission_records WHERE deployment_id = p_deployment_id AND admission_id = v_body->>'admission_id') THEN
      RETURN public.ep_gate_refusal('admission_exists');
    ELSIF EXISTS (SELECT 1 FROM public.ep_gate_operation_heads WHERE deployment_id = p_deployment_id AND operation_id = v_body->>'operation_id') THEN
      RETURN public.ep_gate_refusal('operation_exists');
    ELSE
      RETURN public.ep_gate_refusal('resource_conflict');
    END IF;
  END;
  RETURN jsonb_build_object('ok', true, 'snapshot', p_snapshot, 'record', v_record);
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_admission_release(
  p_deployment_id text,
  p_tenant_id text,
  p_admission_id text,
  p_expected_revision bigint,
  p_owner_digest text,
  p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_current jsonb;
  v_snapshot jsonb;
  v_now timestamptz;
  v_record jsonb;
BEGIN
  PERFORM public.ep_gate_assert_binding(p_deployment_id, p_tenant_id);
  v_current := public.ep_gate_load_admission_locked(p_deployment_id, p_tenant_id, p_admission_id);
  IF v_current IS NULL THEN RETURN public.ep_gate_refusal('admission_not_found'); END IF;
  IF (v_current->>'revision')::bigint <> p_expected_revision THEN RETURN public.ep_gate_refusal('revision_conflict'); END IF;
  IF v_current->>'owner_digest' <> p_owner_digest THEN RETURN public.ep_gate_refusal('owner_conflict'); END IF;
  IF v_current->>'execution_right' = 'CONSUMED' THEN RETURN public.ep_gate_refusal('execution_right_consumed'); END IF;
  IF v_current->>'state' <> 'RESERVED' THEN RETURN public.ep_gate_refusal('state_conflict'); END IF;
  SELECT snapshot_json INTO STRICT v_snapshot FROM public.ep_gate_admission_snapshots
    WHERE deployment_id = p_deployment_id AND snapshot_digest = v_current->>'snapshot_digest';
  PERFORM 1 FROM public.ep_gate_resource_fences
    WHERE deployment_id = p_deployment_id AND admission_id = p_admission_id
    ORDER BY kind, resource_id FOR UPDATE;
  IF v_current->'resources' <> public.ep_gate_expected_resources(v_snapshot, 'RESERVED')
     OR NOT public.ep_gate_resources_exact(p_deployment_id, p_admission_id, v_snapshot, 'RESERVED') THEN
    RAISE EXCEPTION 'reserved resource head mismatch';
  END IF;
  DELETE FROM public.ep_gate_resource_fences
    WHERE deployment_id = p_deployment_id AND admission_id = p_admission_id AND state = 'RESERVED';
  v_now := clock_timestamp();
  v_record := public.ep_gate_apply_transition(
    p_deployment_id,
    v_current,
    jsonb_build_object(
      'state', 'RELEASED',
      'execution_right', 'RELEASED',
      'refusal_reason', p_reason,
      'resources', public.ep_gate_expected_resources(v_snapshot, 'RELEASED')
    ),
    'RELEASED',
    v_now
  );
  RETURN jsonb_build_object('ok', true, 'record', v_record);
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_admission_expire(
  p_deployment_id text,
  p_tenant_id text,
  p_admission_id text,
  p_expected_revision bigint,
  p_owner_digest text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_current jsonb;
  v_snapshot jsonb;
  v_now timestamptz;
  v_record jsonb;
BEGIN
  PERFORM public.ep_gate_assert_binding(p_deployment_id, p_tenant_id);
  v_current := public.ep_gate_load_admission_locked(p_deployment_id, p_tenant_id, p_admission_id);
  IF v_current IS NULL THEN RETURN public.ep_gate_refusal('admission_not_found'); END IF;
  IF (v_current->>'revision')::bigint <> p_expected_revision THEN RETURN public.ep_gate_refusal('revision_conflict'); END IF;
  IF v_current->>'owner_digest' <> p_owner_digest THEN RETURN public.ep_gate_refusal('owner_conflict'); END IF;
  IF v_current->>'state' <> 'RESERVED' THEN RETURN public.ep_gate_refusal('state_conflict'); END IF;
  SELECT snapshot_json INTO STRICT v_snapshot FROM public.ep_gate_admission_snapshots
    WHERE deployment_id = p_deployment_id AND snapshot_digest = v_current->>'snapshot_digest';
  v_now := clock_timestamp();
  IF (v_snapshot->'body'->>'expires_at')::timestamptz > v_now THEN
    RETURN public.ep_gate_refusal('state_conflict');
  END IF;
  PERFORM 1 FROM public.ep_gate_resource_fences
    WHERE deployment_id = p_deployment_id AND admission_id = p_admission_id
    ORDER BY kind, resource_id FOR UPDATE;
  IF v_current->'resources' <> public.ep_gate_expected_resources(v_snapshot, 'RESERVED')
     OR NOT public.ep_gate_resources_exact(p_deployment_id, p_admission_id, v_snapshot, 'RESERVED') THEN
    RAISE EXCEPTION 'reserved resource head mismatch';
  END IF;
  DELETE FROM public.ep_gate_resource_fences
    WHERE deployment_id = p_deployment_id AND admission_id = p_admission_id AND state = 'RESERVED';
  v_record := public.ep_gate_apply_transition(
    p_deployment_id,
    v_current,
    jsonb_build_object(
      'state', 'EXPIRED',
      'execution_right', 'RELEASED',
      'refusal_reason', 'admission_expired',
      'resources', public.ep_gate_expected_resources(v_snapshot, 'RELEASED')
    ),
    'EXPIRED',
    v_now
  );
  RETURN jsonb_build_object('ok', true, 'record', v_record);
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_admission_supersede(
  p_deployment_id text,
  p_tenant_id text,
  p_predecessor_admission_id text,
  p_expected_revision bigint,
  p_owner_digest text,
  p_successor_snapshot jsonb,
  p_successor_owner_digest text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_current jsonb;
  v_predecessor_snapshot jsonb;
  v_successor_body jsonb;
  v_now timestamptz;
  v_predecessor_record jsonb;
  v_successor_record jsonb;
BEGIN
  PERFORM public.ep_gate_assert_binding(p_deployment_id, p_tenant_id);
  PERFORM public.ep_gate_assert_snapshot(p_deployment_id, p_tenant_id, p_successor_snapshot);
  IF p_successor_owner_digest !~ '^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'invalid successor owner digest'; END IF;
  v_current := public.ep_gate_load_admission_locked(p_deployment_id, p_tenant_id, p_predecessor_admission_id);
  IF v_current IS NULL THEN RETURN public.ep_gate_refusal('admission_not_found'); END IF;
  IF (v_current->>'revision')::bigint <> p_expected_revision THEN RETURN public.ep_gate_refusal('revision_conflict'); END IF;
  IF v_current->>'owner_digest' <> p_owner_digest THEN RETURN public.ep_gate_refusal('owner_conflict'); END IF;
  IF v_current->>'state' <> 'RESERVED' OR v_current->>'execution_right' <> 'RESERVED' THEN
    RETURN public.ep_gate_refusal('state_conflict');
  END IF;
  SELECT snapshot_json INTO STRICT v_predecessor_snapshot FROM public.ep_gate_admission_snapshots
    WHERE deployment_id = p_deployment_id AND snapshot_digest = v_current->>'snapshot_digest';
  v_successor_body := p_successor_snapshot->'body';
  IF v_successor_body->>'supersedes_admission_id' IS DISTINCT FROM p_predecessor_admission_id
     OR v_successor_body->'remedy_for' <> 'null'::jsonb THEN
    RETURN public.ep_gate_refusal('relation_conflict');
  END IF;
  IF v_successor_body->>'admission_id' = p_predecessor_admission_id
     OR v_successor_body->>'tenant_id' <> v_predecessor_snapshot->'body'->>'tenant_id'
     OR v_successor_body->>'operation_id' <> v_predecessor_snapshot->'body'->>'operation_id'
     OR v_successor_body->>'caid' <> v_predecessor_snapshot->'body'->>'caid'
     OR v_successor_body->>'action_digest' <> v_predecessor_snapshot->'body'->>'action_digest'
     OR v_successor_body->>'effect_request_digest' <> v_predecessor_snapshot->'body'->>'effect_request_digest'
     OR v_successor_body->'provider' <> v_predecessor_snapshot->'body'->'provider'
     OR v_successor_body->>'executor_adapter_digest' <> v_predecessor_snapshot->'body'->>'executor_adapter_digest'
     OR v_successor_body->>'idempotency_key' <> v_predecessor_snapshot->'body'->>'idempotency_key' THEN
    RETURN public.ep_gate_refusal('operation_conflict');
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.ep_gate_admission_records
    WHERE deployment_id = p_deployment_id AND admission_id = v_successor_body->>'admission_id'
  ) THEN RETURN public.ep_gate_refusal('admission_exists'); END IF;
  v_now := clock_timestamp();
  IF (v_successor_body->>'expires_at')::timestamptz <= v_now THEN
    RETURN public.ep_gate_refusal('admission_expired');
  END IF;
  PERFORM f.resource_id
    FROM public.ep_gate_resource_fences f
    WHERE f.deployment_id = p_deployment_id
      AND (
        f.admission_id = p_predecessor_admission_id
        OR EXISTS (
          SELECT 1 FROM jsonb_array_elements(v_successor_body->'resource_reservations') AS values_(resource)
          WHERE resource->>'kind' = f.kind AND resource->>'resource_id' = f.resource_id
        )
      )
    ORDER BY f.kind, f.resource_id
    FOR UPDATE;
  IF v_current->'resources' <> public.ep_gate_expected_resources(v_predecessor_snapshot, 'RESERVED')
     OR NOT public.ep_gate_resources_exact(p_deployment_id, p_predecessor_admission_id, v_predecessor_snapshot, 'RESERVED') THEN
    RAISE EXCEPTION 'predecessor resource head mismatch';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM jsonb_array_elements(v_successor_body->'resource_reservations') AS values_(resource)
    JOIN public.ep_gate_resource_fences f
      ON f.deployment_id = p_deployment_id
     AND f.kind = resource->>'kind'
     AND f.resource_id = resource->>'resource_id'
    WHERE f.admission_id <> p_predecessor_admission_id
  ) THEN RETURN public.ep_gate_refusal('resource_conflict'); END IF;

  BEGIN
    PERFORM public.ep_gate_advance_monotonic_counters(
      p_deployment_id, p_tenant_id, v_successor_body, v_now
    );
    INSERT INTO public.ep_gate_admission_snapshots (
      deployment_id, tenant_id, snapshot_digest, admission_id, operation_id, snapshot_json, created_at
    ) VALUES (
      p_deployment_id, p_tenant_id, p_successor_snapshot->>'snapshot_digest',
      v_successor_body->>'admission_id', v_successor_body->>'operation_id', p_successor_snapshot, v_now
    );
    v_predecessor_record := public.ep_gate_apply_transition(
      p_deployment_id,
      v_current,
      jsonb_build_object(
        'state', 'SUPERSEDED',
        'execution_right', 'RELEASED',
        'superseded_by_admission_id', v_successor_body->>'admission_id',
        'resources', public.ep_gate_expected_resources(v_predecessor_snapshot, 'RELEASED')
      ),
      'SUPERSEDED',
      v_now
    );
    DELETE FROM public.ep_gate_resource_fences
      WHERE deployment_id = p_deployment_id
        AND admission_id = p_predecessor_admission_id
        AND state = 'RESERVED';
    v_successor_record := public.ep_gate_insert_record_and_journal(
      p_deployment_id,
      public.ep_gate_initial_record(p_successor_snapshot, p_successor_owner_digest, v_now),
      'RESERVED',
      v_now
    );
    INSERT INTO public.ep_gate_resource_fences (
      deployment_id, tenant_id, kind, resource_id, reservation_id, digest,
      expires_at, admission_id, state
    )
    SELECT p_deployment_id, p_tenant_id, resource->>'kind', resource->>'resource_id',
      resource->>'reservation_id', resource->>'digest', (resource->>'expires_at')::timestamptz,
      v_successor_body->>'admission_id', 'RESERVED'
    FROM jsonb_array_elements(v_successor_body->'resource_reservations') AS values_(resource)
    WHERE resource->>'kind' <> 'monotonic_counter'
    ORDER BY resource->>'kind', resource->>'resource_id';
    UPDATE public.ep_gate_operation_heads
      SET admission_id = v_successor_body->>'admission_id', updated_at = v_now
      WHERE deployment_id = p_deployment_id
        AND tenant_id = p_tenant_id
        AND operation_id = v_successor_body->>'operation_id'
        AND admission_id = p_predecessor_admission_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'operation head changed during supersession'; END IF;
  EXCEPTION WHEN unique_violation THEN
    IF EXISTS (SELECT 1 FROM public.ep_gate_admission_records WHERE deployment_id = p_deployment_id AND admission_id = v_successor_body->>'admission_id') THEN
      RETURN public.ep_gate_refusal('admission_exists');
    ELSE
      RETURN public.ep_gate_refusal('resource_conflict');
    END IF;
  END;
  RETURN jsonb_build_object(
    'ok', true,
    'predecessor_record', v_predecessor_record,
    'successor_snapshot', p_successor_snapshot,
    'successor_record', v_successor_record
  );
END;
$$;

-- Currentness-writer contract for adapter/type alignment:
--   * ep_gate_deployment_binding carries the trusted maximum age in milliseconds
--     (default 5000, hard ceiling 300000) plus trust/configuration bindings;
--   * exactly one candidate/runtime head exists per deployment;
--   * one protected-request head exists per operation and binds CAID, action,
--     effect request, provider, adapter, and idempotency identity;
--   * AEB, AEC, local-policy, and authorization heads bind the complete matching
--     AdmissionInput; qualification-status and external-lease heads remain
--     independently current.  Every observed_at is subject to the same maximum.
CREATE OR REPLACE FUNCTION public.ep_gate_admission_begin_invocation(
  p_deployment_id text,
  p_tenant_id text,
  p_admission_id text,
  p_expected_revision bigint,
  p_owner_digest text,
  p_invocation_token_digest text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_binding public.ep_gate_deployment_binding%ROWTYPE;
  v_current jsonb;
  v_snapshot jsonb;
  v_body jsonb;
  v_status public.ep_gate_qualification_status_heads%ROWTYPE;
  v_now timestamptz;
  v_maximum_observation_age interval;
  v_currentness_ok boolean := true;
  v_record jsonb;
BEGIN
  SELECT * INTO v_binding FROM public.ep_gate_assert_binding(p_deployment_id, p_tenant_id);
  IF p_invocation_token_digest !~ '^sha256:[0-9a-f]{64}$' THEN RAISE EXCEPTION 'invalid invocation token digest'; END IF;
  v_current := public.ep_gate_load_admission_locked(p_deployment_id, p_tenant_id, p_admission_id);
  IF v_current IS NULL THEN RETURN public.ep_gate_refusal('admission_not_found'); END IF;
  IF (v_current->>'revision')::bigint <> p_expected_revision THEN RETURN public.ep_gate_refusal('revision_conflict'); END IF;
  IF v_current->>'owner_digest' <> p_owner_digest THEN RETURN public.ep_gate_refusal('owner_conflict'); END IF;
  IF v_current->>'state' <> 'RESERVED'
     OR v_current->>'execution_right' <> 'RESERVED'
     OR v_current->>'provider_attempt' <> 'NOT_ENTERED' THEN
    RETURN public.ep_gate_refusal('state_conflict');
  END IF;
  SELECT snapshot_json INTO STRICT v_snapshot FROM public.ep_gate_admission_snapshots
    WHERE deployment_id = p_deployment_id AND snapshot_digest = v_current->>'snapshot_digest';
  v_body := v_snapshot->'body';
  PERFORM 1 FROM public.ep_gate_resource_fences
    WHERE deployment_id = p_deployment_id AND admission_id = p_admission_id
    ORDER BY kind, resource_id FOR UPDATE;
  IF v_current->'resources' <> public.ep_gate_expected_resources(v_snapshot, 'RESERVED')
     OR NOT public.ep_gate_resources_exact(p_deployment_id, p_admission_id, v_snapshot, 'RESERVED') THEN
    RAISE EXCEPTION 'reserved resource head mismatch';
  END IF;
  PERFORM h.operation_id
    FROM public.ep_gate_protected_request_heads h
    WHERE h.deployment_id = p_deployment_id
      AND h.operation_id = v_body->>'operation_id'
    FOR SHARE;
  PERFORM h.deployment_id
    FROM public.ep_gate_candidate_runtime_heads h
    WHERE h.deployment_id = p_deployment_id
    FOR SHARE;
  PERFORM h.role
    FROM public.ep_gate_evidence_heads h
    JOIN jsonb_array_elements(v_body->'inputs') AS values_(input)
      ON input->>'role' = h.role
     AND input->>'subject' = h.subject
     AND input->>'verifier_id' = h.verifier_id
    WHERE h.deployment_id = p_deployment_id
      AND h.role IN ('aeb', 'aec', 'local_policy', 'authorization')
    ORDER BY h.role, h.subject, h.verifier_id
    FOR SHARE OF h;
  SELECT * INTO v_status
    FROM public.ep_gate_qualification_status_heads
    WHERE deployment_id = p_deployment_id
      AND authority_id = v_body->'qualification_status'->>'authority_id'
    FOR SHARE;
  PERFORM l.resource_id
    FROM public.ep_gate_external_leases l
    WHERE l.deployment_id = p_deployment_id
      AND EXISTS (
        SELECT 1 FROM jsonb_array_elements(v_body->'resource_reservations') AS values_(resource)
        WHERE resource->>'kind' = 'external_lease' AND resource->>'resource_id' = l.resource_id
      )
    ORDER BY l.resource_id
    FOR SHARE;
  PERFORM c.resource_id
    FROM public.ep_gate_monotonic_counters c
    WHERE c.deployment_id = p_deployment_id
      AND EXISTS (
        SELECT 1 FROM jsonb_array_elements(v_body->'resource_reservations') AS values_(resource)
        WHERE resource->>'kind' = 'monotonic_counter'
          AND resource->>'resource_id' = c.resource_id
      )
    ORDER BY c.resource_id
    FOR SHARE;
  v_now := clock_timestamp();
  v_maximum_observation_age := make_interval(
    secs => v_binding.maximum_observation_age_ms::double precision / 1000.0
  );
  IF (v_body->>'expires_at')::timestamptz <= v_now THEN
    RETURN public.ep_gate_refusal('admission_expired');
  END IF;
  v_currentness_ok := v_binding.candidate_match = 'EXACT_MATCH'
    AND v_binding.currentness_observed_at <= v_now
    AND v_binding.currentness_observed_at >= v_now - v_maximum_observation_age
    AND v_binding.trust_epoch = (v_body->>'trust_epoch')::bigint
    AND v_binding.trust_configuration_digest = v_body->>'trust_configuration_digest'
    AND v_binding.configuration_epoch = (v_body->>'configuration_epoch')::bigint
    AND v_binding.configuration_digest = v_body->>'configuration_digest'
    AND v_binding.runtime_measurement_digest = v_body->>'runtime_measurement_digest'
    AND EXISTS (
      SELECT 1
      FROM public.ep_gate_candidate_runtime_heads h
      WHERE h.deployment_id = p_deployment_id
        AND h.candidate_manifest_digest = v_body->>'candidate_manifest_digest'
        AND h.runtime_measurement_digest = v_body->>'runtime_measurement_digest'
        AND h.candidate_match = 'EXACT_MATCH'
        AND h.observed_at BETWEEN v_now - v_maximum_observation_age AND v_now
        AND h.expires_at > v_now
    )
    AND EXISTS (
      SELECT 1
      FROM public.ep_gate_protected_request_heads h
      WHERE h.deployment_id = p_deployment_id
        AND h.operation_id = v_body->>'operation_id'
        AND h.caid = v_body->>'caid'
        AND h.action_digest = v_body->>'action_digest'
        AND h.effect_request_digest = v_body->>'effect_request_digest'
        AND h.provider_id = v_body->'provider'->>'provider_id'
        AND h.provider_account_id = v_body->'provider'->>'account_id'
        AND h.provider_environment = v_body->'provider'->>'environment'
        AND h.executor_adapter_digest = v_body->>'executor_adapter_digest'
        AND h.idempotency_key = v_body->>'idempotency_key'
        AND h.observed_at BETWEEN v_now - v_maximum_observation_age AND v_now
        AND h.expires_at > v_now
    )
    AND NOT EXISTS (
      SELECT 1
      FROM jsonb_array_elements(v_body->'inputs') AS values_(input)
      LEFT JOIN public.ep_gate_evidence_heads h
        ON h.deployment_id = p_deployment_id
       AND h.role = input->>'role'
       AND h.subject = input->>'subject'
       AND h.verifier_id = input->>'verifier_id'
      WHERE input->>'role' IN ('aeb', 'aec', 'local_policy', 'authorization')
        AND (
          h.deployment_id IS NULL
          OR h.artifact_type <> input->>'artifact_type'
          OR h.payload_digest <> input->>'payload_digest'
          OR h.profile_digest <> input->>'profile_digest'
          OR h.trust_configuration_digest <> input->>'trust_configuration_digest'
          OR h.observed_at < v_now - v_maximum_observation_age
          OR h.observed_at > v_now
          OR h.expires_at <= v_now
        )
    )
    AND v_status.authority_id IS NOT NULL
    AND v_status.sequence = (v_body->'qualification_status'->>'sequence')::bigint
    AND v_status.head_payload_digest = v_body->'qualification_status'->>'head_payload_digest'
    AND v_status.observed_at <= v_now
    AND v_status.observed_at >= v_now - v_maximum_observation_age
    AND v_status.expires_at > v_now
    AND NOT EXISTS (
      SELECT 1
      FROM jsonb_array_elements(v_body->'resource_reservations') AS values_(resource)
      LEFT JOIN public.ep_gate_external_leases l
        ON l.deployment_id = p_deployment_id
       AND l.resource_id = resource->>'resource_id'
      WHERE resource->>'kind' = 'external_lease'
        AND (
          l.resource_id IS NULL
          OR l.digest <> resource->>'digest'
          OR l.observed_at < v_now - v_maximum_observation_age
          OR l.observed_at > v_now
          OR l.expires_at <= v_now
        )
    )
    AND NOT EXISTS (
      SELECT 1
      FROM jsonb_array_elements(v_body->'resource_reservations') AS values_(resource)
      LEFT JOIN public.ep_gate_monotonic_counters c
        ON c.deployment_id = p_deployment_id
       AND c.resource_id = resource->>'resource_id'
      WHERE resource->>'kind' = 'monotonic_counter'
        AND (
          c.resource_id IS NULL
          OR c.tenant_id <> p_tenant_id
          OR c.current_value < (resource->>'next_value')::bigint
        )
    );
  IF NOT v_currentness_ok THEN
    DELETE FROM public.ep_gate_resource_fences
      WHERE deployment_id = p_deployment_id AND admission_id = p_admission_id AND state = 'RESERVED';
    PERFORM public.ep_gate_apply_transition(
      p_deployment_id,
      v_current,
      jsonb_build_object(
        'state', 'RELEASED',
        'execution_right', 'RELEASED',
        'refusal_reason', 'currentness_refused',
        'resources', public.ep_gate_expected_resources(v_snapshot, 'RELEASED')
      ),
      'RELEASED',
      v_now
    );
    RETURN public.ep_gate_refusal('currentness_refused');
  END IF;
  UPDATE public.ep_gate_resource_fences
    SET state = 'CONSUMED'
    WHERE deployment_id = p_deployment_id
      AND admission_id = p_admission_id
      AND state = 'RESERVED';
  IF NOT public.ep_gate_resources_exact(p_deployment_id, p_admission_id, v_snapshot, 'CONSUMED') THEN
    RAISE EXCEPTION 'resource consumption did not cover the exact snapshot';
  END IF;
  v_record := public.ep_gate_apply_transition(
    p_deployment_id,
    v_current,
    jsonb_build_object(
      'state', 'INVOKING',
      'execution_right', 'CONSUMED',
      'provider_attempt', 'INVOKING',
      'invocation_token_digest', p_invocation_token_digest,
      'invocation_started_at', public.ep_gate_iso(v_now),
      'resources', public.ep_gate_expected_resources(v_snapshot, 'CONSUMED')
    ),
    'INVOKING',
    v_now
  );
  RETURN jsonb_build_object('ok', true, 'snapshot', v_snapshot, 'record', v_record);
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_admission_recover_indeterminate(
  p_deployment_id text,
  p_tenant_id text,
  p_admission_id text,
  p_owner_digest text,
  p_reconciliation_token_digest text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_current jsonb;
  v_snapshot jsonb;
  v_now timestamptz;
  v_record jsonb;
BEGIN
  PERFORM public.ep_gate_assert_binding(p_deployment_id, p_tenant_id);
  IF p_reconciliation_token_digest !~ '^sha256:[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid reconciliation token digest';
  END IF;
  v_current := public.ep_gate_load_admission_locked(p_deployment_id, p_tenant_id, p_admission_id);
  IF v_current IS NULL THEN RETURN public.ep_gate_refusal('admission_not_found'); END IF;
  IF v_current->>'owner_digest' <> p_owner_digest THEN RETURN public.ep_gate_refusal('owner_conflict'); END IF;
  IF v_current->>'state' <> 'INVOKING' THEN RETURN public.ep_gate_refusal('state_conflict'); END IF;
  SELECT snapshot_json INTO STRICT v_snapshot FROM public.ep_gate_admission_snapshots
    WHERE deployment_id = p_deployment_id AND snapshot_digest = v_current->>'snapshot_digest';
  PERFORM 1 FROM public.ep_gate_resource_fences
    WHERE deployment_id = p_deployment_id AND admission_id = p_admission_id
    ORDER BY kind, resource_id FOR UPDATE;
  IF v_current->'resources' <> public.ep_gate_expected_resources(v_snapshot, 'CONSUMED')
     OR NOT public.ep_gate_resources_exact(p_deployment_id, p_admission_id, v_snapshot, 'CONSUMED') THEN
    RAISE EXCEPTION 'consumed resource head mismatch during recovery';
  END IF;
  v_now := clock_timestamp();
  v_record := public.ep_gate_apply_transition(
    p_deployment_id,
    v_current,
    jsonb_build_object(
      'state', 'INDETERMINATE',
      'provider_attempt', 'INDETERMINATE',
      'invocation_token_digest', p_reconciliation_token_digest,
      'provider_outcome', jsonb_build_object(
        'value', 'INDETERMINATE',
        'evidence_digest', NULL,
        'observed_at', public.ep_gate_iso(v_now)
      ),
      'refusal_reason', 'ambiguous_provider_entry'
    ),
    'RECOVERED_INDETERMINATE',
    v_now
  );
  RETURN jsonb_build_object('ok', true, 'record', v_record);
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_admission_record_provider_outcome(
  p_deployment_id text,
  p_tenant_id text,
  p_admission_id text,
  p_expected_revision bigint,
  p_owner_digest text,
  p_invocation_token_digest text,
  p_value text,
  p_evidence_digest text,
  p_observed_at text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_current jsonb;
  v_snapshot jsonb;
  v_existing jsonb;
  v_now timestamptz;
  v_record jsonb;
BEGIN
  PERFORM public.ep_gate_assert_binding(p_deployment_id, p_tenant_id);
  v_current := public.ep_gate_load_admission_locked(p_deployment_id, p_tenant_id, p_admission_id);
  IF v_current IS NULL THEN RETURN public.ep_gate_refusal('admission_not_found'); END IF;
  IF (v_current->>'revision')::bigint <> p_expected_revision THEN RETURN public.ep_gate_refusal('revision_conflict'); END IF;
  IF v_current->>'owner_digest' <> p_owner_digest THEN RETURN public.ep_gate_refusal('owner_conflict'); END IF;
  IF v_current->>'execution_right' <> 'CONSUMED'
     OR v_current->>'invocation_token_digest' <> p_invocation_token_digest THEN
    RETURN public.ep_gate_refusal('invocation_token_conflict');
  END IF;
  IF v_current->>'state' NOT IN ('INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED') THEN
    RETURN public.ep_gate_refusal('state_conflict');
  END IF;
  IF p_value NOT IN ('COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE') THEN
    RAISE EXCEPTION 'invalid provider outcome';
  END IF;
  IF p_evidence_digest IS NOT NULL AND p_evidence_digest !~ '^sha256:[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid provider evidence digest';
  END IF;
  IF p_value <> 'INDETERMINATE' AND p_evidence_digest IS NULL THEN
    RETURN public.ep_gate_refusal('evidence_required');
  END IF;
  PERFORM p_observed_at::timestamptz;
  v_existing := v_current->'provider_outcome';
  IF v_existing <> 'null'::jsonb
     AND v_existing->>'value' <> 'INDETERMINATE'
     AND (v_existing->>'value' <> p_value
          OR v_existing->>'evidence_digest' IS DISTINCT FROM p_evidence_digest) THEN
    RETURN public.ep_gate_refusal('outcome_conflict');
  END IF;
  SELECT snapshot_json INTO STRICT v_snapshot FROM public.ep_gate_admission_snapshots
    WHERE deployment_id = p_deployment_id AND snapshot_digest = v_current->>'snapshot_digest';
  IF v_current->'resources' <> public.ep_gate_expected_resources(v_snapshot, 'CONSUMED')
     OR NOT public.ep_gate_resources_exact(p_deployment_id, p_admission_id, v_snapshot, 'CONSUMED') THEN
    RAISE EXCEPTION 'consumed resource head mismatch during provider outcome';
  END IF;
  v_now := clock_timestamp();
  v_record := public.ep_gate_apply_transition(
    p_deployment_id,
    v_current,
    jsonb_build_object(
      'state', p_value,
      'provider_attempt', p_value,
      'provider_outcome', jsonb_build_object(
        'value', p_value,
        'evidence_digest', p_evidence_digest,
        'observed_at', p_observed_at
      )
    ),
    'PROVIDER_OUTCOME',
    v_now
  );
  RETURN jsonb_build_object('ok', true, 'record', v_record);
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_admission_record_effect_relation(
  p_deployment_id text,
  p_tenant_id text,
  p_admission_id text,
  p_expected_revision bigint,
  p_owner_digest text,
  p_invocation_token_digest text,
  p_value text,
  p_evidence_digest text,
  p_observed_at text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_current jsonb;
  v_snapshot jsonb;
  v_existing jsonb;
  v_now timestamptz;
  v_record jsonb;
BEGIN
  PERFORM public.ep_gate_assert_binding(p_deployment_id, p_tenant_id);
  v_current := public.ep_gate_load_admission_locked(p_deployment_id, p_tenant_id, p_admission_id);
  IF v_current IS NULL THEN RETURN public.ep_gate_refusal('admission_not_found'); END IF;
  IF (v_current->>'revision')::bigint <> p_expected_revision THEN RETURN public.ep_gate_refusal('revision_conflict'); END IF;
  IF v_current->>'owner_digest' <> p_owner_digest THEN RETURN public.ep_gate_refusal('owner_conflict'); END IF;
  IF v_current->>'execution_right' <> 'CONSUMED'
     OR v_current->>'invocation_token_digest' <> p_invocation_token_digest THEN
    RETURN public.ep_gate_refusal('invocation_token_conflict');
  END IF;
  IF p_value NOT IN ('OBSERVED_AS_REQUESTED', 'DIVERGED', 'INDETERMINATE') THEN
    RAISE EXCEPTION 'invalid effect relation';
  END IF;
  IF p_evidence_digest IS NOT NULL AND p_evidence_digest !~ '^sha256:[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid effect evidence digest';
  END IF;
  IF p_value <> 'INDETERMINATE' AND p_evidence_digest IS NULL THEN
    RETURN public.ep_gate_refusal('evidence_required');
  END IF;
  PERFORM p_observed_at::timestamptz;
  v_existing := v_current->'effect_relation';
  IF v_existing <> 'null'::jsonb
     AND v_existing->>'value' <> 'INDETERMINATE'
     AND (v_existing->>'value' <> p_value
          OR v_existing->>'evidence_digest' IS DISTINCT FROM p_evidence_digest) THEN
    RETURN public.ep_gate_refusal('outcome_conflict');
  END IF;
  SELECT snapshot_json INTO STRICT v_snapshot FROM public.ep_gate_admission_snapshots
    WHERE deployment_id = p_deployment_id AND snapshot_digest = v_current->>'snapshot_digest';
  IF v_current->'resources' <> public.ep_gate_expected_resources(v_snapshot, 'CONSUMED')
     OR NOT public.ep_gate_resources_exact(p_deployment_id, p_admission_id, v_snapshot, 'CONSUMED') THEN
    RAISE EXCEPTION 'consumed resource head mismatch during effect relation';
  END IF;
  v_now := clock_timestamp();
  v_record := public.ep_gate_apply_transition(
    p_deployment_id,
    v_current,
    jsonb_build_object(
      'effect_relation', jsonb_build_object(
        'value', p_value,
        'evidence_digest', p_evidence_digest,
        'observed_at', p_observed_at
      )
    ),
    'EFFECT_RELATION',
    v_now
  );
  RETURN jsonb_build_object('ok', true, 'record', v_record);
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_admission_read(
  p_deployment_id text,
  p_tenant_id text,
  p_admission_id text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE v_record jsonb;
BEGIN
  PERFORM public.ep_gate_assert_binding(p_deployment_id, p_tenant_id);
  SELECT record_json INTO v_record FROM public.ep_gate_admission_records
    WHERE deployment_id = p_deployment_id AND tenant_id = p_tenant_id AND admission_id = p_admission_id;
  IF v_record IS NOT NULL THEN PERFORM public.ep_gate_assert_record(v_record); END IF;
  RETURN v_record;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_admission_read_by_operation(
  p_deployment_id text,
  p_tenant_id text,
  p_operation_id text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE v_record jsonb;
BEGIN
  PERFORM public.ep_gate_assert_binding(p_deployment_id, p_tenant_id);
  SELECT r.record_json INTO v_record
    FROM public.ep_gate_operation_heads h
    JOIN public.ep_gate_admission_records r
      ON r.deployment_id = h.deployment_id AND r.admission_id = h.admission_id
    WHERE h.deployment_id = p_deployment_id
      AND h.tenant_id = p_tenant_id
      AND h.operation_id = p_operation_id;
  IF v_record IS NOT NULL THEN PERFORM public.ep_gate_assert_record(v_record); END IF;
  RETURN v_record;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_admission_read_snapshot(
  p_deployment_id text,
  p_tenant_id text,
  p_snapshot_digest text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE v_snapshot jsonb;
BEGIN
  PERFORM public.ep_gate_assert_binding(p_deployment_id, p_tenant_id);
  SELECT snapshot_json INTO v_snapshot FROM public.ep_gate_admission_snapshots
    WHERE deployment_id = p_deployment_id
      AND tenant_id = p_tenant_id
      AND snapshot_digest = p_snapshot_digest;
  IF v_snapshot IS NOT NULL THEN
    PERFORM public.ep_gate_assert_snapshot(p_deployment_id, p_tenant_id, v_snapshot);
  END IF;
  RETURN v_snapshot;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_admission_journal(
  p_deployment_id text,
  p_tenant_id text,
  p_admission_id text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE v_entries jsonb;
BEGIN
  PERFORM public.ep_gate_assert_binding(p_deployment_id, p_tenant_id);
  SELECT COALESCE(jsonb_agg(entry_json ORDER BY sequence), '[]'::jsonb) INTO v_entries
    FROM public.ep_gate_admission_journal
    WHERE deployment_id = p_deployment_id
      AND tenant_id = p_tenant_id
      AND admission_id = p_admission_id;
  RETURN v_entries;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_gate_admission_check_invariants(
  p_deployment_id text,
  p_tenant_id text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE v_violations jsonb;
BEGIN
  PERFORM public.ep_gate_assert_binding(p_deployment_id, p_tenant_id);
  WITH violations AS (
    SELECT r.admission_id || ':snapshot_or_record_invalid' AS violation
    FROM public.ep_gate_admission_records r
    LEFT JOIN public.ep_gate_admission_snapshots s
      ON s.deployment_id = r.deployment_id AND s.snapshot_digest = r.snapshot_digest
    WHERE r.deployment_id = p_deployment_id
      AND (
        s.snapshot_digest IS NULL
        OR r.record_json->>'record_digest' <> public.ep_gate_hash(
          'EP-GATE-ADMISSION-RECORD-v2:DIGEST', r.record_json - 'record_digest'
        )
        OR s.snapshot_json->>'snapshot_digest' <> public.ep_gate_hash(
          'EP-GATE-ADMISSION-SNAPSHOT-v2:DIGEST', s.snapshot_json->'body'
        )
      )
    UNION ALL
    SELECT r.admission_id || ':journal_head_invalid'
    FROM public.ep_gate_admission_records r
    LEFT JOIN public.ep_gate_admission_journal j
      ON j.deployment_id = r.deployment_id
     AND j.admission_id = r.admission_id
     AND j.sequence = r.revision
    WHERE r.deployment_id = p_deployment_id
      AND (j.record_digest IS DISTINCT FROM r.record_json->>'record_digest'
           OR (SELECT count(*) FROM public.ep_gate_admission_journal j2
               WHERE j2.deployment_id = r.deployment_id AND j2.admission_id = r.admission_id) <> r.revision + 1)
    UNION ALL
    SELECT r.admission_id || ':reserved_resource_invalid'
    FROM public.ep_gate_admission_records r
    JOIN public.ep_gate_admission_snapshots s
      ON s.deployment_id = r.deployment_id AND s.snapshot_digest = r.snapshot_digest
    WHERE r.deployment_id = p_deployment_id
      AND r.record_json->>'state' = 'RESERVED'
      AND (r.record_json->>'execution_right' <> 'RESERVED'
           OR r.record_json->'resources' <> public.ep_gate_expected_resources(s.snapshot_json, 'RESERVED')
           OR NOT public.ep_gate_resources_exact(r.deployment_id, r.admission_id, s.snapshot_json, 'RESERVED'))
    UNION ALL
    SELECT r.admission_id || ':consumed_resource_invalid'
    FROM public.ep_gate_admission_records r
    JOIN public.ep_gate_admission_snapshots s
      ON s.deployment_id = r.deployment_id AND s.snapshot_digest = r.snapshot_digest
    WHERE r.deployment_id = p_deployment_id
      AND r.record_json->>'execution_right' = 'CONSUMED'
      AND (r.record_json->'resources' <> public.ep_gate_expected_resources(s.snapshot_json, 'CONSUMED')
           OR NOT public.ep_gate_resources_exact(r.deployment_id, r.admission_id, s.snapshot_json, 'CONSUMED'))
    UNION ALL
    SELECT r.admission_id || ':monotonic_counter_head_invalid'
    FROM public.ep_gate_admission_records r
    JOIN public.ep_gate_admission_snapshots s
      ON s.deployment_id = r.deployment_id AND s.snapshot_digest = r.snapshot_digest
    WHERE r.deployment_id = p_deployment_id
      AND EXISTS (
        SELECT 1
        FROM jsonb_array_elements(s.snapshot_json->'body'->'resource_reservations') AS values_(resource)
        LEFT JOIN public.ep_gate_monotonic_counters c
          ON c.deployment_id = r.deployment_id
         AND c.resource_id = resource->>'resource_id'
        WHERE resource->>'kind' = 'monotonic_counter'
          AND (c.resource_id IS NULL
               OR c.tenant_id <> p_tenant_id
               OR c.current_value < (resource->>'next_value')::bigint)
      )
    UNION ALL
    SELECT h.operation_id || ':operation_head_invalid'
    FROM public.ep_gate_operation_heads h
    LEFT JOIN public.ep_gate_admission_records r
      ON r.deployment_id = h.deployment_id AND r.admission_id = h.admission_id
    WHERE h.deployment_id = p_deployment_id
      AND (r.admission_id IS NULL OR r.operation_id <> h.operation_id OR r.tenant_id <> p_tenant_id)
  )
  SELECT COALESCE(jsonb_agg(violation ORDER BY violation), '[]'::jsonb) INTO v_violations FROM violations;
  RETURN jsonb_build_object('ok', jsonb_array_length(v_violations) = 0, 'violations', v_violations);
END;
$$;

-- Helpers and RPCs default to no PUBLIC execution.  A deployment owner grants
-- only the ep_gate_admission_* RPCs to its dedicated runtime role.
REVOKE ALL ON FUNCTION public.ep_gate_refuse_history_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_guard_operation_head() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_guard_deployment_binding() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_guard_resource_consumption() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_guard_consumed_record() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_iso(timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_canonical_json(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_hash(text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_jsonb_has_exact_keys(jsonb, text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_jsonb_is_identifier(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_jsonb_is_digest(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_jsonb_is_safe_nonnegative_integer(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_jsonb_is_digest_array(jsonb, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_refusal(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_assert_binding(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_assert_snapshot(text, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_expected_resources(jsonb, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_finalize_record(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_assert_record(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_make_journal_entry(jsonb, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_insert_record_and_journal(text, jsonb, text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_apply_transition(text, jsonb, jsonb, text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_load_admission_locked(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_resources_exact(text, text, jsonb, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_advance_monotonic_counters(text, text, jsonb, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_provision_monotonic_counter(text, text, text, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_initial_record(jsonb, text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_admission_reserve(text, text, jsonb, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_admission_release(text, text, text, bigint, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_admission_expire(text, text, text, bigint, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_admission_supersede(text, text, text, bigint, text, jsonb, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_admission_begin_invocation(text, text, text, bigint, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_admission_recover_indeterminate(text, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_admission_record_provider_outcome(text, text, text, bigint, text, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_admission_record_effect_relation(text, text, text, bigint, text, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_admission_read(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_admission_read_by_operation(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_admission_read_snapshot(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_admission_journal(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_gate_admission_check_invariants(text, text) FROM PUBLIC;

COMMIT;
