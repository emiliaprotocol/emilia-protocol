-- SPDX-License-Identifier: Apache-2.0
-- Durable heterogeneous Remedy Program case-set custody.
-- Shape is emitted by REMEDY_CASE_SET_POSTGRES_DDL; Supabase role ACLs are
-- tightened below in addition to FORCE RLS and tenant policies.

CREATE TABLE IF NOT EXISTS ep_remedy_case_sets (
  tenant_id          TEXT NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),
  case_set_id        TEXT NOT NULL CHECK (octet_length(case_set_id) BETWEEN 1 AND 256),
  revision           BIGINT NOT NULL CHECK (revision >= 0),
  status             TEXT NOT NULL CHECK (status IN ('open', 'indeterminate', 'completed')),
  owner_token_digest TEXT NOT NULL CHECK (owner_token_digest ~ '^sha256:[0-9a-f]{64}$'),
  manifest_json      TEXT NOT NULL,
  manifest_digest    TEXT NOT NULL CHECK (manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
  state_json         TEXT NOT NULL,
  state_digest       TEXT NOT NULL CHECK (state_digest ~ '^sha256:[0-9a-f]{64}$'),
  recorded_at        TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (tenant_id, case_set_id),
  CHECK (octet_length(manifest_json) <= 1048576),
  CHECK (octet_length(state_json) <= 4194304)
);
CREATE TABLE IF NOT EXISTS ep_remedy_case_set_events (
  tenant_id        TEXT NOT NULL,
  case_set_id      TEXT NOT NULL,
  revision         BIGINT NOT NULL CHECK (revision >= 0),
  previous_revision BIGINT NULL CHECK (previous_revision IS NULL OR previous_revision >= 0),
  status           TEXT NOT NULL CHECK (status IN ('open', 'indeterminate', 'completed')),
  state_json       TEXT NOT NULL,
  state_digest     TEXT NOT NULL CHECK (state_digest ~ '^sha256:[0-9a-f]{64}$'),
  recorded_at      TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (tenant_id, case_set_id, revision),
  FOREIGN KEY (tenant_id, case_set_id)
    REFERENCES ep_remedy_case_sets (tenant_id, case_set_id) ON DELETE RESTRICT,
  CHECK (
    (revision = 0 AND previous_revision IS NULL)
    OR (revision > 0 AND previous_revision = revision - 1)
  ),
  CHECK (octet_length(state_json) <= 4194304)
);
CREATE OR REPLACE FUNCTION ep_remedy_case_sets_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'remedy case sets cannot be deleted' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
     OR OLD.case_set_id IS DISTINCT FROM NEW.case_set_id
     OR OLD.owner_token_digest IS DISTINCT FROM NEW.owner_token_digest
     OR OLD.manifest_json IS DISTINCT FROM NEW.manifest_json
     OR OLD.manifest_digest IS DISTINCT FROM NEW.manifest_digest THEN
    RAISE EXCEPTION 'remedy case-set identity, owner, and manifest are immutable'
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status = 'completed' THEN
    RAISE EXCEPTION 'completed remedy case sets are immutable'
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.revision <> OLD.revision + 1 THEN
    RAISE EXCEPTION 'remedy case-set revision must advance by one'
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status = 'open' THEN
    RAISE EXCEPTION 'remedy case sets cannot reopen'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS ep_remedy_case_sets_guard_trigger ON ep_remedy_case_sets;
CREATE TRIGGER ep_remedy_case_sets_guard_trigger
BEFORE UPDATE OR DELETE ON ep_remedy_case_sets
FOR EACH ROW EXECUTE FUNCTION ep_remedy_case_sets_guard();
CREATE OR REPLACE FUNCTION ep_remedy_case_set_events_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'remedy case-set events are immutable'
    USING ERRCODE = 'check_violation';
END;
$$;
DROP TRIGGER IF EXISTS ep_remedy_case_set_events_immutable_trigger
  ON ep_remedy_case_set_events;
CREATE TRIGGER ep_remedy_case_set_events_immutable_trigger
BEFORE UPDATE OR DELETE ON ep_remedy_case_set_events
FOR EACH ROW EXECUTE FUNCTION ep_remedy_case_set_events_immutable();
ALTER TABLE ep_remedy_case_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE ep_remedy_case_set_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ep_remedy_case_sets FORCE ROW LEVEL SECURITY;
ALTER TABLE ep_remedy_case_set_events FORCE ROW LEVEL SECURITY;

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ep_remedy_executor') THEN
    CREATE ROLE ep_remedy_executor NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ep_remedy_store_owner') THEN
    CREATE ROLE ep_remedy_store_owner NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

GRANT ep_remedy_store_owner TO CURRENT_USER;
GRANT USAGE, CREATE ON SCHEMA public TO ep_remedy_store_owner;

CREATE SCHEMA IF NOT EXISTS ep_remedy_private;
REVOKE ALL ON SCHEMA ep_remedy_private FROM PUBLIC, anon, authenticated, service_role;
CREATE TABLE IF NOT EXISTS ep_remedy_private.tenant_principals (
  principal_name NAME NOT NULL,
  tenant_id TEXT NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),
  PRIMARY KEY (principal_name, tenant_id)
);
ALTER SCHEMA ep_remedy_private OWNER TO ep_remedy_store_owner;
ALTER TABLE ep_remedy_private.tenant_principals OWNER TO ep_remedy_store_owner;
ALTER TABLE public.ep_remedy_case_sets OWNER TO ep_remedy_store_owner;
ALTER TABLE public.ep_remedy_case_set_events OWNER TO ep_remedy_store_owner;
ALTER FUNCTION public.ep_remedy_case_sets_guard() OWNER TO ep_remedy_store_owner;
ALTER FUNCTION public.ep_remedy_case_set_events_immutable() OWNER TO ep_remedy_store_owner;
ALTER TABLE ep_remedy_private.tenant_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE ep_remedy_private.tenant_principals FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ep_remedy_principals_owner_only ON ep_remedy_private.tenant_principals;
CREATE POLICY ep_remedy_principals_owner_only ON ep_remedy_private.tenant_principals
  TO ep_remedy_store_owner USING (TRUE) WITH CHECK (TRUE);
DROP POLICY IF EXISTS ep_remedy_case_sets_tenant_policy ON ep_remedy_case_sets;
DROP POLICY IF EXISTS ep_remedy_case_sets_owner_only ON ep_remedy_case_sets;
CREATE POLICY ep_remedy_case_sets_owner_only ON ep_remedy_case_sets
  TO ep_remedy_store_owner USING (TRUE) WITH CHECK (TRUE);
DROP POLICY IF EXISTS ep_remedy_case_set_events_tenant_policy ON ep_remedy_case_set_events;
DROP POLICY IF EXISTS ep_remedy_case_set_events_owner_only ON ep_remedy_case_set_events;
CREATE POLICY ep_remedy_case_set_events_owner_only ON ep_remedy_case_set_events
  TO ep_remedy_store_owner USING (TRUE) WITH CHECK (TRUE);

REVOKE ALL ON ep_remedy_private.tenant_principals
  FROM PUBLIC, anon, authenticated, service_role, ep_remedy_executor;
REVOKE ALL ON ep_remedy_case_sets
  FROM PUBLIC, anon, authenticated, service_role, ep_remedy_executor;
REVOKE ALL ON ep_remedy_case_set_events
  FROM PUBLIC, anon, authenticated, service_role, ep_remedy_executor;
REVOKE EXECUTE ON FUNCTION ep_remedy_case_sets_guard()
  FROM anon, authenticated, PUBLIC, service_role, ep_remedy_executor;
REVOKE EXECUTE ON FUNCTION ep_remedy_case_set_events_immutable()
  FROM anon, authenticated, PUBLIC, service_role, ep_remedy_executor;

CREATE OR REPLACE FUNCTION ep_remedy_private.assert_tenant_principal(p_tenant_id TEXT)
RETURNS TEXT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = ''
AS $fn$
DECLARE v_role_ok BOOLEAN; v_binding_ok BOOLEAN;
BEGIN
  v_role_ok := pg_catalog.pg_has_role(SESSION_USER, 'ep_remedy_executor', 'MEMBER');
  SELECT EXISTS (
    SELECT 1 FROM ep_remedy_private.tenant_principals AS principals
    WHERE principals.principal_name = SESSION_USER
      AND principals.tenant_id = p_tenant_id
  ) INTO v_binding_ok;
  IF v_role_ok IS NOT TRUE OR v_binding_ok IS NOT TRUE THEN
    RAISE EXCEPTION 'REMEDY_TENANT_PRINCIPAL_REFUSED' USING ERRCODE = '42501';
  END IF;
  RETURN p_tenant_id;
END
$fn$;

CREATE OR REPLACE FUNCTION ep_remedy_private.create_case_set(
  p_tenant_id TEXT, p_case_set_id TEXT, p_status TEXT, p_owner_token_digest TEXT,
  p_manifest_json TEXT, p_manifest_digest TEXT, p_state_json TEXT,
  p_state_digest TEXT, p_recorded_at TIMESTAMPTZ
)
RETURNS TABLE(
  tenant_id TEXT, case_set_id TEXT, revision BIGINT, status TEXT,
  owner_token_digest TEXT, manifest_json TEXT, manifest_digest TEXT,
  state_json TEXT, state_digest TEXT, recorded_at TEXT
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_remedy_private.assert_tenant_principal(p_tenant_id);
  RETURN QUERY WITH inserted AS (
    INSERT INTO public.ep_remedy_case_sets (
      tenant_id, case_set_id, revision, status, owner_token_digest,
      manifest_json, manifest_digest, state_json, state_digest, recorded_at
    ) VALUES (
      p_tenant_id, p_case_set_id, 0, p_status, p_owner_token_digest,
      p_manifest_json, p_manifest_digest, p_state_json, p_state_digest, p_recorded_at
    ) ON CONFLICT ON CONSTRAINT ep_remedy_case_sets_pkey DO NOTHING RETURNING *
  ) SELECT inserted.tenant_id, inserted.case_set_id, inserted.revision, inserted.status,
      inserted.owner_token_digest, inserted.manifest_json, inserted.manifest_digest,
      inserted.state_json, inserted.state_digest,
      pg_catalog.to_char(inserted.recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
    FROM inserted;
END
$fn$;

CREATE OR REPLACE FUNCTION ep_remedy_private.get_case_set(
  p_tenant_id TEXT, p_case_set_id TEXT
)
RETURNS TABLE(
  tenant_id TEXT, case_set_id TEXT, revision BIGINT, status TEXT,
  owner_token_digest TEXT, manifest_json TEXT, manifest_digest TEXT,
  state_json TEXT, state_digest TEXT, recorded_at TEXT
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_remedy_private.assert_tenant_principal(p_tenant_id);
  RETURN QUERY SELECT current.tenant_id, current.case_set_id, current.revision, current.status,
      current.owner_token_digest, current.manifest_json, current.manifest_digest,
      current.state_json, current.state_digest,
      pg_catalog.to_char(current.recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
    FROM public.ep_remedy_case_sets AS current
    WHERE current.tenant_id = p_tenant_id AND current.case_set_id = p_case_set_id;
END
$fn$;

CREATE OR REPLACE FUNCTION ep_remedy_private.get_case_set_for_update(
  p_tenant_id TEXT, p_case_set_id TEXT
)
RETURNS TABLE(
  tenant_id TEXT, case_set_id TEXT, revision BIGINT, status TEXT,
  owner_token_digest TEXT, manifest_json TEXT, manifest_digest TEXT,
  state_json TEXT, state_digest TEXT, recorded_at TEXT
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_remedy_private.assert_tenant_principal(p_tenant_id);
  RETURN QUERY SELECT current.tenant_id, current.case_set_id, current.revision, current.status,
      current.owner_token_digest, current.manifest_json, current.manifest_digest,
      current.state_json, current.state_digest,
      pg_catalog.to_char(current.recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
    FROM public.ep_remedy_case_sets AS current
    WHERE current.tenant_id = p_tenant_id AND current.case_set_id = p_case_set_id
    FOR UPDATE;
END
$fn$;

CREATE OR REPLACE FUNCTION ep_remedy_private.compare_and_swap_case_set(
  p_tenant_id TEXT, p_case_set_id TEXT, p_expected_revision BIGINT,
  p_owner_token_digest TEXT, p_next_revision BIGINT, p_status TEXT,
  p_state_json TEXT, p_state_digest TEXT, p_recorded_at TIMESTAMPTZ,
  p_manifest_json TEXT, p_manifest_digest TEXT
)
RETURNS TABLE(
  tenant_id TEXT, case_set_id TEXT, revision BIGINT, status TEXT,
  owner_token_digest TEXT, manifest_json TEXT, manifest_digest TEXT,
  state_json TEXT, state_digest TEXT, recorded_at TEXT
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_remedy_private.assert_tenant_principal(p_tenant_id);
  RETURN QUERY WITH updated AS (
    UPDATE public.ep_remedy_case_sets
    SET revision = p_next_revision, status = p_status, state_json = p_state_json,
        state_digest = p_state_digest, recorded_at = p_recorded_at
    WHERE ep_remedy_case_sets.tenant_id = p_tenant_id
      AND ep_remedy_case_sets.case_set_id = p_case_set_id
      AND ep_remedy_case_sets.revision = p_expected_revision
      AND ep_remedy_case_sets.owner_token_digest = p_owner_token_digest
      AND ep_remedy_case_sets.status <> 'completed'
      AND ep_remedy_case_sets.manifest_json = p_manifest_json
      AND ep_remedy_case_sets.manifest_digest = p_manifest_digest
    RETURNING *
  ) SELECT updated.tenant_id, updated.case_set_id, updated.revision, updated.status,
      updated.owner_token_digest, updated.manifest_json, updated.manifest_digest,
      updated.state_json, updated.state_digest,
      pg_catalog.to_char(updated.recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
    FROM updated;
END
$fn$;

CREATE OR REPLACE FUNCTION ep_remedy_private.append_case_set_event(
  p_tenant_id TEXT, p_case_set_id TEXT, p_revision BIGINT,
  p_previous_revision BIGINT, p_status TEXT, p_state_json TEXT,
  p_state_digest TEXT, p_recorded_at TIMESTAMPTZ
)
RETURNS TABLE(
  tenant_id TEXT, case_set_id TEXT, revision BIGINT,
  state_digest TEXT, recorded_at TEXT
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_remedy_private.assert_tenant_principal(p_tenant_id);
  RETURN QUERY WITH inserted AS (
    INSERT INTO public.ep_remedy_case_set_events (
      tenant_id, case_set_id, revision, previous_revision, status,
      state_json, state_digest, recorded_at
    ) VALUES (
      p_tenant_id, p_case_set_id, p_revision, p_previous_revision, p_status,
      p_state_json, p_state_digest, p_recorded_at
    ) RETURNING *
  ) SELECT inserted.tenant_id, inserted.case_set_id, inserted.revision,
      inserted.state_digest,
      pg_catalog.to_char(inserted.recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
    FROM inserted;
END
$fn$;

ALTER FUNCTION ep_remedy_private.assert_tenant_principal(TEXT)
  OWNER TO ep_remedy_store_owner;
ALTER FUNCTION ep_remedy_private.create_case_set(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  OWNER TO ep_remedy_store_owner;
ALTER FUNCTION ep_remedy_private.get_case_set(TEXT, TEXT)
  OWNER TO ep_remedy_store_owner;
ALTER FUNCTION ep_remedy_private.get_case_set_for_update(TEXT, TEXT)
  OWNER TO ep_remedy_store_owner;
ALTER FUNCTION ep_remedy_private.compare_and_swap_case_set(TEXT, TEXT, BIGINT, TEXT, BIGINT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT, TEXT)
  OWNER TO ep_remedy_store_owner;
ALTER FUNCTION ep_remedy_private.append_case_set_event(TEXT, TEXT, BIGINT, BIGINT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  OWNER TO ep_remedy_store_owner;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ep_remedy_private
  FROM PUBLIC, anon, authenticated, service_role;
GRANT USAGE ON SCHEMA ep_remedy_private TO ep_remedy_executor;
GRANT EXECUTE ON FUNCTION ep_remedy_private.assert_tenant_principal(TEXT),
  ep_remedy_private.create_case_set(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ),
  ep_remedy_private.get_case_set(TEXT, TEXT),
  ep_remedy_private.get_case_set_for_update(TEXT, TEXT),
  ep_remedy_private.compare_and_swap_case_set(TEXT, TEXT, BIGINT, TEXT, BIGINT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT, TEXT),
  ep_remedy_private.append_case_set_event(TEXT, TEXT, BIGINT, BIGINT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  TO ep_remedy_executor;

COMMENT ON TABLE ep_remedy_case_sets IS
  'Current state for tenant-scoped heterogeneous remedy case sets; immutable manifest and owner, revision-fenced CAS.';
COMMENT ON TABLE ep_remedy_case_set_events IS
  'Append-only state history for heterogeneous remedy case sets.';

REVOKE CREATE ON SCHEMA public FROM ep_remedy_store_owner;
REVOKE ep_remedy_store_owner FROM CURRENT_USER;
