// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Tenant-scoped PostgreSQL custody for Remedy Program case sets.
 *
 * The current row and its append-only state events are changed in one pinned
 * transaction. PostgreSQL supplies the transaction clock, while owner-digest
 * and revision fences are checked under a row lock and repeated in the UPDATE.
 * Malformed or ambiguous database outcomes throw so callers fail closed.
 */
import { createHash } from 'node:crypto';
import { canonicalize } from '../execution-binding.js';
export const REMEDY_CASE_SET_PG_STORE_VERSION = 'EP-GATE-REMEDY-CASE-SET-PG-STORE-v1';
export const REMEDY_CASE_SET_TABLE = 'ep_remedy_case_sets';
export const REMEDY_CASE_SET_EVENT_TABLE = 'ep_remedy_case_set_events';
export const REMEDY_CASE_SET_EXECUTOR_ROLE = 'ep_remedy_executor';
export const REMEDY_CASE_SET_OWNER_ROLE = 'ep_remedy_store_owner';
export const REMEDY_CASE_SET_MAX_STATE_BYTES = 4 * 1024 * 1024;
export const REMEDY_CASE_SET_MAX_MANIFEST_BYTES = 1024 * 1024;
export const REMEDY_CASE_SET_MAX_FORWARD_SKEW_MINUTES = 5;
const CASE_SET_VERSION = 'EP-GATE-REMEDY-CASE-SET-v1';
const CASE_SET_ID = /^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,255}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const STRICT_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const STATE_KEYS = new Set([
    'version', 'tenant_id', 'case_set_id', 'status', 'revision', 'created_at',
    'updated_at', 'owner_token_digest', 'manifest', 'manifest_digest',
    'observations', 'create_request_digest', 'last_request_digest',
]);
const MANIFEST_KEYS = new Set(['version', 'tenant_id', 'case_set_id', 'legs']);
const OBSERVATION_KEYS = new Set([
    'leg_id', 'status', 'case_revision', 'receipt_content_digest',
    'state_snapshot_digest',
]);
const CURRENT_ROW_KEYS = new Set([
    'tenant_id', 'case_set_id', 'revision', 'status', 'owner_token_digest',
    'manifest_json', 'manifest_digest', 'state_json', 'state_digest', 'recorded_at',
]);
const EVENT_ROW_KEYS = new Set([
    'tenant_id', 'case_set_id', 'revision', 'state_digest', 'recorded_at',
]);
const TENANT_ROW_KEYS = new Set(['tenant_id']);
const CLOCK_ROW_KEYS = new Set(['recorded_at']);
/** Exact schema consumed by createRemedyCaseSetPostgresStore(). */
export const REMEDY_CASE_SET_POSTGRES_DDL = `CREATE TABLE IF NOT EXISTS ${REMEDY_CASE_SET_TABLE} (
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
  CHECK (octet_length(manifest_json) <= ${REMEDY_CASE_SET_MAX_MANIFEST_BYTES}),
  CHECK (octet_length(state_json) <= ${REMEDY_CASE_SET_MAX_STATE_BYTES})
);
CREATE TABLE IF NOT EXISTS ${REMEDY_CASE_SET_EVENT_TABLE} (
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
    REFERENCES ${REMEDY_CASE_SET_TABLE} (tenant_id, case_set_id) ON DELETE RESTRICT,
  CHECK (
    (revision = 0 AND previous_revision IS NULL)
    OR (revision > 0 AND previous_revision = revision - 1)
  ),
  CHECK (octet_length(state_json) <= ${REMEDY_CASE_SET_MAX_STATE_BYTES})
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
DROP TRIGGER IF EXISTS ep_remedy_case_sets_guard_trigger ON ${REMEDY_CASE_SET_TABLE};
CREATE TRIGGER ep_remedy_case_sets_guard_trigger
BEFORE UPDATE OR DELETE ON ${REMEDY_CASE_SET_TABLE}
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
  ON ${REMEDY_CASE_SET_EVENT_TABLE};
CREATE TRIGGER ep_remedy_case_set_events_immutable_trigger
BEFORE UPDATE OR DELETE ON ${REMEDY_CASE_SET_EVENT_TABLE}
FOR EACH ROW EXECUTE FUNCTION ep_remedy_case_set_events_immutable();
ALTER TABLE ${REMEDY_CASE_SET_TABLE} ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${REMEDY_CASE_SET_EVENT_TABLE} ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${REMEDY_CASE_SET_TABLE} FORCE ROW LEVEL SECURITY;
ALTER TABLE ${REMEDY_CASE_SET_EVENT_TABLE} FORCE ROW LEVEL SECURITY;
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '${REMEDY_CASE_SET_EXECUTOR_ROLE}') THEN
    CREATE ROLE ${REMEDY_CASE_SET_EXECUTOR_ROLE} NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '${REMEDY_CASE_SET_OWNER_ROLE}') THEN
    CREATE ROLE ${REMEDY_CASE_SET_OWNER_ROLE} NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;
GRANT ${REMEDY_CASE_SET_OWNER_ROLE} TO CURRENT_USER;
CREATE SCHEMA IF NOT EXISTS ep_remedy_private;
REVOKE ALL ON SCHEMA ep_remedy_private FROM PUBLIC, anon, authenticated, service_role;
CREATE TABLE IF NOT EXISTS ep_remedy_private.tenant_principals (
  principal_name NAME NOT NULL,
  tenant_id TEXT NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 512),
  PRIMARY KEY (principal_name, tenant_id)
);
ALTER SCHEMA ep_remedy_private OWNER TO ${REMEDY_CASE_SET_OWNER_ROLE};
ALTER TABLE ep_remedy_private.tenant_principals OWNER TO ${REMEDY_CASE_SET_OWNER_ROLE};
ALTER TABLE ${REMEDY_CASE_SET_TABLE} OWNER TO ${REMEDY_CASE_SET_OWNER_ROLE};
ALTER TABLE ${REMEDY_CASE_SET_EVENT_TABLE} OWNER TO ${REMEDY_CASE_SET_OWNER_ROLE};
ALTER FUNCTION ep_remedy_case_sets_guard() OWNER TO ${REMEDY_CASE_SET_OWNER_ROLE};
ALTER FUNCTION ep_remedy_case_set_events_immutable() OWNER TO ${REMEDY_CASE_SET_OWNER_ROLE};
ALTER TABLE ep_remedy_private.tenant_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE ep_remedy_private.tenant_principals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ep_remedy_principals_owner_only ON ep_remedy_private.tenant_principals;
CREATE POLICY ep_remedy_principals_owner_only ON ep_remedy_private.tenant_principals
  TO ${REMEDY_CASE_SET_OWNER_ROLE} USING (TRUE) WITH CHECK (TRUE);
DROP POLICY IF EXISTS ep_remedy_case_sets_tenant_policy ON ${REMEDY_CASE_SET_TABLE};
DROP POLICY IF EXISTS ep_remedy_case_sets_owner_only ON ${REMEDY_CASE_SET_TABLE};
CREATE POLICY ep_remedy_case_sets_owner_only ON ${REMEDY_CASE_SET_TABLE}
  TO ${REMEDY_CASE_SET_OWNER_ROLE} USING (TRUE) WITH CHECK (TRUE);
DROP POLICY IF EXISTS ep_remedy_case_set_events_tenant_policy ON ${REMEDY_CASE_SET_EVENT_TABLE};
DROP POLICY IF EXISTS ep_remedy_case_set_events_owner_only ON ${REMEDY_CASE_SET_EVENT_TABLE};
CREATE POLICY ep_remedy_case_set_events_owner_only ON ${REMEDY_CASE_SET_EVENT_TABLE}
  TO ${REMEDY_CASE_SET_OWNER_ROLE} USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON ep_remedy_private.tenant_principals
  FROM PUBLIC, anon, authenticated, service_role, ${REMEDY_CASE_SET_EXECUTOR_ROLE};
REVOKE ALL ON ${REMEDY_CASE_SET_TABLE}
  FROM PUBLIC, anon, authenticated, service_role, ${REMEDY_CASE_SET_EXECUTOR_ROLE};
REVOKE ALL ON ${REMEDY_CASE_SET_EVENT_TABLE}
  FROM PUBLIC, anon, authenticated, service_role, ${REMEDY_CASE_SET_EXECUTOR_ROLE};
REVOKE EXECUTE ON FUNCTION ep_remedy_case_sets_guard()
  FROM PUBLIC, anon, authenticated, service_role, ${REMEDY_CASE_SET_EXECUTOR_ROLE};
REVOKE EXECUTE ON FUNCTION ep_remedy_case_set_events_immutable()
  FROM PUBLIC, anon, authenticated, service_role, ${REMEDY_CASE_SET_EXECUTOR_ROLE};
CREATE OR REPLACE FUNCTION ep_remedy_private.assert_tenant_principal(p_tenant_id TEXT)
RETURNS TEXT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = ''
AS $fn$
DECLARE v_role_ok BOOLEAN; v_binding_ok BOOLEAN;
BEGIN
  v_role_ok := pg_catalog.pg_has_role(SESSION_USER, '${REMEDY_CASE_SET_EXECUTOR_ROLE}', 'MEMBER');
  SELECT EXISTS (
    SELECT 1 FROM ep_remedy_private.tenant_principals AS principals
    WHERE principals.principal_name = SESSION_USER AND principals.tenant_id = p_tenant_id
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
) RETURNS TABLE(
  tenant_id TEXT, case_set_id TEXT, revision BIGINT, status TEXT,
  owner_token_digest TEXT, manifest_json TEXT, manifest_digest TEXT,
  state_json TEXT, state_digest TEXT, recorded_at TEXT
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_remedy_private.assert_tenant_principal(p_tenant_id);
  RETURN QUERY WITH inserted AS (
    INSERT INTO public.${REMEDY_CASE_SET_TABLE} (
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
) RETURNS TABLE(
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
    FROM public.${REMEDY_CASE_SET_TABLE} AS current
    WHERE current.tenant_id = p_tenant_id AND current.case_set_id = p_case_set_id;
END
$fn$;
CREATE OR REPLACE FUNCTION ep_remedy_private.get_case_set_for_update(
  p_tenant_id TEXT, p_case_set_id TEXT
) RETURNS TABLE(
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
    FROM public.${REMEDY_CASE_SET_TABLE} AS current
    WHERE current.tenant_id = p_tenant_id AND current.case_set_id = p_case_set_id
    FOR UPDATE;
END
$fn$;
CREATE OR REPLACE FUNCTION ep_remedy_private.compare_and_swap_case_set(
  p_tenant_id TEXT, p_case_set_id TEXT, p_expected_revision BIGINT,
  p_owner_token_digest TEXT, p_next_revision BIGINT, p_status TEXT,
  p_state_json TEXT, p_state_digest TEXT, p_recorded_at TIMESTAMPTZ,
  p_manifest_json TEXT, p_manifest_digest TEXT
) RETURNS TABLE(
  tenant_id TEXT, case_set_id TEXT, revision BIGINT, status TEXT,
  owner_token_digest TEXT, manifest_json TEXT, manifest_digest TEXT,
  state_json TEXT, state_digest TEXT, recorded_at TEXT
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_remedy_private.assert_tenant_principal(p_tenant_id);
  RETURN QUERY WITH updated AS (
    UPDATE public.${REMEDY_CASE_SET_TABLE}
    SET revision = p_next_revision, status = p_status, state_json = p_state_json,
        state_digest = p_state_digest, recorded_at = p_recorded_at
    WHERE ${REMEDY_CASE_SET_TABLE}.tenant_id = p_tenant_id
      AND ${REMEDY_CASE_SET_TABLE}.case_set_id = p_case_set_id
      AND ${REMEDY_CASE_SET_TABLE}.revision = p_expected_revision
      AND ${REMEDY_CASE_SET_TABLE}.owner_token_digest = p_owner_token_digest
      AND ${REMEDY_CASE_SET_TABLE}.status <> 'completed'
      AND ${REMEDY_CASE_SET_TABLE}.manifest_json = p_manifest_json
      AND ${REMEDY_CASE_SET_TABLE}.manifest_digest = p_manifest_digest
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
) RETURNS TABLE(
  tenant_id TEXT, case_set_id TEXT, revision BIGINT, state_digest TEXT, recorded_at TEXT
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $fn$
BEGIN
  PERFORM ep_remedy_private.assert_tenant_principal(p_tenant_id);
  RETURN QUERY WITH inserted AS (
    INSERT INTO public.${REMEDY_CASE_SET_EVENT_TABLE} (
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
  OWNER TO ${REMEDY_CASE_SET_OWNER_ROLE};
ALTER FUNCTION ep_remedy_private.create_case_set(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  OWNER TO ${REMEDY_CASE_SET_OWNER_ROLE};
ALTER FUNCTION ep_remedy_private.get_case_set(TEXT, TEXT)
  OWNER TO ${REMEDY_CASE_SET_OWNER_ROLE};
ALTER FUNCTION ep_remedy_private.get_case_set_for_update(TEXT, TEXT)
  OWNER TO ${REMEDY_CASE_SET_OWNER_ROLE};
ALTER FUNCTION ep_remedy_private.compare_and_swap_case_set(TEXT, TEXT, BIGINT, TEXT, BIGINT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT, TEXT)
  OWNER TO ${REMEDY_CASE_SET_OWNER_ROLE};
ALTER FUNCTION ep_remedy_private.append_case_set_event(TEXT, TEXT, BIGINT, BIGINT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  OWNER TO ${REMEDY_CASE_SET_OWNER_ROLE};
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ep_remedy_private
  FROM PUBLIC, anon, authenticated, service_role;
GRANT USAGE ON SCHEMA ep_remedy_private TO ${REMEDY_CASE_SET_EXECUTOR_ROLE};
GRANT EXECUTE ON FUNCTION ep_remedy_private.assert_tenant_principal(TEXT),
  ep_remedy_private.create_case_set(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ),
  ep_remedy_private.get_case_set(TEXT, TEXT),
  ep_remedy_private.get_case_set_for_update(TEXT, TEXT),
  ep_remedy_private.compare_and_swap_case_set(TEXT, TEXT, BIGINT, TEXT, BIGINT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT, TEXT),
  ep_remedy_private.append_case_set_event(TEXT, TEXT, BIGINT, BIGINT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  TO ${REMEDY_CASE_SET_EXECUTOR_ROLE};
REVOKE ${REMEDY_CASE_SET_OWNER_ROLE} FROM CURRENT_USER;`;
/** Exact statements issued by the store, exported for audit and deterministic fakes. */
export const REMEDY_CASE_SET_POSTGRES_SQL = Object.freeze({
    setTenant: `SELECT ep_remedy_private.assert_tenant_principal($1::text) AS tenant_id`,
    clock: `SELECT to_char(
  transaction_timestamp() AT TIME ZONE 'UTC',
  'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
) AS recorded_at`,
    create: `SELECT * FROM ep_remedy_private.create_case_set($1::text, $2::text, $3::text, $4::text, $5::text, $6::text, $7::text, $8::text, $9::timestamptz)`,
    get: `SELECT * FROM ep_remedy_private.get_case_set($1::text, $2::text)`,
    getForUpdate: `SELECT * FROM ep_remedy_private.get_case_set_for_update($1::text, $2::text)`,
    compareAndSwap: `SELECT * FROM ep_remedy_private.compare_and_swap_case_set($1::text, $2::text, $3::bigint, $4::text, $5::bigint, $6::text, $7::text, $8::text, $9::timestamptz, $10::text, $11::text)`,
    appendEvent: `SELECT * FROM ep_remedy_private.append_case_set_event($1::text, $2::text, $3::bigint, $4::bigint, $5::text, $6::text, $7::text, $8::timestamptz)`,
});
function isDataRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null)
        return false;
    return Reflect.ownKeys(value).every((key) => {
        if (typeof key !== 'string')
            return false;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
    });
}
function exactKeys(value, expected) {
    return isDataRecord(value)
        && Reflect.ownKeys(value).length === expected.size
        && Reflect.ownKeys(value).every((key) => typeof key === 'string' && expected.has(key));
}
function assertJsonData(value, seen = new Set()) {
    if (value === null || typeof value === 'string' || typeof value === 'boolean')
        return;
    if (typeof value === 'number') {
        if (!Number.isFinite(value))
            throw new TypeError('remedy case-set state contains a non-JSON number');
        return;
    }
    if (typeof value !== 'object' || seen.has(value)) {
        throw new TypeError('remedy case-set state must be acyclic plain JSON');
    }
    seen.add(value);
    if (Array.isArray(value)) {
        const keys = Reflect.ownKeys(value);
        if (Object.getPrototypeOf(value) !== Array.prototype
            || keys.length !== value.length + 1
            || keys.some((key) => key !== 'length'
                && (typeof key !== 'string' || !/^(?:0|[1-9]\d*)$/.test(key)))) {
            throw new TypeError('remedy case-set state contains an invalid JSON array');
        }
        for (let index = 0; index < value.length; index += 1) {
            if (!Object.hasOwn(value, index)) {
                throw new TypeError('remedy case-set state contains a sparse JSON array');
            }
            assertJsonData(value[index], seen);
        }
    }
    else {
        if (!isDataRecord(value)) {
            throw new TypeError('remedy case-set state contains a non-data object');
        }
        for (const child of Object.values(value))
            assertJsonData(child, seen);
    }
    seen.delete(value);
}
function assertTenantId(value) {
    if (typeof value !== 'string'
        || Buffer.byteLength(value, 'utf8') < 1
        || Buffer.byteLength(value, 'utf8') > 512
        || /[\u0000-\u001f\u007f]/.test(value)) {
        throw new TypeError('remedy case-set tenantId is invalid');
    }
}
function assertCaseSetId(value) {
    if (typeof value !== 'string' || !CASE_SET_ID.test(value)) {
        throw new TypeError('remedy case-set caseSetId is invalid');
    }
}
function assertRevision(value, label) {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(`remedy case-set ${label} revision is invalid`);
    }
}
function assertDigest(value, label) {
    if (typeof value !== 'string' || !DIGEST.test(value)) {
        throw new TypeError(`remedy case-set ${label} is invalid`);
    }
}
function instant(value, label) {
    if (typeof value !== 'string' || !STRICT_INSTANT.test(value)) {
        throw new TypeError(`remedy case-set ${label} is invalid`);
    }
    const parsed = Date.parse(value);
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
        throw new TypeError(`remedy case-set ${label} is invalid`);
    }
    return parsed;
}
function digestJson(value) {
    return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
function validObservation(value) {
    if (!exactKeys(value, OBSERVATION_KEYS)
        || typeof value.leg_id !== 'string'
        || !CASE_SET_ID.test(value.leg_id)
        || !['pending', 'indeterminate', 'executed'].includes(value.status)) {
        return false;
    }
    if (value.status === 'pending') {
        return value.case_revision === null
            && value.receipt_content_digest === null
            && value.state_snapshot_digest === null;
    }
    return Number.isSafeInteger(value.case_revision)
        && value.case_revision >= 0
        && typeof value.receipt_content_digest === 'string'
        && DIGEST.test(value.receipt_content_digest)
        && typeof value.state_snapshot_digest === 'string'
        && DIGEST.test(value.state_snapshot_digest);
}
function encodeState(value, tenantId, caseSetId, revision) {
    assertJsonData(value);
    let stateJson;
    let state;
    try {
        stateJson = canonicalize(value);
        state = JSON.parse(stateJson);
    }
    catch {
        throw new TypeError('remedy case-set state must be canonical JSON');
    }
    if (Buffer.byteLength(stateJson, 'utf8') > REMEDY_CASE_SET_MAX_STATE_BYTES) {
        throw new TypeError('remedy case-set state exceeds the durable store limit');
    }
    if (!exactKeys(state, STATE_KEYS)
        || state.version !== CASE_SET_VERSION
        || state.tenant_id !== tenantId
        || state.case_set_id !== caseSetId
        || state.revision !== revision
        || !['open', 'indeterminate', 'completed'].includes(state.status)
        || !exactKeys(state.manifest, MANIFEST_KEYS)
        || state.manifest.version !== CASE_SET_VERSION
        || state.manifest.tenant_id !== tenantId
        || state.manifest.case_set_id !== caseSetId
        || !Array.isArray(state.manifest.legs)
        || state.manifest.legs.length < 1
        || state.manifest.legs.length > 256
        || state.manifest.legs.some((leg) => !isDataRecord(leg)
            || typeof leg.leg_id !== 'string'
            || !CASE_SET_ID.test(leg.leg_id))
        || !Array.isArray(state.observations)
        || state.observations.length !== state.manifest.legs.length
        || !state.observations.every(validObservation)
        || state.observations.some((observation, index) => (observation.leg_id !== state.manifest.legs[index].leg_id))) {
        throw new TypeError('remedy case-set state binding is invalid');
    }
    const statuses = state.observations.map((entry) => entry.status);
    if ((state.status === 'open' && !statuses.every((status) => status === 'pending'))
        || (state.status === 'completed'
            && !statuses.every((status) => status === 'executed'))
        || (state.status === 'indeterminate'
            && (!statuses.includes('indeterminate')
                || !statuses.every((status) => status !== 'pending')))) {
        throw new TypeError('remedy case-set status binding is invalid');
    }
    const createdAtMs = instant(state.created_at, 'created_at');
    const eventAtMs = instant(state.updated_at, 'updated_at');
    if (eventAtMs < createdAtMs) {
        throw new TypeError('remedy case-set state clock regressed before creation');
    }
    assertDigest(state.owner_token_digest, 'owner_token_digest');
    assertDigest(state.manifest_digest, 'manifest_digest');
    assertDigest(state.create_request_digest, 'create_request_digest');
    if (state.last_request_digest !== null) {
        assertDigest(state.last_request_digest, 'last_request_digest');
    }
    const manifestJson = canonicalize(state.manifest);
    if (Buffer.byteLength(manifestJson, 'utf8') > REMEDY_CASE_SET_MAX_MANIFEST_BYTES) {
        throw new TypeError('remedy case-set manifest exceeds the durable store limit');
    }
    const manifestDigest = digestJson(manifestJson);
    if (state.manifest_digest !== manifestDigest) {
        throw new TypeError('remedy case-set manifest digest is invalid');
    }
    return {
        state: state,
        stateJson,
        stateDigest: digestJson(stateJson),
        manifestJson,
        manifestDigest,
        eventAt: state.updated_at,
        eventAtMs,
        createdAt: state.created_at,
        ownerTokenDigest: state.owner_token_digest,
        status: state.status,
    };
}
function safeRevision(value) {
    const revision = typeof value === 'string' && /^(?:0|[1-9]\d*)$/.test(value)
        ? Number(value)
        : value;
    if (!Number.isSafeInteger(revision) || revision < 0) {
        throw new Error('remedy case-set PostgreSQL returned an invalid revision');
    }
    return revision;
}
function strictRows(result, operation, maximum) {
    if (!result
        || !Number.isSafeInteger(result.rowCount)
        || result.rowCount < 0
        || result.rowCount > maximum
        || !Array.isArray(result.rows)
        || result.rows.length !== result.rowCount) {
        throw new Error(`remedy case-set ${operation} outcome is ambiguous`);
    }
    return result.rows;
}
function decodeCurrentRow(row, tenantId, caseSetId, expected, expectedRecordedAt) {
    if (!exactKeys(row, CURRENT_ROW_KEYS)
        || row.tenant_id !== tenantId
        || row.case_set_id !== caseSetId
        || !['open', 'indeterminate', 'completed'].includes(row.status)
        || typeof row.owner_token_digest !== 'string'
        || !DIGEST.test(row.owner_token_digest)
        || typeof row.manifest_json !== 'string'
        || Buffer.byteLength(row.manifest_json, 'utf8') > REMEDY_CASE_SET_MAX_MANIFEST_BYTES
        || typeof row.manifest_digest !== 'string'
        || !DIGEST.test(row.manifest_digest)
        || row.manifest_digest !== digestJson(row.manifest_json)
        || typeof row.state_json !== 'string'
        || Buffer.byteLength(row.state_json, 'utf8') > REMEDY_CASE_SET_MAX_STATE_BYTES
        || typeof row.state_digest !== 'string'
        || !DIGEST.test(row.state_digest)
        || row.state_digest !== digestJson(row.state_json)) {
        throw new Error('remedy case-set PostgreSQL returned an invalid state envelope');
    }
    const revision = safeRevision(row.revision);
    let parsed;
    try {
        parsed = JSON.parse(row.state_json);
        if (canonicalize(parsed) !== row.state_json)
            throw new Error('non-canonical state');
    }
    catch {
        throw new Error('remedy case-set PostgreSQL returned non-canonical state');
    }
    const encoded = encodeState(parsed, tenantId, caseSetId, revision);
    if (encoded.status !== row.status
        || encoded.ownerTokenDigest !== row.owner_token_digest
        || encoded.manifestJson !== row.manifest_json
        || encoded.manifestDigest !== row.manifest_digest
        || encoded.stateJson !== row.state_json
        || encoded.stateDigest !== row.state_digest) {
        throw new Error('remedy case-set PostgreSQL returned mismatched state columns');
    }
    const recordedAt = instant(row.recorded_at, 'PostgreSQL recorded_at');
    if (expectedRecordedAt !== undefined
        && (row.recorded_at !== expectedRecordedAt
            || recordedAt !== instant(expectedRecordedAt, 'transaction clock'))) {
        throw new Error('remedy case-set PostgreSQL returned an unexpected transaction clock');
    }
    if (expected && (encoded.stateJson !== expected.stateJson
        || encoded.stateDigest !== expected.stateDigest
        || encoded.manifestJson !== expected.manifestJson
        || encoded.manifestDigest !== expected.manifestDigest)) {
        throw new Error('remedy case-set PostgreSQL did not persist the exact state');
    }
    return encoded;
}
function validateTenantContext(result, tenantId) {
    const rows = strictRows(result, 'tenant context', 1);
    const row = rows[0];
    if (!exactKeys(row, TENANT_ROW_KEYS) || row.tenant_id !== tenantId) {
        throw new Error('remedy case-set PostgreSQL tenant context is invalid');
    }
}
function transactionClock(result) {
    const rows = strictRows(result, 'transaction clock', 1);
    const row = rows[0];
    if (!exactKeys(row, CLOCK_ROW_KEYS)) {
        throw new Error('remedy case-set PostgreSQL transaction clock is malformed');
    }
    return {
        value: row.recorded_at,
        milliseconds: instant(row.recorded_at, 'PostgreSQL transaction clock'),
    };
}
function validateEvent(result, tenantId, caseSetId, revision, stateDigest, recordedAt) {
    const rows = strictRows(result, 'appendEvent', 1);
    const row = rows[0];
    if (!exactKeys(row, EVENT_ROW_KEYS)
        || row.tenant_id !== tenantId
        || row.case_set_id !== caseSetId
        || safeRevision(row.revision) !== revision
        || row.state_digest !== stateDigest
        || row.recorded_at !== recordedAt
        || instant(row.recorded_at, 'event recorded_at') !== Date.parse(recordedAt)) {
        throw new Error('remedy case-set appendEvent outcome is malformed');
    }
}
function lookupInput(value) {
    if (!isDataRecord(value)
        || Reflect.ownKeys(value).length !== 2
        || !Object.hasOwn(value, 'tenantId')
        || !Object.hasOwn(value, 'caseSetId')) {
        throw new TypeError('remedy case-set lookup input is invalid');
    }
    assertTenantId(value.tenantId);
    assertCaseSetId(value.caseSetId);
    return { tenantId: value.tenantId, caseSetId: value.caseSetId };
}
function fail(reason) {
    return { ok: false, reason };
}
function assertNotForwardSkewed(eventAt, databaseNow) {
    const maximum = databaseNow + REMEDY_CASE_SET_MAX_FORWARD_SKEW_MINUTES * 60_000;
    if (eventAt > maximum) {
        throw new TypeError('remedy case-set state clock exceeds PostgreSQL forward-skew limit');
    }
}
/** Build the exact durable store consumed by createRemedyCaseSetCoordinator(). */
export function createRemedyCaseSetPostgresStore({ pool } = {}) {
    if (!pool || typeof pool.connect !== 'function') {
        throw new TypeError('createRemedyCaseSetPostgresStore requires a transaction-capable pg pool');
    }
    async function transaction(readOnly, tenantId, work) {
        const client = await pool.connect();
        if (!client || typeof client.query !== 'function' || typeof client.release !== 'function') {
            throw new TypeError('remedy case-set pg pool returned an invalid client');
        }
        let began = false;
        try {
            await client.query(readOnly
                ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'
                : 'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE');
            began = true;
            validateTenantContext(await client.query(REMEDY_CASE_SET_POSTGRES_SQL.setTenant, [tenantId]), tenantId);
            const clock = transactionClock(await client.query(REMEDY_CASE_SET_POSTGRES_SQL.clock));
            const result = await work(client, clock);
            await client.query('COMMIT');
            began = false;
            return result;
        }
        catch (error) {
            if (began) {
                try {
                    await client.query('ROLLBACK');
                }
                catch (rollbackError) {
                    throw new AggregateError([error, rollbackError], 'remedy case-set transaction and rollback both failed');
                }
            }
            throw error;
        }
        finally {
            client.release();
        }
    }
    return Object.freeze({
        durable: true,
        async create(state) {
            const tenantId = state?.tenant_id;
            const caseSetId = state?.case_set_id;
            assertTenantId(tenantId);
            assertCaseSetId(caseSetId);
            const encoded = encodeState(state, tenantId, caseSetId, 0);
            if (encoded.status !== 'open') {
                throw new TypeError('remedy case-set creation requires an open revision zero');
            }
            return transaction(false, tenantId, async (client, clock) => {
                assertNotForwardSkewed(encoded.eventAtMs, clock.milliseconds);
                const rows = strictRows(await client.query(REMEDY_CASE_SET_POSTGRES_SQL.create, [
                    tenantId,
                    caseSetId,
                    encoded.status,
                    encoded.ownerTokenDigest,
                    encoded.manifestJson,
                    encoded.manifestDigest,
                    encoded.stateJson,
                    encoded.stateDigest,
                    clock.value,
                ]), 'create', 1);
                if (rows.length === 0)
                    return fail('case_set_exists');
                const stored = decodeCurrentRow(rows[0], tenantId, caseSetId, encoded, clock.value);
                validateEvent(await client.query(REMEDY_CASE_SET_POSTGRES_SQL.appendEvent, [
                    tenantId,
                    caseSetId,
                    0,
                    null,
                    encoded.status,
                    encoded.stateJson,
                    encoded.stateDigest,
                    clock.value,
                ]), tenantId, caseSetId, 0, encoded.stateDigest, clock.value);
                return { ok: true, state: stored.state };
            });
        },
        async get(input) {
            const { tenantId, caseSetId } = lookupInput(input);
            return transaction(true, tenantId, async (client) => {
                const rows = strictRows(await client.query(REMEDY_CASE_SET_POSTGRES_SQL.get, [tenantId, caseSetId]), 'get', 1);
                return rows.length === 0
                    ? fail('case_set_not_found')
                    : { ok: true, state: decodeCurrentRow(rows[0], tenantId, caseSetId).state };
            });
        },
        async compareAndSwap(input) {
            if (!isDataRecord(input)
                || Reflect.ownKeys(input).length !== 5
                || !Object.hasOwn(input, 'tenantId')
                || !Object.hasOwn(input, 'caseSetId')
                || !Object.hasOwn(input, 'expectedRevision')
                || !Object.hasOwn(input, 'ownerTokenDigest')
                || !Object.hasOwn(input, 'state')) {
                throw new TypeError('remedy case-set compareAndSwap input is invalid');
            }
            const { tenantId, caseSetId, expectedRevision, ownerTokenDigest, state, } = input;
            assertTenantId(tenantId);
            assertCaseSetId(caseSetId);
            assertRevision(expectedRevision, 'expected');
            assertDigest(ownerTokenDigest, 'ownerTokenDigest');
            const nextRevision = expectedRevision + 1;
            if (!Number.isSafeInteger(nextRevision)) {
                throw new TypeError('remedy case-set next revision is invalid');
            }
            const encoded = encodeState(state, tenantId, caseSetId, nextRevision);
            return transaction(false, tenantId, async (client, clock) => {
                const rows = strictRows(await client.query(REMEDY_CASE_SET_POSTGRES_SQL.getForUpdate, [tenantId, caseSetId]), 'getForUpdate', 1);
                if (rows.length === 0)
                    return fail('case_set_not_found');
                const current = decodeCurrentRow(rows[0], tenantId, caseSetId);
                if (current.ownerTokenDigest !== ownerTokenDigest) {
                    return fail('ownership_conflict');
                }
                if (current.state.revision !== expectedRevision) {
                    return fail('revision_conflict');
                }
                if (current.status === 'completed')
                    return fail('case_set_terminal');
                if (encoded.ownerTokenDigest !== current.ownerTokenDigest) {
                    throw new TypeError('remedy case-set owner digest is immutable');
                }
                if (encoded.manifestJson !== current.manifestJson
                    || encoded.manifestDigest !== current.manifestDigest) {
                    return fail('manifest_conflict');
                }
                if (encoded.createdAt !== current.createdAt) {
                    throw new TypeError('remedy case-set created_at is immutable');
                }
                if (encoded.status === 'open')
                    return fail('case_set_reopen_refused');
                if (encoded.eventAtMs < current.eventAtMs)
                    return fail('clock_regression');
                assertNotForwardSkewed(encoded.eventAtMs, clock.milliseconds);
                const updatedRows = strictRows(await client.query(REMEDY_CASE_SET_POSTGRES_SQL.compareAndSwap, [
                    tenantId,
                    caseSetId,
                    expectedRevision,
                    ownerTokenDigest,
                    nextRevision,
                    encoded.status,
                    encoded.stateJson,
                    encoded.stateDigest,
                    clock.value,
                    encoded.manifestJson,
                    encoded.manifestDigest,
                ]), 'compareAndSwap', 1);
                if (updatedRows.length !== 1) {
                    throw new Error('remedy case-set compareAndSwap lost its locked row');
                }
                const stored = decodeCurrentRow(updatedRows[0], tenantId, caseSetId, encoded, clock.value);
                validateEvent(await client.query(REMEDY_CASE_SET_POSTGRES_SQL.appendEvent, [
                    tenantId,
                    caseSetId,
                    nextRevision,
                    expectedRevision,
                    encoded.status,
                    encoded.stateJson,
                    encoded.stateDigest,
                    clock.value,
                ]), tenantId, caseSetId, nextRevision, encoded.stateDigest, clock.value);
                return { ok: true, state: stored.state };
            });
        },
    });
}
export default {
    REMEDY_CASE_SET_PG_STORE_VERSION,
    REMEDY_CASE_SET_TABLE,
    REMEDY_CASE_SET_EVENT_TABLE,
    REMEDY_CASE_SET_EXECUTOR_ROLE,
    REMEDY_CASE_SET_MAX_STATE_BYTES,
    REMEDY_CASE_SET_MAX_MANIFEST_BYTES,
    REMEDY_CASE_SET_MAX_FORWARD_SKEW_MINUTES,
    REMEDY_CASE_SET_POSTGRES_DDL,
    REMEDY_CASE_SET_POSTGRES_SQL,
    createRemedyCaseSetPostgresStore,
};
//# sourceMappingURL=remedy-case-set-postgres.js.map