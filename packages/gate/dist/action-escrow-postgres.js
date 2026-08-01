// SPDX-License-Identifier: Apache-2.0
/**
 * Durable Postgres backend for the Action Escrow state-machine store contract.
 *
 * Each transition compares the exact prior serialized snapshot and installs
 * the exact replacement in one SQL statement. Backend errors propagate; the
 * state machine must refuse rather than treating an outage as absent state.
 */
import crypto from 'node:crypto';
import { strictJsonGate } from './strict-json.js';
export const ACTION_ESCROW_PG_STORE_VERSION = 'EP-ACTION-ESCROW-PG-STORE-v1';
export const ACTION_ESCROW_STATE_TABLE = 'ep_action_escrow_state';
export const ACTION_ESCROW_EVENT_TABLE = 'ep_action_escrow_state_events';
export const ACTION_ESCROW_MAX_STATE_BYTES = 4 * 1024 * 1024;
export const ACTION_ESCROW_STATE_DDL = `CREATE TABLE IF NOT EXISTS ${ACTION_ESCROW_STATE_TABLE} (
  agreement_key TEXT PRIMARY KEY,
  revision      BIGINT NOT NULL CHECK (revision >= 0),
  record_json   TEXT NOT NULL,
  updated_at    BIGINT NOT NULL,
CHECK (octet_length(record_json) <= ${ACTION_ESCROW_MAX_STATE_BYTES})
);
CREATE TABLE IF NOT EXISTS ${ACTION_ESCROW_EVENT_TABLE} (
  agreement_key     TEXT NOT NULL,
  revision          BIGINT NOT NULL CHECK (revision >= 0),
  previous_revision BIGINT NULL,
  record_json       TEXT NOT NULL,
  record_digest     TEXT NOT NULL CHECK (record_digest ~ '^sha256:[0-9a-f]{64}$'),
  recorded_at       BIGINT NOT NULL,
  PRIMARY KEY (agreement_key, revision),
  CHECK (
    (revision = 0 AND previous_revision IS NULL)
    OR previous_revision = revision - 1
  ),
  CHECK (octet_length(record_json) <= ${ACTION_ESCROW_MAX_STATE_BYTES})
);
REVOKE ALL ON ${ACTION_ESCROW_STATE_TABLE} FROM PUBLIC;
REVOKE ALL ON ${ACTION_ESCROW_EVENT_TABLE} FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON ${ACTION_ESCROW_EVENT_TABLE} FROM PUBLIC;`;
/**
 * @param {string} roleName
 */
export function actionEscrowRuntimeGrantDdl(roleName) {
    if (typeof roleName !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(roleName)) {
        throw new TypeError('action-escrow runtime role name is invalid');
    }
    const role = `"${roleName}"`;
    return `REVOKE ALL ON ${ACTION_ESCROW_STATE_TABLE} FROM ${role};
REVOKE ALL ON ${ACTION_ESCROW_EVENT_TABLE} FROM ${role};
GRANT SELECT, INSERT, UPDATE ON ${ACTION_ESCROW_STATE_TABLE} TO ${role};
GRANT SELECT, INSERT ON ${ACTION_ESCROW_EVENT_TABLE} TO ${role};
REVOKE DELETE, TRUNCATE ON ${ACTION_ESCROW_STATE_TABLE} FROM ${role};
REVOKE UPDATE, DELETE, TRUNCATE ON ${ACTION_ESCROW_EVENT_TABLE} FROM ${role};`;
}
export const ACTION_ESCROW_STATE_SQL = Object.freeze({
    health: `SELECT
  to_regclass('public.${ACTION_ESCROW_STATE_TABLE}') IS NOT NULL AS table_ready,
  to_regclass('public.${ACTION_ESCROW_EVENT_TABLE}') IS NOT NULL AS event_table_ready,
  CASE WHEN to_regclass('public.${ACTION_ESCROW_STATE_TABLE}') IS NULL THEN FALSE
    ELSE has_table_privilege(current_user, to_regclass('public.${ACTION_ESCROW_STATE_TABLE}'), 'SELECT')
      AND has_table_privilege(current_user, to_regclass('public.${ACTION_ESCROW_STATE_TABLE}'), 'INSERT')
      AND has_table_privilege(current_user, to_regclass('public.${ACTION_ESCROW_STATE_TABLE}'), 'UPDATE') END AS can_use,
  CASE WHEN to_regclass('public.${ACTION_ESCROW_EVENT_TABLE}') IS NULL THEN FALSE
    ELSE has_table_privilege(current_user, to_regclass('public.${ACTION_ESCROW_EVENT_TABLE}'), 'SELECT')
      AND has_table_privilege(current_user, to_regclass('public.${ACTION_ESCROW_EVENT_TABLE}'), 'INSERT') END AS can_append_history,
  CASE WHEN to_regclass('public.${ACTION_ESCROW_STATE_TABLE}') IS NULL THEN TRUE
    ELSE (SELECT relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
      FROM pg_class WHERE oid = to_regclass('public.${ACTION_ESCROW_STATE_TABLE}')) END AS owns_state_table,
  CASE WHEN to_regclass('public.${ACTION_ESCROW_EVENT_TABLE}') IS NULL THEN TRUE
    ELSE (SELECT relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
      FROM pg_class WHERE oid = to_regclass('public.${ACTION_ESCROW_EVENT_TABLE}')) END AS owns_event_table,
  CASE WHEN to_regclass('public.${ACTION_ESCROW_STATE_TABLE}') IS NULL THEN TRUE
    ELSE has_table_privilege(current_user, to_regclass('public.${ACTION_ESCROW_STATE_TABLE}'), 'DELETE')
      OR has_table_privilege(current_user, to_regclass('public.${ACTION_ESCROW_STATE_TABLE}'), 'TRUNCATE') END AS can_destroy_state,
  CASE WHEN to_regclass('public.${ACTION_ESCROW_EVENT_TABLE}') IS NULL THEN TRUE
    ELSE has_table_privilege(current_user, to_regclass('public.${ACTION_ESCROW_EVENT_TABLE}'), 'UPDATE')
      OR has_table_privilege(current_user, to_regclass('public.${ACTION_ESCROW_EVENT_TABLE}'), 'DELETE')
      OR has_table_privilege(current_user, to_regclass('public.${ACTION_ESCROW_EVENT_TABLE}'), 'TRUNCATE') END AS can_mutate_history`,
    read: `SELECT revision, record_json FROM ${ACTION_ESCROW_STATE_TABLE} WHERE agreement_key = $1`,
    history: `SELECT revision, previous_revision, record_json, record_digest, recorded_at
FROM ${ACTION_ESCROW_EVENT_TABLE}
WHERE agreement_key = $1
ORDER BY revision ASC`,
    create: `WITH installed AS (
  INSERT INTO ${ACTION_ESCROW_STATE_TABLE} (agreement_key, revision, record_json, updated_at)
  VALUES ($1, 0, $2, $3)
  ON CONFLICT (agreement_key) DO NOTHING
  RETURNING agreement_key, revision, record_json, updated_at
), journaled AS (
  INSERT INTO ${ACTION_ESCROW_EVENT_TABLE}
    (agreement_key, revision, previous_revision, record_json, record_digest, recorded_at)
  SELECT agreement_key, revision, NULL, record_json, $4, updated_at
  FROM installed
  RETURNING revision
)
SELECT revision FROM journaled`,
    compareAndSwap: `WITH installed AS (
UPDATE ${ACTION_ESCROW_STATE_TABLE}
SET revision = $3, record_json = $4, updated_at = $5
WHERE agreement_key = $1 AND revision = $2 AND updated_at <= $5
RETURNING agreement_key, revision, record_json, updated_at
), journaled AS (
  INSERT INTO ${ACTION_ESCROW_EVENT_TABLE}
    (agreement_key, revision, previous_revision, record_json, record_digest, recorded_at)
  SELECT agreement_key, revision, $2, record_json, $6, updated_at
  FROM installed
  RETURNING revision
)
SELECT revision FROM journaled`,
});
/**
 * @param {*} value
 */
function validKey(value) {
    return typeof value === 'string'
        && value.length >= 1
        && value.length <= 512
        && !/[\u0000-\u001f\u007f]/.test(value);
}
/**
 * @param {*} value
 */
function parsedState(value) {
    if (typeof value !== 'string'
        || Buffer.byteLength(value, 'utf8') > ACTION_ESCROW_MAX_STATE_BYTES
        || !strictJsonGate(value).ok) {
        return null;
    }
    try {
        const parsed = JSON.parse(value);
        return parsed !== null
            && typeof parsed === 'object'
            && !Array.isArray(parsed)
            && Object.getPrototypeOf(parsed) === Object.prototype
            ? parsed
            : null;
    }
    catch {
        return null;
    }
}
/**
 * @param {string} value
 */
function recordDigest(value) {
    return `sha256:${crypto.createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
/**
 * @param {*} result
 * @param {string} operation
 */
function assertResult(result, operation) {
    if (!result || typeof result.rowCount !== 'number' || !Number.isSafeInteger(result.rowCount)
        || result.rowCount < 0) {
        throw new Error(`${operation}: malformed Postgres result`);
    }
    return result;
}
export function createActionEscrowPostgresStore({ query, now = Date.now, } = {}) {
    if (typeof query !== 'function') {
        throw new TypeError('createActionEscrowPostgresStore requires an async pg-style query function');
    }
    let lastNow = Number.NEGATIVE_INFINITY;
    function nowMs() {
        const value = typeof now === 'function' ? now() : now;
        if (!Number.isSafeInteger(value) || value < 0) {
            throw new Error('action-escrow store clock must be a non-negative safe-integer epoch millisecond');
        }
        if (value < lastNow) {
            throw new Error(`action-escrow store clock regression refused: ${value} < ${lastNow}`);
        }
        lastNow = value;
        return value;
    }
    /**
     * @param {*} key
     */
    function assertKey(key) {
        if (!validKey(key))
            throw new TypeError('action-escrow agreement key is invalid');
    }
    /**
     * @param {*} value
     * @param {number} revision
     */
    function assertState(value, revision) {
        const parsed = parsedState(value);
        if (!parsed) {
            throw new TypeError('action-escrow state must be bounded strict JSON text');
        }
        if (!Number.isSafeInteger(parsed.revision)
            || parsed.revision < 0
            || parsed.revision !== revision) {
            throw new TypeError('action-escrow state revision must match the CAS revision');
        }
    }
    /**
     * @param {string} key
     */
    async function loadHistory(key) {
        // query is validated as a function above; the guard's narrowing does not
        // carry into this hoisted function declaration's closure.
        const result = assertResult(await query(ACTION_ESCROW_STATE_SQL.history, [key]), 'action-escrow history');
        if (!Array.isArray(result.rows) || result.rows.length !== result.rowCount) {
            throw new Error('action-escrow history: malformed Postgres result');
        }
        let previousRecordedAt = Number.NEGATIVE_INFINITY;
        const history = result.rows.map(/** @param {*} row @param {number} index */ (row, index) => {
            const revision = Number(row?.revision);
            const previousRevision = row?.previous_revision === null
                ? null
                : Number(row?.previous_revision);
            const recordedAt = Number(row?.recorded_at);
            if (!Number.isSafeInteger(revision)
                || revision !== index
                || previousRevision !== (revision === 0 ? null : revision - 1)
                || !Number.isSafeInteger(recordedAt)
                || recordedAt < 0
                || recordedAt < previousRecordedAt
                || !parsedState(row?.record_json)
                || row?.record_digest !== recordDigest(row.record_json)) {
                throw new Error('action-escrow history: invalid or non-contiguous event');
            }
            assertState(row.record_json, revision);
            previousRecordedAt = recordedAt;
            return Object.freeze({
                revision,
                previous_revision: previousRevision,
                record_json: row.record_json,
                record_digest: row.record_digest,
                recorded_at: recordedAt,
            });
        });
        return Object.freeze(history);
    }
    async function read(key) {
        assertKey(key);
        for (let attempt = 0; attempt < 2; attempt += 1) {
            const result = assertResult(
            // query is validated as a function above; the guard's narrowing does
            // not carry into this hoisted function declaration's closure.
            await query(ACTION_ESCROW_STATE_SQL.read, [key]), 'action-escrow read');
            if (result.rowCount > 1
                || !Array.isArray(result.rows)
                || result.rows.length !== result.rowCount) {
                throw new Error('action-escrow read: database returned malformed or ambiguous state');
            }
            const history = await loadHistory(key);
            if (result.rowCount === 0) {
                if (history.length === 0)
                    return null;
                continue;
            }
            if (!Number.isSafeInteger(Number(result.rows[0]?.revision))
                || Number(result.rows[0].revision) < 0
                || !parsedState(result.rows[0]?.record_json)) {
                throw new Error('action-escrow read: database returned malformed or ambiguous state');
            }
            const revision = Number(result.rows[0].revision);
            assertState(result.rows[0].record_json, revision);
            const tail = history.at(-1);
            if (tail?.revision === revision
                && tail.record_json === result.rows[0].record_json
                && tail.record_digest === recordDigest(result.rows[0].record_json)) {
                return { revision, value: result.rows[0].record_json };
            }
        }
        throw new Error('action-escrow read: state and append-only journal do not agree');
    }
    return Object.freeze({
        version: ACTION_ESCROW_PG_STORE_VERSION,
        durable: true,
        atomicExpectedRevisionCas: true,
        linearizableReads: true,
        monotonicRevisions: true,
        nonExpiring: true,
        maxStateBytes: ACTION_ESCROW_MAX_STATE_BYTES,
        async health() {
            const result = assertResult(await query(ACTION_ESCROW_STATE_SQL.health, []), 'action-escrow health');
            if (result.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1) {
                throw new Error('action-escrow health: malformed Postgres result');
            }
            return {
                ok: result.rows[0].table_ready === true
                    && result.rows[0].event_table_ready === true
                    && result.rows[0].can_use === true
                    && result.rows[0].can_append_history === true
                    && result.rows[0].owns_state_table === false
                    && result.rows[0].owns_event_table === false
                    && result.rows[0].can_destroy_state === false
                    && result.rows[0].can_mutate_history === false,
                version: ACTION_ESCROW_PG_STORE_VERSION,
            };
        },
        read,
        async readHistory(key) {
            assertKey(key);
            return loadHistory(key);
        },
        async compareAndSwap(key, expectedRevision, value) {
            assertKey(key);
            if (expectedRevision !== null
                && (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0)) {
                throw new TypeError('action-escrow expected revision is invalid');
            }
            const nextRevision = expectedRevision === null ? 0 : expectedRevision + 1;
            assertState(value, nextRevision);
            const sql = expectedRevision === null
                ? ACTION_ESCROW_STATE_SQL.create
                : ACTION_ESCROW_STATE_SQL.compareAndSwap;
            const params = expectedRevision === null
                ? [key, value, nowMs(), recordDigest(value)]
                : [key, expectedRevision, nextRevision, value, nowMs(), recordDigest(value)];
            const result = assertResult(await query(sql, params), 'action-escrow compareAndSwap');
            if (result.rowCount > 1) {
                throw new Error('action-escrow compareAndSwap affected multiple rows');
            }
            if (result.rowCount === 0)
                return { applied: false, revision: null };
            if (!Array.isArray(result.rows)
                || result.rows.length !== 1
                || Number(result.rows[0]?.revision) !== nextRevision) {
                throw new Error('action-escrow compareAndSwap returned a malformed revision');
            }
            return { applied: true, revision: nextRevision };
        },
    });
}
export default {
    ACTION_ESCROW_PG_STORE_VERSION,
    ACTION_ESCROW_STATE_TABLE,
    ACTION_ESCROW_EVENT_TABLE,
    ACTION_ESCROW_MAX_STATE_BYTES,
    ACTION_ESCROW_STATE_DDL,
    actionEscrowRuntimeGrantDdl,
    ACTION_ESCROW_STATE_SQL,
    createActionEscrowPostgresStore,
};
//# sourceMappingURL=action-escrow-postgres.js.map