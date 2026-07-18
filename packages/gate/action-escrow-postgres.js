// SPDX-License-Identifier: Apache-2.0
/**
 * Durable Postgres backend for the Action Escrow state-machine store contract.
 *
 * Each transition compares the exact prior serialized snapshot and installs
 * the exact replacement in one SQL statement. Backend errors propagate; the
 * state machine must refuse rather than treating an outage as absent state.
 */
import { strictJsonGate } from './strict-json.js';

export const ACTION_ESCROW_PG_STORE_VERSION = 'EP-ACTION-ESCROW-PG-STORE-v1';
export const ACTION_ESCROW_STATE_TABLE = 'ep_action_escrow_state';
export const ACTION_ESCROW_MAX_STATE_BYTES = 4 * 1024 * 1024;

export const ACTION_ESCROW_STATE_DDL = `CREATE TABLE IF NOT EXISTS ${ACTION_ESCROW_STATE_TABLE} (
  agreement_key TEXT PRIMARY KEY,
  revision      BIGINT NOT NULL CHECK (revision >= 0),
  record_json   TEXT NOT NULL,
  updated_at    BIGINT NOT NULL,
  CHECK (octet_length(record_json) <= ${ACTION_ESCROW_MAX_STATE_BYTES})
);
REVOKE ALL ON ${ACTION_ESCROW_STATE_TABLE} FROM PUBLIC;`;

export const ACTION_ESCROW_STATE_SQL = Object.freeze({
  health: `SELECT
  to_regclass('public.${ACTION_ESCROW_STATE_TABLE}') IS NOT NULL AS table_ready,
  CASE WHEN to_regclass('public.${ACTION_ESCROW_STATE_TABLE}') IS NULL THEN FALSE
    ELSE has_table_privilege(current_user, to_regclass('public.${ACTION_ESCROW_STATE_TABLE}'), 'SELECT,INSERT,UPDATE') END AS can_use`,
  read: `SELECT revision, record_json FROM ${ACTION_ESCROW_STATE_TABLE} WHERE agreement_key = $1`,
  create: `INSERT INTO ${ACTION_ESCROW_STATE_TABLE} (agreement_key, revision, record_json, updated_at)
VALUES ($1, 0, $2, $3)
ON CONFLICT (agreement_key) DO NOTHING
RETURNING revision`,
  compareAndSwap: `UPDATE ${ACTION_ESCROW_STATE_TABLE}
SET revision = $3, record_json = $4, updated_at = $5
WHERE agreement_key = $1 AND revision = $2
RETURNING revision`,
});

function validKey(value) {
  return typeof value === 'string'
    && value.length >= 1
    && value.length <= 512
    && !/[\u0000-\u001f\u007f]/.test(value);
}

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
  } catch {
    return null;
  }
}

function assertResult(result, operation) {
  if (!result || typeof result.rowCount !== 'number' || !Number.isSafeInteger(result.rowCount)
    || result.rowCount < 0) {
    throw new Error(`${operation}: malformed Postgres result`);
  }
  return result;
}

/**
 * @param {object} options
 * @param {(text:string, params:any[]) => Promise<{rowCount:number,rows?:any[]}>} options.query
 * @param {number|Function} [options.now=Date.now]
 */
export function createActionEscrowPostgresStore({
  query,
  now = Date.now,
} = {}) {
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

  function assertKey(key) {
    if (!validKey(key)) throw new TypeError('action-escrow agreement key is invalid');
  }

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

  async function read(key) {
    assertKey(key);
    const result = assertResult(
      await query(ACTION_ESCROW_STATE_SQL.read, [key]),
      'action-escrow read',
    );
    if (result.rowCount === 0) return null;
    if (result.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1
      || !Number.isSafeInteger(Number(result.rows[0]?.revision))
      || Number(result.rows[0].revision) < 0
      || !parsedState(result.rows[0]?.record_json)) {
      throw new Error('action-escrow read: database returned malformed or ambiguous state');
    }
    const revision = Number(result.rows[0].revision);
    assertState(result.rows[0].record_json, revision);
    return { revision, value: result.rows[0].record_json };
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
      const result = assertResult(
        await query(ACTION_ESCROW_STATE_SQL.health, []),
        'action-escrow health',
      );
      if (result.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1) {
        throw new Error('action-escrow health: malformed Postgres result');
      }
      return {
        ok: result.rows[0].table_ready === true && result.rows[0].can_use === true,
        version: ACTION_ESCROW_PG_STORE_VERSION,
      };
    },
    read,
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
        ? [key, value, nowMs()]
        : [key, expectedRevision, nextRevision, value, nowMs()];
      const result = assertResult(
        await query(sql, params),
        'action-escrow compareAndSwap',
      );
      if (result.rowCount > 1) {
        throw new Error('action-escrow compareAndSwap affected multiple rows');
      }
      if (result.rowCount === 0) return { applied: false, revision: null };
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
  ACTION_ESCROW_MAX_STATE_BYTES,
  ACTION_ESCROW_STATE_DDL,
  ACTION_ESCROW_STATE_SQL,
  createActionEscrowPostgresStore,
};
