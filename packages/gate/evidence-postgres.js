// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate production evidence backend for Postgres.
 *
 * The deployment SQL exposes one SECURITY DEFINER append function. That
 * function locks the tenant/gate/stream head, checks the caller's expected
 * head, inserts one immutable record, and advances the head in the same SQL
 * statement transaction. Runtime roles receive SELECT and EXECUTE only; they
 * cannot insert, update, delete, or truncate evidence tables directly.
 *
 * Database errors and malformed driver responses always propagate on the
 * write path. A storage outage must never be mistaken for a successful append
 * or an ordinary contention retry.
 */

import {
  canonicalEvidenceJson,
  verifyEvidenceRecord,
} from './evidence.js';

export const PG_EVIDENCE_VERSION = 'EP-GATE-PG-EVIDENCE-v1';
export const EVIDENCE_SCHEMA = 'emilia_gate_evidence';
export const EVIDENCE_RECORDS_TABLE = `${EVIDENCE_SCHEMA}.records`;
export const EVIDENCE_HEADS_TABLE = `${EVIDENCE_SCHEMA}.heads`;
export const EVIDENCE_APPEND_FUNCTION = `${EVIDENCE_SCHEMA}.append_record`;

const HEX_256 = /^[0-9a-f]{64}$/;
// evidence.js permits 1 MiB of raw string/key bytes. JSON control-character
// escaping can expand those bytes by up to 6x, plus bounded container syntax.
const MAX_CANONICAL_BYTES = 8 * 1024 * 1024;

/** Exact statements issued by the adapter, exported for audit and test fakes. */
export const EVIDENCE_SQL = Object.freeze({
  health: `SELECT
  to_regclass('${EVIDENCE_RECORDS_TABLE}') IS NOT NULL AS records_ready,
  to_regclass('${EVIDENCE_HEADS_TABLE}') IS NOT NULL AS heads_ready,
  to_regprocedure('${EVIDENCE_APPEND_FUNCTION}(text,text,text,text,jsonb,text)') IS NOT NULL AS append_ready,
  CASE WHEN to_regclass('${EVIDENCE_RECORDS_TABLE}') IS NULL THEN FALSE
    ELSE has_table_privilege(current_user, to_regclass('${EVIDENCE_RECORDS_TABLE}'), 'SELECT') END AS can_read_records,
  CASE WHEN to_regclass('${EVIDENCE_HEADS_TABLE}') IS NULL THEN FALSE
    ELSE has_table_privilege(current_user, to_regclass('${EVIDENCE_HEADS_TABLE}'), 'SELECT') END AS can_read_heads,
  CASE WHEN to_regclass('${EVIDENCE_RECORDS_TABLE}') IS NULL THEN FALSE ELSE (
    has_table_privilege(current_user, to_regclass('${EVIDENCE_RECORDS_TABLE}'), 'INSERT')
    OR has_table_privilege(current_user, to_regclass('${EVIDENCE_RECORDS_TABLE}'), 'UPDATE')
    OR has_table_privilege(current_user, to_regclass('${EVIDENCE_RECORDS_TABLE}'), 'DELETE')
    OR has_table_privilege(current_user, to_regclass('${EVIDENCE_RECORDS_TABLE}'), 'TRUNCATE')
  ) END AS can_write_records_directly,
  CASE WHEN to_regclass('${EVIDENCE_HEADS_TABLE}') IS NULL THEN FALSE ELSE (
    has_table_privilege(current_user, to_regclass('${EVIDENCE_HEADS_TABLE}'), 'INSERT')
    OR has_table_privilege(current_user, to_regclass('${EVIDENCE_HEADS_TABLE}'), 'UPDATE')
    OR has_table_privilege(current_user, to_regclass('${EVIDENCE_HEADS_TABLE}'), 'DELETE')
    OR has_table_privilege(current_user, to_regclass('${EVIDENCE_HEADS_TABLE}'), 'TRUNCATE')
  ) END AS can_write_heads_directly,
  CASE WHEN to_regprocedure('${EVIDENCE_APPEND_FUNCTION}(text,text,text,text,jsonb,text)') IS NULL THEN FALSE
    ELSE has_function_privilege(current_user,
      to_regprocedure('${EVIDENCE_APPEND_FUNCTION}(text,text,text,text,jsonb,text)'), 'EXECUTE') END AS can_append`,

  readHead: `SELECT head_seq AS seq, head_hash AS hash
FROM ${EVIDENCE_HEADS_TABLE}
WHERE tenant_id = $1 AND gate_id = $2 AND stream_id = $3`,

  getById: `SELECT seq, record_id, prev_hash, hash, record
FROM ${EVIDENCE_RECORDS_TABLE}
WHERE tenant_id = $1 AND gate_id = $2 AND stream_id = $3 AND record_id = $4`,

  readAll: `SELECT seq, record_id, prev_hash, hash, record
FROM ${EVIDENCE_RECORDS_TABLE}
WHERE tenant_id = $1 AND gate_id = $2 AND stream_id = $3
ORDER BY seq ASC`,

  // One SELECT gives verify() a single MVCC snapshot of rows and head.
  snapshot: `SELECT
  COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
      'seq', r.seq,
      'record_id', r.record_id,
      'prev_hash', r.prev_hash,
      'hash', r.hash,
      'record', r.record
    ) ORDER BY r.seq ASC)
    FROM ${EVIDENCE_RECORDS_TABLE} r
    WHERE r.tenant_id = $1 AND r.gate_id = $2 AND r.stream_id = $3
  ), '[]'::jsonb) AS record_rows,
  (
    SELECT CASE WHEN h.head_seq = -1 THEN NULL ELSE jsonb_build_object(
      'seq', h.head_seq, 'hash', h.head_hash
    ) END
    FROM ${EVIDENCE_HEADS_TABLE} h
    WHERE h.tenant_id = $1 AND h.gate_id = $2 AND h.stream_id = $3
  ) AS head`,

  appendIfHead: `SELECT ${EVIDENCE_APPEND_FUNCTION}($1, $2, $3, $4, $5::jsonb, $6) AS appended`,
});

function assertScopedId(value, label, { minLength = 1, maxLength = 256 } = {}) {
  if (typeof value !== 'string' || value.length < minLength
      || value.length > maxLength || value.includes('\0')) {
    throw new Error(`${label} must be a string of ${minLength} to ${maxLength} characters`);
  }
  return value;
}

function queryRows(result, operation) {
  if (!result || !Number.isInteger(result.rowCount) || result.rowCount < 0
      || !Array.isArray(result.rows) || result.rows.length !== result.rowCount) {
    throw new Error(`${operation}: malformed Postgres result; storage outcome is unproven`);
  }
  return result.rows;
}

function parseSequence(value, operation, { sentinel = false } = {}) {
  let parsed = value;
  if (typeof value === 'string' && /^-?(0|[1-9][0-9]*)$/.test(value)) parsed = Number(value);
  const minimum = sentinel ? -1 : 0;
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    throw new Error(`${operation}: Postgres returned an invalid evidence sequence`);
  }
  return parsed;
}

function parseJson(value, operation) {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    throw new Error(`${operation}: Postgres returned malformed JSON`);
  }
}

function normalizeHead(value, operation) {
  const head = parseJson(value, operation);
  if (head === null || head === undefined) return null;
  if (!head || typeof head !== 'object' || Array.isArray(head)) {
    throw new Error(`${operation}: Postgres returned a malformed evidence head`);
  }
  const seq = parseSequence(head.seq, operation, { sentinel: true });
  if (seq === -1) {
    if (head.hash !== null && head.hash !== undefined) {
      throw new Error(`${operation}: empty evidence head has a hash`);
    }
    return null;
  }
  if (typeof head.hash !== 'string' || !HEX_256.test(head.hash)) {
    throw new Error(`${operation}: Postgres returned a malformed evidence head hash`);
  }
  return { seq, hash: head.hash };
}

function normalizeRecordRow(value, operation) {
  const row = parseJson(value, operation);
  if (!row || typeof row !== 'object' || Array.isArray(row)) {
    throw new Error(`${operation}: Postgres returned a malformed evidence row`);
  }
  const seq = parseSequence(row.seq, operation);
  const record = parseJson(row.record, operation);
  if (!record || typeof record !== 'object' || Array.isArray(record)
      || record.seq !== seq
      || record.record_id !== row.record_id
      || record.prev_hash !== row.prev_hash
      || record.hash !== row.hash) {
    throw new Error(`${operation}: evidence row metadata does not match its record`);
  }
  return structuredClone(record);
}

function canonicalAppendPayload(record, expectedHeadHash) {
  if (expectedHeadHash !== null && (typeof expectedHeadHash !== 'string' || !HEX_256.test(expectedHeadHash))) {
    throw new Error('appendIfHead: expected head must be null or a lowercase SHA-256 hash');
  }
  if (!verifyEvidenceRecord(record, { atomicRequired: true })) {
    throw new Error('appendIfHead: record is not a valid canonical atomic evidence record');
  }
  if (expectedHeadHash === null) {
    if (record.seq !== 0 || record.prev_hash !== 'genesis') {
      throw new Error('appendIfHead: genesis append has an invalid sequence or predecessor');
    }
  } else if (record.seq < 1 || record.prev_hash !== expectedHeadHash) {
    throw new Error('appendIfHead: record does not extend the expected head');
  }

  let persisted;
  try {
    persisted = JSON.parse(JSON.stringify(record));
  } catch {
    throw new Error('appendIfHead: record is not losslessly JSON-serializable');
  }
  if (!persisted || typeof persisted !== 'object' || Array.isArray(persisted)
      || canonicalEvidenceJson(persisted) !== canonicalEvidenceJson(record)
      || !verifyEvidenceRecord(persisted, { atomicRequired: true })) {
    throw new Error('appendIfHead: record is not losslessly JSON-serializable');
  }

  const { hash: _hash, ...body } = persisted;
  const canonicalBody = canonicalEvidenceJson(body);
  if (typeof canonicalBody !== 'string' || Buffer.byteLength(canonicalBody, 'utf8') > MAX_CANONICAL_BYTES) {
    throw new Error('appendIfHead: canonical evidence body exceeds the Postgres limit');
  }
  return { canonicalBody, persisted };
}

function verifyHistory(records, head) {
  const recordIds = new Set();
  const sequences = new Set();
  let previous = 'genesis';

  for (let index = 0; index < records.length; index++) {
    const record = records[index];
    if (sequences.has(record.seq)) return { ok: false, at: record.seq, reason: 'fork_detected' };
    sequences.add(record.seq);
    if (record.seq !== index) return { ok: false, at: index, reason: 'sequence_gap_or_rollback' };
    if (record.prev_hash !== previous) {
      return { ok: false, at: index, reason: 'fork_or_predecessor_mismatch' };
    }
    if (recordIds.has(record.record_id)) {
      return { ok: false, at: index, reason: 'duplicate_record_id' };
    }
    if (!verifyEvidenceRecord(record, { atomicRequired: true })) {
      return { ok: false, at: index, reason: 'hash_mismatch_or_malformed_record' };
    }
    recordIds.add(record.record_id);
    previous = record.hash;
  }

  const expectedHead = records.length === 0
    ? null
    : { seq: records.length - 1, hash: previous };
  if ((expectedHead === null && head !== null)
      || (expectedHead !== null && (head === null
        || head.seq !== expectedHead.seq || head.hash !== expectedHead.hash))) {
    return { ok: false, reason: 'head_rollback_or_mismatch' };
  }
  return { ok: true, length: records.length, head: expectedHead?.hash ?? null };
}

/**
 * Create a tenant-and-gate-bound backend for createAtomicEvidenceLog().
 *
 * `query` is a node-postgres style function such as `pool.query.bind(pool)`.
 * The migration must be installed and the connection role must inherit or SET
 * ROLE to `emilia_gate_evidence_runtime`.
 *
 * @param {{ query?: (text: string, params: any[]) => Promise<{ rowCount: number, rows?: any[] }>, tenantId?: any, gateId?: any }} [options]
 */
export function createPostgresEvidenceBackend({ query, tenantId, gateId } = {}) {
  if (typeof query !== 'function') {
    throw new Error('createPostgresEvidenceBackend: query must be an async pg-style function that throws on failure');
  }
  const tenant = assertScopedId(tenantId, 'tenantId');
  const gate = assertScopedId(gateId, 'gateId');
  const scope = Object.freeze({ tenantId: tenant, gateId: gate });
  const scopeParams = (streamId) => [tenant, gate, assertScopedId(streamId, 'streamId')];

  async function readHead(streamId) {
    const rows = queryRows(await query(EVIDENCE_SQL.readHead, scopeParams(streamId)), 'readHead');
    if (rows.length > 1) throw new Error('readHead: Postgres returned multiple scoped heads');
    return rows.length === 0 ? null : normalizeHead(rows[0], 'readHead');
  }

  async function getById(streamId, recordId) {
    assertScopedId(recordId, 'recordId', { minLength: 16 });
    const rows = queryRows(
      await query(EVIDENCE_SQL.getById, [...scopeParams(streamId), recordId]),
      'getById',
    );
    if (rows.length > 1) throw new Error('getById: Postgres returned duplicate scoped record IDs');
    return rows.length === 0 ? null : normalizeRecordRow(rows[0], 'getById');
  }

  async function appendIfHead(streamId, expectedHeadHash, record) {
    const params = scopeParams(streamId);
    const { canonicalBody, persisted } = canonicalAppendPayload(record, expectedHeadHash);
    const rows = queryRows(
      await query(EVIDENCE_SQL.appendIfHead, [
        ...params,
        expectedHeadHash,
        persisted,
        canonicalBody,
      ]),
      'appendIfHead',
    );
    if (rows.length !== 1 || typeof rows[0]?.appended !== 'boolean') {
      throw new Error('appendIfHead: Postgres did not return a definitive append verdict');
    }
    return rows[0].appended;
  }

  async function readAll(streamId) {
    const rows = queryRows(await query(EVIDENCE_SQL.readAll, scopeParams(streamId)), 'readAll');
    return rows.map((row) => normalizeRecordRow(row, 'readAll'));
  }

  async function readSnapshot(streamId) {
    const rows = queryRows(await query(EVIDENCE_SQL.snapshot, scopeParams(streamId)), 'verify');
    if (rows.length !== 1) throw new Error('verify: Postgres did not return one scoped snapshot');
    const recordRows = parseJson(rows[0].record_rows, 'verify');
    if (!Array.isArray(recordRows)) throw new Error('verify: Postgres returned malformed evidence history');
    return {
      records: recordRows.map((row) => normalizeRecordRow(row, 'verify')),
      head: normalizeHead(rows[0].head, 'verify'),
    };
  }

  return {
    durable: true,
    persisted: true,
    strict: true,
    forkAware: true,
    atomicAppend: true,
    appendOnly: true,
    version: PG_EVIDENCE_VERSION,
    scope,
    readHead,
    head: readHead,
    getById,
    appendIfHead,
    readAll,
    all: readAll,
    async verify(streamId) {
      try {
        const snapshot = await readSnapshot(streamId);
        return verifyHistory(snapshot.records, snapshot.head);
      } catch {
        return { ok: false, reason: 'backend_read_failed_or_malformed' };
      }
    },
    async health() {
      const rows = queryRows(await query(EVIDENCE_SQL.health, []), 'health');
      if (rows.length !== 1) throw new Error('health: Postgres did not return one readiness row');
      const checks = {
        recordsReady: rows[0].records_ready === true,
        headsReady: rows[0].heads_ready === true,
        appendReady: rows[0].append_ready === true,
        canReadRecords: rows[0].can_read_records === true,
        canReadHeads: rows[0].can_read_heads === true,
        noDirectRecordWrites: rows[0].can_write_records_directly === false,
        noDirectHeadWrites: rows[0].can_write_heads_directly === false,
        canAppend: rows[0].can_append === true,
      };
      return {
        ok: Object.values(checks).every(Boolean),
        version: PG_EVIDENCE_VERSION,
        scope,
        checks,
      };
    },
  };
}

const postgresEvidence = {
  createPostgresEvidenceBackend,
  EVIDENCE_SQL,
  EVIDENCE_SCHEMA,
  EVIDENCE_RECORDS_TABLE,
  EVIDENCE_HEADS_TABLE,
  EVIDENCE_APPEND_FUNCTION,
  PG_EVIDENCE_VERSION,
};

export default postgresEvidence;
