// SPDX-License-Identifier: Apache-2.0
/**
 * Durable PostgreSQL store for the Gate Trust Program kernel.
 *
 * The database is RPC-only. Every operation runs on one pinned pg client so a
 * transaction can never be split across pooled connections. Logical conflicts
 * are returned as stable store reasons; database ambiguity and outages throw.
 */
import crypto from 'node:crypto';
import { canonicalize } from './execution-binding.js';

export const TRUST_PROGRAM_PG_STORE_VERSION = 'EP-GATE-TRUST-PROGRAM-PG-STORE-v1';
export const TRUST_PROGRAM_MAX_STATE_BYTES = 4 * 1024 * 1024;

const INSTANCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const STRICT_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

type RecordLike = Record<string, any>;
type QueryResult = { rowCount: number | null; rows?: any[] };
type PgClient = {
  query: (text: string, params?: any[]) => Promise<QueryResult>;
  release: () => void;
};
type PgPool = { connect: () => Promise<PgClient> };

export const TRUST_PROGRAM_POSTGRES_SQL = Object.freeze({
  create: `SELECT ok, reason, instance_id, revision, state_json, state_digest
FROM trust_program_private.trust_program_create($1::text, $2::text, $3::text, $4::text)`,
  get: `SELECT ok, reason, instance_id, revision, state_json, state_digest
FROM trust_program_private.trust_program_get($1::text)`,
  compareAndSwap: `SELECT ok, reason, instance_id, revision, state_json, state_digest
FROM trust_program_private.trust_program_compare_and_swap(
  $1::text, $2::bigint, $3::bigint, $4::text, $5::text, $6::text
)`,
  invalidate: `SELECT ok, reason, instance_id, revision, state_json, state_digest
FROM trust_program_private.trust_program_invalidate(
  $1::text, $2::bigint, $3::text, $4::text, $5::text, $6::text
)`,
});

function isRecord(value: unknown): value is RecordLike {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function fail(reason: string) {
  return { ok: false as const, reason };
}

function assertInstanceId(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !INSTANCE_ID.test(value)) {
    throw new TypeError('trust-program instanceId is invalid');
  }
}

function assertRevision(value: unknown, label: string): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`trust-program ${label} revision is invalid`);
  }
}

function stateDigest(stateJson: string) {
  return `sha256:${crypto.createHash('sha256').update(stateJson, 'utf8').digest('hex')}`;
}

function stateEventAt(state: RecordLike) {
  const value = state.updated_at;
  if (typeof value !== 'string' || !STRICT_INSTANT.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new TypeError('trust-program state updated_at is invalid');
  }
  return value;
}

function encodeState(state: unknown, instanceId: string, revision: number) {
  if (!isRecord(state) || state.instance_id !== instanceId || state.revision !== revision) {
    throw new TypeError('trust-program state binding does not match the store operation');
  }
  let stateJson: string;
  try {
    stateJson = canonicalize(state);
  } catch {
    throw new TypeError('trust-program state must be canonical JSON');
  }
  if (Buffer.byteLength(stateJson, 'utf8') > TRUST_PROGRAM_MAX_STATE_BYTES) {
    throw new TypeError('trust-program state exceeds the durable store limit');
  }
  return {
    stateJson,
    stateDigest: stateDigest(stateJson),
    eventAt: stateEventAt(state),
  };
}

function safeRevision(value: unknown) {
  const revision = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(revision) || (revision as number) < 0) {
    throw new Error('trust-program Postgres returned an invalid revision');
  }
  return revision as number;
}

function decodeState(row: RecordLike, expectedInstanceId: string, expectedRevision?: number) {
  if (row.instance_id !== expectedInstanceId
      || typeof row.state_json !== 'string'
      || typeof row.state_digest !== 'string'
      || !DIGEST.test(row.state_digest)
      || Buffer.byteLength(row.state_json, 'utf8') > TRUST_PROGRAM_MAX_STATE_BYTES
      || row.state_digest !== stateDigest(row.state_json)) {
    throw new Error('trust-program Postgres returned an invalid state envelope');
  }
  const revision = safeRevision(row.revision);
  if (expectedRevision !== undefined && revision !== expectedRevision) {
    throw new Error('trust-program Postgres returned an unexpected revision');
  }
  let state: unknown;
  try {
    state = JSON.parse(row.state_json);
    if (!isRecord(state)
        || canonicalize(state) !== row.state_json
        || state.instance_id !== expectedInstanceId
        || state.revision !== revision) {
      throw new Error('state mismatch');
    }
    stateEventAt(state);
  } catch {
    throw new Error('trust-program Postgres returned non-canonical state');
  }
  return state as RecordLike;
}

function definitiveRow(
  result: QueryResult,
  operation: string,
  instanceId: string,
  allowedReasons: ReadonlySet<string>,
  expectedRevision?: number,
) {
  if (!result || result.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1) {
    throw new Error(`trust-program ${operation} outcome is ambiguous`);
  }
  const row = result.rows[0];
  if (!isRecord(row) || typeof row.ok !== 'boolean') {
    throw new Error(`trust-program ${operation} outcome is malformed`);
  }
  if (!row.ok) {
    if (typeof row.reason !== 'string' || !allowedReasons.has(row.reason)
        || row.instance_id !== instanceId
        || (row.revision !== null && row.revision !== undefined)
        || (row.state_json !== null && row.state_json !== undefined)
        || (row.state_digest !== null && row.state_digest !== undefined)) {
      throw new Error(`trust-program ${operation} refusal is unrecognized`);
    }
    return fail(row.reason);
  }
  if (row.reason !== null && row.reason !== undefined && row.reason !== '') {
    throw new Error(`trust-program ${operation} success carried a refusal reason`);
  }
  return { ok: true as const, state: decodeState(row, instanceId, expectedRevision) };
}

function invalidatedState(current: RecordLike, reason: string, at: number) {
  if (!isRecord(current.stages)
      || Object.values(current.stages).some((stage) => !isRecord(stage))
      || !isRecord(current.execution)) {
    throw new Error('trust-program stored state cannot be invalidated safely');
  }
  const next = structuredClone(current);
  next.status = 'invalidated';
  next.invalidation_reason = reason;
  next.revision += 1;
  next.updated_at = new Date(at).toISOString();
  for (const stage of Object.values(next.stages) as RecordLike[]) stage.status = 'invalidated';
  if (['locked', 'ready'].includes(next.execution.status)) {
    next.execution.status = 'invalidated';
  }
  return next;
}

/**
 * Create the exact durable store consumed by createTrustProgramKernel().
 * `pool` must provide node-postgres-style connect(), returning a pinned client
 * with query() and release().
 */
export function createTrustProgramPostgresStore({ pool }: { pool?: PgPool } = {}) {
  if (!pool || typeof pool.connect !== 'function') {
    throw new TypeError('createTrustProgramPostgresStore requires a transaction-capable pg pool');
  }

  async function transaction<T>(readOnly: boolean, work: (client: PgClient) => Promise<T>) {
    const client = await pool!.connect();
    if (!client || typeof client.query !== 'function' || typeof client.release !== 'function') {
      throw new TypeError('trust-program pg pool returned an invalid client');
    }
    let began = false;
    try {
      await client.query(readOnly
        ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'
        : 'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE');
      began = true;
      const value = await work(client);
      await client.query('COMMIT');
      began = false;
      return value;
    } catch (error) {
      if (began) {
        try {
          await client.query('ROLLBACK');
        } catch (rollbackError) {
          throw new AggregateError(
            [error, rollbackError],
            'trust-program transaction and rollback both failed',
          );
        }
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async function getWithClient(client: PgClient, instanceId: string) {
    return definitiveRow(
      await client.query(TRUST_PROGRAM_POSTGRES_SQL.get, [instanceId]),
      'get',
      instanceId,
      new Set(['instance_not_found']),
    );
  }

  return Object.freeze({
    version: TRUST_PROGRAM_PG_STORE_VERSION,
    durable: true,
    async create(state: RecordLike) {
      const instanceId = state?.instance_id;
      assertInstanceId(instanceId);
      const encoded = encodeState(state, instanceId, 0);
      return transaction(false, async (client) => definitiveRow(
        await client.query(TRUST_PROGRAM_POSTGRES_SQL.create, [
          instanceId, encoded.stateJson, encoded.stateDigest, encoded.eventAt,
        ]),
        'create',
        instanceId,
        new Set(['instance_exists']),
        0,
      ));
    },
    async get(instanceId: string) {
      assertInstanceId(instanceId);
      return transaction(true, (client) => getWithClient(client, instanceId));
    },
    async compareAndSwap({ instanceId, expectedRevision, state }: RecordLike) {
      assertInstanceId(instanceId);
      assertRevision(expectedRevision, 'expected');
      const nextRevision = expectedRevision + 1;
      if (!Number.isSafeInteger(nextRevision)) {
        throw new TypeError('trust-program next revision is invalid');
      }
      const encoded = encodeState(state, instanceId, nextRevision);
      return transaction(false, async (client) => definitiveRow(
        await client.query(TRUST_PROGRAM_POSTGRES_SQL.compareAndSwap, [
          instanceId,
          expectedRevision,
          nextRevision,
          encoded.stateJson,
          encoded.stateDigest,
          encoded.eventAt,
        ]),
        'compareAndSwap',
        instanceId,
        new Set(['instance_not_found', 'revision_conflict', 'clock_regression']),
        nextRevision,
      ));
    },
    async invalidate({ instanceId, expectedRevision, reason, at }: RecordLike) {
      assertInstanceId(instanceId);
      assertRevision(expectedRevision, 'expected');
      if (typeof reason !== 'string' || reason.length < 1 || reason.length > 256) {
        throw new TypeError('trust-program invalidation reason is invalid');
      }
      if (!Number.isSafeInteger(at) || at < 0 || at > 8_640_000_000_000_000) {
        throw new TypeError('trust-program invalidation time is invalid');
      }
      return transaction(false, async (client) => {
        const loaded = await getWithClient(client, instanceId);
        if (!loaded.ok) return loaded;
        if (loaded.state.revision !== expectedRevision) return fail('revision_conflict');
        if (loaded.state.status === 'invalidated') return fail('program_instance_invalidated');
        const next = invalidatedState(loaded.state, reason, at);
        const encoded = encodeState(next, instanceId, expectedRevision + 1);
        return definitiveRow(
          await client.query(TRUST_PROGRAM_POSTGRES_SQL.invalidate, [
            instanceId,
            expectedRevision,
            reason,
            encoded.eventAt,
            encoded.stateJson,
            encoded.stateDigest,
          ]),
          'invalidate',
          instanceId,
          new Set([
            'instance_not_found', 'revision_conflict', 'program_instance_invalidated',
            'clock_regression',
          ]),
          expectedRevision + 1,
        );
      });
    },
  });
}

export default {
  TRUST_PROGRAM_PG_STORE_VERSION,
  TRUST_PROGRAM_MAX_STATE_BYTES,
  TRUST_PROGRAM_POSTGRES_SQL,
  createTrustProgramPostgresStore,
};
