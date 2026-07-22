// SPDX-License-Identifier: Apache-2.0
/**
 * Durable, tenant-aware PostgreSQL CAS store for the Remedy Program kernel.
 *
 * Tables are never addressed directly. Each operation calls one service-role
 * RPC on one pinned pg client inside an explicit transaction. Logical refusals
 * have stable reasons; malformed rows, connection failures, and uncertain
 * commit outcomes throw so callers cannot mistake ambiguity for success.
 */
import { createHash } from 'node:crypto';
import { canonicalize } from '../execution-binding.js';
import type {
  RemedyProgramResult,
  RemedyProgramState,
  RemedyProgramStore,
} from './remedy-program.js';

export const REMEDY_PROGRAM_PG_STORE_VERSION = 'EP-GATE-REMEDY-PROGRAM-PG-STORE-v1';
export const REMEDY_PROGRAM_MAX_STATE_BYTES = 4 * 1024 * 1024;
export const REMEDY_PROGRAM_MAX_FORWARD_SKEW_MINUTES = 5;

const INSTANCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const STRICT_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const ENVELOPE_KEYS = new Set([
  'ok', 'reason', 'tenant_id', 'instance_id', 'revision',
  'state_json', 'state_digest', 'recorded_at',
]);

type RecordLike = Record<string, any>;
type QueryResult = { rowCount: number | null; rows?: any[] };
type PgClient = {
  query: (text: string, params?: any[]) => Promise<QueryResult>;
  release: () => void;
};
type PgPool = { connect: () => Promise<PgClient> };

export const REMEDY_PROGRAM_POSTGRES_SQL = Object.freeze({
  create: `SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest, recorded_at
FROM remedy_program_private.remedy_program_create(
  $1::text, $2::text, $3::text, $4::text, $5::text
)`,
  get: `SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest, recorded_at
FROM remedy_program_private.remedy_program_get($1::text, $2::text)`,
  compareAndSwap: `SELECT ok, reason, tenant_id, instance_id, revision, state_json, state_digest, recorded_at
FROM remedy_program_private.remedy_program_compare_and_swap(
  $1::text, $2::text, $3::bigint, $4::bigint, $5::text, $6::text, $7::text
)`,
});

function isRecord(value: unknown): value is RecordLike {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: RecordLike, expected: ReadonlySet<string>) {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.size
    && keys.every((key) => typeof key === 'string' && expected.has(key));
}

function fail(reason: string): RemedyProgramResult {
  return { ok: false, reason };
}

function assertTenantId(value: unknown): asserts value is string {
  if (typeof value !== 'string'
      || Buffer.byteLength(value, 'utf8') < 1
      || Buffer.byteLength(value, 'utf8') > 512
      || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new TypeError('remedy-program tenantId is invalid');
  }
}

function assertInstanceId(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !INSTANCE_ID.test(value)) {
    throw new TypeError('remedy-program instanceId is invalid');
  }
}

function assertRevision(value: unknown, label: string): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`remedy-program ${label} revision is invalid`);
  }
}

function stateDigest(stateJson: string) {
  return `sha256:${createHash('sha256').update(stateJson, 'utf8').digest('hex')}`;
}

function stateEventAt(state: RecordLike) {
  const value = state.updated_at;
  if (typeof value !== 'string'
      || !STRICT_INSTANT.test(value)
      || !Number.isFinite(Date.parse(value))) {
    throw new TypeError('remedy-program state updated_at is invalid');
  }
  return value;
}

function encodeState(
  state: unknown,
  tenantId: string,
  instanceId: string,
  revision: number,
) {
  if (!isRecord(state)
      || state.tenant_id !== tenantId
      || state.instance_id !== instanceId
      || state.revision !== revision) {
    throw new TypeError('remedy-program state binding does not match the store operation');
  }
  let stateJson: string;
  try {
    stateJson = canonicalize(state);
  } catch {
    throw new TypeError('remedy-program state must be canonical JSON');
  }
  if (Buffer.byteLength(stateJson, 'utf8') > REMEDY_PROGRAM_MAX_STATE_BYTES) {
    throw new TypeError('remedy-program state exceeds the durable store limit');
  }
  return {
    stateJson,
    stateDigest: stateDigest(stateJson),
    eventAt: stateEventAt(state),
  };
}

function safeRevision(value: unknown) {
  const revision = typeof value === 'string' && /^(?:0|[1-9]\d*)$/.test(value)
    ? Number(value)
    : value;
  if (!Number.isSafeInteger(revision) || (revision as number) < 0) {
    throw new Error('remedy-program Postgres returned an invalid revision');
  }
  return revision as number;
}

function assertRecordedAt(value: unknown) {
  if (typeof value !== 'string'
      || !STRICT_INSTANT.test(value)
      || !Number.isFinite(Date.parse(value))) {
    throw new Error('remedy-program Postgres returned an invalid recorded_at');
  }
}

function decodeState(
  row: RecordLike,
  expectedTenantId: string,
  expectedInstanceId: string,
  expectedRevision?: number,
) {
  if (row.tenant_id !== expectedTenantId
      || row.instance_id !== expectedInstanceId
      || typeof row.state_json !== 'string'
      || typeof row.state_digest !== 'string'
      || !DIGEST.test(row.state_digest)
      || Buffer.byteLength(row.state_json, 'utf8') > REMEDY_PROGRAM_MAX_STATE_BYTES
      || row.state_digest !== stateDigest(row.state_json)) {
    throw new Error('remedy-program Postgres returned an invalid state envelope');
  }
  assertRecordedAt(row.recorded_at);
  const revision = safeRevision(row.revision);
  if (expectedRevision !== undefined && revision !== expectedRevision) {
    throw new Error('remedy-program Postgres returned an unexpected revision');
  }

  let state: unknown;
  try {
    state = JSON.parse(row.state_json);
    if (!isRecord(state)
        || canonicalize(state) !== row.state_json
        || state.tenant_id !== expectedTenantId
        || state.instance_id !== expectedInstanceId
        || state.revision !== revision) {
      throw new Error('state binding mismatch');
    }
    stateEventAt(state);
  } catch {
    throw new Error('remedy-program Postgres returned non-canonical state');
  }
  return state as RemedyProgramState;
}

function definitiveRow(
  result: QueryResult,
  operation: string,
  tenantId: string,
  instanceId: string,
  allowedReasons: ReadonlySet<string>,
  expectedRevision?: number,
): RemedyProgramResult {
  if (!result || result.rowCount !== 1 || !Array.isArray(result.rows) || result.rows.length !== 1) {
    throw new Error(`remedy-program ${operation} outcome is ambiguous`);
  }
  const row = result.rows[0];
  if (!isRecord(row) || !exactKeys(row, ENVELOPE_KEYS) || typeof row.ok !== 'boolean') {
    throw new Error(`remedy-program ${operation} outcome is malformed`);
  }
  if (row.tenant_id !== tenantId || row.instance_id !== instanceId) {
    throw new Error(`remedy-program ${operation} Postgres returned a mismatched identity`);
  }
  if (!row.ok) {
    if (typeof row.reason !== 'string'
        || !allowedReasons.has(row.reason)
        || row.revision !== null
        || row.state_json !== null
        || row.state_digest !== null
        || row.recorded_at !== null) {
      throw new Error(`remedy-program ${operation} refusal is unrecognized`);
    }
    return fail(row.reason);
  }
  if (row.reason !== null) {
    throw new Error(`remedy-program ${operation} success carried a refusal reason`);
  }
  return {
    ok: true,
    state: decodeState(row, tenantId, instanceId, expectedRevision),
  };
}

function lookupInput(value: unknown) {
  if (!isRecord(value)
      || Reflect.ownKeys(value).length !== 2
      || !Object.hasOwn(value, 'tenantId')
      || !Object.hasOwn(value, 'instanceId')) {
    throw new TypeError('remedy-program lookup input is invalid');
  }
  assertTenantId(value.tenantId);
  assertInstanceId(value.instanceId);
  return { tenantId: value.tenantId, instanceId: value.instanceId };
}

/** Build the exact durable store consumed by createRemedyProgramKernel(). */
export function createRemedyProgramPostgresStore(
  { pool }: { pool?: PgPool } = {},
): RemedyProgramStore {
  if (!pool || typeof pool.connect !== 'function') {
    throw new TypeError(
      'createRemedyProgramPostgresStore requires a transaction-capable pg pool',
    );
  }

  async function transaction<T>(readOnly: boolean, work: (client: PgClient) => Promise<T>) {
    const client = await pool!.connect();
    if (!client || typeof client.query !== 'function' || typeof client.release !== 'function') {
      throw new TypeError('remedy-program pg pool returned an invalid client');
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
            'remedy-program transaction and rollback both failed',
          );
        }
      }
      throw error;
    } finally {
      client.release();
    }
  }

  return Object.freeze({
    durable: true,
    async create(state: RemedyProgramState) {
      const tenantId = (state as RecordLike)?.tenant_id;
      const instanceId = (state as RecordLike)?.instance_id;
      assertTenantId(tenantId);
      assertInstanceId(instanceId);
      const encoded = encodeState(state, tenantId, instanceId, 0);
      return transaction(false, async (client) => definitiveRow(
        await client.query(REMEDY_PROGRAM_POSTGRES_SQL.create, [
          tenantId,
          instanceId,
          encoded.stateJson,
          encoded.stateDigest,
          encoded.eventAt,
        ]),
        'create',
        tenantId,
        instanceId,
        new Set([
          'instance_exists', 'clock_forward_skew',
          'evidence_replayed', 'remedy_operation_replayed',
        ]),
        0,
      ));
    },
    async get(input: { tenantId: string; instanceId: string }) {
      const { tenantId, instanceId } = lookupInput(input);
      return transaction(true, async (client) => definitiveRow(
        await client.query(REMEDY_PROGRAM_POSTGRES_SQL.get, [tenantId, instanceId]),
        'get',
        tenantId,
        instanceId,
        new Set(['instance_not_found']),
      ));
    },
    async compareAndSwap(input: {
      tenantId: string;
      instanceId: string;
      expectedRevision: number;
      state: RemedyProgramState;
    }) {
      if (!isRecord(input)
          || Reflect.ownKeys(input).length !== 4
          || !Object.hasOwn(input, 'tenantId')
          || !Object.hasOwn(input, 'instanceId')
          || !Object.hasOwn(input, 'expectedRevision')
          || !Object.hasOwn(input, 'state')) {
        throw new TypeError('remedy-program compareAndSwap input is invalid');
      }
      const { tenantId, instanceId, expectedRevision, state } = input;
      assertTenantId(tenantId);
      assertInstanceId(instanceId);
      assertRevision(expectedRevision, 'expected');
      const nextRevision = expectedRevision + 1;
      if (!Number.isSafeInteger(nextRevision)) {
        throw new TypeError('remedy-program next revision is invalid');
      }
      const encoded = encodeState(state, tenantId, instanceId, nextRevision);
      return transaction(false, async (client) => definitiveRow(
        await client.query(REMEDY_PROGRAM_POSTGRES_SQL.compareAndSwap, [
          tenantId,
          instanceId,
          expectedRevision,
          nextRevision,
          encoded.stateJson,
          encoded.stateDigest,
          encoded.eventAt,
        ]),
        'compareAndSwap',
        tenantId,
        instanceId,
        new Set([
          'instance_not_found', 'revision_conflict',
          'clock_regression', 'clock_forward_skew',
          'evidence_replayed', 'remedy_operation_replayed',
        ]),
        nextRevision,
      ));
    },
  });
}

export default {
  REMEDY_PROGRAM_PG_STORE_VERSION,
  REMEDY_PROGRAM_MAX_STATE_BYTES,
  REMEDY_PROGRAM_MAX_FORWARD_SKEW_MINUTES,
  REMEDY_PROGRAM_POSTGRES_SQL,
  createRemedyProgramPostgresStore,
};
