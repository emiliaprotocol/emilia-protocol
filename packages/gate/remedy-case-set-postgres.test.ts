// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { canonicalize } from './execution-binding.js';
import {
  REMEDY_CASE_SET_EVENT_TABLE,
  REMEDY_CASE_SET_POSTGRES_DDL,
  REMEDY_CASE_SET_POSTGRES_SQL,
  REMEDY_CASE_SET_TABLE,
  createRemedyCaseSetPostgresStore,
} from './remedy-case-set-postgres.js';

const VERSION = 'EP-GATE-REMEDY-CASE-SET-v1';
const HASH = (char: string) => `sha256:${char.repeat(64)}`;
const CAID = (char: string) => `caid:1:remedy.perform.1:jcs-sha256:${char.repeat(43)}`;

function digest(value: unknown) {
  return `sha256:${createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}

function caseState({
  tenantId = 'tenant-1',
  caseSetId = 'case-set-1',
  ownerTokenDigest = HASH('a'),
  revision = 0,
  status = revision === 0 ? 'open' : 'indeterminate',
}: {
  tenantId?: string;
  caseSetId?: string;
  ownerTokenDigest?: string;
  revision?: number;
  status?: 'open' | 'indeterminate' | 'completed';
} = {}) {
  const manifest = {
    version: VERSION,
    tenant_id: tenantId,
    case_set_id: caseSetId,
    legs: [{
      leg_id: 'return',
      child_instance_id: 'child-return',
      remedy_profile_digest: HASH('b'),
      destination_binding_digest: HASH('c'),
      max_remedy_units: 1,
      unit: 'item',
      original: {
        caid: CAID('O'),
        action_digest: HASH('d'),
        operation_id: 'purchase-1',
        consequence_mode: 'receipt-program',
        consequence_digest: HASH('e'),
        terminal_evidence_digest: HASH('f'),
        outcome: 'executed',
        occurred_at: '2026-07-22T18:00:00.000Z',
      },
      remedy: {
        operation_id: 'return-1',
        caid: CAID('R'),
        action_digest: HASH('1'),
        owner_mode: 'receipt-program',
        owner_digest: HASH('2'),
      },
    }],
  };
  const observationStatus = status === 'open'
    ? 'pending'
    : status === 'completed' ? 'executed' : 'indeterminate';
  return {
    version: VERSION,
    tenant_id: tenantId,
    case_set_id: caseSetId,
    status,
    revision,
    created_at: '2026-07-22T19:00:00.000Z',
    updated_at: new Date(Date.parse('2026-07-22T19:00:00.000Z') + revision * 1_000).toISOString(),
    owner_token_digest: ownerTokenDigest,
    manifest,
    manifest_digest: digest(manifest),
    observations: [{
      leg_id: 'return',
      status: observationStatus,
      case_revision: status === 'open' ? null : revision,
      receipt_content_digest: status === 'open' ? null : HASH('3'),
      state_snapshot_digest: status === 'open' ? null : HASH('4'),
    }],
    create_request_digest: HASH('5'),
    last_request_digest: revision === 0 ? null : HASH('6'),
  };
}

type CurrentRow = {
  tenant_id: string;
  case_set_id: string;
  revision: number;
  status: string;
  owner_token_digest: string;
  manifest_json: string;
  manifest_digest: string;
  state_json: string;
  state_digest: string;
  recorded_at: string;
};

type EventRow = {
  tenant_id: string;
  case_set_id: string;
  revision: number;
  previous_revision: number | null;
  status: string;
  state_json: string;
  state_digest: string;
  recorded_at: string;
};

type QueryResult = { rowCount: number | null; rows: Record<string, unknown>[] };

function fakePostgres() {
  const records = new Map<string, CurrentRow>();
  const events = new Map<string, EventRow[]>();
  const key = (tenantId: string, caseSetId: string) => JSON.stringify([tenantId, caseSetId]);
  let nextClock = Date.parse('2026-07-22T19:00:10.000Z');
  let failNextCommit = false;
  let transformNext: null | {
    target: string;
    transform: (text: string, result: QueryResult) => QueryResult;
  } = null;

  function cloneMap<T>(source: Map<string, T>) {
    return new Map(Array.from(source, ([entryKey, value]) => [entryKey, structuredClone(value)]));
  }

  function restoreMap<T>(target: Map<string, T>, snapshot: Map<string, T>) {
    target.clear();
    for (const [entryKey, value] of snapshot) target.set(entryKey, structuredClone(value));
  }

  function currentResult(row: CurrentRow): QueryResult {
    return {
      rowCount: 1,
      rows: [{
        tenant_id: row.tenant_id,
        case_set_id: row.case_set_id,
        revision: row.revision,
        status: row.status,
        owner_token_digest: row.owner_token_digest,
        manifest_json: row.manifest_json,
        manifest_digest: row.manifest_digest,
        state_json: row.state_json,
        state_digest: row.state_digest,
        recorded_at: row.recorded_at,
      }],
    };
  }

  const pool = {
    async connect() {
      let recordSnapshot = cloneMap(records);
      let eventSnapshot = cloneMap(events);
      let inTransaction = false;
      let tenantContext: string | null = null;
      let transactionClock: string | null = null;

      return {
        async query(text: string, params: any[] = []): Promise<QueryResult> {
          let result: QueryResult;
          if (text.startsWith('BEGIN ')) {
            recordSnapshot = cloneMap(records);
            eventSnapshot = cloneMap(events);
            inTransaction = true;
            result = { rowCount: null, rows: [] };
          } else if (text === 'COMMIT') {
            if (failNextCommit) {
              failNextCommit = false;
              throw new Error('commit unavailable');
            }
            inTransaction = false;
            result = { rowCount: null, rows: [] };
          } else if (text === 'ROLLBACK') {
            restoreMap(records, recordSnapshot);
            restoreMap(events, eventSnapshot);
            inTransaction = false;
            result = { rowCount: null, rows: [] };
          } else if (text === REMEDY_CASE_SET_POSTGRES_SQL.setTenant) {
            tenantContext = params[0];
            result = { rowCount: 1, rows: [{ tenant_id: tenantContext }] };
          } else if (text === REMEDY_CASE_SET_POSTGRES_SQL.clock) {
            transactionClock ??= new Date(nextClock++).toISOString();
            result = { rowCount: 1, rows: [{ recorded_at: transactionClock }] };
          } else if (text === REMEDY_CASE_SET_POSTGRES_SQL.create) {
            const [
              tenantId, caseSetId, status, ownerTokenDigest, manifestJson,
              manifestDigest, stateJson, stateDigest, recordedAt,
            ] = params;
            assert.equal(tenantContext, tenantId);
            const recordKey = key(tenantId, caseSetId);
            if (records.has(recordKey)) {
              result = { rowCount: 0, rows: [] };
            } else {
              const row: CurrentRow = {
                tenant_id: tenantId,
                case_set_id: caseSetId,
                revision: 0,
                status,
                owner_token_digest: ownerTokenDigest,
                manifest_json: manifestJson,
                manifest_digest: manifestDigest,
                state_json: stateJson,
                state_digest: stateDigest,
                recorded_at: recordedAt,
              };
              records.set(recordKey, row);
              result = currentResult(row);
            }
          } else if (text === REMEDY_CASE_SET_POSTGRES_SQL.get
              || text === REMEDY_CASE_SET_POSTGRES_SQL.getForUpdate) {
            const [tenantId, caseSetId] = params;
            assert.equal(tenantContext, tenantId);
            const row = records.get(key(tenantId, caseSetId));
            result = row ? currentResult(row) : { rowCount: 0, rows: [] };
          } else if (text === REMEDY_CASE_SET_POSTGRES_SQL.compareAndSwap) {
            const [
              tenantId, caseSetId, expectedRevision, ownerTokenDigest,
              nextRevision, status, stateJson, stateDigest, recordedAt,
              manifestJson, manifestDigest,
            ] = params;
            assert.equal(tenantContext, tenantId);
            const recordKey = key(tenantId, caseSetId);
            const row = records.get(recordKey);
            if (!row
                || row.revision !== expectedRevision
                || row.owner_token_digest !== ownerTokenDigest
                || row.status === 'completed'
                || row.manifest_json !== manifestJson
                || row.manifest_digest !== manifestDigest) {
              result = { rowCount: 0, rows: [] };
            } else {
              const updated = {
                ...row,
                revision: nextRevision,
                status,
                state_json: stateJson,
                state_digest: stateDigest,
                recorded_at: recordedAt,
              };
              records.set(recordKey, updated);
              result = currentResult(updated);
            }
          } else if (text === REMEDY_CASE_SET_POSTGRES_SQL.appendEvent) {
            const [
              tenantId, caseSetId, revision, previousRevision, status,
              stateJson, stateDigest, recordedAt,
            ] = params;
            assert.equal(tenantContext, tenantId);
            const recordKey = key(tenantId, caseSetId);
            const history = events.get(recordKey) ?? [];
            const event: EventRow = {
              tenant_id: tenantId,
              case_set_id: caseSetId,
              revision,
              previous_revision: previousRevision,
              status,
              state_json: stateJson,
              state_digest: stateDigest,
              recorded_at: recordedAt,
            };
            history.push(event);
            events.set(recordKey, history);
            result = {
              rowCount: 1,
              rows: [{
                tenant_id: tenantId,
                case_set_id: caseSetId,
                revision,
                state_digest: stateDigest,
                recorded_at: recordedAt,
              }],
            };
          } else {
            throw new Error(`unexpected SQL: ${text}`);
          }

          if (transformNext?.target === text) {
            const { transform } = transformNext;
            transformNext = null;
            return transform(text, structuredClone(result));
          }
          return structuredClone(result);
        },
        release() {
          if (inTransaction) throw new Error('client released with open transaction');
        },
      };
    },
  };

  return {
    pool,
    records,
    events,
    key,
    failCommit() {
      failNextCommit = true;
    },
    transformNextResult(
      target: string,
      transform: (text: string, result: QueryResult) => QueryResult,
    ) {
      transformNext = { target, transform };
    },
  };
}

test('DDL is tenant-keyed, RPC-only, and makes manifests, terminal rows, and events immutable', () => {
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, new RegExp(
    `CREATE TABLE IF NOT EXISTS ${REMEDY_CASE_SET_TABLE}`,
  ));
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, /PRIMARY KEY \(tenant_id, case_set_id\)/);
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, /ENABLE ROW LEVEL SECURITY/);
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, /CREATE ROLE ep_remedy_executor NOLOGIN/);
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, /CREATE ROLE ep_remedy_store_owner NOLOGIN/);
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, /TO ep_remedy_store_owner USING \(TRUE\) WITH CHECK \(TRUE\)/);
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, /OWNER TO ep_remedy_store_owner/);
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, /NOBYPASSRLS/);
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, /principals\.principal_name = SESSION_USER/);
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, /SECURITY DEFINER SET search_path = ''/);
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, /REVOKE ALL ON ep_remedy_case_sets[\s\S]+service_role/);
  assert.doesNotMatch(REMEDY_CASE_SET_POSTGRES_DDL, /GRANT ALL ON ep_remedy_case_sets/);
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, /transaction_timestamp\(\)/);
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, /OLD\.manifest_json IS DISTINCT FROM NEW\.manifest_json/);
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, /OLD\.status = 'completed'/);
  assert.match(REMEDY_CASE_SET_POSTGRES_DDL, new RegExp(
    `BEFORE UPDATE OR DELETE ON ${REMEDY_CASE_SET_EVENT_TABLE}`,
  ));
});

test('concurrent create has one winner and one tenant-scoped conflict', async () => {
  const pg = fakePostgres();
  const first = createRemedyCaseSetPostgresStore({ pool: pg.pool });
  const second = createRemedyCaseSetPostgresStore({ pool: pg.pool });
  const state = caseState();

  const results = await Promise.all([first.create(state as any), second.create(state as any)]);
  assert.equal(results.filter((result) => result.ok).length, 1);
  assert.equal(
    results.filter((result) => !result.ok && result.reason === 'case_set_exists').length,
    1,
  );
  assert.equal(pg.records.size, 1);
  assert.equal(pg.events.get(pg.key('tenant-1', 'case-set-1'))?.length, 1);
});

test('same case-set id is isolated across tenants and a restarted store resumes exact CAS state', async () => {
  const pg = fakePostgres();
  const firstProcess = createRemedyCaseSetPostgresStore({ pool: pg.pool });
  const tenantOne = caseState({ tenantId: 'tenant-a', caseSetId: 'shared-case' });
  const tenantTwo = caseState({ tenantId: 'tenant-b', caseSetId: 'shared-case' });

  assert.equal((await firstProcess.create(tenantOne as any)).ok, true);
  assert.equal((await firstProcess.create(tenantTwo as any)).ok, true);
  assert.deepEqual(
    await firstProcess.get({ tenantId: 'tenant-c', caseSetId: 'shared-case' }),
    { ok: false, reason: 'case_set_not_found' },
  );

  const restarted = createRemedyCaseSetPostgresStore({ pool: pg.pool });
  assert.deepEqual(
    (await restarted.get({ tenantId: 'tenant-b', caseSetId: 'shared-case' })).state,
    tenantTwo,
  );
  const resumed = caseState({
    tenantId: 'tenant-b',
    caseSetId: 'shared-case',
    revision: 1,
    status: 'indeterminate',
  });
  assert.equal((await restarted.compareAndSwap({
    tenantId: 'tenant-b',
    caseSetId: 'shared-case',
    expectedRevision: 0,
    ownerTokenDigest: tenantTwo.owner_token_digest,
    state: resumed as any,
  })).ok, true);
  assert.deepEqual(
    (await restarted.get({ tenantId: 'tenant-b', caseSetId: 'shared-case' })).state,
    resumed,
  );
});

test('CAS refuses the wrong owner digest without changing state', async () => {
  const pg = fakePostgres();
  const store = createRemedyCaseSetPostgresStore({ pool: pg.pool });
  const initial = caseState();
  await store.create(initial as any);
  const next = caseState({ revision: 1, status: 'indeterminate' });

  assert.deepEqual(await store.compareAndSwap({
    tenantId: initial.tenant_id,
    caseSetId: initial.case_set_id,
    expectedRevision: 0,
    ownerTokenDigest: HASH('9'),
    state: next as any,
  }), { ok: false, reason: 'ownership_conflict' });
  assert.equal(pg.records.get(pg.key(initial.tenant_id, initial.case_set_id))?.revision, 0);
  assert.equal(pg.events.get(pg.key(initial.tenant_id, initial.case_set_id))?.length, 1);
});

test('CAS refuses a changed manifest even when its replacement digest is internally valid', async () => {
  const pg = fakePostgres();
  const store = createRemedyCaseSetPostgresStore({ pool: pg.pool });
  const initial = caseState();
  await store.create(initial as any);
  const changed = caseState({ revision: 1, status: 'indeterminate' });
  changed.manifest.legs[0].unit = 'replacement-item';
  changed.manifest_digest = digest(changed.manifest);

  assert.deepEqual(await store.compareAndSwap({
    tenantId: initial.tenant_id,
    caseSetId: initial.case_set_id,
    expectedRevision: 0,
    ownerTokenDigest: initial.owner_token_digest,
    state: changed as any,
  }), { ok: false, reason: 'manifest_conflict' });
  assert.equal(pg.records.get(pg.key(initial.tenant_id, initial.case_set_id))?.revision, 0);
  assert.equal(pg.events.get(pg.key(initial.tenant_id, initial.case_set_id))?.length, 1);
});

test('CAS refuses a stale revision and preserves the winning update', async () => {
  const pg = fakePostgres();
  const store = createRemedyCaseSetPostgresStore({ pool: pg.pool });
  const initial = caseState();
  await store.create(initial as any);
  const next = caseState({ revision: 1, status: 'indeterminate' });
  assert.equal((await store.compareAndSwap({
    tenantId: initial.tenant_id,
    caseSetId: initial.case_set_id,
    expectedRevision: 0,
    ownerTokenDigest: initial.owner_token_digest,
    state: next as any,
  })).ok, true);

  assert.deepEqual(await store.compareAndSwap({
    tenantId: initial.tenant_id,
    caseSetId: initial.case_set_id,
    expectedRevision: 0,
    ownerTokenDigest: initial.owner_token_digest,
    state: next as any,
  }), { ok: false, reason: 'revision_conflict' });
  assert.deepEqual(
    (await store.get({ tenantId: initial.tenant_id, caseSetId: initial.case_set_id })).state,
    next,
  );
});

test('completed case sets cannot be reopened or rewritten', async () => {
  const pg = fakePostgres();
  const store = createRemedyCaseSetPostgresStore({ pool: pg.pool });
  const initial = caseState();
  const terminal = caseState({ revision: 1, status: 'completed' });
  await store.create(initial as any);
  assert.equal((await store.compareAndSwap({
    tenantId: initial.tenant_id,
    caseSetId: initial.case_set_id,
    expectedRevision: 0,
    ownerTokenDigest: initial.owner_token_digest,
    state: terminal as any,
  })).ok, true);

  const reopened = caseState({ revision: 2, status: 'indeterminate' });
  assert.deepEqual(await store.compareAndSwap({
    tenantId: initial.tenant_id,
    caseSetId: initial.case_set_id,
    expectedRevision: 1,
    ownerTokenDigest: initial.owner_token_digest,
    state: reopened as any,
  }), { ok: false, reason: 'case_set_terminal' });
  assert.deepEqual(
    (await store.get({ tenantId: initial.tenant_id, caseSetId: initial.case_set_id })).state,
    terminal,
  );
});

test('malformed PostgreSQL responses and database errors fail closed', async () => {
  const pg = fakePostgres();
  const store = createRemedyCaseSetPostgresStore({ pool: pg.pool });
  const initial = caseState();
  await store.create(initial as any);

  pg.transformNextResult(REMEDY_CASE_SET_POSTGRES_SQL.setTenant, (_text, _result) => {
    return { rowCount: 1, rows: [{ tenant_id: 'tenant-confused' }] };
  });
  await assert.rejects(
    () => store.get({ tenantId: initial.tenant_id, caseSetId: initial.case_set_id }),
    /tenant context/,
  );

  pg.transformNextResult(REMEDY_CASE_SET_POSTGRES_SQL.get, (_text, result) => {
    return {
      ...result,
      rows: [{ ...result.rows[0], state_digest: HASH('0'), unexpected: true }],
    };
  });
  await assert.rejects(
    () => store.get({ tenantId: initial.tenant_id, caseSetId: initial.case_set_id }),
    /malformed|invalid/,
  );

  const unavailable = createRemedyCaseSetPostgresStore({
    pool: { connect: async () => { throw new Error('database unavailable'); } },
  });
  await assert.rejects(
    () => unavailable.get({ tenantId: initial.tenant_id, caseSetId: initial.case_set_id }),
    /database unavailable/,
  );
});

test('write failure rolls current state and event back; uncertain commit fails closed', async () => {
  const pg = fakePostgres();
  const store = createRemedyCaseSetPostgresStore({ pool: pg.pool });
  const initial = caseState();
  await store.create(initial as any);
  const next = caseState({ revision: 1, status: 'indeterminate' });

  pg.transformNextResult(REMEDY_CASE_SET_POSTGRES_SQL.appendEvent, (_text, result) => ({
    ...result,
    rows: [{ ...result.rows[0], unexpected: true }],
  }));
  await assert.rejects(
    () => store.compareAndSwap({
      tenantId: initial.tenant_id,
      caseSetId: initial.case_set_id,
      expectedRevision: 0,
      ownerTokenDigest: initial.owner_token_digest,
      state: next as any,
    }),
    /appendEvent outcome is malformed/,
  );
  assert.equal(pg.records.get(pg.key(initial.tenant_id, initial.case_set_id))?.revision, 0);
  assert.equal(pg.events.get(pg.key(initial.tenant_id, initial.case_set_id))?.length, 1);

  pg.failCommit();

  await assert.rejects(
    () => store.compareAndSwap({
      tenantId: initial.tenant_id,
      caseSetId: initial.case_set_id,
      expectedRevision: 0,
      ownerTokenDigest: initial.owner_token_digest,
      state: next as any,
    }),
    /commit unavailable/,
  );
  assert.equal(pg.records.get(pg.key(initial.tenant_id, initial.case_set_id))?.revision, 0);
  assert.equal(pg.events.get(pg.key(initial.tenant_id, initial.case_set_id))?.length, 1);
});
