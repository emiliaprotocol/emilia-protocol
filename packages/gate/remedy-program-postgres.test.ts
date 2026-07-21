// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  REMEDY_PROGRAM_POSTGRES_SQL,
  createRemedyProgramPostgresStore,
} from './remedy-program-postgres.js';

const MIGRATION = readFileSync(
  new URL('../../supabase/migrations/20260721223000_remedy_program_store.sql', import.meta.url),
  'utf8',
);
const RECORDED_AT = '2026-07-21T22:30:00.000000Z';

function digest(value: string) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function initialState(tenantId = 'tenant-1', instanceId = 'remedy-1') {
  return {
    version: 'EP-GATE-REMEDY-PROGRAM-PROFILE-v1',
    tenant_id: tenantId,
    instance_id: instanceId,
    status: 'effect_executed',
    revision: 0,
    created_at: '2026-07-21T22:00:00.000Z',
    updated_at: '2026-07-21T22:00:00.000Z',
    remedied_units: 0,
    remaining_units: 10_000,
    used_evidence_ids: [],
    used_evidence_digests: [digest(`${tenantId}:${instanceId}:original-evidence`)],
    original_reconciliation: null,
    active_remedy: null,
    remedies: [],
  };
}

function authorizedAttempt(suffix: string, overrides: Record<string, unknown> = {}) {
  return {
    remedy_operation_id: `remedy-operation-${suffix}`,
    remedy_action_digest: digest(`remedy-action-${suffix}`),
    remedy_caid: `caid:1:payments.refund.1:jcs-sha256:${suffix[0]!.repeat(43)}`,
    status: 'authorized',
    ...overrides,
  };
}

function fakePostgres() {
  type Stored = {
    tenant_id: string;
    instance_id: string;
    revision: number;
    state_json: string;
    state_digest: string;
    event_at: string;
    recorded_at: string;
  };
  type Event = Stored & { previous_revision: number | null; event_kind: 'create' | 'cas' };

  let records = new Map<string, Stored>();
  let events = new Map<string, Event[]>();
  let evidenceIds = new Map<string, string>();
  let evidenceDigests = new Map<string, string>();
  let remedyOperations = new Map<string, string>();
  let remedyActions = new Map<string, string>();
  let remedyCaids = new Map<string, string>();
  let snapshot: {
    records: Map<string, Stored>;
    events: Map<string, Event[]>;
    evidenceIds: Map<string, string>;
    evidenceDigests: Map<string, string>;
    remedyOperations: Map<string, string>;
    remedyActions: Map<string, string>;
    remedyCaids: Map<string, string>;
  } | null = null;
  let nextResult: unknown = null;
  let nextError: Error | null = null;
  let nextEnvelopeMutation: ((result: any) => any) | null = null;
  let failCommit = false;
  let releases = 0;
  const transactionLog: string[] = [];

  const key = (tenantId: string, instanceId: string) => JSON.stringify([tenantId, instanceId]);
  const copyRecords = () => new Map(
    [...records].map(([recordKey, value]) => [recordKey, structuredClone(value)]),
  );
  const copyEvents = () => new Map(
    [...events].map(([recordKey, value]) => [recordKey, structuredClone(value)]),
  );
  const claimKey = (tenantId: string, value: string) => JSON.stringify([tenantId, value]);
  const attempts = (state: any) => [
    ...(state.active_remedy === null ? [] : [state.active_remedy]),
    ...state.remedies,
  ];
  const newClaims = (current: any | null, candidate: any) => {
    const currentIds = new Set(current?.used_evidence_ids ?? []);
    const currentDigests = new Set(current?.used_evidence_digests ?? []);
    const currentOperations = new Set(
      current === null ? [] : attempts(current).map((attempt) => attempt.remedy_operation_id),
    );
    return {
      evidenceIds: candidate.used_evidence_ids.filter((value: string) => !currentIds.has(value)),
      evidenceDigests: candidate.used_evidence_digests.filter(
        (value: string) => !currentDigests.has(value),
      ),
      attempts: attempts(candidate).filter(
        (attempt) => !currentOperations.has(attempt.remedy_operation_id),
      ),
    };
  };
  const replayReason = (tenantId: string, claims: ReturnType<typeof newClaims>) => {
    if (claims.evidenceIds.some((value: string) => evidenceIds.has(claimKey(tenantId, value)))
        || claims.evidenceDigests.some(
          (value: string) => evidenceDigests.has(claimKey(tenantId, value)),
        )) {
      return 'evidence_replayed';
    }
    if (claims.attempts.some((attempt) => (
      remedyOperations.has(claimKey(tenantId, attempt.remedy_operation_id))
      || remedyActions.has(claimKey(tenantId, attempt.remedy_action_digest))
      || remedyCaids.has(claimKey(tenantId, attempt.remedy_caid))
    ))) {
      return 'remedy_operation_replayed';
    }
    return null;
  };
  const reserveClaims = (
    tenantId: string,
    instanceId: string,
    claims: ReturnType<typeof newClaims>,
  ) => {
    for (const value of claims.evidenceIds) evidenceIds.set(claimKey(tenantId, value), instanceId);
    for (const value of claims.evidenceDigests) {
      evidenceDigests.set(claimKey(tenantId, value), instanceId);
    }
    for (const attempt of claims.attempts) {
      remedyOperations.set(claimKey(tenantId, attempt.remedy_operation_id), instanceId);
      remedyActions.set(claimKey(tenantId, attempt.remedy_action_digest), instanceId);
      remedyCaids.set(claimKey(tenantId, attempt.remedy_caid), instanceId);
    }
  };
  const refusal = (tenantId: string, instanceId: string, reason: string) => ({
    rowCount: 1,
    rows: [{
      ok: false,
      reason,
      tenant_id: tenantId,
      instance_id: instanceId,
      revision: null,
      state_json: null,
      state_digest: null,
      recorded_at: null,
    }],
  });
  const success = (record: Stored) => ({
    rowCount: 1,
    rows: [{
      ok: true,
      reason: null,
      tenant_id: record.tenant_id,
      instance_id: record.instance_id,
      revision: String(record.revision),
      state_json: record.state_json,
      state_digest: record.state_digest,
      recorded_at: record.recorded_at,
    }],
  });
  const respond = (result: any) => {
    if (!nextEnvelopeMutation) return result;
    const mutation = nextEnvelopeMutation;
    nextEnvelopeMutation = null;
    return mutation(structuredClone(result));
  };

  const client = {
    async query(text: string, params: any[] = []) {
      if (text.startsWith('BEGIN ')) {
        assert.equal(snapshot, null, 'fake permits only one pinned transaction at a time');
        snapshot = {
          records: copyRecords(),
          events: copyEvents(),
          evidenceIds: new Map(evidenceIds),
          evidenceDigests: new Map(evidenceDigests),
          remedyOperations: new Map(remedyOperations),
          remedyActions: new Map(remedyActions),
          remedyCaids: new Map(remedyCaids),
        };
        transactionLog.push(text);
        return { rowCount: null, rows: [] };
      }
      if (text === 'COMMIT') {
        assert.notEqual(snapshot, null);
        transactionLog.push(text);
        if (failCommit) {
          failCommit = false;
          throw new Error('commit outcome unknown');
        }
        snapshot = null;
        return { rowCount: null, rows: [] };
      }
      if (text === 'ROLLBACK') {
        assert.notEqual(snapshot, null);
        records = snapshot!.records;
        events = snapshot!.events;
        evidenceIds = snapshot!.evidenceIds;
        evidenceDigests = snapshot!.evidenceDigests;
        remedyOperations = snapshot!.remedyOperations;
        remedyActions = snapshot!.remedyActions;
        remedyCaids = snapshot!.remedyCaids;
        snapshot = null;
        transactionLog.push(text);
        return { rowCount: null, rows: [] };
      }
      if (nextError) {
        const error = nextError;
        nextError = null;
        throw error;
      }
      if (nextResult) {
        const result = nextResult;
        nextResult = null;
        return result;
      }

      if (text === REMEDY_PROGRAM_POSTGRES_SQL.create) {
        const [tenantId, instanceId, stateJson, stateDigest, eventAt] = params;
        const recordKey = key(tenantId, instanceId);
        if (records.has(recordKey)) return refusal(tenantId, instanceId, 'instance_exists');
        if (Date.parse(eventAt) > Date.parse(RECORDED_AT) + 5 * 60 * 1000) {
          return refusal(tenantId, instanceId, 'clock_forward_skew');
        }
        const state = JSON.parse(stateJson);
        const claims = newClaims(null, state);
        const replay = replayReason(tenantId, claims);
        if (replay) return refusal(tenantId, instanceId, replay);
        const record = {
          tenant_id: tenantId,
          instance_id: instanceId,
          revision: 0,
          state_json: stateJson,
          state_digest: stateDigest,
          event_at: eventAt,
          recorded_at: RECORDED_AT,
        };
        records.set(recordKey, record);
        events.set(recordKey, [{
          ...record,
          previous_revision: null,
          event_kind: 'create',
        }]);
        reserveClaims(tenantId, instanceId, claims);
        return respond(success(record));
      }

      if (text === REMEDY_PROGRAM_POSTGRES_SQL.get) {
        const [tenantId, instanceId] = params;
        const record = records.get(key(tenantId, instanceId));
        return respond(record
          ? success(record)
          : refusal(tenantId, instanceId, 'instance_not_found'));
      }

      if (text === REMEDY_PROGRAM_POSTGRES_SQL.compareAndSwap) {
        const [tenantId, instanceId, expectedRevision, nextRevision,
          stateJson, stateDigest, eventAt] = params;
        const recordKey = key(tenantId, instanceId);
        const current = records.get(recordKey);
        if (!current) return refusal(tenantId, instanceId, 'instance_not_found');
        if (current.revision !== expectedRevision) {
          return refusal(tenantId, instanceId, 'revision_conflict');
        }
        if (Date.parse(eventAt) < Date.parse(current.event_at)) {
          return refusal(tenantId, instanceId, 'clock_regression');
        }
        if (Date.parse(eventAt) > Date.parse(RECORDED_AT) + 5 * 60 * 1000) {
          return refusal(tenantId, instanceId, 'clock_forward_skew');
        }
        const currentState = JSON.parse(current.state_json);
        const candidate = JSON.parse(stateJson);
        const claims = newClaims(currentState, candidate);
        const replay = replayReason(tenantId, claims);
        if (replay) return refusal(tenantId, instanceId, replay);
        const record = {
          tenant_id: tenantId,
          instance_id: instanceId,
          revision: nextRevision,
          state_json: stateJson,
          state_digest: stateDigest,
          event_at: eventAt,
          recorded_at: RECORDED_AT,
        };
        records.set(recordKey, record);
        events.get(recordKey)!.push({
          ...record,
          previous_revision: expectedRevision,
          event_kind: 'cas',
        });
        reserveClaims(tenantId, instanceId, claims);
        return respond(success(record));
      }

      throw new Error(`unexpected SQL: ${text}`);
    },
    release() {
      releases += 1;
    },
  };

  return {
    pool: {
      async connect() {
        return client;
      },
    },
    key,
    get records() {
      return records;
    },
    get events() {
      return events;
    },
    get evidenceIds() {
      return evidenceIds;
    },
    get evidenceDigests() {
      return evidenceDigests;
    },
    get remedyOperations() {
      return remedyOperations;
    },
    transactionLog,
    get releases() {
      return releases;
    },
    returnNext(result: unknown) {
      nextResult = result;
    },
    throwNext(error: Error) {
      nextError = error;
    },
    mutateNextEnvelope(mutation: (result: any) => any) {
      nextEnvelopeMutation = mutation;
    },
    failNextCommit() {
      failCommit = true;
    },
  };
}

test('migration uses composite tenant keys, immutable ledgers, and DB-clock custody', () => {
  assert.match(MIGRATION, /CREATE SCHEMA IF NOT EXISTS remedy_program_private/);
  assert.match(MIGRATION, /PRIMARY KEY \(tenant_id, instance_id\)/);
  assert.match(MIGRATION, /PRIMARY KEY \(tenant_id, instance_id, revision\)/);
  assert.match(
    MIGRATION,
    /FOREIGN KEY \(tenant_id, instance_id\)\s+REFERENCES remedy_program_private\.instances\(tenant_id, instance_id\) ON DELETE RESTRICT/,
  );
  assert.match(MIGRATION, /BEFORE UPDATE OR DELETE ON remedy_program_private\.events/);
  for (const table of [
    'evidence_id_consumptions', 'evidence_digest_consumptions', 'remedy_authorizations',
  ]) {
    assert.match(
      MIGRATION,
      new RegExp(`BEFORE UPDATE OR DELETE ON remedy_program_private\\.${table}`),
    );
  }
  assert.match(MIGRATION, /PRIMARY KEY \(tenant_id, evidence_id\)/);
  assert.match(MIGRATION, /PRIMARY KEY \(tenant_id, evidence_digest\)/);
  assert.match(MIGRATION, /PRIMARY KEY \(tenant_id, remedy_operation_id\)/);
  assert.match(MIGRATION, /UNIQUE \(tenant_id, remedy_action_digest\)/);
  assert.match(MIGRATION, /UNIQUE \(tenant_id, remedy_caid\)/);
  assert.match(MIGRATION, /FOREIGN KEY \(tenant_id, instance_id, revision\)\s+REFERENCES remedy_program_private\.events/);
  assert.match(MIGRATION, /v_recorded_at := pg_catalog\.clock_timestamp\(\)/);
  assert.match(MIGRATION, /p_event_at::pg_catalog\.timestamptz < v_current\.event_at/);
  assert.match(
    MIGRATION,
    /p_event_at::pg_catalog\.timestamptz\s+> v_recorded_at \+ pg_catalog\.make_interval\(mins => 5\)/,
  );
  assert.match(MIGRATION, /'clock_regression'::pg_catalog\.text/);
  assert.match(MIGRATION, /'clock_forward_skew'::pg_catalog\.text/);
  assert.match(MIGRATION, /'evidence_replayed'::pg_catalog\.text/);
  assert.match(MIGRATION, /'remedy_operation_replayed'::pg_catalog\.text/);
  assert.match(MIGRATION, /v_next_state -> 'original' IS DISTINCT FROM v_current_state -> 'original'/);
  assert.match(MIGRATION, /RP_RECORDED_FACT_CHANGED/);
  assert.match(MIGRATION, /RP_REMEDY_ACCOUNTING_REGRESSION/);
});

test('migration is RPC-only service_role with FORCE RLS and pinned search paths', () => {
  assert.equal((MIGRATION.match(/FORCE ROW LEVEL SECURITY/g) ?? []).length, 6);
  assert.doesNotMatch(MIGRATION, /GRANT\s+[^;]*\bON TABLE\b[^;]*\bservice_role\b/is);
  for (const table of [
    'store_root', 'instances', 'events',
    'evidence_id_consumptions', 'evidence_digest_consumptions', 'remedy_authorizations',
  ]) {
    assert.match(
      MIGRATION,
      new RegExp(`REVOKE ALL ON TABLE remedy_program_private\\.${table}\\s+FROM PUBLIC, anon, authenticated, service_role;`),
    );
  }
  assert.match(MIGRATION, /GRANT USAGE ON SCHEMA remedy_program_private TO service_role/);

  for (const name of ['create', 'get', 'compare_and_swap']) {
    const marker = `CREATE OR REPLACE FUNCTION remedy_program_private.remedy_program_${name}(`;
    const start = MIGRATION.indexOf(marker);
    assert.notEqual(start, -1, `${name} RPC must exist`);
    const block = MIGRATION.slice(start, MIGRATION.indexOf('$$;', start) + 3);
    assert.match(block, /SECURITY DEFINER/);
    assert.match(block, /SET search_path = ''/);
    assert.match(
      MIGRATION,
      new RegExp(`REVOKE ALL ON FUNCTION remedy_program_private\\.remedy_program_${name}\\([\\s\\S]*?FROM PUBLIC, anon, authenticated, service_role;`),
    );
    assert.match(
      MIGRATION,
      new RegExp(`GRANT EXECUTE ON FUNCTION remedy_program_private\\.remedy_program_${name}\\([\\s\\S]*?TO service_role;`),
    );
  }
});

test('same instance id is isolated across tenants and cannot be read cross-tenant', async () => {
  const pg = fakePostgres();
  const store = createRemedyProgramPostgresStore({ pool: pg.pool });
  const tenantOne = initialState('tenant-1', 'shared-remedy');
  const tenantTwo = initialState('tenant-2', 'shared-remedy');
  tenantTwo.used_evidence_digests = [...tenantOne.used_evidence_digests];

  assert.equal(store.durable, true);
  assert.deepEqual(await store.create(tenantOne as any), { ok: true, state: tenantOne });
  assert.deepEqual(await store.create(tenantTwo as any), { ok: true, state: tenantTwo });
  assert.deepEqual(
    await store.get({ tenantId: 'tenant-3', instanceId: 'shared-remedy' }),
    { ok: false, reason: 'instance_not_found' },
  );
  assert.deepEqual(
    (await store.get({ tenantId: 'tenant-2', instanceId: 'shared-remedy' })).state,
    tenantTwo,
  );
  assert.equal(pg.records.size, 2);
  assert.equal(pg.events.get(pg.key('tenant-1', 'shared-remedy'))!.length, 1);
  assert.equal(pg.events.get(pg.key('tenant-2', 'shared-remedy'))!.length, 1);
});

test('CAS is tenant-bound, revision-fenced, canonical, and append-only', async () => {
  const pg = fakePostgres();
  const store = createRemedyProgramPostgresStore({ pool: pg.pool });
  const created = await store.create(initialState('tenant-a', 'cas-1') as any);
  const next = structuredClone(created.state!);
  next.revision = 1;
  next.status = 'disputed';
  next.updated_at = '2026-07-21T22:01:00.000Z';

  assert.deepEqual(await store.compareAndSwap({
    tenantId: 'tenant-a', instanceId: 'cas-1', expectedRevision: 0, state: next,
  }), { ok: true, state: next });
  assert.deepEqual(await store.compareAndSwap({
    tenantId: 'tenant-a', instanceId: 'cas-1', expectedRevision: 0, state: next,
  }), { ok: false, reason: 'revision_conflict' });
  assert.deepEqual(await store.compareAndSwap({
    tenantId: 'tenant-b', instanceId: 'cas-1', expectedRevision: 1,
    state: { ...next, tenant_id: 'tenant-b', revision: 2 },
  }), { ok: false, reason: 'instance_not_found' });

  const record = pg.records.get(pg.key('tenant-a', 'cas-1'))!;
  assert.equal(
    record.state_digest,
    `sha256:${createHash('sha256').update(record.state_json, 'utf8').digest('hex')}`,
  );
  assert.deepEqual(JSON.parse(record.state_json), next);
  assert.notEqual(record.recorded_at, next.updated_at);
  assert.deepEqual(
    pg.events.get(pg.key('tenant-a', 'cas-1'))!.map((event) => ({
      tenant: event.tenant_id,
      instance: event.instance_id,
      revision: event.revision,
      previous: event.previous_revision,
      kind: event.event_kind,
    })),
    [
      { tenant: 'tenant-a', instance: 'cas-1', revision: 0, previous: null, kind: 'create' },
      { tenant: 'tenant-a', instance: 'cas-1', revision: 1, previous: 0, kind: 'cas' },
    ],
  );
  assert.match(pg.transactionLog[0], /READ WRITE/);
  assert.ok(pg.transactionLog.some((entry) => /READ ONLY/.test(entry)) === false);
});

test('tenant-global evidence ids and digests are one-use, including original reconciliation', async () => {
  const pg = fakePostgres();
  const store = createRemedyProgramPostgresStore({ pool: pg.pool });
  const first = initialState('tenant-global', 'evidence-a');
  const second = initialState('tenant-global', 'evidence-b');
  await store.create(first as any);
  await store.create(second as any);

  const reconciliationId = 'original-reconciliation-evidence';
  const reconciliationDigest = digest('original-reconciliation-evidence');
  const firstNext = {
    ...first,
    revision: 1,
    status: 'original_proved_no_effect',
    updated_at: '2026-07-21T22:01:00.000Z',
    used_evidence_ids: [reconciliationId],
    used_evidence_digests: [...first.used_evidence_digests, reconciliationDigest],
    original_reconciliation: {
      evidence_id: reconciliationId,
      evidence_digest: reconciliationDigest,
      outcome: 'proved_no_effect',
    },
  };
  assert.equal((await store.compareAndSwap({
    tenantId: first.tenant_id,
    instanceId: first.instance_id,
    expectedRevision: 0,
    state: firstNext,
  })).ok, true);

  assert.deepEqual(await store.compareAndSwap({
    tenantId: second.tenant_id,
    instanceId: second.instance_id,
    expectedRevision: 0,
    state: {
      ...second,
      revision: 1,
      updated_at: '2026-07-21T22:01:00.000Z',
      used_evidence_ids: [reconciliationId],
      used_evidence_digests: [...second.used_evidence_digests, digest('different-evidence')],
    },
  }), { ok: false, reason: 'evidence_replayed' });

  assert.deepEqual(await store.compareAndSwap({
    tenantId: second.tenant_id,
    instanceId: second.instance_id,
    expectedRevision: 0,
    state: {
      ...second,
      revision: 1,
      updated_at: '2026-07-21T22:01:00.000Z',
      used_evidence_ids: ['different-evidence'],
      used_evidence_digests: [...second.used_evidence_digests, reconciliationDigest],
    },
  }), { ok: false, reason: 'evidence_replayed' });
  assert.equal(pg.evidenceIds.get(JSON.stringify(['tenant-global', reconciliationId])), 'evidence-a');
  assert.equal(
    pg.evidenceDigests.get(JSON.stringify(['tenant-global', reconciliationDigest])),
    'evidence-a',
  );
});

test('remedy operation, action digest, and CAID remain reserved after proved_no_effect', async () => {
  const pg = fakePostgres();
  const store = createRemedyProgramPostgresStore({ pool: pg.pool });
  const first = initialState('tenant-remedy-global', 'operation-a');
  const second = initialState('tenant-remedy-global', 'operation-b');
  await store.create(first as any);
  await store.create(second as any);

  const reserved = authorizedAttempt('A');
  const authorized = {
    ...first,
    revision: 1,
    status: 'remedy_authorized',
    updated_at: '2026-07-21T22:01:00.000Z',
    active_remedy: reserved,
  };
  assert.equal((await store.compareAndSwap({
    tenantId: first.tenant_id,
    instanceId: first.instance_id,
    expectedRevision: 0,
    state: authorized,
  })).ok, true);

  const provedNoEffect = {
    ...authorized,
    revision: 2,
    status: 'disputed',
    updated_at: '2026-07-21T22:02:00.000Z',
    active_remedy: null,
    remedies: [{ ...reserved, status: 'proved_no_effect' }],
  };
  assert.equal((await store.compareAndSwap({
    tenantId: first.tenant_id,
    instanceId: first.instance_id,
    expectedRevision: 1,
    state: provedNoEffect,
  })).ok, true);

  const replayAttempts = [
    authorizedAttempt('B', { remedy_operation_id: reserved.remedy_operation_id }),
    authorizedAttempt('C', { remedy_action_digest: reserved.remedy_action_digest }),
    authorizedAttempt('D', { remedy_caid: reserved.remedy_caid }),
  ];
  for (const attempt of replayAttempts) {
    assert.deepEqual(await store.compareAndSwap({
      tenantId: second.tenant_id,
      instanceId: second.instance_id,
      expectedRevision: 0,
      state: {
        ...second,
        revision: 1,
        status: 'remedy_authorized',
        updated_at: '2026-07-21T22:01:00.000Z',
        active_remedy: attempt,
      },
    }), { ok: false, reason: 'remedy_operation_replayed' });
  }
  assert.equal(
    pg.remedyOperations.get(JSON.stringify(['tenant-remedy-global', reserved.remedy_operation_id])),
    'operation-a',
  );
});

test('state bindings and application event clocks fail closed', async () => {
  const pg = fakePostgres();
  const store = createRemedyProgramPostgresStore({ pool: pg.pool });
  await store.create(initialState('tenant-clock', 'clock-1') as any);

  const regressed = initialState('tenant-clock', 'clock-1');
  regressed.revision = 1;
  regressed.updated_at = '2026-07-21T21:59:59.999Z';
  assert.deepEqual(await store.compareAndSwap({
    tenantId: 'tenant-clock', instanceId: 'clock-1', expectedRevision: 0, state: regressed,
  }), { ok: false, reason: 'clock_regression' });

  const future = initialState('tenant-clock', 'future-1');
  future.created_at = '2026-07-21T22:36:00.000Z';
  future.updated_at = future.created_at;
  assert.deepEqual(
    await store.create(future as any),
    { ok: false, reason: 'clock_forward_skew' },
  );
  await assert.rejects(
    () => store.create({ ...initialState('tenant-x', 'bound-1'), revision: 1 } as any),
    /binding does not match/,
  );
  await assert.rejects(
    () => store.compareAndSwap({
      tenantId: 'tenant-clock', instanceId: 'clock-1', expectedRevision: 0,
      state: { ...regressed, revision: 4 },
    }),
    /binding does not match/,
  );
});

test('modified and ambiguous database envelopes are rejected and rolled back', async () => {
  const pg = fakePostgres();
  const store = createRemedyProgramPostgresStore({ pool: pg.pool });
  await store.create(initialState('tenant-closed', 'closed-1') as any);

  const mutations = [
    (result: any) => ({ ...result, rows: [{ ...result.rows[0], tenant_id: 'tenant-other' }] }),
    (result: any) => ({ ...result, rows: [{ ...result.rows[0], revision: '7' }] }),
    (result: any) => ({ ...result, rows: [{ ...result.rows[0], state_digest: `sha256:${'0'.repeat(64)}` }] }),
    (result: any) => ({ ...result, rows: [{ ...result.rows[0], recorded_at: 'not-a-db-time' }] }),
    (result: any) => ({ ...result, rows: [{ ...result.rows[0], injected: true }] }),
  ];
  for (const mutation of mutations) {
    pg.mutateNextEnvelope(mutation);
    await assert.rejects(
      () => store.get({ tenantId: 'tenant-closed', instanceId: 'closed-1' }),
      /Postgres returned|outcome is malformed/,
    );
    assert.equal(pg.transactionLog.at(-1), 'ROLLBACK');
  }

  pg.returnNext({ rowCount: 0, rows: [] });
  await assert.rejects(
    () => store.get({ tenantId: 'tenant-closed', instanceId: 'closed-1' }),
    /outcome is ambiguous/,
  );
  assert.equal(pg.transactionLog.at(-1), 'ROLLBACK');

  pg.throwNext(new Error('database unavailable'));
  await assert.rejects(
    () => store.get({ tenantId: 'tenant-closed', instanceId: 'closed-1' }),
    /database unavailable/,
  );
  assert.equal(pg.transactionLog.at(-1), 'ROLLBACK');
});

test('malformed success and uncertain commit roll back state and event together', async () => {
  const pg = fakePostgres();
  const store = createRemedyProgramPostgresStore({ pool: pg.pool });
  const initial = initialState('tenant-rollback', 'rollback-1');
  await store.create(initial as any);
  const next = { ...initial, revision: 1, status: 'disputed', updated_at: '2026-07-21T22:01:00.000Z' };

  pg.mutateNextEnvelope((result) => ({ ...result, rowCount: 2 }));
  await assert.rejects(
    () => store.compareAndSwap({
      tenantId: 'tenant-rollback', instanceId: 'rollback-1', expectedRevision: 0, state: next,
    }),
    /outcome is ambiguous/,
  );
  assert.equal(pg.records.get(pg.key('tenant-rollback', 'rollback-1'))!.revision, 0);
  assert.equal(pg.events.get(pg.key('tenant-rollback', 'rollback-1'))!.length, 1);

  pg.failNextCommit();
  await assert.rejects(
    () => store.compareAndSwap({
      tenantId: 'tenant-rollback', instanceId: 'rollback-1', expectedRevision: 0, state: next,
    }),
    /commit outcome unknown/,
  );
  assert.equal(pg.records.get(pg.key('tenant-rollback', 'rollback-1'))!.revision, 0);
  assert.equal(pg.events.get(pg.key('tenant-rollback', 'rollback-1'))!.length, 1);
  assert.equal(pg.transactionLog.at(-1), 'ROLLBACK');
  assert.equal(pg.releases, 3);
});

test('requires a transaction-capable pool', () => {
  assert.throws(
    () => createRemedyProgramPostgresStore({ pool: { query: async () => ({}) } as any }),
    /transaction-capable pg pool/,
  );
});
