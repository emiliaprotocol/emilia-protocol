// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
const {
  TRUST_PROGRAM_POSTGRES_SQL,
  createTrustProgramPostgresStore,
} = await import(process.env.TRUST_PROGRAM_TEST_SOURCE === '1'
  ? './src/trust-program-postgres.ts'
  : './trust-program-postgres.js');

const MIGRATION = readFileSync(
  new URL('../../supabase/migrations/20260721163000_trust_program_store.sql', import.meta.url),
  'utf8',
);

function digest(value: string) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function initialState(
  tenantId = 'tenant-1',
  instanceId = 'instance-1',
  rootMarker = 'A',
) {
  return {
    version: 'EP-GATE-TRUST-PROGRAM-PROFILE-v1',
    tenant_id: tenantId,
    instance_id: instanceId,
    program_id: 'program-1',
    program_version: 1,
    program_digest: `sha256:${'11'.repeat(32)}`,
    root_caid: `caid:1:trust.root.1:jcs-sha256:${rootMarker.repeat(43)}`,
    action_digest: digest(`root-action-${rootMarker}`),
    status: 'active',
    revision: 0,
    created_at: '2026-07-21T16:30:00.000Z',
    updated_at: '2026-07-21T16:30:00.000Z',
    stages: {
      identify: {
        status: 'collecting',
        predecessor_receipt_digests: [],
        evidence: {},
        receipt: null,
      },
      approve: {
        status: 'locked',
        predecessor_receipt_digests: [],
        evidence: {},
        receipt: null,
      },
    },
    used_evidence_ids: [],
    execution: {
      status: 'locked',
      claim_token_digest: null,
      evidence_digest: null,
      outcome: null,
    },
    invalidation_reason: null,
  };
}

function createState(store: any, state: any) {
  return store.create({ tenantId: state.tenant_id, state });
}

function fakePostgres() {
  let records = new Map();
  let events = new Map();
  let evidenceIds = new Map();
  let evidenceDigests = new Map();
  let rootActions = new Map();
  let rootCaids = new Map();
  let executionOperations = new Map();
  let snapshot = null;
  let nextResult = null;
  let nextError = null;
  const transactionLog = [];
  let releases = 0;

  function copyMap(map) {
    return new Map([...map].map(([key, value]) => [key, structuredClone(value)]));
  }

  const key = (tenantId, instanceId) => JSON.stringify([tenantId, instanceId]);
  const claimKey = (tenantId, value) => JSON.stringify([tenantId, value]);
  const stateEvidence = (state) => Object.values(state.stages)
    .flatMap((stage) => Object.values(stage.evidence));

  function reserve(state, revision) {
    for (const evidence of stateEvidence(state)) {
      evidenceIds.set(claimKey(state.tenant_id, evidence.evidence_id), state.instance_id);
      evidenceDigests.set(claimKey(state.tenant_id, evidence.evidence_digest), state.instance_id);
    }
    rootActions.set(claimKey(state.tenant_id, state.action_digest), state.instance_id);
    rootCaids.set(claimKey(state.tenant_id, state.root_caid), state.instance_id);
    if (state.execution.operation_id) {
      executionOperations.set(
        claimKey(state.tenant_id, state.execution.operation_id),
        { instanceId: state.instance_id, revision },
      );
    }
  }

  function replayReason(state) {
    const other = (map, value) => {
      const owner = map.get(claimKey(state.tenant_id, value));
      return owner !== undefined
        && (typeof owner === 'string' ? owner : owner.instanceId) !== state.instance_id;
    };
    if (stateEvidence(state).some((evidence) =>
      other(evidenceIds, evidence.evidence_id)
      || other(evidenceDigests, evidence.evidence_digest))) return 'evidence_replayed';
    if (other(rootActions, state.action_digest)
        || other(rootCaids, state.root_caid)
        || (state.execution.operation_id
          && other(executionOperations, state.execution.operation_id))) {
      return 'trust_operation_replayed';
    }
    return null;
  }

  function refusal(tenantId, instanceId, reason) {
    return {
      rowCount: 1,
      rows: [{
        ok: false,
        reason,
        tenant_id: tenantId,
        instance_id: instanceId,
        revision: null,
        state_json: null,
        state_digest: null,
      }],
    };
  }

  function success(record) {
    return {
      rowCount: 1,
      rows: [{
        ok: true,
        reason: null,
        tenant_id: record.tenant_id,
        instance_id: record.instance_id,
        revision: String(record.revision),
        state_json: record.state_json,
        state_digest: record.state_digest,
      }],
    };
  }

  const client = {
    async query(text, params = []) {
      if (text.startsWith('BEGIN ')) {
        assert.equal(snapshot, null, 'fake permits only one pinned transaction at a time');
        snapshot = {
          records: copyMap(records),
          events: copyMap(events),
          evidenceIds: copyMap(evidenceIds),
          evidenceDigests: copyMap(evidenceDigests),
          rootActions: copyMap(rootActions),
          rootCaids: copyMap(rootCaids),
          executionOperations: copyMap(executionOperations),
        };
        transactionLog.push(text);
        return { rowCount: null, rows: [] };
      }
      if (text === 'COMMIT') {
        assert.notEqual(snapshot, null);
        snapshot = null;
        transactionLog.push(text);
        return { rowCount: null, rows: [] };
      }
      if (text === 'ROLLBACK') {
        assert.notEqual(snapshot, null);
        records = snapshot.records;
        events = snapshot.events;
        evidenceIds = snapshot.evidenceIds;
        evidenceDigests = snapshot.evidenceDigests;
        rootActions = snapshot.rootActions;
        rootCaids = snapshot.rootCaids;
        executionOperations = snapshot.executionOperations;
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

      if (text === TRUST_PROGRAM_POSTGRES_SQL.create) {
        const [tenantId, instanceId, stateJson, stateDigest, eventAt] = params;
        const recordKey = key(tenantId, instanceId);
        if (records.has(recordKey)) return refusal(tenantId, instanceId, 'instance_exists');
        const state = JSON.parse(stateJson);
        const replay = replayReason(state);
        if (replay) return refusal(tenantId, instanceId, replay);
        const record = {
          tenant_id: tenantId,
          instance_id: instanceId,
          revision: 0,
          state_json: stateJson,
          state_digest: stateDigest,
          updated_at: eventAt,
        };
        records.set(recordKey, record);
        events.set(recordKey, [{
          tenant_id: tenantId,
          instance_id: instanceId,
          revision: 0,
          previous_revision: null,
          event_kind: 'create',
          state_json: stateJson,
          state_digest: stateDigest,
          reason: null,
          recorded_at: eventAt,
        }]);
        reserve(state, 0);
        return success(record);
      }

      if (text === TRUST_PROGRAM_POSTGRES_SQL.get) {
        const [tenantId, instanceId] = params;
        const record = records.get(key(tenantId, instanceId));
        return record ? success(record) : refusal(tenantId, instanceId, 'instance_not_found');
      }

      if (text === TRUST_PROGRAM_POSTGRES_SQL.compareAndSwap) {
        const [tenantId, instanceId, expectedRevision, nextRevision,
          stateJson, stateDigest, eventAt] = params;
        const recordKey = key(tenantId, instanceId);
        const current = records.get(recordKey);
        if (!current) return refusal(tenantId, instanceId, 'instance_not_found');
        if (current.revision !== expectedRevision) {
          return refusal(tenantId, instanceId, 'revision_conflict');
        }
        if (Date.parse(eventAt) < Date.parse(current.updated_at)) {
          return refusal(tenantId, instanceId, 'clock_regression');
        }
        const state = JSON.parse(stateJson);
        const replay = replayReason(state);
        if (replay) return refusal(tenantId, instanceId, replay);
        const record = {
          tenant_id: tenantId,
          instance_id: instanceId,
          revision: nextRevision,
          state_json: stateJson,
          state_digest: stateDigest,
          updated_at: eventAt,
        };
        records.set(recordKey, record);
        events.get(recordKey).push({
          tenant_id: tenantId,
          instance_id: instanceId,
          revision: nextRevision,
          previous_revision: expectedRevision,
          event_kind: 'cas',
          state_json: stateJson,
          state_digest: stateDigest,
          reason: null,
          recorded_at: eventAt,
        });
        reserve(state, nextRevision);
        return success(record);
      }

      if (text === TRUST_PROGRAM_POSTGRES_SQL.invalidate) {
        const [tenantId, instanceId, expectedRevision,
          reason, eventAt, stateJson, stateDigest] = params;
        const recordKey = key(tenantId, instanceId);
        const current = records.get(recordKey);
        if (!current) return refusal(tenantId, instanceId, 'instance_not_found');
        if (current.revision !== expectedRevision) {
          return refusal(tenantId, instanceId, 'revision_conflict');
        }
        if (Date.parse(eventAt) < Date.parse(current.updated_at)) {
          return refusal(tenantId, instanceId, 'clock_regression');
        }
        if (JSON.parse(current.state_json).status === 'invalidated') {
          return refusal(tenantId, instanceId, 'program_instance_invalidated');
        }
        const record = {
          tenant_id: tenantId,
          instance_id: instanceId,
          revision: expectedRevision + 1,
          state_json: stateJson,
          state_digest: stateDigest,
          updated_at: eventAt,
        };
        records.set(recordKey, record);
        events.get(recordKey).push({
          tenant_id: tenantId,
          instance_id: instanceId,
          revision: expectedRevision + 1,
          previous_revision: expectedRevision,
          event_kind: 'invalidate',
          state_json: stateJson,
          state_digest: stateDigest,
          reason,
          recorded_at: eventAt,
        });
        return success(record);
      }

      throw new Error(`unexpected SQL: ${text}`);
    },
    release() {
      releases += 1;
    },
  };

  return {
    pool: { async connect() { return client; } },
    key,
    get records() { return records; },
    get events() { return events; },
    get evidenceIds() { return evidenceIds; },
    get evidenceDigests() { return evidenceDigests; },
    get rootActions() { return rootActions; },
    get rootCaids() { return rootCaids; },
    get executionOperations() { return executionOperations; },
    transactionLog,
    get releases() { return releases; },
    returnNext(result) { nextResult = result; },
    throwNext(error) { nextError = error; },
  };
}

test('migration is private, RPC-only, force-RLS, and append-only', () => {
  assert.match(MIGRATION, /CREATE SCHEMA IF NOT EXISTS trust_program_private/);
  assert.match(MIGRATION, /root_id SMALLINT PRIMARY KEY CHECK \(root_id = 1\)/);
  assert.match(MIGRATION, /INSERT INTO trust_program_private\.store_root \(root_id\) VALUES \(1\)/);
  assert.match(MIGRATION, /PRIMARY KEY \(tenant_id, instance_id\)/);
  assert.match(MIGRATION, /PRIMARY KEY \(tenant_id, instance_id, revision\)/);
  assert.match(
    MIGRATION,
    /FOREIGN KEY \(tenant_id, instance_id\)\s+REFERENCES trust_program_private\.instances\(tenant_id, instance_id\) ON DELETE RESTRICT/,
  );
  assert.match(MIGRATION, /PRIMARY KEY \(tenant_id, evidence_id\)/);
  assert.match(MIGRATION, /PRIMARY KEY \(tenant_id, evidence_digest\)/);
  assert.match(MIGRATION, /PRIMARY KEY \(tenant_id, root_action_digest\)/);
  assert.match(MIGRATION, /UNIQUE \(tenant_id, root_caid\)/);
  assert.match(MIGRATION, /PRIMARY KEY \(tenant_id, operation_id\)/);
  for (const table of [
    'events', 'evidence_id_consumptions', 'evidence_digest_consumptions',
    'trust_roots', 'execution_operation_consumptions',
  ]) {
    assert.match(
      MIGRATION,
      new RegExp(`BEFORE UPDATE OR DELETE ON trust_program_private\\.${table}`),
    );
  }
  assert.equal((MIGRATION.match(/FORCE ROW LEVEL SECURITY/g) ?? []).length, 7);
  assert.doesNotMatch(MIGRATION, /GRANT\s+[^;]*\bON TABLE\b[^;]*\bservice_role\b/is);
  assert.match(
    MIGRATION,
    /REVOKE ALL ON TABLE trust_program_private\.events\s+FROM PUBLIC, anon, authenticated, service_role;/,
  );
  assert.match(MIGRATION, /GRANT USAGE ON SCHEMA trust_program_private TO service_role/);
  assert.match(MIGRATION, /'evidence_replayed'::pg_catalog\.text/);
  assert.match(MIGRATION, /'trust_operation_replayed'::pg_catalog\.text/);

  for (const name of ['create', 'get', 'compare_and_swap', 'invalidate']) {
    const start = MIGRATION.indexOf(`trust_program_private.trust_program_${name}(`);
    assert.notEqual(start, -1, `${name} RPC must exist`);
    const block = MIGRATION.slice(start, MIGRATION.indexOf('$$;', start) + 3);
    assert.match(block, /SECURITY DEFINER/);
    assert.match(block, /SET search_path = ''/);
    assert.match(
      MIGRATION,
      new RegExp(`REVOKE ALL ON FUNCTION trust_program_private\\.trust_program_${name}\\([\\s\\S]*?FROM PUBLIC, anon, authenticated, service_role;`),
    );
    assert.match(
      MIGRATION,
      new RegExp(`GRANT EXECUTE ON FUNCTION trust_program_private\\.trust_program_${name}\\([\\s\\S]*?TO service_role;`),
    );
  }

  for (const name of ['create', 'compare_and_swap', 'invalidate']) {
    const start = MIGRATION.indexOf(`trust_program_private.trust_program_${name}(`);
    const block = MIGRATION.slice(start, MIGRATION.indexOf('$$;', start) + 3);
    assert.match(block, /FROM trust_program_private\.store_root AS r[\s\S]*?FOR UPDATE/);
    assert.match(block, /INSERT INTO trust_program_private\.events/);
  }
});

test('create and get implement the durable kernel store contract', async () => {
  const pg = fakePostgres();
  const store = createTrustProgramPostgresStore({ pool: pg.pool });
  const state = initialState();
  const lookup = { tenantId: state.tenant_id, instanceId: state.instance_id };

  assert.equal(store.durable, true);
  assert.deepEqual(await store.get(lookup), { ok: false, reason: 'instance_not_found' });
  assert.deepEqual(await createState(store, state), { ok: true, state });
  assert.deepEqual(await createState(store, state), { ok: false, reason: 'instance_exists' });

  const loaded = await store.get(lookup);
  assert.deepEqual(loaded, { ok: true, state });
  loaded.state.status = 'caller-mutated';
  assert.equal((await store.get(lookup)).state.status, 'active');
  assert.ok(pg.transactionLog.includes('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'));
  assert.ok(pg.transactionLog.includes('BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE'));
  assert.equal(pg.releases, 5);
});

test('compareAndSwap installs and journals exactly one next revision', async () => {
  const pg = fakePostgres();
  const store = createTrustProgramPostgresStore({ pool: pg.pool });
  const created = await createState(store, initialState('tenant-cas', 'instance-cas'));
  const next = structuredClone(created.state);
  next.revision = 1;
  next.updated_at = '2026-07-21T16:31:00.000Z';
  next.stages.identify.status = 'satisfied';

  assert.deepEqual(await store.compareAndSwap({
    tenantId: 'tenant-cas', instanceId: 'instance-cas', expectedRevision: 0, state: next,
  }), { ok: true, state: next });
  assert.deepEqual(await store.compareAndSwap({
    tenantId: 'tenant-cas', instanceId: 'instance-cas', expectedRevision: 0, state: next,
  }), { ok: false, reason: 'revision_conflict' });

  const history = pg.events.get(pg.key('tenant-cas', 'instance-cas'));
  assert.equal(history.length, 2);
  assert.deepEqual(
    history.map(({ revision, previous_revision, event_kind }) => ({
      revision, previous_revision, event_kind,
    })),
    [
      { revision: 0, previous_revision: null, event_kind: 'create' },
      { revision: 1, previous_revision: 0, event_kind: 'cas' },
    ],
  );
  assert.equal(history[1].state_json, pg.records.get(pg.key('tenant-cas', 'instance-cas')).state_json);
  assert.equal(history[1].state_digest, pg.records.get(pg.key('tenant-cas', 'instance-cas')).state_digest);
});

test('durable transitions refuse a timestamp older than the stored revision', async () => {
  const pg = fakePostgres();
  const store = createTrustProgramPostgresStore({ pool: pg.pool });
  const created = await createState(store, initialState('tenant-clock', 'instance-clock'));
  const next = structuredClone(created.state);
  next.revision = 1;
  next.updated_at = '2026-07-21T16:29:59.999Z';

  assert.deepEqual(await store.compareAndSwap({
    tenantId: 'tenant-clock', instanceId: 'instance-clock', expectedRevision: 0, state: next,
  }), { ok: false, reason: 'clock_regression' });
  assert.equal((await store.get({ tenantId: 'tenant-clock', instanceId: 'instance-clock' })).state.revision, 0);
  assert.match(MIGRATION, /'clock_regression'::pg_catalog\.text/);
});

test('invalidation matches the kernel transition and is revision-fenced', async () => {
  const pg = fakePostgres();
  const store = createTrustProgramPostgresStore({ pool: pg.pool });
  await createState(store, initialState('tenant-invalidate', 'instance-invalidate'));

  assert.deepEqual(await store.invalidate({
    tenantId: 'tenant-invalidate', instanceId: 'instance-invalidate', expectedRevision: 7,
    reason: 'operator revoked authorization', at: Date.parse('2026-07-21T16:32:00.000Z'),
  }), { ok: false, reason: 'revision_conflict' });

  const invalidated = await store.invalidate({
    tenantId: 'tenant-invalidate', instanceId: 'instance-invalidate', expectedRevision: 0,
    reason: 'operator revoked authorization', at: Date.parse('2026-07-21T16:32:00.000Z'),
  });
  assert.equal(invalidated.ok, true);
  assert.equal(invalidated.state.status, 'invalidated');
  assert.equal(invalidated.state.revision, 1);
  assert.equal(invalidated.state.updated_at, '2026-07-21T16:32:00.000Z');
  assert.equal(invalidated.state.invalidation_reason, 'operator revoked authorization');
  assert.deepEqual(
    Object.values(invalidated.state.stages).map((stage) => stage.status),
    ['invalidated', 'invalidated'],
  );
  assert.equal(invalidated.state.execution.status, 'invalidated');

  const event = pg.events.get(pg.key('tenant-invalidate', 'instance-invalidate')).at(-1);
  assert.deepEqual(
    { revision: event.revision, previous_revision: event.previous_revision, kind: event.event_kind, reason: event.reason },
    { revision: 1, previous_revision: 0, kind: 'invalidate', reason: 'operator revoked authorization' },
  );
  assert.deepEqual(await store.invalidate({
    tenantId: 'tenant-invalidate', instanceId: 'instance-invalidate', expectedRevision: 1,
    reason: 'again', at: Date.parse('2026-07-21T16:33:00.000Z'),
  }), { ok: false, reason: 'program_instance_invalidated' });
});

test('invalidation preserves claimed and indeterminate consequences for safe reconciliation', async () => {
  for (const executionStatus of ['claimed', 'indeterminate']) {
    const pg = fakePostgres();
    const store = createTrustProgramPostgresStore({ pool: pg.pool });
    const instanceId = `instance-${executionStatus}`;
    const current = initialState('tenant-consequence', instanceId);
    current.execution.status = executionStatus;
    await createState(store, current);

    const invalidated = await store.invalidate({
      tenantId: 'tenant-consequence',
      instanceId,
      expectedRevision: 0,
      reason: 'authorization revoked while consequence is in flight',
      at: Date.parse('2026-07-21T16:34:00.000Z'),
    });

    assert.equal(invalidated.ok, true);
    assert.equal(invalidated.state.status, 'invalidated');
    assert.equal(invalidated.state.execution.status, executionStatus);
  }
});

test('hostile tenant confusion cannot address another tenant instance', async () => {
  const pg = fakePostgres();
  const store = createTrustProgramPostgresStore({ pool: pg.pool });
  const first = initialState('tenant-a', 'shared-instance');
  const second = initialState('tenant-b', 'shared-instance');

  await assert.rejects(() => store.create(first as any), /create input is invalid/);
  await assert.rejects(() => store.create({
    tenantId: 'tenant-a', state: { ...first, tenant_id: 'tenant-b' },
  }), /state binding does not match/);
  assert.equal((await createState(store, first)).ok, true);
  assert.equal((await createState(store, second)).ok, true);
  assert.deepEqual(
    await store.get({ tenantId: 'tenant-c', instanceId: 'shared-instance' }),
    { ok: false, reason: 'instance_not_found' },
  );
  assert.equal(
    (await store.get({ tenantId: 'tenant-b', instanceId: 'shared-instance' })).state.tenant_id,
    'tenant-b',
  );
  await assert.rejects(() => store.get('shared-instance' as any), /lookup input is invalid/);

  const forged = { ...first, tenant_id: 'tenant-b', revision: 1 };
  await assert.rejects(() => store.compareAndSwap({
    tenantId: 'tenant-a', instanceId: 'shared-instance', expectedRevision: 0,
    state: forged,
  } as any), /state binding does not match/);
  assert.equal(pg.records.size, 2);
});

test('hostile root action digest and CAID reuse fail closed within a tenant', async () => {
  const pg = fakePostgres();
  const store = createTrustProgramPostgresStore({ pool: pg.pool });
  const first = initialState('tenant-root', 'root-a', 'A');
  assert.equal((await createState(store, first)).ok, true);

  const reusedAction = initialState('tenant-root', 'root-b', 'B');
  reusedAction.action_digest = first.action_digest;
  assert.deepEqual(await createState(store, reusedAction), {
    ok: false, reason: 'trust_operation_replayed',
  });

  const reusedCaid = initialState('tenant-root', 'root-c', 'C');
  reusedCaid.root_caid = first.root_caid;
  assert.deepEqual(await createState(store, reusedCaid), {
    ok: false, reason: 'trust_operation_replayed',
  });

  assert.equal((await createState(store, initialState('tenant-other', 'root-b', 'A'))).ok, true);
});

test('hostile evidence id, digest, and execution operation reuse fail closed across instances', async () => {
  const pg = fakePostgres();
  const store = createTrustProgramPostgresStore({ pool: pg.pool });
  const first = initialState('tenant-replay', 'replay-a', 'A');
  const second = initialState('tenant-replay', 'replay-b', 'B');
  await createState(store, first);
  await createState(store, second);

  const evidenceDigest = digest('shared-evidence');
  const firstEvidence = structuredClone(first);
  firstEvidence.revision = 1;
  firstEvidence.updated_at = '2026-07-21T16:31:00.000Z';
  firstEvidence.stages.identify.evidence.proof = {
    evidence_id: 'shared-evidence-id', evidence_digest: evidenceDigest,
  };
  firstEvidence.used_evidence_ids = ['shared-evidence-id'];
  assert.equal((await store.compareAndSwap({
    tenantId: first.tenant_id, instanceId: first.instance_id,
    expectedRevision: 0, state: firstEvidence,
  })).ok, true);

  const replayId = structuredClone(second);
  replayId.revision = 1;
  replayId.updated_at = '2026-07-21T16:31:00.000Z';
  replayId.stages.identify.evidence.proof = {
    evidence_id: 'shared-evidence-id', evidence_digest: digest('different-evidence'),
  };
  replayId.used_evidence_ids = ['shared-evidence-id'];
  assert.deepEqual(await store.compareAndSwap({
    tenantId: second.tenant_id, instanceId: second.instance_id,
    expectedRevision: 0, state: replayId,
  }), { ok: false, reason: 'evidence_replayed' });

  replayId.stages.identify.evidence.proof = {
    evidence_id: 'different-evidence-id', evidence_digest: evidenceDigest,
  };
  replayId.used_evidence_ids = ['different-evidence-id'];
  assert.deepEqual(await store.compareAndSwap({
    tenantId: second.tenant_id, instanceId: second.instance_id,
    expectedRevision: 0, state: replayId,
  }), { ok: false, reason: 'evidence_replayed' });

  const firstOperation = { ...firstEvidence, revision: 2,
    updated_at: '2026-07-21T16:32:00.000Z', execution: {
      ...firstEvidence.execution, operation_id: 'shared-operation',
    } };
  assert.equal((await store.compareAndSwap({
    tenantId: first.tenant_id, instanceId: first.instance_id,
    expectedRevision: 1, state: firstOperation,
  })).ok, true);

  const replayOperation = structuredClone(second);
  replayOperation.revision = 1;
  replayOperation.updated_at = '2026-07-21T16:31:00.000Z';
  replayOperation.execution.operation_id = 'shared-operation';
  assert.deepEqual(await store.compareAndSwap({
    tenantId: second.tenant_id, instanceId: second.instance_id,
    expectedRevision: 0, state: replayOperation,
  }), { ok: false, reason: 'trust_operation_replayed' });
});

test('malformed rows, digest mismatch, ambiguous outcomes, and errors fail closed', async () => {
  const pg = fakePostgres();
  const store = createTrustProgramPostgresStore({ pool: pg.pool });
  await createState(store, initialState('tenant-closed', 'instance-closed'));

  pg.records.get(pg.key('tenant-closed', 'instance-closed')).state_digest = `sha256:${'00'.repeat(32)}`;
  await assert.rejects(
    () => store.get({ tenantId: 'tenant-closed', instanceId: 'instance-closed' }),
    /invalid state envelope/,
  );
  assert.equal(pg.transactionLog.at(-1), 'ROLLBACK');

  pg.returnNext({ rowCount: 0, rows: [] });
  await assert.rejects(
    () => store.get({ tenantId: 'tenant-closed', instanceId: 'instance-missing' }),
    /outcome is ambiguous/,
  );
  assert.equal(pg.transactionLog.at(-1), 'ROLLBACK');

  pg.throwNext(new Error('database unavailable'));
  await assert.rejects(
    () => store.get({ tenantId: 'tenant-closed', instanceId: 'instance-missing' }),
    /database unavailable/,
  );
  assert.equal(pg.transactionLog.at(-1), 'ROLLBACK');

  assert.throws(
    () => createTrustProgramPostgresStore({ pool: { query: async () => ({}) } }),
    /transaction-capable pg pool/,
  );
});
