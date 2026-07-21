// SPDX-License-Identifier: Apache-2.0
// Generated from trust-program-postgres.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { TRUST_PROGRAM_POSTGRES_SQL, createTrustProgramPostgresStore, } from './trust-program-postgres.js';
const MIGRATION = readFileSync(new URL('../../supabase/migrations/20260721163000_trust_program_store.sql', import.meta.url), 'utf8');
function initialState(instanceId = 'instance-1') {
    return {
        version: 'EP-GATE-TRUST-PROGRAM-PROFILE-v1',
        instance_id: instanceId,
        program_id: 'program-1',
        program_version: 1,
        program_digest: `sha256:${'11'.repeat(32)}`,
        root_caid: 'caid:root-1',
        action_digest: `sha256:${'22'.repeat(32)}`,
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
function fakePostgres() {
    let records = new Map();
    let events = new Map();
    let snapshot = null;
    let nextResult = null;
    let nextError = null;
    const transactionLog = [];
    let releases = 0;
    function copyMap(map) {
        return new Map([...map].map(([key, value]) => [key, structuredClone(value)]));
    }
    function refusal(instanceId, reason) {
        return {
            rowCount: 1,
            rows: [{
                    ok: false,
                    reason,
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
                snapshot = { records: copyMap(records), events: copyMap(events) };
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
                const [instanceId, stateJson, stateDigest, eventAt] = params;
                if (records.has(instanceId))
                    return refusal(instanceId, 'instance_exists');
                const record = {
                    instance_id: instanceId,
                    revision: 0,
                    state_json: stateJson,
                    state_digest: stateDigest,
                    updated_at: eventAt,
                };
                records.set(instanceId, record);
                events.set(instanceId, [{
                        instance_id: instanceId,
                        revision: 0,
                        previous_revision: null,
                        event_kind: 'create',
                        state_json: stateJson,
                        state_digest: stateDigest,
                        reason: null,
                        recorded_at: eventAt,
                    }]);
                return success(record);
            }
            if (text === TRUST_PROGRAM_POSTGRES_SQL.get) {
                const record = records.get(params[0]);
                return record ? success(record) : refusal(params[0], 'instance_not_found');
            }
            if (text === TRUST_PROGRAM_POSTGRES_SQL.compareAndSwap) {
                const [instanceId, expectedRevision, nextRevision, stateJson, stateDigest, eventAt] = params;
                const current = records.get(instanceId);
                if (!current)
                    return refusal(instanceId, 'instance_not_found');
                if (current.revision !== expectedRevision)
                    return refusal(instanceId, 'revision_conflict');
                if (Date.parse(eventAt) < Date.parse(current.updated_at)) {
                    return refusal(instanceId, 'clock_regression');
                }
                const record = {
                    instance_id: instanceId,
                    revision: nextRevision,
                    state_json: stateJson,
                    state_digest: stateDigest,
                    updated_at: eventAt,
                };
                records.set(instanceId, record);
                events.get(instanceId).push({
                    instance_id: instanceId,
                    revision: nextRevision,
                    previous_revision: expectedRevision,
                    event_kind: 'cas',
                    state_json: stateJson,
                    state_digest: stateDigest,
                    reason: null,
                    recorded_at: eventAt,
                });
                return success(record);
            }
            if (text === TRUST_PROGRAM_POSTGRES_SQL.invalidate) {
                const [instanceId, expectedRevision, reason, eventAt, stateJson, stateDigest] = params;
                const current = records.get(instanceId);
                if (!current)
                    return refusal(instanceId, 'instance_not_found');
                if (current.revision !== expectedRevision)
                    return refusal(instanceId, 'revision_conflict');
                if (Date.parse(eventAt) < Date.parse(current.updated_at)) {
                    return refusal(instanceId, 'clock_regression');
                }
                if (JSON.parse(current.state_json).status === 'invalidated') {
                    return refusal(instanceId, 'program_instance_invalidated');
                }
                const record = {
                    instance_id: instanceId,
                    revision: expectedRevision + 1,
                    state_json: stateJson,
                    state_digest: stateDigest,
                    updated_at: eventAt,
                };
                records.set(instanceId, record);
                events.get(instanceId).push({
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
        get records() { return records; },
        get events() { return events; },
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
    assert.match(MIGRATION, /PRIMARY KEY \(instance_id, revision\)/);
    assert.match(MIGRATION, /BEFORE UPDATE OR DELETE ON trust_program_private\.events/);
    assert.equal((MIGRATION.match(/FORCE ROW LEVEL SECURITY/g) ?? []).length, 3);
    assert.doesNotMatch(MIGRATION, /GRANT\s+[^;]*\bON TABLE\b[^;]*\bservice_role\b/is);
    assert.match(MIGRATION, /REVOKE ALL ON TABLE trust_program_private\.events\s+FROM PUBLIC, anon, authenticated, service_role;/);
    assert.match(MIGRATION, /GRANT USAGE ON SCHEMA trust_program_private TO service_role/);
    for (const name of ['create', 'get', 'compare_and_swap', 'invalidate']) {
        const start = MIGRATION.indexOf(`trust_program_private.trust_program_${name}(`);
        assert.notEqual(start, -1, `${name} RPC must exist`);
        const block = MIGRATION.slice(start, MIGRATION.indexOf('$$;', start) + 3);
        assert.match(block, /SECURITY DEFINER/);
        assert.match(block, /SET search_path = ''/);
        assert.match(MIGRATION, new RegExp(`REVOKE ALL ON FUNCTION trust_program_private\\.trust_program_${name}\\([\\s\\S]*?FROM PUBLIC, anon, authenticated, service_role;`));
        assert.match(MIGRATION, new RegExp(`GRANT EXECUTE ON FUNCTION trust_program_private\\.trust_program_${name}\\([\\s\\S]*?TO service_role;`));
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
    assert.equal(store.durable, true);
    assert.deepEqual(await store.get(state.instance_id), { ok: false, reason: 'instance_not_found' });
    assert.deepEqual(await store.create(state), { ok: true, state });
    assert.deepEqual(await store.create(state), { ok: false, reason: 'instance_exists' });
    const loaded = await store.get(state.instance_id);
    assert.deepEqual(loaded, { ok: true, state });
    loaded.state.status = 'caller-mutated';
    assert.equal((await store.get(state.instance_id)).state.status, 'active');
    assert.ok(pg.transactionLog.includes('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'));
    assert.ok(pg.transactionLog.includes('BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE'));
    assert.equal(pg.releases, 5);
});
test('compareAndSwap installs and journals exactly one next revision', async () => {
    const pg = fakePostgres();
    const store = createTrustProgramPostgresStore({ pool: pg.pool });
    const created = await store.create(initialState('instance-cas'));
    const next = structuredClone(created.state);
    next.revision = 1;
    next.updated_at = '2026-07-21T16:31:00.000Z';
    next.stages.identify.status = 'satisfied';
    assert.deepEqual(await store.compareAndSwap({
        instanceId: 'instance-cas', expectedRevision: 0, state: next,
    }), { ok: true, state: next });
    assert.deepEqual(await store.compareAndSwap({
        instanceId: 'instance-cas', expectedRevision: 0, state: next,
    }), { ok: false, reason: 'revision_conflict' });
    const history = pg.events.get('instance-cas');
    assert.equal(history.length, 2);
    assert.deepEqual(history.map(({ revision, previous_revision, event_kind }) => ({
        revision, previous_revision, event_kind,
    })), [
        { revision: 0, previous_revision: null, event_kind: 'create' },
        { revision: 1, previous_revision: 0, event_kind: 'cas' },
    ]);
    assert.equal(history[1].state_json, pg.records.get('instance-cas').state_json);
    assert.equal(history[1].state_digest, pg.records.get('instance-cas').state_digest);
});
test('durable transitions refuse a timestamp older than the stored revision', async () => {
    const pg = fakePostgres();
    const store = createTrustProgramPostgresStore({ pool: pg.pool });
    const created = await store.create(initialState('instance-clock'));
    const next = structuredClone(created.state);
    next.revision = 1;
    next.updated_at = '2026-07-21T16:29:59.999Z';
    assert.deepEqual(await store.compareAndSwap({
        instanceId: 'instance-clock', expectedRevision: 0, state: next,
    }), { ok: false, reason: 'clock_regression' });
    assert.equal((await store.get('instance-clock')).state.revision, 0);
    assert.match(MIGRATION, /'clock_regression'::pg_catalog\.text/);
});
test('invalidation matches the kernel transition and is revision-fenced', async () => {
    const pg = fakePostgres();
    const store = createTrustProgramPostgresStore({ pool: pg.pool });
    await store.create(initialState('instance-invalidate'));
    assert.deepEqual(await store.invalidate({
        instanceId: 'instance-invalidate', expectedRevision: 7,
        reason: 'operator revoked authorization', at: Date.parse('2026-07-21T16:32:00.000Z'),
    }), { ok: false, reason: 'revision_conflict' });
    const invalidated = await store.invalidate({
        instanceId: 'instance-invalidate', expectedRevision: 0,
        reason: 'operator revoked authorization', at: Date.parse('2026-07-21T16:32:00.000Z'),
    });
    assert.equal(invalidated.ok, true);
    assert.equal(invalidated.state.status, 'invalidated');
    assert.equal(invalidated.state.revision, 1);
    assert.equal(invalidated.state.updated_at, '2026-07-21T16:32:00.000Z');
    assert.equal(invalidated.state.invalidation_reason, 'operator revoked authorization');
    assert.deepEqual(Object.values(invalidated.state.stages).map((stage) => stage.status), ['invalidated', 'invalidated']);
    assert.equal(invalidated.state.execution.status, 'invalidated');
    const event = pg.events.get('instance-invalidate').at(-1);
    assert.deepEqual({ revision: event.revision, previous_revision: event.previous_revision, kind: event.event_kind, reason: event.reason }, { revision: 1, previous_revision: 0, kind: 'invalidate', reason: 'operator revoked authorization' });
    assert.deepEqual(await store.invalidate({
        instanceId: 'instance-invalidate', expectedRevision: 1,
        reason: 'again', at: Date.parse('2026-07-21T16:33:00.000Z'),
    }), { ok: false, reason: 'program_instance_invalidated' });
});
test('invalidation preserves claimed and indeterminate consequences for safe reconciliation', async () => {
    for (const executionStatus of ['claimed', 'indeterminate']) {
        const pg = fakePostgres();
        const store = createTrustProgramPostgresStore({ pool: pg.pool });
        const instanceId = `instance-${executionStatus}`;
        const current = initialState(instanceId);
        current.execution.status = executionStatus;
        await store.create(current);
        const invalidated = await store.invalidate({
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
test('malformed rows, digest mismatch, ambiguous outcomes, and errors fail closed', async () => {
    const pg = fakePostgres();
    const store = createTrustProgramPostgresStore({ pool: pg.pool });
    await store.create(initialState('instance-closed'));
    pg.records.get('instance-closed').state_digest = `sha256:${'00'.repeat(32)}`;
    await assert.rejects(() => store.get('instance-closed'), /invalid state envelope/);
    assert.equal(pg.transactionLog.at(-1), 'ROLLBACK');
    pg.returnNext({ rowCount: 0, rows: [] });
    await assert.rejects(() => store.get('instance-missing'), /outcome is ambiguous/);
    assert.equal(pg.transactionLog.at(-1), 'ROLLBACK');
    pg.throwNext(new Error('database unavailable'));
    await assert.rejects(() => store.get('instance-missing'), /database unavailable/);
    assert.equal(pg.transactionLog.at(-1), 'ROLLBACK');
    assert.throws(() => createTrustProgramPostgresStore({ pool: { query: async () => ({}) } }), /transaction-capable pg pool/);
});
