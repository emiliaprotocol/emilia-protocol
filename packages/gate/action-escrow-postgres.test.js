// SPDX-License-Identifier: Apache-2.0
// Generated from action-escrow-postgres.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { ACTION_ESCROW_EVENT_TABLE, ACTION_ESCROW_MAX_STATE_BYTES, ACTION_ESCROW_STATE_DDL, ACTION_ESCROW_STATE_SQL, actionEscrowRuntimeGrantDdl, createActionEscrowPostgresStore, } from './action-escrow-postgres.js';
function fakePostgres() {
    const records = new Map();
    const events = new Map();
    let available = true;
    let loseNextResponse = false;
    return {
        records,
        events,
        set available(value) { available = value; },
        loseNextResponse() { loseNextResponse = true; },
        async query(text, params) {
            if (!available)
                throw new Error('database unavailable');
            let result;
            if (text === ACTION_ESCROW_STATE_SQL.health) {
                result = {
                    rowCount: 1,
                    rows: [{
                            table_ready: true,
                            event_table_ready: true,
                            can_use: true,
                            can_append_history: true,
                            owns_state_table: false,
                            owns_event_table: false,
                            can_destroy_state: false,
                            can_mutate_history: false,
                        }],
                };
            }
            else if (text === ACTION_ESCROW_STATE_SQL.read) {
                result = records.has(params[0])
                    ? { rowCount: 1, rows: [{ ...records.get(params[0]) }] }
                    : { rowCount: 0, rows: [] };
            }
            else if (text === ACTION_ESCROW_STATE_SQL.history) {
                const rows = [...(events.get(params[0]) ?? [])];
                result = { rowCount: rows.length, rows };
            }
            else if (text === ACTION_ESCROW_STATE_SQL.create) {
                if (records.has(params[0]))
                    result = { rowCount: 0, rows: [] };
                else {
                    records.set(params[0], {
                        revision: 0,
                        record_json: params[1],
                        updated_at: params[2],
                    });
                    events.set(params[0], [{
                            revision: 0,
                            previous_revision: null,
                            record_json: params[1],
                            record_digest: params[3],
                            recorded_at: params[2],
                        }]);
                    result = { rowCount: 1, rows: [{ revision: 0 }] };
                }
            }
            else if (text === ACTION_ESCROW_STATE_SQL.compareAndSwap) {
                if (records.get(params[0])?.revision !== params[1]
                    || records.get(params[0])?.updated_at > params[4]) {
                    result = { rowCount: 0, rows: [] };
                }
                else {
                    records.set(params[0], {
                        revision: params[2],
                        record_json: params[3],
                        updated_at: params[4],
                    });
                    const history = events.get(params[0]) ?? [];
                    history.push({
                        revision: params[2],
                        previous_revision: params[1],
                        record_json: params[3],
                        record_digest: params[5],
                        recorded_at: params[4],
                    });
                    events.set(params[0], history);
                    result = { rowCount: 1, rows: [{ revision: params[2] }] };
                }
            }
            else {
                throw new Error('unexpected SQL');
            }
            if (loseNextResponse) {
                loseNextResponse = false;
                throw new Error('response lost after database commit');
            }
            return result;
        },
    };
}
test('DDL creates a private state table with an exact size constraint', () => {
    assert.match(ACTION_ESCROW_STATE_DDL, /CREATE TABLE IF NOT EXISTS ep_action_escrow_state/);
    assert.match(ACTION_ESCROW_STATE_DDL, /revision\s+BIGINT NOT NULL CHECK \(revision >= 0\)/);
    assert.match(ACTION_ESCROW_STATE_DDL, new RegExp(`octet_length\\(record_json\\) <= ${ACTION_ESCROW_MAX_STATE_BYTES}`));
    assert.match(ACTION_ESCROW_STATE_DDL, /REVOKE ALL ON ep_action_escrow_state FROM PUBLIC/);
    assert.match(ACTION_ESCROW_STATE_DDL, new RegExp(`CREATE TABLE IF NOT EXISTS ${ACTION_ESCROW_EVENT_TABLE}`));
    assert.match(ACTION_ESCROW_STATE_DDL, /PRIMARY KEY \(agreement_key, revision\)/);
    assert.match(ACTION_ESCROW_STATE_DDL, /REVOKE UPDATE, DELETE, TRUNCATE ON ep_action_escrow_state_events FROM PUBLIC/);
});
test('runtime grants keep the application role non-destructive', () => {
    const ddl = actionEscrowRuntimeGrantDdl('emilia_action_escrow_runtime');
    assert.match(ddl, /GRANT SELECT, INSERT, UPDATE ON ep_action_escrow_state/);
    assert.match(ddl, /GRANT SELECT, INSERT ON ep_action_escrow_state_events/);
    assert.match(ddl, /REVOKE DELETE, TRUNCATE ON ep_action_escrow_state/);
    assert.match(ddl, /REVOKE UPDATE, DELETE, TRUNCATE ON ep_action_escrow_state_events/);
    assert.throws(() => actionEscrowRuntimeGrantDdl('runtime"; DROP TABLE x;--'), /role name is invalid/);
});
test('atomically creates, reads, and compare-and-swaps expected revisions', async () => {
    const pg = fakePostgres();
    let clock = 1000;
    const store = createActionEscrowPostgresStore({
        query: pg.query.bind(pg),
        now: () => clock++,
    });
    const first = '{"revision":0,"state":"draft"}';
    const second = '{"revision":1,"state":"awaiting_acceptance"}';
    assert.equal((await store.health()).ok, true);
    assert.equal(await store.read('agreement-1'), null);
    assert.deepEqual(await store.compareAndSwap('agreement-1', null, first), { applied: true, revision: 0 });
    assert.deepEqual(await store.compareAndSwap('agreement-1', null, first), { applied: false, revision: null });
    assert.deepEqual(await store.read('agreement-1'), { revision: 0, value: first });
    assert.deepEqual(await store.compareAndSwap('agreement-1', 7, '{"revision":8,"state":"awaiting_acceptance"}'), { applied: false, revision: null });
    assert.deepEqual(await store.compareAndSwap('agreement-1', 0, second), { applied: true, revision: 1 });
    assert.deepEqual(await store.read('agreement-1'), { revision: 1, value: second });
    assert.deepEqual((await store.readHistory('agreement-1')).map((entry) => ({
        revision: entry.revision,
        previous_revision: entry.previous_revision,
    })), [
        { revision: 0, previous_revision: null },
        { revision: 1, previous_revision: 0 },
    ]);
});
test('concurrent creates and transitions have one winner', async () => {
    const pg = fakePostgres();
    const store = createActionEscrowPostgresStore({
        query: pg.query.bind(pg),
        now: () => 1000,
    });
    const first = '{"revision":0,"state":"draft"}';
    const createResults = await Promise.all(Array.from({ length: 32 }, () => store.compareAndSwap('agreement-race', null, first)));
    assert.equal(createResults.filter((result) => result.applied).length, 1);
    const replacements = Array.from({ length: 32 }, (_, index) => `{"revision":1,"state":"effective","winner":${index}}`);
    const transitionResults = await Promise.all(replacements.map((replacement) => store.compareAndSwap('agreement-race', 0, replacement)));
    assert.equal(transitionResults.filter((result) => result.applied).length, 1);
    assert.match((await store.read('agreement-race')).value, /"state":"effective"/);
});
test('a response lost after CAS remains committed and never looks absent', async () => {
    const pg = fakePostgres();
    const store = createActionEscrowPostgresStore({
        query: pg.query.bind(pg),
        now: () => 1000,
    });
    const before = '{"revision":4,"state":"release_reserved"}';
    const after = '{"revision":5,"state":"release_indeterminate"}';
    for (let revision = 0; revision <= 4; revision += 1) {
        const value = revision === 4
            ? before
            : JSON.stringify({ revision, state: revision === 0 ? 'draft' : 'milestone_submitted' });
        await store.compareAndSwap('agreement-loss', revision === 0 ? null : revision - 1, value);
    }
    pg.loseNextResponse();
    await assert.rejects(store.compareAndSwap('agreement-loss', 4, after), /response lost/);
    assert.equal((await store.read('agreement-loss')).value, after);
    assert.deepEqual(await store.compareAndSwap('agreement-loss', 4, '{"revision":5,"state":"released"}'), { applied: false, revision: null });
});
test('history verification refuses mutation, gaps, and digest substitution', async () => {
    const pg = fakePostgres();
    const store = createActionEscrowPostgresStore({
        query: pg.query.bind(pg),
        now: () => 1000,
    });
    await store.compareAndSwap('agreement-history', null, '{"revision":0}');
    await store.compareAndSwap('agreement-history', 0, '{"revision":1}');
    pg.events.get('agreement-history')[1].record_digest = `sha256:${'0'.repeat(64)}`;
    await assert.rejects(store.readHistory('agreement-history'), /invalid or non-contiguous event/);
});
test('normal reads refuse truncated, reordered, or state-divergent journals', async (t) => {
    async function fixture() {
        const pg = fakePostgres();
        let clock = 1000;
        const store = createActionEscrowPostgresStore({
            query: pg.query.bind(pg),
            now: () => clock++,
        });
        await store.compareAndSwap('agreement-journal', null, '{"revision":0,"state":"draft"}');
        await store.compareAndSwap('agreement-journal', 0, '{"revision":1,"state":"awaiting_acceptance"}');
        return { pg, store };
    }
    await t.test('truncated', async () => {
        const { pg, store } = await fixture();
        pg.events.get('agreement-journal').pop();
        await assert.rejects(store.read('agreement-journal'), /state and append-only journal do not agree/);
    });
    await t.test('state divergent', async () => {
        const { pg, store } = await fixture();
        pg.records.get('agreement-journal').record_json =
            '{"revision":1,"state":"released"}';
        await assert.rejects(store.read('agreement-journal'), /state and append-only journal do not agree/);
    });
    await t.test('time reordered', async () => {
        const { pg, store } = await fixture();
        pg.events.get('agreement-journal')[1].recorded_at = 999;
        await assert.rejects(store.read('agreement-journal'), /invalid or non-contiguous event/);
    });
});
test('database outage and malformed driver results propagate fail closed', async () => {
    const pg = fakePostgres();
    const store = createActionEscrowPostgresStore({
        query: pg.query.bind(pg),
        now: () => 1000,
    });
    pg.available = false;
    await assert.rejects(store.read('agreement-outage'), /database unavailable/);
    await assert.rejects(store.compareAndSwap('agreement-outage', null, '{"revision":0}'), /database unavailable/);
    const malformed = createActionEscrowPostgresStore({
        query: async () => ({}),
        now: () => 1000,
    });
    await assert.rejects(malformed.read('agreement-malformed'), /malformed Postgres result/);
});
test('strict JSON, bounds, keys, and monotonic time are enforced', async () => {
    const pg = fakePostgres();
    let time = 2000;
    const store = createActionEscrowPostgresStore({
        query: pg.query.bind(pg),
        now: () => time,
    });
    await assert.rejects(store.compareAndSwap('agreement-duplicate', null, '{"revision":0,"state":"draft","state":"released"}'), /bounded strict JSON/);
    await assert.rejects(store.compareAndSwap('agreement-scalar', null, '"released"'), /bounded strict JSON/);
    await assert.rejects(store.compareAndSwap('agreement-array', null, '["draft"]'), /bounded strict JSON/);
    await assert.rejects(store.compareAndSwap('agreement-oversize', null, JSON.stringify({ revision: 0, value: 'x'.repeat(ACTION_ESCROW_MAX_STATE_BYTES) })), /bounded strict JSON/);
    await assert.rejects(store.compareAndSwap('bad\u0000key', null, '{"revision":0}'), /agreement key is invalid/);
    await store.compareAndSwap('agreement-clock', null, '{"revision":0}');
    time = 1999;
    await assert.rejects(store.compareAndSwap('agreement-clock', 0, '{"revision":1}'), /clock regression refused/);
    await assert.rejects(store.compareAndSwap('agreement-revision', null, '{"revision":1}'), /revision must match/);
});
test('database time fencing refuses rollback across separate store processes', async () => {
    const pg = fakePostgres();
    const first = createActionEscrowPostgresStore({
        query: pg.query.bind(pg),
        now: () => 2000,
    });
    const restarted = createActionEscrowPostgresStore({
        query: pg.query.bind(pg),
        now: () => 1000,
    });
    await first.compareAndSwap('agreement-restart-clock', null, '{"revision":0}');
    assert.deepEqual(await restarted.compareAndSwap('agreement-restart-clock', 0, '{"revision":1}'), { applied: false, revision: null });
    assert.deepEqual(await first.read('agreement-restart-clock'), { revision: 0, value: '{"revision":0}' });
});
test('health refuses owner or destructive runtime privileges', async () => {
    const unsafeRows = [
        { owns_state_table: true },
        { owns_event_table: true },
        { can_destroy_state: true },
        { can_mutate_history: true },
    ];
    for (const override of unsafeRows) {
        const store = createActionEscrowPostgresStore({
            query: async (text) => {
                assert.equal(text, ACTION_ESCROW_STATE_SQL.health);
                return {
                    rowCount: 1,
                    rows: [{
                            table_ready: true,
                            event_table_ready: true,
                            can_use: true,
                            can_append_history: true,
                            owns_state_table: false,
                            owns_event_table: false,
                            can_destroy_state: false,
                            can_mutate_history: false,
                            ...override,
                        }],
                };
            },
        });
        assert.equal((await store.health()).ok, false);
    }
});
