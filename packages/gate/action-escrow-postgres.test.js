// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ACTION_ESCROW_MAX_STATE_BYTES,
  ACTION_ESCROW_STATE_DDL,
  ACTION_ESCROW_STATE_SQL,
  createActionEscrowPostgresStore,
} from './action-escrow-postgres.js';

function fakePostgres() {
  const records = new Map();
  let available = true;
  let loseNextResponse = false;

  return {
    records,
    set available(value) { available = value; },
    loseNextResponse() { loseNextResponse = true; },
    async query(text, params) {
      if (!available) throw new Error('database unavailable');
      let result;
      if (text === ACTION_ESCROW_STATE_SQL.health) {
        result = { rowCount: 1, rows: [{ table_ready: true, can_use: true }] };
      } else if (text === ACTION_ESCROW_STATE_SQL.read) {
        result = records.has(params[0])
          ? { rowCount: 1, rows: [{ ...records.get(params[0]) }] }
          : { rowCount: 0, rows: [] };
      } else if (text === ACTION_ESCROW_STATE_SQL.create) {
        if (records.has(params[0])) result = { rowCount: 0, rows: [] };
        else {
          records.set(params[0], { revision: 0, record_json: params[1] });
          result = { rowCount: 1, rows: [{ revision: 0 }] };
        }
      } else if (text === ACTION_ESCROW_STATE_SQL.compareAndSwap) {
        if (records.get(params[0])?.revision !== params[1]) {
          result = { rowCount: 0, rows: [] };
        }
        else {
          records.set(params[0], { revision: params[2], record_json: params[3] });
          result = { rowCount: 1, rows: [{ revision: params[2] }] };
        }
      } else {
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
  assert.deepEqual(
    await store.compareAndSwap('agreement-1', null, first),
    { applied: true, revision: 0 },
  );
  assert.deepEqual(
    await store.compareAndSwap('agreement-1', null, first),
    { applied: false, revision: null },
  );
  assert.deepEqual(await store.read('agreement-1'), { revision: 0, value: first });
  assert.deepEqual(
    await store.compareAndSwap(
      'agreement-1',
      7,
      '{"revision":8,"state":"awaiting_acceptance"}',
    ),
    { applied: false, revision: null },
  );
  assert.deepEqual(
    await store.compareAndSwap('agreement-1', 0, second),
    { applied: true, revision: 1 },
  );
  assert.deepEqual(await store.read('agreement-1'), { revision: 1, value: second });
});

test('concurrent creates and transitions have one winner', async () => {
  const pg = fakePostgres();
  const store = createActionEscrowPostgresStore({
    query: pg.query.bind(pg),
    now: () => 1000,
  });
  const first = '{"revision":0,"state":"draft"}';
  const createResults = await Promise.all(
    Array.from(
      { length: 32 },
      () => store.compareAndSwap('agreement-race', null, first),
    ),
  );
  assert.equal(createResults.filter((result) => result.applied).length, 1);

  const replacements = Array.from(
    { length: 32 },
    (_, index) => `{"revision":1,"state":"effective","winner":${index}}`,
  );
  const transitionResults = await Promise.all(
    replacements.map((replacement) => store.compareAndSwap('agreement-race', 0, replacement)),
  );
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
  pg.records.set('agreement-loss', { revision: 4, record_json: before });
  pg.loseNextResponse();
  await assert.rejects(
    store.compareAndSwap('agreement-loss', 4, after),
    /response lost/,
  );
  assert.equal((await store.read('agreement-loss')).value, after);
  assert.deepEqual(
    await store.compareAndSwap(
      'agreement-loss',
      4,
      '{"revision":5,"state":"released"}',
    ),
    { applied: false, revision: null },
  );
});

test('database outage and malformed driver results propagate fail closed', async () => {
  const pg = fakePostgres();
  const store = createActionEscrowPostgresStore({
    query: pg.query.bind(pg),
    now: () => 1000,
  });
  pg.available = false;
  await assert.rejects(store.read('agreement-outage'), /database unavailable/);
  await assert.rejects(
    store.compareAndSwap('agreement-outage', null, '{"revision":0}'),
    /database unavailable/,
  );

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
  await assert.rejects(
    store.compareAndSwap(
      'agreement-duplicate',
      null,
      '{"revision":0,"state":"draft","state":"released"}',
    ),
    /bounded strict JSON/,
  );
  await assert.rejects(
    store.compareAndSwap('agreement-scalar', null, '"released"'),
    /bounded strict JSON/,
  );
  await assert.rejects(
    store.compareAndSwap('agreement-array', null, '["draft"]'),
    /bounded strict JSON/,
  );
  await assert.rejects(
    store.compareAndSwap(
      'agreement-oversize',
      null,
      JSON.stringify({ revision: 0, value: 'x'.repeat(ACTION_ESCROW_MAX_STATE_BYTES) }),
    ),
    /bounded strict JSON/,
  );
  await assert.rejects(
    store.compareAndSwap('bad\u0000key', null, '{"revision":0}'),
    /agreement key is invalid/,
  );

  await store.compareAndSwap('agreement-clock', null, '{"revision":0}');
  time = 1999;
  await assert.rejects(
    store.compareAndSwap('agreement-clock', 0, '{"revision":1}'),
    /clock regression refused/,
  );
  await assert.rejects(
    store.compareAndSwap('agreement-revision', null, '{"revision":1}'),
    /revision must match/,
  );
});
