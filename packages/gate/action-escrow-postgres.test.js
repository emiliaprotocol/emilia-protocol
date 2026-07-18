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
      } else if (text === ACTION_ESCROW_STATE_SQL.get) {
        result = records.has(params[0])
          ? { rowCount: 1, rows: [{ record_json: records.get(params[0]) }] }
          : { rowCount: 0, rows: [] };
      } else if (text === ACTION_ESCROW_STATE_SQL.addIfAbsent) {
        if (records.has(params[0])) result = { rowCount: 0, rows: [] };
        else {
          records.set(params[0], params[1]);
          result = { rowCount: 1, rows: [] };
        }
      } else if (text === ACTION_ESCROW_STATE_SQL.compareAndSet) {
        if (records.get(params[0]) !== params[1]) result = { rowCount: 0, rows: [] };
        else {
          records.set(params[0], params[2]);
          result = { rowCount: 1, rows: [] };
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
  assert.match(ACTION_ESCROW_STATE_DDL, new RegExp(`octet_length\\(record_json\\) <= ${ACTION_ESCROW_MAX_STATE_BYTES}`));
  assert.match(ACTION_ESCROW_STATE_DDL, /REVOKE ALL ON ep_action_escrow_state FROM PUBLIC/);
});

test('atomically creates, reads, and compare-and-swaps exact serialized snapshots', async () => {
  const pg = fakePostgres();
  let clock = 1000;
  const store = createActionEscrowPostgresStore({
    query: pg.query.bind(pg),
    now: () => clock++,
  });
  const first = '{"revision":0,"state":"draft"}';
  const second = '{"revision":1,"state":"awaiting_acceptance"}';

  assert.equal((await store.health()).ok, true);
  assert.equal(await store.get('agreement-1'), undefined);
  assert.equal(await store.addIfAbsent('agreement-1', first), true);
  assert.equal(await store.addIfAbsent('agreement-1', first), false);
  assert.equal(await store.read('agreement-1'), first);
  assert.equal(await store.compareAndSet('agreement-1', '{"wrong":true}', second), false);
  assert.equal(await store.compareAndSet('agreement-1', first, second), true);
  assert.equal(await store.get('agreement-1'), second);
});

test('concurrent creates and transitions have one winner', async () => {
  const pg = fakePostgres();
  const store = createActionEscrowPostgresStore({
    query: pg.query.bind(pg),
    now: () => 1000,
  });
  const first = '{"revision":0,"state":"draft"}';
  const createResults = await Promise.all(
    Array.from({ length: 32 }, () => store.addIfAbsent('agreement-race', first)),
  );
  assert.equal(createResults.filter(Boolean).length, 1);

  const replacements = Array.from(
    { length: 32 },
    (_, index) => `{"revision":1,"state":"effective","winner":${index}}`,
  );
  const transitionResults = await Promise.all(
    replacements.map((replacement) => store.compareAndSet('agreement-race', first, replacement)),
  );
  assert.equal(transitionResults.filter(Boolean).length, 1);
  assert.match(await store.get('agreement-race'), /"state":"effective"/);
});

test('a response lost after CAS remains committed and never looks absent', async () => {
  const pg = fakePostgres();
  const store = createActionEscrowPostgresStore({
    query: pg.query.bind(pg),
    now: () => 1000,
  });
  const before = '{"revision":4,"state":"release_reserved"}';
  const after = '{"revision":5,"state":"release_indeterminate"}';
  await store.addIfAbsent('agreement-loss', before);
  pg.loseNextResponse();
  await assert.rejects(
    store.compareAndSet('agreement-loss', before, after),
    /response lost/,
  );
  assert.equal(await store.get('agreement-loss'), after);
  assert.equal(await store.compareAndSet('agreement-loss', before, '{"revision":5,"state":"released"}'), false);
});

test('database outage and malformed driver results propagate fail closed', async () => {
  const pg = fakePostgres();
  const store = createActionEscrowPostgresStore({
    query: pg.query.bind(pg),
    now: () => 1000,
  });
  pg.available = false;
  await assert.rejects(store.get('agreement-outage'), /database unavailable/);
  await assert.rejects(
    store.addIfAbsent('agreement-outage', '{"revision":0}'),
    /database unavailable/,
  );

  const malformed = createActionEscrowPostgresStore({
    query: async () => ({}),
    now: () => 1000,
  });
  await assert.rejects(malformed.get('agreement-malformed'), /malformed Postgres result/);
});

test('strict JSON, bounds, keys, and monotonic time are enforced', async () => {
  const pg = fakePostgres();
  let time = 2000;
  const store = createActionEscrowPostgresStore({
    query: pg.query.bind(pg),
    now: () => time,
  });
  await assert.rejects(
    store.addIfAbsent('agreement-duplicate', '{"state":"draft","state":"released"}'),
    /bounded strict JSON/,
  );
  await assert.rejects(
    store.addIfAbsent('agreement-scalar', '"released"'),
    /bounded strict JSON/,
  );
  await assert.rejects(
    store.addIfAbsent('agreement-array', '["draft"]'),
    /bounded strict JSON/,
  );
  await assert.rejects(
    store.addIfAbsent('agreement-oversize', JSON.stringify({ value: 'x'.repeat(ACTION_ESCROW_MAX_STATE_BYTES) })),
    /bounded strict JSON/,
  );
  await assert.rejects(
    store.addIfAbsent('bad\u0000key', '{"revision":0}'),
    /agreement key is invalid/,
  );

  await store.addIfAbsent('agreement-clock', '{"revision":0}');
  time = 1999;
  await assert.rejects(
    store.compareAndSet('agreement-clock', '{"revision":0}', '{"revision":1}'),
    /clock regression refused/,
  );
});
