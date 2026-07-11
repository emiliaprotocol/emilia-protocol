// SPDX-License-Identifier: Apache-2.0
/**
 * @emilia-protocol/gate — Postgres consumption backend tests. `node --test`.
 *
 * No database: a fake in-memory pg client implements the exact statements in
 * CONSUMPTION_SQL with real INSERT ... ON CONFLICT semantics — each statement
 * executes as one atomic (synchronous) block after an async driver hop, which
 * is precisely the guarantee a single SQL statement gives on a real server.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createPostgresBackend,
  CONSUMPTION_TABLE,
  CONSUMPTION_TABLE_DDL,
  CONSUMPTION_SQL,
  PG_CONSUMPTION_VERSION,
} from './store-postgres.js';
import { createDurableConsumptionStore } from './store.js';

/** Fake pg client. `failOn(text, params)` -> true makes query() throw. */
function createFakePg({ failOn } = {}) {
  const table = new Map(); // consumption_key -> { state, consumed_at, expires_at }
  async function query(text, params) {
    // Simulate the network hop BEFORE touching state: concurrent callers all
    // get in flight, then each statement runs as one atomic sync block below.
    await Promise.resolve();
    if (failOn && failOn(text, params)) throw new Error('pg_unavailable');
    switch (text) {
      case CONSUMPTION_SQL.addIfAbsent: {
        const [key, state, consumedAt, expiresAt] = params;
        if (table.has(key)) return { rowCount: 0, rows: [] }; // ON CONFLICT DO NOTHING
        table.set(key, { state, consumed_at: consumedAt, expires_at: expiresAt });
        return { rowCount: 1, rows: [] };
      }
      case CONSUMPTION_SQL.compareAndSet: {
        const [key, expected, replacement, consumedAt, expiresAt] = params;
        if (table.get(key)?.state !== expected) return { rowCount: 0, rows: [] };
        table.set(key, { state: replacement, consumed_at: consumedAt, expires_at: expiresAt });
        return { rowCount: 1, rows: [] };
      }
      case CONSUMPTION_SQL.deleteIfValue: {
        const [key, expected] = params;
        if (table.get(key)?.state !== expected) return { rowCount: 0, rows: [] };
        return { rowCount: table.delete(key) ? 1 : 0, rows: [] };
      }
      case CONSUMPTION_SQL.has: {
        return table.has(params[0])
          ? { rowCount: 1, rows: [{ '?column?': 1 }] }
          : { rowCount: 0, rows: [] };
      }
      case CONSUMPTION_SQL.cleanupExpired: {
        const [nowArg] = params;
        let n = 0;
        for (const [k, v] of table) {
          if (v.state.startsWith('committed:') && v.expires_at != null && v.expires_at <= nowArg) { table.delete(k); n += 1; }
        }
        return { rowCount: n, rows: [] };
      }
      default:
        throw new Error(`fake pg: unrecognized statement: ${text}`);
    }
  }
  return { query, table };
}

function makeBackend(opts = {}) {
  const fake = createFakePg(opts.fake);
  const clock = { t: 1_000_000 };
  const backend = createPostgresBackend({ query: fake.query, now: () => clock.t, ...opts.backend });
  return { fake, clock, backend };
}

test('version + DDL: single table, PK on consumption key, consumed_at, expires_at', () => {
  assert.equal(PG_CONSUMPTION_VERSION, 'EP-GATE-PG-CONSUMPTION-v2');
  assert.match(CONSUMPTION_TABLE_DDL, /CREATE TABLE IF NOT EXISTS ep_gate_consumption/);
  assert.match(CONSUMPTION_TABLE_DDL, /consumption_key TEXT PRIMARY KEY/);
  assert.match(CONSUMPTION_TABLE_DDL, /consumed_at\s+BIGINT NOT NULL/);
  assert.match(CONSUMPTION_TABLE_DDL, /expires_at\s+BIGINT/);
  // exactly ONE table in the DDL
  assert.equal(CONSUMPTION_TABLE_DDL.match(/CREATE TABLE/g).length, 1);
  assert.match(CONSUMPTION_SQL.addIfAbsent, /ON CONFLICT \(consumption_key\) DO NOTHING/);
});

test('fails closed at construction: query must be a function', () => {
  assert.throws(() => createPostgresBackend({}), /query must be/);
  assert.throws(() => createPostgresBackend(), /query must be/);
  assert.throws(() => createPostgresBackend({ query: 'not-a-fn' }), /query must be/);
});

test('addIfAbsent: first insert wins, replay refused (row count decides)', async () => {
  const { backend } = makeBackend();
  assert.equal(await backend.addIfAbsent('rcpt_1', 'committed'), true);
  assert.equal(await backend.addIfAbsent('rcpt_1', 'committed'), false); // replay
  assert.equal(await backend.has('rcpt_1'), true);
  assert.equal(await backend.has('rcpt_never'), false);
});

test('durable store contract: consume once, replay refused across the full store', async () => {
  const { backend } = makeBackend();
  const store = createDurableConsumptionStore(backend);
  assert.equal(await store.consume('rcpt_a'), true);
  assert.equal(await store.consume('rcpt_a'), false); // replay refused
  assert.equal(await store.has('rcpt_a'), true);
});

test('durable store contract: reserve/commit/release use ownership-fenced transitions', async () => {
  const { backend, fake } = makeBackend();
  const store = createDurableConsumptionStore(backend);
  // reserve blocks a concurrent replay, commit makes it permanent
  assert.equal(await store.reserve('rcpt_b'), true);
  assert.equal(await store.reserve('rcpt_b'), false);
  assert.match(fake.table.get('rcpt_b').state, /^reserved:v2:/);
  assert.equal(fake.table.get('rcpt_b').expires_at, null, 'in-flight reservations never expire automatically');
  assert.equal(await store.commit('rcpt_b'), true);
  assert.equal(fake.table.get('rcpt_b').state, 'committed:v2');
  assert.equal(await store.consume('rcpt_b'), false); // still consumed
  // release after a FAILED action leaves the approval retryable
  assert.equal(await store.reserve('rcpt_c'), true);
  assert.equal(await store.release('rcpt_c'), true);
  assert.equal(await store.reserve('rcpt_c'), true); // retryable again
});

test('concurrent duplicate consume: two racing calls, exactly one wins', async () => {
  const { backend } = makeBackend();
  const store = createDurableConsumptionStore(backend);
  const results = await Promise.all([store.consume('rcpt_race'), store.consume('rcpt_race')]);
  results.sort();
  assert.deepEqual(results, [false, true]); // one winner, one replay — never two
  // and the same under reserve()
  const r2 = await Promise.all([store.reserve('rcpt_race2'), store.reserve('rcpt_race2')]);
  assert.deepEqual(r2.sort(), [false, true]);
});

test('crash/failover: another store cannot commit or release a reservation it does not own', async () => {
  const { backend } = makeBackend();
  const owner = createDurableConsumptionStore(backend, { reservationTokenFactory: () => 'owner-token-00000001' });
  const failover = createDurableConsumptionStore(backend, { reservationTokenFactory: () => 'failover-token-0001' });
  assert.equal(await owner.reserve('rcpt_crash'), true);
  assert.equal(await failover.reserve('rcpt_crash'), false);
  await assert.rejects(failover.commit('rcpt_crash'), /does not own reservation/);
  await assert.rejects(failover.release('rcpt_crash'), /does not own reservation/);
  assert.equal(await backend.has('rcpt_crash'), true, 'the uncertain reservation remains fail closed');
});

test('stale release cannot delete a reservation whose ownership changed', async () => {
  const { backend, fake } = makeBackend();
  const stale = createDurableConsumptionStore(backend, { reservationTokenFactory: () => 'stale-owner-token01' });
  assert.equal(await stale.reserve('rcpt_fenced'), true);
  assert.equal(
    await backend.compareAndSet(
      'rcpt_fenced',
      'reserved:v2:stale-owner-token01',
      'reserved:v2:newer-owner-token01',
    ),
    true,
  );
  await assert.rejects(stale.release('rcpt_fenced'), /ownership was lost/);
  assert.equal(fake.table.get('rcpt_fenced').state, 'reserved:v2:newer-owner-token01');
});

test('FAIL-CLOSED: backend error PROPAGATES — never treated as not-consumed', async () => {
  const { backend } = makeBackend({ fake: { failOn: () => true } });
  const store = createDurableConsumptionStore(backend);
  // Every path rejects; none resolves to a false ("replay") or true ("fresh") verdict.
  await assert.rejects(store.consume('rcpt_x'), /pg_unavailable/);
  await assert.rejects(store.reserve('rcpt_x'), /pg_unavailable/);
  await assert.rejects(store.commit('rcpt_x'), /does not own reservation/);
  await assert.rejects(store.release('rcpt_x'), /does not own reservation/);
  await assert.rejects(backend.compareAndSet('rcpt_x', 'reserved:a', 'committed:v2'), /pg_unavailable/);
  await assert.rejects(backend.deleteIfValue('rcpt_x', 'reserved:a'), /pg_unavailable/);
  await assert.rejects(store.has('rcpt_x'), /pg_unavailable/);
  await assert.rejects(backend.cleanupExpired(1_000_000), /pg_unavailable/);
});

test('FAIL-CLOSED: malformed driver result (no rowCount) throws instead of guessing', async () => {
  const backend = createPostgresBackend({ query: async () => ({ rows: [] }) });
  await assert.rejects(backend.addIfAbsent('rcpt_y', 'committed'), /cannot prove one-time use/);
  await assert.rejects(backend.compareAndSet('rcpt_y', 'a', 'b'), /cannot prove reservation ownership/);
  await assert.rejects(backend.deleteIfValue('rcpt_y', 'a'), /cannot prove reservation ownership/);
});

test('ttlSeconds stamps expires_at from the injected clock; no TTL -> NULL', async () => {
  const { backend, fake, clock } = makeBackend();
  clock.t = 5_000_000;
  const store = createDurableConsumptionStore(backend, { ttlSeconds: 60 });
  await store.consume('rcpt_ttl');
  assert.equal(fake.table.get('rcpt_ttl').expires_at, 5_000_000 + 60_000);
  assert.equal(fake.table.get('rcpt_ttl').consumed_at, 5_000_000);
  await backend.addIfAbsent('rcpt_forever', 'committed:v2'); // no opt -> never expires
  assert.equal(fake.table.get('rcpt_forever').expires_at, null);
});

test('cleanupExpired removes ONLY expired rows', async () => {
  const { backend, fake, clock } = makeBackend();
  clock.t = 0;
  await backend.addIfAbsent('rcpt_short', 'committed:v2', { ttlSeconds: 60 });     // expires at 60s
  await backend.addIfAbsent('rcpt_long', 'committed:v2', { ttlSeconds: 3600 });    // expires at 1h
  await backend.addIfAbsent('rcpt_forever', 'committed:v2');                       // never expires
  clock.t = 61_000; // 61s later
  const removed = await backend.cleanupExpired();
  assert.equal(removed, 1);
  assert.equal(await backend.has('rcpt_short'), false);   // GC'd — consumable again
  assert.equal(await backend.has('rcpt_long'), true);     // not yet expired
  assert.equal(await backend.has('rcpt_forever'), true);  // NULL expiry survives forever
  assert.equal(fake.table.size, 2);
  // after GC the id is fresh again (mirrors Redis TTL semantics)
  assert.equal(await backend.addIfAbsent('rcpt_short', 'committed', { ttlSeconds: 60 }), true);
});

test('expired-but-uncleaned row STILL refuses: TTL is garbage collection, never a grant', async () => {
  const { backend, clock } = makeBackend();
  clock.t = 0;
  const store = createDurableConsumptionStore(backend, { ttlSeconds: 1 });
  assert.equal(await store.consume('rcpt_stale'), true);
  clock.t = 10_000; // long past expiry, but cleanupExpired has NOT run
  assert.equal(await store.consume('rcpt_stale'), false); // conservative refusal
  assert.equal(await store.has('rcpt_stale'), true);
});

test('cleanupExpired with explicit `at` uses the given instant, not the clock', async () => {
  const { backend, clock } = makeBackend();
  clock.t = 0;
  await backend.addIfAbsent('rcpt_z', 'committed:v2', { ttlSeconds: 10 });
  assert.equal(await backend.cleanupExpired(9_999), 0);  // one ms early — kept
  assert.equal(await backend.cleanupExpired(10_000), 1); // boundary — removed
});

test('clock regression fails closed before any expiry-bearing write or cleanup', async () => {
  const { backend, fake, clock } = makeBackend();
  clock.t = 50_000;
  assert.equal(await backend.addIfAbsent('clock-a', 'committed:v2', { ttlSeconds: 60 }), true);
  const before = new Map(fake.table);

  clock.t = 49_999;
  await assert.rejects(
    backend.addIfAbsent('clock-b', 'committed:v2', { ttlSeconds: 60 }),
    /clock regression refused/,
  );
  await assert.rejects(backend.cleanupExpired(49_000), /clock regression refused/);
  assert.deepEqual(fake.table, before, 'clock regression must not mutate durable state');
});

test('malformed clock values fail closed instead of creating immortal or premature rows', async () => {
  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    const fake = createFakePg();
    const backend = createPostgresBackend({ query: fake.query, now: () => bad });
    await assert.rejects(backend.addIfAbsent('bad-clock', 'committed:v2', { ttlSeconds: 1 }), /safe-integer/);
    assert.equal(fake.table.size, 0);
  }
});

test('table name constant matches the DDL and every statement', () => {
  assert.equal(CONSUMPTION_TABLE, 'ep_gate_consumption');
  for (const sql of Object.values(CONSUMPTION_SQL)) {
    assert.ok(sql.includes(CONSUMPTION_TABLE), `statement missing table name: ${sql}`);
  }
});
