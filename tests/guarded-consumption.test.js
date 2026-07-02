// SPDX-License-Identifier: Apache-2.0
//
// Replay-defense consumption store for /api/v1/guarded.
//
// The route path (in-memory backend) is covered by guarded-replay.test.js. This
// file covers the DURABLE Supabase backend and its fail-closed error branches:
// a unique-violation means "already consumed" (replay → false), and ANY other
// backend error must throw so the route refuses rather than allowing a possible
// replay.

import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  consumeKey,
  createSupabaseBackend,
  getGuardedConsumptionStore,
  __resetGuardedConsumptionStoreForTests,
} from '../lib/http/guarded-consumption.js';

// getGuardedConsumptionStore dynamically imports @/lib/supabase on the
// production path; mock it so we can drive both the durable-store branch and
// the fail-closed throw without a real Supabase.
const getServiceClient = vi.fn();
vi.mock('@/lib/supabase', () => ({ getServiceClient: (...a) => getServiceClient(...a) }));

// A minimal chainable Supabase double. Each terminal call (.insert, .eq after
// .update/.delete, .maybeSingle) resolves to the result configured for that
// table op. The builder is thenable so `await supabase.from(t).insert(...)` and
// `await supabase.from(t).update(...).eq(...)` both resolve to `result`.
function fakeSupabase(result) {
  // The chain is itself thenable so terminal ops that end at `.eq()` (update /
  // delete) resolve to `result` when awaited, while `.select().eq().maybeSingle()`
  // resolves via maybeSingle. `.insert()` resolves directly.
  const chain = {
    insert: () => Promise.resolve(result),
    update: () => chain,
    delete: () => chain,
    select: () => chain,
    eq: () => chain,
    maybeSingle: () => Promise.resolve(result),
    then: (resolve) => resolve(result),
  };
  return { from: () => chain };
}

describe('consumeKey', () => {
  it('is deterministic for the same (action, receiptId)', () => {
    expect(consumeKey('payment.release', 'r1')).toBe(consumeKey('payment.release', 'r1'));
  });

  it('is action-scoped: same receipt, different action → different key', () => {
    expect(consumeKey('payment.release', 'r1')).not.toBe(consumeKey('data.delete', 'r1'));
  });

  it('is receipt-scoped: same action, different receipt → different key', () => {
    expect(consumeKey('payment.release', 'r1')).not.toBe(consumeKey('payment.release', 'r2'));
  });
});

describe('createSupabaseBackend', () => {
  describe('addIfAbsent', () => {
    it('returns true when the insert succeeds (first-seen)', async () => {
      const be = createSupabaseBackend(fakeSupabase({ error: null }));
      await expect(be.addIfAbsent('k', 'reserved')).resolves.toBe(true);
    });

    it('returns false on unique_violation (23505) — the receipt was already consumed', async () => {
      const be = createSupabaseBackend(fakeSupabase({ error: { code: '23505' } }));
      await expect(be.addIfAbsent('k', 'reserved')).resolves.toBe(false);
    });

    it('throws (fail closed) on any other backend error', async () => {
      const be = createSupabaseBackend(fakeSupabase({ error: { message: 'connection reset' } }));
      await expect(be.addIfAbsent('k', 'reserved')).rejects.toThrow(/insert failed/);
    });
  });

  describe('set', () => {
    it('resolves when the update succeeds', async () => {
      const be = createSupabaseBackend(fakeSupabase({ error: null }));
      await expect(be.set('k', 'committed')).resolves.toBeUndefined();
    });

    it('throws (fail closed) when the update errors', async () => {
      const be = createSupabaseBackend(fakeSupabase({ error: { message: 'boom' } }));
      await expect(be.set('k', 'committed')).rejects.toThrow(/set failed/);
    });
  });

  describe('delete', () => {
    it('resolves when the delete succeeds', async () => {
      const be = createSupabaseBackend(fakeSupabase({ error: null }));
      await expect(be.delete('k')).resolves.toBeUndefined();
    });

    it('throws (fail closed) when the delete errors', async () => {
      const be = createSupabaseBackend(fakeSupabase({ error: { message: 'boom' } }));
      await expect(be.delete('k')).rejects.toThrow(/delete failed/);
    });
  });

  describe('has', () => {
    it('returns true when a row exists', async () => {
      const be = createSupabaseBackend(fakeSupabase({ data: { consume_key: 'k' }, error: null }));
      await expect(be.has('k')).resolves.toBe(true);
    });

    it('returns false when no row exists', async () => {
      const be = createSupabaseBackend(fakeSupabase({ data: null, error: null }));
      await expect(be.has('k')).resolves.toBe(false);
    });

    it('throws (fail closed) when the lookup errors', async () => {
      const be = createSupabaseBackend(fakeSupabase({ data: null, error: { message: 'boom' } }));
      await expect(be.has('k')).rejects.toThrow(/has failed/);
    });
  });
});

describe('getGuardedConsumptionStore (dev posture)', () => {
  it('reserves once, refuses replay, and releases in the in-memory backend', async () => {
    delete process.env.NODE_ENV; // force dev posture → in-memory backend
    __resetGuardedConsumptionStoreForTests();
    const store = await getGuardedConsumptionStore();

    expect(await store.reserve('key-a')).toBe(true);
    // Second reserve of the same key loses the race — replay refused.
    expect(await store.reserve('key-a')).toBe(false);

    await store.commit('key-a');
    // A distinct key is independent.
    expect(await store.reserve('key-b')).toBe(true);
    await store.release('key-b');
  });

  it('returns the same memoized store until reset', async () => {
    delete process.env.NODE_ENV;
    __resetGuardedConsumptionStoreForTests();
    const a = await getGuardedConsumptionStore();
    const b = await getGuardedConsumptionStore();
    expect(a).toBe(b);
  });
});

describe('getGuardedConsumptionStore (production posture)', () => {
  const originalNodeEnv = process.env.NODE_ENV;

  afterEach(() => {
    if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalNodeEnv;
    getServiceClient.mockReset();
    __resetGuardedConsumptionStoreForTests();
  });

  it('returns a durable Supabase-backed store that reserves once', async () => {
    process.env.NODE_ENV = 'production';
    // fakeSupabase({ error: null }) → addIfAbsent inserts cleanly → reserve true.
    getServiceClient.mockReturnValue(fakeSupabase({ error: null }));
    const store = await getGuardedConsumptionStore();
    expect(await store.reserve('prod-key')).toBe(true);
  });

  it('fails closed: throws when Supabase is unconfigured (getServiceClient throws)', async () => {
    process.env.NODE_ENV = 'production';
    getServiceClient.mockImplementation(() => { throw new Error('Missing Supabase environment variables'); });
    await expect(getGuardedConsumptionStore()).rejects.toThrow(/Missing Supabase/);
  });
});
