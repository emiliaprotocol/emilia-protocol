// SPDX-License-Identifier: Apache-2.0
//
// Replay defense for the /api/v1/guarded reference DEMAND route.
//
// A verified EMILIA receipt authorizes ONE action, once. This wires the gate's
// consumption-store contract (packages/gate/store.js) to a durable, cross-pod
// backend so a receipt consumed on one instance cannot be replayed on another.
//
//   reserve(key) → true iff first-seen (atomic INSERT-if-absent)
//   commit(key)  → mark consumed after the action is authorized
//   release(key) → undo a reservation if the action ends up refused
//
// The guarded route deliberately does NOT release on a failed commit: the
// reservation is what blocks a replay, and dropping it would re-open the window
// it exists to close.
//
// Production posture (FAIL CLOSED): if the durable backend is unconfigured or a
// consumption operation errors, reserve() throws — the route MUST refuse rather
// than allow a possibly-replayed receipt. Development falls back to an in-memory
// backend so local demos and tests run without Supabase.

import crypto from 'node:crypto';
import { createDurableConsumptionStore, createMemoryBackend } from '@/packages/gate/store.js';
import { isProduction } from '@/lib/env';

const TABLE = 'guarded_receipt_consumptions';

/** Derive the replay-defense key: action-scoped so the same receipt can't be
 * reused for the same action, while distinct actions are independent. */
export function consumeKey(action, receiptId) {
  return crypto.createHash('sha256').update(`${action}:${receiptId}`, 'utf8').digest('hex');
}

/**
 * Supabase-backed atomic key-value backend for the consumption store.
 * addIfAbsent uses the UNIQUE(consume_key) constraint as the atomic gate:
 * a duplicate insert raises 23505 (unique_violation) → returns false.
 */
export function createSupabaseBackend(supabase) {
  return {
    async addIfAbsent(key, value) {
      const { error } = await supabase
        .from(TABLE)
        .insert({ consume_key: key, state: value });
      if (!error) return true;
      // Postgres unique_violation → the key already existed (replay).
      if (error.code === '23505') return false;
      // Any other error is a control-plane failure: fail closed.
      throw new Error(`guarded consumption backend insert failed: ${error.message || error.code || error}`);
    },
    async compareAndSet(key, expected, replacement) {
      const { data, error } = await supabase
        .from(TABLE)
        .update({ state: replacement, updated_at: new Date().toISOString() })
        .eq('consume_key', key)
        .eq('state', expected)
        .select('consume_key')
        .maybeSingle();
      if (error) throw new Error(`guarded consumption backend compare-and-set failed: ${error.message || error}`);
      return !!data;
    },
    async deleteIfValue(key, expected) {
      const { data, error } = await supabase
        .from(TABLE)
        .delete()
        .eq('consume_key', key)
        .eq('state', expected)
        .select('consume_key')
        .maybeSingle();
      if (error) throw new Error(`guarded consumption backend conditional delete failed: ${error.message || error}`);
      return !!data;
    },
    async has(key) {
      const { data, error } = await supabase
        .from(TABLE)
        .select('consume_key')
        .eq('consume_key', key)
        .maybeSingle();
      if (error) throw new Error(`guarded consumption backend has failed: ${error.message || error}`);
      return !!data;
    },
  };
}

let _memoryStore: ReturnType<typeof createDurableConsumptionStore> | null = null;

/**
 * Resolve the consumption store.
 * - Production: durable Supabase-backed store. Throws if Supabase is
 *   unconfigured (the route treats a construction failure as fail-closed).
 * - Dev/test: process-memory store (single-process replay defense only).
 *
 * CONSUMPTION HERE IS PERMANENT. The store was previously constructed with
 * `{ ttlSeconds: 900 }`, which sets permanentConsumption:false and advertises a
 * 900-second retention (packages/gate/src/store.ts). Nothing honored it: the
 * backend above inserts only (consume_key, state), writes no expiry column, and
 * no job reaps the table -- so the advertised retention described a reaper that
 * does not exist, while the rows lived forever. The rows living forever is the
 * behavior we want (a consumed receipt id must never become replayable again);
 * the TTL was the false half, so it is gone. Reintroduce it only together with
 * a real expiry column AND a reaper, so the claim and the storage agree.
 */
export async function getGuardedConsumptionStore() {
  if (isProduction()) {
    const { getServiceClient } = await import('@/lib/supabase');
    const supabase = getServiceClient(); // throws if env is missing → fail closed
    return createDurableConsumptionStore(createSupabaseBackend(supabase));
  }
  if (!_memoryStore) _memoryStore = createDurableConsumptionStore(createMemoryBackend());
  return _memoryStore;
}

/** Test-only: reset the dev in-memory store between cases. */
export function __resetGuardedConsumptionStoreForTests() {
  _memoryStore = null;
}
