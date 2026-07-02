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
    async set(key, value) {
      const { error } = await supabase
        .from(TABLE)
        .update({ state: value, updated_at: new Date().toISOString() })
        .eq('consume_key', key);
      if (error) throw new Error(`guarded consumption backend set failed: ${error.message || error}`);
    },
    async delete(key) {
      const { error } = await supabase.from(TABLE).delete().eq('consume_key', key);
      if (error) throw new Error(`guarded consumption backend delete failed: ${error.message || error}`);
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

let _memoryStore = null;

/**
 * Resolve the consumption store.
 * - Production: durable Supabase-backed store. Throws if Supabase is
 *   unconfigured (the route treats a construction failure as fail-closed).
 * - Dev/test: process-memory store (single-process replay defense only).
 */
export async function getGuardedConsumptionStore() {
  if (isProduction()) {
    const { getServiceClient } = await import('@/lib/supabase');
    const supabase = getServiceClient(); // throws if env is missing → fail closed
    // TTL matches the guarded route's max receipt age so consumed ids can be
    // reaped by an operator job without ever re-opening a replay window.
    return createDurableConsumptionStore(createSupabaseBackend(supabase), { ttlSeconds: 900 });
  }
  if (!_memoryStore) _memoryStore = createDurableConsumptionStore(createMemoryBackend());
  return _memoryStore;
}

/** Test-only: reset the dev in-memory store between cases. */
export function __resetGuardedConsumptionStoreForTests() {
  _memoryStore = null;
}
