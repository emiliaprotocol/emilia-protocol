// SPDX-License-Identifier: Apache-2.0
//
// Proves the true-concurrency driver (harness.concurrent) has TEETH: it detects
// the async-guard bug class — a check-then-act window between a budget read and
// its mutation. Named .selftest.mjs so the vitest gate never collects it; run
// with: node --test fuzz/race-teeth.selftest.mjs
//
// Two assertions:
//   1. Against a deliberately NON-ATOMIC store (an `await` between reading the
//      budget and mutating it), driven concurrently, the over-budget invariant
//      MUST fire — the exact failure a reintroduced async-guard bug would cause.
//   2. Against the SHIPPED atomic createMemoryCapabilityStore, the same driver
//      MUST pass — confirming the guard is a clean regression signal, not noise.

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { concurrent, InvariantViolation, invariant } from './harness.mjs';
import {
  CAPABILITY_SCOPE_PROFILE,
  capabilityActionDigest,
  createMemoryCapabilityStore,
  mintCapabilityReceipt,
} from '../packages/gate/capability-receipt.js';

const { privateKey } = generateKeyPairSync('ed25519');
const CURRENCY = 'usd';
const NOW = 1_700_000_000_000;
const clock = () => NOW;
const EXPIRY = new Date(NOW + 86_400_000).toISOString();
const baseReceipt = (id) => ({ '@version': 'EP-RECEIPT-v1', payload: { receipt_id: id, claim: { capability_only: true } } });
const STORE_ACTION_DIGEST = capabilityActionDigest({ operation_id: 'fuzz-store-template' });
const STORE_SCOPE = {
  profile: CAPABILITY_SCOPE_PROFILE,
  operation_id_field: 'operation_id',
  action_digests: [STORE_ACTION_DIGEST],
};

// A deliberately NON-ATOMIC budget store: reserveSpend reads the remaining
// budget, yields to the event loop (the check-then-act window), then mutates.
// This is exactly the async-guard bug shape. Concurrent callers both see budget
// available and both reserve -> over-commit.
function nonAtomicStore(budget) {
  const state = { budget, consumed: 0, reserved: 0 };
  const ops = new Map();
  return {
    getState: () => ({ ...state }),
    async reserveSpend({ operationId, amount }) {
      const available = state.budget - state.consumed - state.reserved; // READ
      await Promise.resolve();                                          // await gap
      if (available < amount) return { ok: false, reason: 'budget_exceeded' };
      state.reserved += amount;                                        // ACT (too late)
      const token = `tok-${operationId}`;
      ops.set(operationId, { amount, token, status: 'reserved' });
      return { ok: true, reservation_token: token };
    },
    async commitSpend({ operationId, reservationToken }) {
      const op = ops.get(operationId);
      if (!op || op.status !== 'reserved' || op.reservation_token === reservationToken) {
        // (token match check intentionally loose — not what this test probes)
      }
      if (!op || op.status !== 'reserved') return { ok: false, reason: 'already' };
      op.status = 'committed';
      state.reserved -= op.amount;
      state.consumed += op.amount;
      return { ok: true };
    },
  };
}

function spendSeq(store, operationId, amount, acc) {
  const s = { token: null };
  return [
    async () => { const r = await store.reserveSpend({ operationId, amount }); if (r.ok) s.token = r.reservation_token; },
    async () => { if (!s.token) return; const c = await store.commitSpend({ operationId, reservationToken: s.token }); if (c.ok) acc.committed += amount; },
  ];
}

test('concurrent driver DETECTS over-commit in a non-atomic store (teeth)', async () => {
  const budget = 100;
  const store = nonAtomicStore(budget);
  const acc = { committed: 0 };
  // 10 concurrent ops each bidding 40 against a budget of 100: an atomic store
  // commits at most 2 (80); the non-atomic store lets many pass the stale read.
  const seqs = Array.from({ length: 10 }, (_, i) => spendSeq(store, `op${i}`, 40, acc));
  await concurrent(seqs);
  // The check the fuzz target runs. Against this racy store it MUST fire.
  assert.throws(
    () => invariant(store.getState().consumed <= budget, 'total-committed<=budget',
      `consumed=${store.getState().consumed} budget=${budget}`),
    InvariantViolation,
    'the concurrent driver failed to surface the non-atomic over-commit',
  );
  assert.ok(store.getState().consumed > budget, `expected over-commit, got consumed=${store.getState().consumed}`);
});

test('concurrent driver PASSES against the shipped atomic store (clean signal)', async () => {
  const budget = 100;
  const capabilityId = 'cap-teeth';
  const { capabilityReceipt } = mintCapabilityReceipt(baseReceipt('r-teeth'), {
    issuerPrivateKey: privateKey, budget: { amount: budget, currency: CURRENCY }, expiry: EXPIRY, capabilityId,
    scope: STORE_SCOPE,
  });
  const store = createMemoryCapabilityStore();
  store.registerCapability(capabilityReceipt);
  const fingerprint = store.getState(capabilityId).capability_fingerprint;
  const acc = { committed: 0 };
  const seqs = Array.from({ length: 10 }, (_, i) => {
    const s = { token: null };
    return [
      async () => {
        const r = await store.reserveSpend({ capabilityId, capabilityFingerprint: fingerprint, operationId: `op${i}`, actionDigest: STORE_ACTION_DIGEST, amount: 40, currency: CURRENCY, now: clock });
        if (r.ok) s.token = r.reservation_token;
      },
      async () => { if (!s.token) return; const c = await store.commitSpend({ capabilityId, operationId: `op${i}`, reservationToken: s.token, now: clock }); if (c.ok) acc.committed += 40; },
    ];
  });
  await concurrent(seqs);
  const st = store.getState(capabilityId);
  assert.ok(st.consumed_amount <= budget, `atomic store over-committed: ${st.consumed_amount}`);
  assert.equal(st.consumed_amount, acc.committed);
});
