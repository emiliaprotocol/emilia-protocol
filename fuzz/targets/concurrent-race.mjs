// SPDX-License-Identifier: Apache-2.0
//
// Fuzz target: TRUE-concurrency race against the capability budget store.
//
// This is the target that actually exercises the async-guard bug CLASS — an
// internal check-then-act window between a budget read and its mutation. Unlike
// capability-race.mjs (which interleaves at whole-method boundaries under an
// atomic-method assumption), this target fires every op via Promise.all so
// that, if reserve/commit were ever non-atomic, concurrent calls would
// interleave inside the method and over-commit.
//
// Against the shipped createMemoryCapabilityStore — whose reserve/commit bodies
// are synchronous under async (run-to-completion atomic in single-threaded JS)
// — every invariant holds. That is the point: this is a REGRESSION GUARD. A
// change that reintroduces a non-atomic check-then-act reserve/commit would make
// this target fail. fuzz/race-teeth.selftest.mjs proves the driver has teeth by
// running it against a deliberately non-atomic store and showing the over-commit
// invariant fires.

import { generateKeyPairSync } from 'node:crypto';
import {
  CAPABILITY_SCOPE_PROFILE,
  capabilityActionDigest,
  createMemoryCapabilityStore,
  mintCapabilityReceipt,
} from '../../packages/gate/capability-receipt.js';
import { invariant, concurrent } from '../harness.mjs';

const { privateKey } = generateKeyPairSync('ed25519');
const CURRENCY = 'usd';
const NOW = 1_700_000_000_000;
const clock = () => NOW;
const EXPIRY = new Date(NOW + 86_400_000).toISOString();

function baseReceipt(receiptId) {
  return { '@version': 'EP-RECEIPT-v1', payload: { receipt_id: receiptId, claim: { capability_only: true } } };
}
const STORE_ACTION_DIGEST = capabilityActionDigest({ operation_id: 'fuzz-store-template' });
const STORE_SCOPE = {
  profile: CAPABILITY_SCOPE_PROFILE,
  operation_id_field: 'operation_id',
  action_digests: [STORE_ACTION_DIGEST],
};

// Build a capability + registered store; return the store, id, fingerprint.
export function freshCapability(store, capabilityId, budget) {
  const { capabilityReceipt } = mintCapabilityReceipt(baseReceipt(`r-${capabilityId}`), {
    issuerPrivateKey: privateKey,
    budget: { amount: budget, currency: CURRENCY },
    expiry: EXPIRY,
    capabilityId,
    scope: STORE_SCOPE,
  });
  invariant(store.registerCapability(capabilityReceipt), 'registration', 'capability failed to register');
  return store.getState(capabilityId).capability_fingerprint;
}

// One op sequence: reserve then (if reserved) commit, tracking the confirmed
// committed amount on a shared accumulator.
export function spendSequence({ store, capabilityId, fingerprint, operationId, amount, acc }) {
  const state = { token: null };
  return [
    async () => {
      const r = await store.reserveSpend({
        capabilityId, capabilityFingerprint: fingerprint, operationId, actionDigest: STORE_ACTION_DIGEST, amount, currency: CURRENCY, now: clock,
      });
      if (r.ok) state.token = r.reservation_token;
    },
    async () => {
      if (!state.token) return;
      const c = await store.commitSpend({ capabilityId, operationId, reservationToken: state.token, now: clock });
      if (c.ok) { acc.committed += amount; acc.count += 1; }
    },
  ];
}

export function checkInvariants({ store, capabilityId, budget, acc }) {
  const s = store.getState(capabilityId);
  invariant(acc.committed <= budget, 'total-committed<=budget',
    `independently-tracked committed sum=${acc.committed} budget=${budget}`);
  invariant(s.consumed_amount <= budget, 'total-committed<=budget',
    `store consumed=${s.consumed_amount} budget=${budget}`);
  invariant(s.consumed_amount === acc.committed, 'consumed==sum-of-committed-amounts',
    `store consumed=${s.consumed_amount} tracked=${acc.committed}`);
  invariant(s.consumed_amount + s.reserved_amount <= budget, 'consumed+reserved<=budget',
    `consumed=${s.consumed_amount} reserved=${s.reserved_amount} budget=${budget}`);
}

export default {
  name: 'concurrent-race',
  invariants: [
    'total-committed<=budget', 'consumed==sum-of-committed-amounts', 'consumed+reserved<=budget',
  ],
  async iterate({ rng, iteration }) {
    const budget = rng.int(20, 500);
    const opCount = rng.int(4, 40);
    const maxBid = rng.int(1, Math.max(2, Math.floor(budget / 2)));
    const capabilityId = `cap-${iteration}-${rng.int(0, 1_000_000)}`;
    const store = createMemoryCapabilityStore();
    const fingerprint = freshCapability(store, capabilityId, budget);
    const acc = { committed: 0, count: 0 };

    const sequences = [];
    for (let i = 0; i < opCount; i += 1) {
      sequences.push(spendSequence({
        store, capabilityId, fingerprint,
        operationId: `op-${iteration}-${i}`, amount: rng.int(1, maxBid), acc,
      }));
    }
    await concurrent(sequences);
    checkInvariants({ store, capabilityId, budget, acc });
    return { ops: opCount };
  },
};
