// SPDX-License-Identifier: Apache-2.0
//
// Fuzz target: interleaved-consumption invariant regression test.
//
// HONEST SCOPE: this target interleaves reserve/commit calls at whole-METHOD
// boundaries under the harness's interleave() scheduler, which awaits each step
// to completion. Because the shipped store methods are synchronous bodies under
// async (run-to-completion atomic in single-threaded JS), this does NOT
// manufacture an intra-method check-then-act race — it is a deterministic
// linearizability/accounting regression guard over the real store: many
// interleaved spend operations plus adversarial ops (double-commit, forged
// token, over-budget bids) must never violate the budget/consumption invariants.
//
// The TRUE-concurrency race detector (the async-guard bug class) is the sibling
// target concurrent-race.mjs, whose teeth are proven in race-teeth.selftest.mjs.
//
// The target imports and drives the ACTUAL createMemoryCapabilityStore and
// mintCapabilityReceipt exported from packages/gate/capability-receipt.js — no
// reimplementation. Each scenario mints a fresh capability, registers it, then
// interleaves N randomized spend operations (each: reserve -> commit) plus a
// seeded mix of adversarial operations (double-commit, wrong-token commit,
// over-budget bids). After the interleaving settles, the store's own state is
// checked against the safety invariants.

import { generateKeyPairSync } from 'node:crypto';
import {
  createMemoryCapabilityStore,
  mintCapabilityReceipt,
} from '../../packages/gate/capability-receipt.js';
import { invariant } from '../harness.mjs';

// One issuer key for the whole run; irrelevant to the invariants, so reused to
// keep each iteration cheap.
const { privateKey } = generateKeyPairSync('ed25519');

function baseReceipt(receiptId) {
  return { '@version': 'EP-RECEIPT-v1', payload: { receipt_id: receiptId } };
}

const CURRENCY = 'usd';
// A fixed logical clock well before the capability expiry; the store treats
// `now` as an injectable function, so no Date.now nondeterminism enters here.
const NOW = 1_700_000_000_000;
const clock = () => NOW;
const EXPIRY = new Date(NOW + 86_400_000).toISOString();

export default {
  name: 'capability-race',
  invariants: [
    'total-committed<=budget',
    'no-double-commit',
    'unique-reservation-tokens-among-commits',
    'consumed-monotonic',
    'consumed+reserved<=budget',
    'consumed==sum-of-committed-amounts',
  ],
  async iterate({ rng, iteration }) {
    const budget = rng.int(20, 500);
    const opCount = rng.int(4, 40);
    // Per-op max bid ranges from "tiny" to "can exceed budget alone", so both
    // the fits-easily and the heavily-contended regimes get exercised.
    const maxBid = rng.int(1, Math.max(2, Math.floor(budget / 2)));

    const capabilityId = `cap-${iteration}-${rng.int(0, 1_000_000)}`;
    const { capabilityReceipt } = mintCapabilityReceipt(baseReceipt(`r-${capabilityId}`), {
      issuerPrivateKey: privateKey,
      budget: { amount: budget, currency: CURRENCY },
      expiry: EXPIRY,
      capabilityId,
    });

    const store = createMemoryCapabilityStore();
    invariant(store.registerCapability(capabilityReceipt), 'registration', 'capability failed to register');

    // The envelope fingerprint reserveSpend requires is exactly the one the
    // store computed at registration; read it back rather than recompute.
    const fingerprint = store.getState(capabilityId).capability_fingerprint;

    // Shared accounting the invariant check will compare against the store's
    // own internal state.
    const committedOps = [];
    let expectedCommittedTotal = 0;
    let lastConsumed = 0;

    const assertConsumedMonotonic = () => {
      const consumed = store.getState(capabilityId).consumed_amount;
      invariant(consumed >= lastConsumed, 'consumed-monotonic', `consumed went ${lastConsumed} -> ${consumed}`);
      lastConsumed = consumed;
    };

    const ops = [];
    for (let i = 0; i < opCount; i += 1) {
      const operationId = `op-${iteration}-${i}`;
      const amount = rng.int(1, maxBid);
      const kind = rng.pick(['normal', 'normal', 'normal', 'double-commit', 'wrong-token']);
      const state = { reserved: false, token: null };

      const reserveStep = async () => {
        const r = await store.reserveSpend({
          capabilityId,
          capabilityFingerprint: fingerprint,
          operationId,
          amount,
          currency: CURRENCY,
          now: clock,
        });
        if (r.ok) {
          state.reserved = true;
          state.token = r.reservation_token;
          invariant(typeof r.reservation_token === 'string' && r.reservation_token.length >= 16,
            'reservation-token-shape', `token=${r.reservation_token}`);
        } else {
          // The only legitimate reasons to refuse a fresh, in-window,
          // matching-currency reservation are budget exhaustion.
          invariant(r.reason === 'budget_exceeded' || r.reason === 'operation_in_flight'
            || r.reason === 'operation_already_committed',
          'reserve-refusal-reason', `unexpected reserve refusal: ${r.reason}`);
        }
      };

      const commitStep = async () => {
        if (!state.reserved) return;
        const c = await store.commitSpend({
          capabilityId,
          operationId,
          reservationToken: state.token,
          now: clock,
        });
        invariant(c.ok, 'commit-owner', `owner commit refused: ${c.reason}`);
        committedOps.push({ operationId, token: state.token, amount });
        expectedCommittedTotal += amount;
        assertConsumedMonotonic();
      };

      if (kind === 'normal') {
        ops.push([reserveStep, commitStep]);
      } else if (kind === 'double-commit') {
        // Second commit on the same operation MUST be refused (no double-spend).
        const doubleStep = async () => {
          if (!state.reserved) return;
          const again = await store.commitSpend({
            capabilityId,
            operationId,
            reservationToken: state.token,
            now: clock,
          });
          invariant(!again.ok && again.reason === 'capability_operation_already_finalized',
            'no-double-commit', `second commit of ${operationId} returned ${JSON.stringify(again)}`);
        };
        ops.push([reserveStep, commitStep, doubleStep]);
      } else {
        // Commit with a forged reservation token MUST be refused.
        const wrongTokenStep = async () => {
          if (!state.reserved) return;
          const forged = await store.commitSpend({
            capabilityId,
            operationId,
            reservationToken: 'forged-token-0000000000000000',
            now: clock,
          });
          invariant(!forged.ok, 'reservation-owner-fencing', `forged-token commit of ${operationId} succeeded`);
        };
        ops.push([reserveStep, wrongTokenStep, commitStep]);
      }
    }

    const { interleave } = await import('../harness.mjs');
    await interleave(ops, rng);

    // ── Invariants ─────────────────────────────────────────────────────────
    // The primary safety check is on the amount WE independently observed the
    // store confirm as committed — never only the store's self-reported field,
    // which a racy implementation could clobber while still over-committing.
    invariant(expectedCommittedTotal <= budget,
      'total-committed<=budget',
      `independently-tracked committed sum=${expectedCommittedTotal} budget=${budget}`);

    const finalState = store.getState(capabilityId);

    invariant(finalState.consumed_amount <= budget,
      'total-committed<=budget',
      `store consumed=${finalState.consumed_amount} budget=${budget}`);

    invariant(finalState.consumed_amount === expectedCommittedTotal,
      'consumed==sum-of-committed-amounts',
      `store consumed=${finalState.consumed_amount} tracked=${expectedCommittedTotal}`);

    invariant(finalState.consumed_amount + finalState.reserved_amount <= budget,
      'consumed+reserved<=budget',
      `consumed=${finalState.consumed_amount} reserved=${finalState.reserved_amount} budget=${budget}`);

    const uniqueOps = new Set(committedOps.map((o) => o.operationId));
    invariant(uniqueOps.size === committedOps.length,
      'no-double-commit',
      `${committedOps.length} commits but ${uniqueOps.size} distinct operations`);

    const uniqueTokens = new Set(committedOps.map((o) => o.token));
    invariant(uniqueTokens.size === committedOps.length,
      'unique-reservation-tokens-among-commits',
      `${committedOps.length} commits but ${uniqueTokens.size} distinct tokens`);

    return { ops: opCount };
  },
};
