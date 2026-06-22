// SPDX-License-Identifier: Apache-2.0
//
// EP-QUORUM-v1 conformance test. Loads the adversarial quorum vectors (real
// multi-approver WebAuthn assertions) and asserts the verifier returns
// expect.valid for every one — proving the quorum predicate is FAIL-CLOSED:
// one bad signature, a duplicate human, an out-of-order signature, a mismatched
// action, an expired window, an under-threshold set, or an ineligible role each
// drives the whole quorum to invalid. Pure Node test (no vitest), zero-dep.
import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { verifyQuorum } from './quorum.js';

const suite = JSON.parse(
  readFileSync(new URL('../../conformance/vectors/quorum.v1.json', import.meta.url), 'utf8'),
);
const OPTS = { rpId: 'emiliaprotocol.ai' };

test('EP-QUORUM-v1: every conformance vector matches expect.valid', () => {
  for (const v of suite.vectors) {
    const { valid } = verifyQuorum(v.quorum, OPTS);
    assert.strictEqual(valid, v.expect.valid, `${v.id}: expected valid=${v.expect.valid}, got ${valid}`);
  }
});

// Belt-and-suspenders: each negative trips the SPECIFIC predicate it targets,
// so a future refactor can't accidentally pass a reject vector for the wrong reason.
const byId = Object.fromEntries(suite.vectors.map((v) => [v.id, v]));
const predicateFor = {
  reject_under_threshold: 'threshold_met',
  reject_duplicate_human: 'distinct_humans',
  reject_out_of_order: 'order_satisfied',
  reject_action_mismatch: 'action_binding',
  reject_expired_window: 'within_window',
  reject_one_bad_signature: 'all_signatures_valid',
  reject_wrong_role: 'roles_admitted',
  reject_broken_chain: 'chain_linked',
  reject_duplicate_key: 'distinct_keys',
};
test('EP-QUORUM-v1: each negative fails on its targeted predicate', () => {
  for (const [id, predicate] of Object.entries(predicateFor)) {
    const { valid, checks } = verifyQuorum(byId[id].quorum, OPTS);
    assert.strictEqual(valid, false, `${id} should be invalid`);
    assert.strictEqual(checks[predicate], false, `${id}: expected ${predicate}=false`);
  }
});

test('EP-QUORUM-v1: a happy quorum passes every individual check', () => {
  const { valid, checks } = verifyQuorum(byId.accept_ordered_3of3.quorum, OPTS);
  assert.strictEqual(valid, true);
  for (const [k, v] of Object.entries(checks)) assert.strictEqual(v, true, `check ${k} should be true`);
});

// Fail-closed on malformed input — never throws, always returns valid:false.
test('EP-QUORUM-v1: malformed input fails closed without throwing', () => {
  for (const bad of [null, {}, { policy: {}, members: [] }, { action_hash: 'x', members: [{}], policy: { mode: 'ordered', approvers: [] } }]) {
    const r = verifyQuorum(bad, OPTS);
    assert.strictEqual(r.valid, false);
  }
});
