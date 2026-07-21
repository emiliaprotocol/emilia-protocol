// SPDX-License-Identifier: Apache-2.0
// Generated from agent-binding.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// PIP-008 L4->L7 binding: evaluateAgentBinding records the relied-on agent
// identity/delegation evidence and (optionally) enforces its freshness.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateAgentBinding } from './index.js';
const HASH = 'sha256:' + 'a'.repeat(64);
const ctx = (binding) => ({ agent_binding: binding });
test('absent binding -> present:false, fresh:null', () => {
    const r = evaluateAgentBinding({});
    assert.equal(r.present, false);
    assert.equal(r.fresh, null);
    assert.equal(r.reason, 'no_agent_binding');
});
test('records the relied-on L4 evidence (no freshness check without maxAgeSec)', () => {
    const r = evaluateAgentBinding(ctx({
        agent_id: 'did:agent:42',
        delegation: { scheme: 'DRP', ref: 'rcpt_1', hash: HASH, observed_at: '2026-06-24T18:00:00Z' },
    }));
    assert.equal(r.present, true);
    assert.equal(r.agent_id, 'did:agent:42');
    assert.equal(r.delegation.scheme, 'DRP');
    assert.equal(r.evidence_hash, HASH);
    assert.equal(r.observed_at, '2026-06-24T18:00:00Z');
    assert.equal(r.fresh, null); // not evaluated when maxAgeSec is absent
});
test('fresh within the window', () => {
    const r = evaluateAgentBinding(ctx({ agent_id: 'a', delegation: { scheme: 'WIMSE', ref: 'x', observed_at: '2026-06-24T18:00:00Z' } }), { maxAgeSec: 600, at: '2026-06-24T18:05:00Z' });
    assert.equal(r.fresh, true);
    assert.equal(r.age_seconds, 300);
});
test('stale beyond the window -> fresh:false', () => {
    const r = evaluateAgentBinding(ctx({ agent_id: 'a', delegation: { scheme: 'WIMSE', ref: 'x', observed_at: '2026-06-24T18:00:00Z' } }), { maxAgeSec: 60, at: '2026-06-24T18:05:00Z' });
    assert.equal(r.fresh, false);
    assert.match(r.reason, /stale/);
});
test('freshness required but no observed_at -> fail-closed', () => {
    const r = evaluateAgentBinding(ctx({ agent_id: 'a', delegation: { scheme: 'WIMSE', ref: 'x' } }), { maxAgeSec: 600 });
    assert.equal(r.fresh, false);
    assert.equal(r.reason, 'freshness_required_but_no_observed_at');
});
test('observed_at in the future -> not fresh', () => {
    const r = evaluateAgentBinding(ctx({ agent_id: 'a', delegation: { scheme: 'WIMSE', ref: 'x', observed_at: '2026-06-24T18:10:00Z' } }), { maxAgeSec: 600, at: '2026-06-24T18:00:00Z' });
    assert.equal(r.fresh, false);
    assert.equal(r.reason, 'observed_at_in_future');
});
