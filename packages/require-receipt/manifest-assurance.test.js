// SPDX-License-Identifier: Apache-2.0
// Generated from manifest-assurance.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Regression: a manifest-guarded action MUST declare an assurance_class. Omitting
// it once silently downgraded a guarded (possibly critical) action to the weakest
// 'software' tier at enforcement time, letting it accept a bare machine-signed
// receipt with no human signoff. The validator now rejects that at author time
// (defense in depth: createGate.check also fails closed on a guarded action with
// no declared tier).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateActionRiskManifest, ACTION_RISK_MANIFEST_VERSION } from './index.js';
const V = ACTION_RISK_MANIFEST_VERSION;
const action = (extra) => ({ '@version': V, actions: [{ id: 'm', match: { tool: 'stripe' }, ...extra }] });
test('FAIL-CLOSED: a guarded action with no assurance_class is rejected', () => {
    const r = validateActionRiskManifest(action({
        action_type: 'payment.release', risk: 'critical', receipt_required: true,
    }));
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.includes('assurance_class is required when receipt_required is true')), `expected a required-assurance_class error, got: ${JSON.stringify(r.errors)}`);
});
test('a high-risk guarded action validates on any tier (software allowed below critical)', () => {
    for (const tier of ['software', 'class_a', 'quorum']) {
        const r = validateActionRiskManifest(action({
            action_type: 'payment.release', risk: 'high', receipt_required: true, assurance_class: tier,
        }));
        assert.equal(r.ok, true, `tier ${tier} should validate at high risk, got: ${JSON.stringify(r.errors)}`);
    }
});
test('KEY-CLASS FLOOR: a critical action MUST NOT accept the software tier', () => {
    const r = validateActionRiskManifest(action({
        action_type: 'payment.release', risk: 'critical', receipt_required: true, assurance_class: 'software',
    }));
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.includes('must be class_a or quorum when risk is critical')), `expected a critical-key-class-floor error, got: ${JSON.stringify(r.errors)}`);
});
test('a critical action validates on class_a and quorum (the human tiers)', () => {
    for (const tier of ['class_a', 'quorum']) {
        const r = validateActionRiskManifest(action({
            action_type: 'payment.release', risk: 'critical', receipt_required: true, assurance_class: tier,
        }));
        assert.equal(r.ok, true, `tier ${tier} should validate at critical risk, got: ${JSON.stringify(r.errors)}`);
    }
});
test('an UNguarded action needs no assurance_class (no over-block)', () => {
    const r = validateActionRiskManifest(action({ receipt_required: false }));
    assert.equal(r.ok, true, `ungated action should validate, got: ${JSON.stringify(r.errors)}`);
});
