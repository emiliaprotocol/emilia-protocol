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
            execution_binding: { required_fields: ['amount'] },
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
            execution_binding: { required_fields: ['amount'] },
        }));
        assert.equal(r.ok, true, `tier ${tier} should validate at critical risk, got: ${JSON.stringify(r.errors)}`);
    }
});
// EXECUTION-BINDING FLOOR. A guarded action with no required_fields is bound to
// the action TYPE alone at enforcement time: verifyExecutionBinding() returns ok
// on an empty field list, so a receipt signed for "$1.00 to acct_OK" authorizes
// "$999,999.99 to acct_ATTACKER". Reject it at author time, like assurance_class.
test('FAIL-CLOSED: a guarded action with no execution_binding is rejected', () => {
    const r = validateActionRiskManifest(action({
        action_type: 'payment.release', risk: 'critical', receipt_required: true,
        assurance_class: 'class_a',
    }));
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.includes('execution_binding.required_fields must be a non-empty array')), `expected a required-execution_binding error, got: ${JSON.stringify(r.errors)}`);
});
test('FAIL-CLOSED: an empty or malformed required_fields list is rejected', () => {
    const bindings = [
        { required_fields: [] },
        { required_fields: 'amount' },
        { required_fields: ['amount', ''] },
        { required_fields: ['amount', 42] },
        { required_fields: ['amount', 'amount'] },
        {},
    ];
    for (const execution_binding of bindings) {
        const r = validateActionRiskManifest(action({
            action_type: 'payment.release', risk: 'critical', receipt_required: true,
            assurance_class: 'class_a', execution_binding,
        }));
        assert.equal(r.ok, false, `binding must be rejected: ${JSON.stringify(execution_binding)}`);
        assert.ok(r.errors.some((e) => e.includes('execution_binding.required_fields')), `expected an execution_binding error, got: ${JSON.stringify(r.errors)}`);
    }
});
test('an UNguarded action needs no execution_binding (no over-block)', () => {
    const r = validateActionRiskManifest(action({ receipt_required: false }));
    assert.equal(r.ok, true, `ungated action should validate, got: ${JSON.stringify(r.errors)}`);
});
test('an UNguarded action needs no assurance_class (no over-block)', () => {
    const r = validateActionRiskManifest(action({ receipt_required: false }));
    assert.equal(r.ok, true, `ungated action should validate, got: ${JSON.stringify(r.errors)}`);
});
const guarded = (id, actionType, match) => ({
    id,
    action_type: actionType,
    match,
    risk: 'high',
    receipt_required: true,
    assurance_class: 'class_a',
    execution_binding: { required_fields: ['amount'] },
});
test('AMBIGUITY: equal, subset, and disjoint legacy match shapes are rejected', () => {
    const cases = [
        [{ protocol: 'mcp', tool: 'release' }, { protocol: 'mcp', tool: 'release' }],
        [{ protocol: 'mcp', tool: 'release' }, { tool: 'release' }],
        [{ protocol: 'mcp', tool: 'release' }, { method: 'POST', path: '/release' }],
    ];
    for (const [left, right] of cases) {
        const r = validateActionRiskManifest({
            '@version': V,
            actions: [
                guarded('one', 'payment.release.one', left),
                guarded('two', 'payment.release.two', right),
            ],
        });
        assert.equal(r.ok, false, `overlap must be rejected: ${JSON.stringify([left, right])}`);
        assert.ok(r.errors.some((e) => e.includes('actions[0].match overlaps actions[1].match')));
    }
});
test('SELECTOR SHAPE: empty, extension-only, and non-string matches are rejected', () => {
    const invalidMatches = [
        {},
        { extension_only: 'release' },
        { protocol: 'mcp', tool: { name: 'release' } },
        { protocol: '' },
    ];
    for (const match of invalidMatches) {
        const r = validateActionRiskManifest({
            '@version': V,
            actions: [guarded('one', 'payment.release', match)],
        });
        assert.equal(r.ok, false, `unsupported match must be rejected: ${JSON.stringify(match)}`);
        assert.ok(r.errors.some((e) => e.includes('supported selector field') || e.includes('must be a non-empty string')));
    }
});
test('AMBIGUITY: ignored extension fields cannot disguise an overlapping runtime selector', () => {
    const r = validateActionRiskManifest({
        '@version': V,
        actions: [
            guarded('one', 'payment.release.one', { protocol: 'mcp', tool: 'release', extension: 'one' }),
            guarded('two', 'payment.release.two', { protocol: 'mcp', tool: 'release', extension: 'two' }),
        ],
    });
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.includes('actions[0].match overlaps actions[1].match')));
});
test('distinct complete selectors remain valid', () => {
    const r = validateActionRiskManifest({
        '@version': V,
        actions: [
            guarded('one', 'payment.release.one', { protocol: 'mcp', tool: 'release_one' }),
            guarded('two', 'payment.release.two', { protocol: 'mcp', tool: 'release_two' }),
            guarded('three', 'payment.release.three', { protocol: 'http', method: 'POST', path: '/release' }),
        ],
    });
    assert.equal(r.ok, true, `non-overlapping selectors should validate: ${JSON.stringify(r.errors)}`);
});
