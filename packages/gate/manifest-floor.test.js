// SPDX-License-Identifier: Apache-2.0
// Generated from manifest-floor.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Regression: the gate's action-control manifest validator enforces the key-class
// floor. A critical (typically irreversible) action must be bound to a human key,
// so it MUST NOT be satisfiable by the weakest 'software' tier. This matters twice
// over here because normalizeAssurance() defaults a missing or unrecognized tier to
// 'software' — without the floor, a critical action that simply omitted its tier
// would be silently downgraded to a bare machine key. Parity with the author-time
// guard in packages/require-receipt.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDefaultActionControlManifest, validateActionControlManifest } from './action-control-manifest.js';
const critical = (assurance_class) => createDefaultActionControlManifest({
    includePassThrough: false,
    extraActions: [{
            id: 'wire',
            action_type: 'payment.release',
            match: { protocol: 'mcp', tool: 'release_payment' },
            receipt_required: true,
            risk: 'critical',
            max_age_sec: 900,
            execution_binding: { required_fields: ['amount', 'account'] },
            ...(assurance_class ? { assurance_class } : {}),
        }],
});
test('KEY-CLASS FLOOR: a critical action on the software tier is rejected', () => {
    const r = validateActionControlManifest(critical('software'));
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.includes('must be class_a or quorum when risk is critical')), `expected the critical key-class floor to fire, got: ${JSON.stringify(r.errors)}`);
});
test('KEY-CLASS FLOOR: a critical action with an omitted tier fails closed (normalize -> software)', () => {
    const r = validateActionControlManifest(critical(null));
    assert.equal(r.ok, false, 'an omitted tier on a critical action must not silently pass as software');
    assert.ok(r.errors.some((e) => e.includes('must be class_a or quorum when risk is critical')));
});
test('a critical action on class_a or quorum validates', () => {
    for (const tier of ['class_a', 'quorum']) {
        const r = validateActionControlManifest(critical(tier));
        assert.equal(r.ok, true, `tier ${tier} should validate at critical risk, got: ${JSON.stringify(r.errors)}`);
    }
});
