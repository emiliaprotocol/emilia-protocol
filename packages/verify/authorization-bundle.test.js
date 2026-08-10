// SPDX-License-Identifier: Apache-2.0
// Generated from authorization-bundle.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { bindAuthorizationBundleToGrant, verifyAuthorizationBundle, } from './authorization-bundle.js';
import { OAUTH_RAR_AUTHORIZATION_BINDING_VERSION, parseOAuthRarAuthorizationBinding, } from './oauth-rar-authorization-binding.js';
const vectors = JSON.parse(fs.readFileSync(new URL('../../conformance/vectors/authorization-bundle.v1.json', import.meta.url), 'utf8'));
test('Authorization Bundle publishes a closed hostile-case inventory', () => {
    assert.equal(vectors['@version'], 'EP-AUTHORIZATION-BUNDLE-CASES-v1');
    assert.equal(vectors.status, 'implementation-profile-cases');
    assert.match(vectors.claim_boundary, /not an authorization decision/i);
    assert.equal(vectors.cases.length, 24);
    assert.equal(new Set(vectors.cases.map((entry) => entry.id)).size, 24);
});
for (const vector of vectors.cases) {
    test(`Authorization Bundle hostile case: ${vector.id}`, () => {
        const expectedAuthorizationBinding = vector.expected_authorization_binding?.profile
            === OAUTH_RAR_AUTHORIZATION_BINDING_VERSION
            ? parseOAuthRarAuthorizationBinding(vector.expected_authorization_binding) ?? undefined
            : vector.expected_authorization_binding;
        const result = verifyAuthorizationBundle(vector.bundle, {
            now: vector.now,
            audience: vector.audience,
            approverKeys: vector.approver_keys,
            expectedApprovers: vector.expected_approvers,
            acceptedKeyClasses: vector.accepted_key_classes,
            currentPolicy: vector.current_policy,
            expectedAction: vector.expected_action,
            expectedAuthorizationBinding,
            requireAuthorizationBinding: vector.require_authorization_binding,
            currentStatus: vector.current_status,
            requireCurrentStatus: vector.require_current_status,
        });
        assert.equal(result.verdict, vector.expect.verdict);
        assert.equal(result.authorization_decision, false);
        assert.equal(result.evidence_satisfied, vector.expect.verdict === 'SATISFIED');
        for (const reason of vector.expect.reasons ?? []) {
            assert.ok(result.reasons.includes(reason), `${vector.id}: missing reason ${reason}`);
        }
    });
}
test('Authorization Bundle verifier fails closed on hostile accessors and proxies', () => {
    const accessor = Object.create(null);
    Object.defineProperty(accessor, 'bundle_version', {
        enumerable: true,
        get() { throw new Error('must not escape'); },
    });
    for (const [key, value] of Object.entries({
        bundle_id: 'bundle:hostile',
        action: {},
        action_hash: `sha256:${'a'.repeat(64)}`,
        contexts: [],
        signoffs: [],
        approver_key_proofs: [],
        presentation_evidence: [],
    })) {
        Object.defineProperty(accessor, key, { enumerable: true, value });
    }
    const options = {
        now: '2026-08-09T18:00:00Z',
        audience: 'https://payments.example.com',
        approverKeys: {},
        expectedApprovers: [],
        acceptedKeyClasses: [],
        currentPolicy: {},
        expectedAction: {},
    };
    assert.doesNotThrow(() => verifyAuthorizationBundle(accessor, options));
    assert.deepEqual(verifyAuthorizationBundle(accessor, options).reasons, [
        'bundle_or_verifier_input_malformed',
    ]);
    const hostileOptions = new Proxy(options, {
        getPrototypeOf() { throw new Error('must not escape'); },
    });
    assert.doesNotThrow(() => verifyAuthorizationBundle({}, hostileOptions));
    assert.deepEqual(verifyAuthorizationBundle({}, hostileOptions).reasons, [
        'bundle_or_verifier_input_malformed',
    ]);
});
test('bundle-to-grant binding is idempotent only for the same grant', () => {
    const first = {
        bundle_digest: `sha256:${'a'.repeat(64)}`,
        grant_id: 'grant-1',
    };
    assert.equal(bindAuthorizationBundleToGrant(null, first).outcome, 'BOUND');
    assert.equal(bindAuthorizationBundleToGrant(first, first).outcome, 'IDEMPOTENT');
    assert.deepEqual(bindAuthorizationBundleToGrant(first, { ...first, grant_id: 'grant-2' }), {
        outcome: 'REFUSE',
        state: first,
        reason: 'bundle_already_bound_to_another_grant',
    });
    assert.equal(bindAuthorizationBundleToGrant(first, {
        bundle_digest: `sha256:${'b'.repeat(64)}`,
        grant_id: 'grant-1',
    }).reason, 'bundle_digest_mismatch');
});
