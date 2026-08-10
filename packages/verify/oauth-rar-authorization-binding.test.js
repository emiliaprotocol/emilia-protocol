// SPDX-License-Identifier: Apache-2.0
// Generated from oauth-rar-authorization-binding.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { OAUTH_RAR_AUTHORIZATION_BINDING_VERSION, matchOAuthRarAuthorizationBinding, parseOAuthRarAuthorizationBinding, } from './oauth-rar-authorization-binding.js';
const BINDING = {
    profile: OAUTH_RAR_AUTHORIZATION_BINDING_VERSION,
    authorization_server: 'https://as.example.com',
    transaction_id: 'txn-7',
    actor: 'spiffe://example.com/agent/recon-7',
    delegated_subject: 'user:alice',
    authorization_details_digest: `sha256:${'a'.repeat(64)}`,
    action_mapping_profile: 'https://profiles.example.com/payment-release-v1',
};
test('OAuth/RAR binding profile returns a safe normalized closed object', () => {
    assert.deepEqual(parseOAuthRarAuthorizationBinding(BINDING), BINDING);
    assert.equal(parseOAuthRarAuthorizationBinding({ ...BINDING, extra: true }), null);
    assert.equal(parseOAuthRarAuthorizationBinding({
        ...BINDING,
        authorization_details_digest: `sha256:${'A'.repeat(64)}`,
    }), null);
});
test('OAuth/RAR binding profile matches only an independently derived projection', () => {
    assert.deepEqual(matchOAuthRarAuthorizationBinding(BINDING, structuredClone(BINDING)), {
        verdict: 'MATCH',
        binding: BINDING,
        reason: null,
    });
    assert.equal(matchOAuthRarAuthorizationBinding(BINDING, {
        ...BINDING,
        actor: 'spiffe://example.com/agent/other',
    }).verdict, 'MISMATCH');
    assert.equal(matchOAuthRarAuthorizationBinding(BINDING, undefined).verdict, 'INDETERMINATE');
});
test('OAuth/RAR binding profile fails closed without invoking accessors or proxy traps', () => {
    const accessor = Object.create(null);
    Object.defineProperty(accessor, 'profile', {
        enumerable: true,
        get() { throw new Error('must not execute'); },
    });
    assert.doesNotThrow(() => parseOAuthRarAuthorizationBinding(accessor));
    assert.equal(parseOAuthRarAuthorizationBinding(accessor), null);
    const hostileProxy = new Proxy({}, {
        getPrototypeOf() { throw new Error('must not escape'); },
    });
    assert.doesNotThrow(() => matchOAuthRarAuthorizationBinding(hostileProxy, BINDING));
    assert.equal(matchOAuthRarAuthorizationBinding(hostileProxy, BINDING).verdict, 'MISMATCH');
});
