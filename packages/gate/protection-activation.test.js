// SPDX-License-Identifier: Apache-2.0
// Generated from protection-activation.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { createProtectionPlan } from './protection-plan.js';
import { PROTECTION_ACTIVATION_CLAIM_BOUNDARY, signProtectionActivation, verifyProtectionActivation, } from './protection-activation.js';
const NOW = '2026-08-20T18:00:00.000Z';
function fixture() {
    const keys = generateKeyPairSync('ed25519');
    const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const plan = createProtectionPlan({
        planId: 'customer-owned-gateway',
        ownerLabel: 'Example customer',
        createdAt: '2026-08-20T17:55:00.000Z',
        selections: [{ presetId: 'spend-money' }, { presetId: 'publish-code' }],
    });
    const activation = signProtectionActivation({
        activation_id: 'activation:customer-owned-gateway:01',
        tenant_id: 'tenant:example',
        gateway_id: 'gateway:example:mcp',
        epoch: 4,
        issued_at: '2026-08-20T17:56:00.000Z',
        valid_from: '2026-08-20T17:57:00.000Z',
        expires_at: '2026-08-21T18:00:00.000Z',
        plan,
    }, {
        issuer_id: 'customer:example',
        key_id: 'key:customer-protection',
        private_key: keys.privateKey,
    });
    const options = {
        trusted_keys: {
            'key:customer-protection': {
                issuer_id: 'customer:example',
                public_key: publicKey,
            },
        },
        expected: {
            activation_id: 'activation:customer-owned-gateway:01',
            tenant_id: 'tenant:example',
            gateway_id: 'gateway:example:mcp',
            minimum_epoch: 4,
            authorizer_id: 'customer:example',
        },
        now: NOW,
    };
    return { activation, options };
}
test('customer signature activates a pinned manifest without becoming action authority', () => {
    const { activation, options } = fixture();
    const verified = verifyProtectionActivation(activation, options);
    assert.equal(verified.accepted, true);
    assert.equal(verified.claim_boundary, PROTECTION_ACTIVATION_CLAIM_BOUNDARY);
    assert.equal(verified.activation.epoch, 4);
    assert.equal(verified.manifest.actions.length, 2);
    assert.equal(verified.activation.plan.authority.status, 'unsigned_owner_draft');
    assert.equal(verified.activation.plan.activation.status, 'not_active');
});
test('activation refuses mutation, wrong gateway, stale epoch, and expiry', () => {
    const { activation, options } = fixture();
    const mutated = structuredClone(activation);
    mutated.plan.action_control_manifest.actions[0].assurance_class = 'software';
    assert.notEqual(verifyProtectionActivation(mutated, options).accepted, true);
    assert.equal(verifyProtectionActivation(activation, {
        ...options,
        expected: { ...options.expected, gateway_id: 'gateway:attacker' },
    }).reason, 'protection_activation_context_mismatch');
    assert.equal(verifyProtectionActivation(activation, {
        ...options,
        expected: { ...options.expected, minimum_epoch: 5 },
    }).reason, 'protection_activation_epoch_stale');
    assert.equal(verifyProtectionActivation(activation, {
        ...options,
        now: '2026-08-21T18:00:00.000Z',
    }).reason, 'protection_activation_expired');
});
