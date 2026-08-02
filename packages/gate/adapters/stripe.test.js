// SPDX-License-Identifier: Apache-2.0
// Generated from stripe.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGate, createEg1Harness } from '../index.js';
import { createStripeManifest, createStripeAllowanceConnector, guardStripeAllowanceMutation, guardStripeMutation, STRIPE_OPS, } from './stripe.js';
import { issueGateAllowance, } from '../allowance.js';
import { createMemoryCapabilityStore } from '../capability-receipt.js';
import { generateKeyPairSync } from 'node:crypto';
function fakeStripe(accountId = 'acct_authorized') {
    const calls = [];
    return {
        calls,
        payouts: {
            create: async (p, requestOptions) => {
                calls.push(requestOptions === undefined
                    ? ['payout', p]
                    : ['payout', p, requestOptions]);
                return { id: 'po_1', ...p };
            },
        },
        refunds: { create: async (p) => { calls.push(['refund', p]); return { id: 're_1', ...p }; } },
        accounts: {
            retrieve: async () => ({ id: accountId }),
            updateExternalAccount: async (acct, ext, u) => { calls.push(['ext', { acct, ext, u }]); return { id: ext }; },
        },
    };
}
function setup(action) {
    const harness = createEg1Harness({ action });
    return { harness, gate: createGate({ manifest: createStripeManifest(), trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys, quorumPolicy: harness.quorumPolicy, rpId: harness.rpId, allowedOrigins: harness.allowedOrigins, allowEphemeralStore: true }), stripe: fakeStripe() };
}
const PAYOUT = { action_type: 'stripe.payout.create', amount: 40000, currency: 'usd', destination: 'acct_x' };
const STRIPE_CONNECTOR_ID = 'stripe:acct_authorized';
const stripeConnector = (stripe) => createStripeAllowanceConnector({ stripe });
test('exposes the destructive Stripe ops', () => {
    assert.deepEqual([...STRIPE_OPS].sort(), ['bank_account.change', 'payout.create', 'refund.create']);
});
test('payout WITHOUT a receipt never reaches Stripe', async () => {
    const { gate, stripe } = setup(PAYOUT);
    await assert.rejects(() => guardStripeMutation(gate, stripe, { op: 'payout.create', params: { amount: 40000, currency: 'usd', destination: 'acct_x' } }), (e) => e.code === 'EMILIA_RECEIPT_REQUIRED' && e.status === 428);
    assert.equal(stripe.calls.length, 0);
});
test('payout WITH a valid Class-A receipt executes and returns reliance', async () => {
    const { gate, harness, stripe } = setup(PAYOUT);
    const { result, reliance } = await guardStripeMutation(gate, stripe, {
        op: 'payout.create', params: { amount: 40000, currency: 'usd', destination: 'acct_x' }, receipt: harness.mint({ outcome: 'allow_with_signoff' }),
    });
    assert.equal(result.id, 'po_1');
    assert.equal(String(reliance.verdict).toLowerCase(), 'rely');
});
test('payout refuses an inflated amount (drift)', async () => {
    const { gate, harness, stripe } = setup(PAYOUT);
    const receipt = harness.mint({ outcome: 'allow_with_signoff' }); // authorizes 40000
    await assert.rejects(() => guardStripeMutation(gate, stripe, { op: 'payout.create', params: { amount: 999999, currency: 'usd', destination: 'acct_x' }, receipt }), (e) => /binding/.test(e.gate.reason));
    assert.equal(stripe.calls.length, 0);
});
test('payout refuses a replayed receipt', async () => {
    const { gate, harness, stripe } = setup(PAYOUT);
    const receipt = harness.mint({ outcome: 'allow_with_signoff' });
    const params = { amount: 40000, currency: 'usd', destination: 'acct_x' };
    await guardStripeMutation(gate, stripe, { op: 'payout.create', params, receipt });
    await assert.rejects(() => guardStripeMutation(gate, stripe, { op: 'payout.create', params, receipt }), (e) => /replay/.test(e.gate.reason));
    assert.equal(stripe.calls.length, 1);
});
test('payout-destination change requires quorum', async () => {
    const action = { action_type: 'stripe.bank_account.change', account: 'acct_x', external_account: 'ba_new' };
    const { gate, harness, stripe } = setup(action);
    const params = { account: 'acct_x', external_account: 'ba_new' };
    await assert.rejects(() => guardStripeMutation(gate, stripe, { op: 'bank_account.change', params, receipt: harness.mint({ outcome: 'allow_with_signoff' }) }), (e) => /assurance/.test(e.gate.reason));
    const quorum = harness.mint({ outcome: 'allow_with_signoff', quorum: { signers: ['ep:a', 'ep:b'], threshold: 2 } });
    const { result } = await guardStripeMutation(gate, stripe, { op: 'bank_account.change', params, receipt: quorum });
    assert.equal(result.id, 'ba_new');
});
test('typed Stripe payout allowance keeps the client local and executes in-envelope without a per-event receipt', async () => {
    const keys = generateKeyPairSync('ed25519');
    const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const authorizationReceipt = {
        '@version': 'EP-RECEIPT-v1',
        payload: {
            receipt_id: 'receipt:stripe-allowance:01',
            claim: { action_type: 'gate.allowance.issue', capability_only: true },
        },
    };
    const issued = issueGateAllowance({
        authorizationReceipt,
        allowance: {
            allowance_id: 'allowance:stripe-payout:adapter',
            tenant_id: 'tenant:example',
            subject_id: 'agent:finance:01',
            audience: 'gate:finance:production',
            connector_id: STRIPE_CONNECTOR_ID,
            action_type: 'stripe.payout.create',
            revision: 1,
            supersedes_allowance_digest: null,
            presentation_digest: `sha256:${'1'.repeat(64)}`,
            issued_at: '2026-07-30T17:59:00.000Z',
            valid_from: '2026-07-30T18:00:00.000Z',
            expires_at: '2026-07-31T18:00:00.000Z',
            constraints: {
                currency: 'USD',
                aggregate_amount: 50_000,
                max_amount_per_action: 5_000,
                material_fields: ['action_type', 'amount', 'currency', 'destination', 'operation_id'],
                operation_id_field: 'operation_id',
                amount_field: 'amount',
                currency_field: 'currency',
                target_field: 'destination',
                allowed_targets: ['acct_known'],
                allowed_values: {},
            },
        },
        signer: {
            issuer_id: 'customer:security',
            key_id: 'key:allowance',
            private_key: keys.privateKey,
        },
        capabilityIssuerPrivateKey: keys.privateKey,
    });
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(issued.capabilityReceipt), true);
    const stripe = fakeStripe();
    const connector = await stripeConnector(stripe);
    const result = await guardStripeAllowanceMutation({
        connector,
        params: { amount: 4_000, currency: 'USD', destination: 'acct_known' },
        operationId: 'stripe:payout:01',
        allowance: issued.allowance,
        capabilityReceipt: issued.capabilityReceipt,
        secret: issued.secret,
        store,
        verifyAuthorizationReceipt: () => true,
        verifyAllowanceStatus: () => true,
        trustedAllowanceKeys: {
            'key:allowance': {
                issuer_id: 'customer:security',
                public_key: publicKey,
            },
        },
        trustedCapabilityIssuerKeys: [publicKey],
        expected: {
            allowance_id: 'allowance:stripe-payout:adapter',
            tenant_id: 'tenant:example',
            subject_id: 'agent:finance:01',
            audience: 'gate:finance:production',
            authorizer_id: 'customer:security',
        },
        now: Date.parse('2026-07-30T18:00:00.000Z'),
    });
    assert.equal(result.ok, true);
    assert.equal(result.result.id, 'po_1');
    assert.deepEqual(stripe.calls, [[
            'payout',
            { amount: 4_000, currency: 'USD', destination: 'acct_known' },
            { idempotencyKey: 'stripe:payout:01' },
        ]]);
});
test('typed Stripe payout executes the immutable verified action when caller params mutate during verification', async () => {
    const keys = generateKeyPairSync('ed25519');
    const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const issued = issueGateAllowance({
        authorizationReceipt: {
            '@version': 'EP-RECEIPT-v1',
            payload: {
                receipt_id: 'receipt:stripe-allowance:mutation',
                claim: { action_type: 'gate.allowance.issue', capability_only: true },
            },
        },
        allowance: {
            allowance_id: 'allowance:stripe-payout:mutation',
            tenant_id: 'tenant:example',
            subject_id: 'agent:finance:01',
            audience: 'gate:finance:production',
            connector_id: STRIPE_CONNECTOR_ID,
            action_type: 'stripe.payout.create',
            revision: 1,
            supersedes_allowance_digest: null,
            presentation_digest: `sha256:${'3'.repeat(64)}`,
            issued_at: '2026-07-30T17:59:00.000Z',
            valid_from: '2026-07-30T18:00:00.000Z',
            expires_at: '2026-07-31T18:00:00.000Z',
            constraints: {
                currency: 'USD',
                aggregate_amount: 50_000,
                max_amount_per_action: 5_000,
                material_fields: ['action_type', 'amount', 'currency', 'destination', 'operation_id'],
                operation_id_field: 'operation_id',
                amount_field: 'amount',
                currency_field: 'currency',
                target_field: 'destination',
                allowed_targets: ['acct_known'],
                allowed_values: {},
            },
        },
        signer: {
            issuer_id: 'customer:security',
            key_id: 'key:allowance',
            private_key: keys.privateKey,
        },
        capabilityIssuerPrivateKey: keys.privateKey,
    });
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(issued.capabilityReceipt), true);
    const stripe = fakeStripe();
    const connector = await stripeConnector(stripe);
    const params = { amount: 4_000, currency: 'USD', destination: 'acct_known' };
    const result = await guardStripeAllowanceMutation({
        connector,
        params,
        operationId: 'stripe:payout:mutation',
        allowance: issued.allowance,
        capabilityReceipt: issued.capabilityReceipt,
        secret: issued.secret,
        store,
        verifyAuthorizationReceipt: async () => {
            params.amount = 40_000;
            params.destination = 'acct_attacker';
            return true;
        },
        verifyAllowanceStatus: () => true,
        trustedAllowanceKeys: {
            'key:allowance': {
                issuer_id: 'customer:security',
                public_key: publicKey,
            },
        },
        trustedCapabilityIssuerKeys: [publicKey],
        expected: {
            allowance_id: 'allowance:stripe-payout:mutation',
            tenant_id: 'tenant:example',
            subject_id: 'agent:finance:01',
            audience: 'gate:finance:production',
            authorizer_id: 'customer:security',
        },
        now: Date.parse('2026-07-30T18:00:00.000Z'),
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.deepEqual(stripe.calls, [[
            'payout',
            { amount: 4_000, currency: 'USD', destination: 'acct_known' },
            { idempotencyKey: 'stripe:payout:mutation' },
        ]]);
});
test('typed Stripe payout refuses cross-protocol and cross-account connector substitution', async () => {
    for (const [signedConnectorId, providerAccountId] of [
        ['github:installation:101', 'acct_authorized'],
        [STRIPE_CONNECTOR_ID, 'acct_attacker'],
    ]) {
        const keys = generateKeyPairSync('ed25519');
        const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
        const issued = issueGateAllowance({
            authorizationReceipt: {
                '@version': 'EP-RECEIPT-v1',
                payload: {
                    receipt_id: `receipt:stripe-connector:${signedConnectorId}`,
                    claim: { action_type: 'gate.allowance.issue', capability_only: true },
                },
            },
            allowance: {
                allowance_id: `allowance:stripe-connector:${signedConnectorId}`,
                tenant_id: 'tenant:example',
                subject_id: 'agent:finance:01',
                audience: 'gate:finance:production',
                connector_id: signedConnectorId,
                action_type: 'stripe.payout.create',
                revision: 1,
                supersedes_allowance_digest: null,
                presentation_digest: `sha256:${'4'.repeat(64)}`,
                issued_at: '2026-07-30T17:59:00.000Z',
                valid_from: '2026-07-30T18:00:00.000Z',
                expires_at: '2026-07-31T18:00:00.000Z',
                constraints: {
                    currency: 'USD',
                    aggregate_amount: 5_000,
                    max_amount_per_action: 5_000,
                    material_fields: ['action_type', 'amount', 'currency', 'destination', 'operation_id'],
                    operation_id_field: 'operation_id',
                    amount_field: 'amount',
                    currency_field: 'currency',
                    target_field: 'destination',
                    allowed_targets: ['acct_known'],
                    allowed_values: {},
                },
            },
            signer: {
                issuer_id: 'customer:security',
                key_id: 'key:allowance',
                private_key: keys.privateKey,
            },
            capabilityIssuerPrivateKey: keys.privateKey,
        });
        const store = createMemoryCapabilityStore();
        assert.equal(store.registerCapability(issued.capabilityReceipt), true);
        const stripe = fakeStripe(providerAccountId);
        const connector = await stripeConnector(stripe);
        const result = await guardStripeAllowanceMutation({
            connector,
            params: { amount: 1_000, currency: 'USD', destination: 'acct_known' },
            operationId: `stripe:connector:${providerAccountId}`,
            allowance: issued.allowance,
            capabilityReceipt: issued.capabilityReceipt,
            secret: issued.secret,
            store,
            verifyAuthorizationReceipt: () => true,
            verifyAllowanceStatus: () => true,
            trustedAllowanceKeys: {
                'key:allowance': {
                    issuer_id: 'customer:security',
                    public_key: publicKey,
                },
            },
            trustedCapabilityIssuerKeys: [publicKey],
            expected: {
                allowance_id: `allowance:stripe-connector:${signedConnectorId}`,
                tenant_id: 'tenant:example',
                subject_id: 'agent:finance:01',
                audience: 'gate:finance:production',
                authorizer_id: 'customer:security',
            },
            now: Date.parse('2026-07-30T18:00:00.000Z'),
        });
        assert.deepEqual(result, { ok: false, reason: 'connector_mismatch' });
        assert.equal(stripe.calls.length, 0);
    }
});
test('typed Stripe connector derives account identity before any action can execute', async () => {
    const stripe = fakeStripe('acct_attacker');
    const connector = await stripeConnector(stripe);
    assert.ok(connector);
    await assert.rejects(() => createStripeAllowanceConnector({ stripe: fakeStripe('not-an-account') }), /invalid account/);
});
