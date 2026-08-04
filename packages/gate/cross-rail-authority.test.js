// SPDX-License-Identifier: Apache-2.0
// Generated from cross-rail-authority.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { CROSS_RAIL_AUTHORITY_CLAIM_BOUNDARY, HUMAN_INTERRUPTION_DECISION_VERSION, RAIL_ENTRY_PERMIT_VERSION, createCrossRailConnector, createRailEntryPermitBroker, executeCrossRailAllowance, signHumanInterruptionDecision, verifyHumanInterruptionDecision, } from './cross-rail-authority.js';
import { allowanceDigest, issueGateAllowance } from './allowance.js';
import { capabilityActionDigest, createMemoryCapabilityStore, } from './capability-receipt.js';
import { riskDigest } from './dist/reliance-risk-crypto.js';
const NOW = Date.parse('2026-08-03T18:00:00.000Z');
const D = (label) => `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
const CAID = `caid:1:commerce.payment.1:jcs-sha256:${Buffer.alloc(32, 7).toString('base64url')}`;
function signer(issuer = 'customer:security', keyId = 'key:authority') {
    const pair = generateKeyPairSync('ed25519');
    const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    return {
        pair,
        signer: { issuer_id: issuer, key_id: keyId, private_key: pair.privateKey },
        trusted: { [keyId]: { issuer_id: issuer, public_key: publicKey } },
        publicKey,
    };
}
function action(operationId = 'operation:01', actionType = 'stripe.payout.create') {
    return {
        action_type: actionType,
        amount: 2_500,
        currency: 'USD',
        destination: 'acct_known',
        operation_id: operationId,
    };
}
function decisionInput(connectorId, projectedAction = action(), request = { amount: 2_500, currency: 'USD', destination: 'acct_known' }, mode = 'standing_policy') {
    return {
        decision_id: 'decision:rail-entry:01',
        tenant_id: 'tenant:example',
        subject_id: 'agent:finance:01',
        connector_id: connectorId,
        caid: CAID,
        action_digest: capabilityActionDigest(projectedAction),
        provider_request_digest: riskDigest(request),
        policy_digest: D('policy'),
        configuration_digest: D('configuration'),
        mode,
        reason_codes: mode === 'require_human' ? ['amount_threshold'] : ['within_standing_policy'],
        issued_at: '2026-08-03T17:59:00.000Z',
        expires_at: '2026-08-03T18:05:00.000Z',
    };
}
function issuedAllowance(connectorId, keys, actionType = 'stripe.payout.create') {
    const authorizationReceipt = {
        '@version': 'EP-RECEIPT-v1',
        payload: { receipt_id: 'receipt:allowance:01', claim: { action_type: 'gate.allowance.issue', capability_only: true } },
    };
    const issued = issueGateAllowance({
        authorizationReceipt,
        allowance: {
            allowance_id: 'allowance:cross-rail:01',
            tenant_id: 'tenant:example',
            subject_id: 'agent:finance:01',
            audience: 'gate:finance:production',
            connector_id: connectorId,
            action_type: actionType,
            revision: 1,
            supersedes_allowance_digest: null,
            presentation_digest: D('allowance-presentation'),
            issued_at: '2026-08-03T17:55:00.000Z',
            valid_from: '2026-08-03T17:56:00.000Z',
            expires_at: '2026-08-04T18:00:00.000Z',
            constraints: {
                currency: 'USD', aggregate_amount: 20_000, max_amount_per_action: 5_000,
                material_fields: ['action_type', 'amount', 'currency', 'destination', 'operation_id'],
                operation_id_field: 'operation_id', amount_field: 'amount', currency_field: 'currency',
                target_field: 'destination', allowed_targets: ['acct_known'], allowed_values: {},
            },
        },
        signer: keys.signer,
        capabilityIssuerPrivateKey: keys.pair.privateKey,
    });
    const store = createMemoryCapabilityStore();
    assert.equal(store.registerCapability(issued.capabilityReceipt), true);
    const status = { status_epoch: 1, status_head_digest: D('status:1') };
    assert.equal(store.advanceAllowanceStatus({
        allowance_profile_id: `${issued.allowance.tenant_id}/${issued.allowance.allowance_id}`,
        allowance_digest: allowanceDigest(issued.allowance), revision: 1,
        ...status, expected_status_epoch: null, expected_status_head_digest: null, status: 'active',
    }).ok, true);
    return { ...issued, store, status };
}
function executionFixture({ mode = 'standing_policy', rail = 'stripe' } = {}) {
    const authority = signer();
    const permitAuthority = signer('gate:production', 'key:rail-entry');
    const connectorId = `${rail}:account:production`;
    const actionType = rail === 'ap2' ? 'ap2.payment.execute' : 'stripe.payout.create';
    const providerCalls = [];
    const connector = createCrossRailConnector({
        connector_id: connectorId,
        rail,
        action_class: 'commerce.payment',
        action_type: actionType,
        project_request: (request) => ({
            action: action(request.operation_id, actionType),
            provider_request: { amount: request.amount, currency: request.currency, destination: request.destination },
        }),
        resolve_caid: () => CAID,
        invoke: async (request, context) => {
            providerCalls.push({ request, context });
            return { provider_id: `${rail}:result:01` };
        },
    });
    const request = { amount: 2_500, currency: 'USD', destination: 'acct_known', operation_id: 'operation:01' };
    const projectedAction = action(request.operation_id, actionType);
    const decision = signHumanInterruptionDecision(decisionInput(connectorId, projectedAction, { amount: 2_500, currency: 'USD', destination: 'acct_known' }, mode), authority.signer);
    const issued = issuedAllowance(connectorId, authority, actionType);
    const broker = createRailEntryPermitBroker({ signer: permitAuthority.signer, now: () => NOW });
    return { authority, connectorId, connector, providerCalls, request, projectedAction, decision, issued, broker };
}
function executeOptions(fixture, extra = {}) {
    const { authority, connectorId, connector, request, decision, issued, broker } = fixture;
    return {
        connector, permit_broker: broker, request, interruption_decision: decision,
        allowance: issued.allowance, capabilityReceipt: issued.capabilityReceipt,
        secret: issued.secret, operationId: request.operation_id, store: issued.store,
        verifyAuthorizationReceipt: () => true,
        verifyAllowanceStatus: () => ({ ok: true, ...issued.status }),
        trustedAllowanceKeys: authority.trusted,
        trustedCapabilityIssuerKeys: [authority.publicKey],
        trustedInterruptionKeys: authority.trusted,
        expected: {
            allowance_id: 'allowance:cross-rail:01', tenant_id: 'tenant:example',
            subject_id: 'agent:finance:01', audience: 'gate:finance:production',
            connector_id: connectorId, authorizer_id: 'customer:security',
        },
        expectedInterruption: { policy_digest: D('policy'), configuration_digest: D('configuration') },
        now: () => NOW,
        ...extra,
    };
}
test('interruption decision is signed, exact-action bound, and claims only interruption selection', () => {
    const keys = signer();
    const input = decisionInput('stripe:account:production');
    const artifact = signHumanInterruptionDecision(input, keys.signer);
    assert.equal(artifact['@version'], HUMAN_INTERRUPTION_DECISION_VERSION);
    assert.equal(artifact.claim_boundary, CROSS_RAIL_AUTHORITY_CLAIM_BOUNDARY.interruption_decision);
    assert.equal(verifyHumanInterruptionDecision(artifact, {
        trusted_keys: keys.trusted, now: NOW,
        expected: { ...input, reason_codes: undefined },
    }).accepted, true);
    const spliced = structuredClone(artifact);
    spliced.provider_request_digest = D('different-request');
    assert.equal(verifyHumanInterruptionDecision(spliced, {
        trusted_keys: keys.trusted, now: NOW,
        expected: { ...input, reason_codes: undefined },
    }).accepted, false);
});
test('standing authority mints one opaque permit after reservation and enters a trusted rail once', async () => {
    const fixture = executionFixture();
    const observations = [];
    const result = await executeCrossRailAllowance(executeOptions(fixture, {
        observe: (event) => observations.push(event),
    }));
    assert.equal(result.ok, true);
    assert.equal(result.rail_entry_permit_version, RAIL_ENTRY_PERMIT_VERSION);
    assert.equal(result.rail_entry_permit_consumed, true);
    assert.match(result.rail_entry_permit_digest, /^sha256:/);
    assert.equal(fixture.providerCalls.length, 1);
    assert.deepEqual(fixture.providerCalls[0].request, { amount: 2_500, currency: 'USD', destination: 'acct_known' });
    assert.equal(Object.hasOwn(fixture.providerCalls[0].context, 'credential'), false);
    assert.deepEqual(Object.keys(observations[0]).sort(), [
        '@version', 'action_class', 'connector_class', 'human_interruption', 'occurred_at', 'outcome', 'reason_class',
    ]);
    assert.equal(JSON.stringify(observations).includes('acct_known'), false);
    const replay = await executeCrossRailAllowance(executeOptions(fixture));
    assert.equal(replay.ok, false);
    assert.equal(fixture.providerCalls.length, 1);
});
test('a require-human decision refuses standing policy and accepts only an exact bound human result', async () => {
    const missing = executionFixture({ mode: 'require_human' });
    const refused = await executeCrossRailAllowance(executeOptions(missing));
    assert.deepEqual(refused, { ok: false, reason: 'human_authorization_required' });
    assert.equal(missing.providerCalls.length, 0);
    const fixture = executionFixture({ mode: 'require_human' });
    const decisionDigest = riskDigest(fixture.decision);
    const result = await executeCrossRailAllowance(executeOptions(fixture, {
        human_authorization: { kind: 'webauthn-fixture' },
        verifyHumanAuthorization: () => ({
            ok: true, human_authorized: true, artifact_digest: D('human-authorization'),
            interruption_decision_digest: decisionDigest, caid: CAID,
            action_digest: capabilityActionDigest(fixture.projectedAction),
            provider_request_digest: riskDigest({ amount: 2_500, currency: 'USD', destination: 'acct_known' }),
        }),
    }));
    assert.equal(result.ok, true);
    assert.equal(fixture.providerCalls.length, 1);
});
test('request splicing and provider uncertainty fail closed without blind retry', async () => {
    const spliced = executionFixture();
    const refused = await executeCrossRailAllowance(executeOptions(spliced, {
        request: { ...spliced.request, amount: 4_999 },
    }));
    assert.equal(refused.ok, false);
    assert.equal(refused.reason, 'interruption_provider_request_mismatch');
    assert.equal(spliced.providerCalls.length, 0);
    const fixture = executionFixture({ rail: 'ap2' });
    const timedOutConnector = createCrossRailConnector({
        connector_id: fixture.connectorId, rail: 'ap2', action_class: 'commerce.payment', action_type: 'ap2.payment.execute',
        project_request: (request) => ({
            action: action(request.operation_id, 'ap2.payment.execute'),
            provider_request: { amount: request.amount, currency: request.currency, destination: request.destination },
        }),
        resolve_caid: () => CAID,
        invoke: async () => { throw new Error('provider connection lost'); },
    });
    const options = executeOptions(fixture, { connector: timedOutConnector });
    const first = await executeCrossRailAllowance(options);
    assert.equal(first.ok, false);
    assert.equal(first.reason, 'effect_indeterminate');
    const retry = await executeCrossRailAllowance(options);
    assert.equal(retry.ok, false);
    assert.notEqual(retry.reason, 'effect_indeterminate');
});
test('hostile configuration, human-binding, and connector substitution attempts refuse before provider entry', async () => {
    const missingPolicy = executionFixture();
    const missingPolicyResult = await executeCrossRailAllowance(executeOptions(missingPolicy, {
        expectedInterruption: undefined,
    }));
    assert.deepEqual(missingPolicyResult, { ok: false, reason: 'interruption_expected_policy_required' });
    assert.equal(missingPolicy.providerCalls.length, 0);
    const human = executionFixture({ mode: 'require_human' });
    const wrongHuman = await executeCrossRailAllowance(executeOptions(human, {
        human_authorization: { kind: 'webauthn-fixture' },
        verifyHumanAuthorization: () => ({
            ok: true, human_authorized: true, artifact_digest: D('human-authorization'),
            interruption_decision_digest: riskDigest(human.decision), caid: CAID,
            action_digest: capabilityActionDigest(human.projectedAction),
            provider_request_digest: D('spliced-provider-request'),
        }),
    }));
    assert.deepEqual(wrongHuman, { ok: false, reason: 'human_authorization_binding_failed' });
    assert.equal(human.providerCalls.length, 0);
    const forged = executionFixture();
    const forgedResult = await executeCrossRailAllowance(executeOptions(forged, { connector: Object.freeze({}) }));
    assert.deepEqual(forgedResult, { ok: false, reason: 'cross_rail_connector_required' });
    assert.equal(forged.providerCalls.length, 0);
    assert.deepEqual(Object.keys(forged.broker), []);
});
