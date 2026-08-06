// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-aps-adapter.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto, {} from 'node:crypto';
import test from 'node:test';
import { canonicalizeAeb, digestAeb, } from './aeb-adapter-contract.js';
import { APS_AEB_ADAPTER_ID, APS_AEB_ADAPTER_VERSION, APS_AEB_CONFIG_VERSION, APS_CAID_MAPPER_ID, APS_CAID_MAPPING_VERSION, APS_DRAFT_REVISION, APS_TRUST_ROOT_VERSION, computeApsActionRef, computeApsDecisionRef, computeApsPayloadRef, computeApsReceiptId, createApsActionDefinition, createApsAebAdapter, } from './aeb-aps-adapter.js';
const NOW = '2026-08-06T12:00:03.000Z';
const ACTION_TYPE = 'commerce.preflight.1';
const AGENT = 'did:key:z6MkAgent';
const BOUNDARY = 'did:web:gate.example';
const DELEGATION_REF = `sha256:${'1'.repeat(64)}`;
const EFFECTIVE_AUTHORITY_REF = '2'.repeat(64);
const POLICY_REF = '3'.repeat(64);
const CONTEXT_REF = '4'.repeat(64);
function spki(key) {
    return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}
function signReceipt(receipt, signer, keyId, privateKey) {
    const unsigned = structuredClone(receipt);
    delete unsigned.signatures;
    const descriptor = { signer, key_id: keyId, alg: 'Ed25519' };
    const bytes = Buffer.concat([
        Buffer.from('APS-RECEIPT-SIG-V1\0', 'utf8'),
        Buffer.from(canonicalizeAeb({ receipt: unsigned, signer: descriptor }), 'utf8'),
    ]);
    receipt.signatures = [{
            ...descriptor,
            value: crypto.sign(null, bytes, privateKey).toString('hex'),
        }];
    return receipt;
}
function makeFixture() {
    const agentKey = crypto.generateKeyPairSync('ed25519');
    const boundaryKey = crypto.generateKeyPairSync('ed25519');
    const payload = { amount: '5000.00', currency: 'GBP', creditor: 'Example Ltd' };
    const actionInput = {
        profile: 'aps-action-ref-v2',
        agent_id: AGENT,
        action_type: 'commerce_preflight',
        target: 'https://api.example/payments',
        payload_ref: computeApsPayloadRef(payload),
        scope_required: ['commerce:read', 'commerce:write'],
        issued_at: '2026-08-06T12:00:00.000Z',
        nonce: '0123456789abcdef0123456789abcdef',
    };
    const actionRef = computeApsActionRef(actionInput);
    const intent = {
        profile: 'aps-receipt-v1',
        receipt_id: '',
        receipt_type: 'aps:action-intent:v1',
        issuer: AGENT,
        subject_agent: AGENT,
        action_ref: actionRef,
        delegation_ref: DELEGATION_REF,
        issued_at: '2026-08-06T12:00:00.000Z',
        evidence_refs: [],
        result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
        signatures: [],
    };
    intent.receipt_id = computeApsReceiptId(intent);
    signReceipt(intent, AGENT, `${AGENT}#agent-key`, agentKey.privateKey);
    const decisionOutput = {
        profile: 'aps-core-decision-output-v1',
        verdict: 'permit',
        effective_authority_ref: EFFECTIVE_AUTHORITY_REF,
        constraints: ['amount<=5000.00', 'currency=GBP'],
        valid_until: '2026-08-06T12:05:00.000Z',
    };
    const decisionMaterial = {
        authority_state: {
            profile: 'test-authority-state-v1',
            delegation_ref: DELEGATION_REF,
            effective_authority_ref: EFFECTIVE_AUTHORITY_REF,
            subject_agent: AGENT,
            valid: true,
        },
        policy_input: { profile: 'test-policy-v1', policy_ref: POLICY_REF },
        decision_context: { profile: 'test-context-v1', context_ref: CONTEXT_REF },
    };
    const decisionRef = computeApsDecisionRef({
        action_ref: actionRef,
        ...decisionMaterial,
        decision_output: decisionOutput,
    });
    const decision = {
        profile: 'aps-receipt-v1',
        receipt_id: '',
        receipt_type: 'aps:policy-decision:v1',
        issuer: BOUNDARY,
        subject_agent: AGENT,
        action_ref: actionRef,
        delegation_ref: DELEGATION_REF,
        decision_ref: decisionRef,
        issued_at: '2026-08-06T12:00:01.000Z',
        prev: intent.receipt_id,
        evidence_refs: [],
        result: decisionOutput,
        signatures: [],
    };
    decision.receipt_id = computeApsReceiptId(decision);
    signReceipt(decision, BOUNDARY, `${BOUNDARY}#boundary-key`, boundaryKey.privateKey);
    const expectedAction = {
        action_type: ACTION_TYPE,
        aps_action: {
            profile: actionInput.profile,
            agent_id: actionInput.agent_id,
            action_type: actionInput.action_type,
            target: actionInput.target,
            payload,
            scope_required: actionInput.scope_required,
            issued_at: actionInput.issued_at,
            nonce: actionInput.nonce,
        },
    };
    const authorityVerifierDescriptor = {
        id: 'test:aps-authority-verifier',
        version: '1',
        implementation_digest: digestAeb({ implementation: 'test:aps-authority-verifier', version: '1' }),
    };
    const config = {
        '@version': APS_AEB_CONFIG_VERSION,
        evidence_role: 'policy-permit',
        subject: { id: 'system:gate-example', kind: 'system', native_id: BOUNDARY },
        action_type: ACTION_TYPE,
        authority_verifier: authorityVerifierDescriptor,
        clock_skew_seconds: 2,
        max_receipt_age_seconds: 300,
        max_status_age_seconds: 120,
    };
    const trustRoots = [
        {
            '@version': APS_TRUST_ROOT_VERSION,
            signer: AGENT,
            key_id: `${AGENT}#agent-key`,
            public_key: spki(agentKey.publicKey),
        },
        {
            '@version': APS_TRUST_ROOT_VERSION,
            signer: BOUNDARY,
            key_id: `${BOUNDARY}#boundary-key`,
            public_key: spki(boundaryKey.publicKey),
        },
    ];
    const authorityVerifier = {
        ...authorityVerifierDescriptor,
        verify(input) {
            const state = input.authority_state;
            return state?.profile === 'test-authority-state-v1'
                && state?.valid === true
                && state?.delegation_ref === input.delegation_ref
                && state?.effective_authority_ref === input.effective_authority_ref
                && state?.subject_agent === input.subject_agent
                ? { verified: true, reason: null }
                : { verified: false, reason: 'test_authority_state_invalid' };
        },
    };
    return {
        agentKey,
        boundaryKey,
        payload,
        actionInput,
        intent,
        decision,
        decisionMaterial,
        expectedAction,
        config,
        trustRoots,
        authorityVerifier,
    };
}
function profile() {
    return {
        version: APS_CAID_MAPPING_VERSION,
        definition: createApsActionDefinition(ACTION_TYPE),
        registry_entry_ref: 'mapping:aps-commerce-preflight',
        mapper_id: APS_CAID_MAPPER_ID,
        resolver: {
            id: APS_CAID_MAPPER_ID,
            version: '1',
            implementation_digest: digestAeb({ implementation: APS_CAID_MAPPER_ID, version: '1' }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: [
                'receipt.receipt_id',
                'receipt.issuer',
                'receipt.evidence_refs',
                'receipt.signatures',
            ],
        },
        profile_digest: digestAeb(null),
    };
}
function input(fixture, overrides = {}) {
    return {
        artifact: {
            action_input: fixture.actionInput,
            payload: fixture.payload,
            action_intent: fixture.intent,
            policy_decision: fixture.decision,
            decision_material: fixture.decisionMaterial,
        },
        artifact_ref: 'aps:policy-decision:test-1',
        status: {
            checked_at: '2026-08-06T12:00:02.000Z',
            expires_at: '2026-08-06T12:01:00.000Z',
            revocation_checked: true,
            revoked: false,
            consumed: false,
        },
        trust_roots: fixture.trustRoots,
        adapter_config: fixture.config,
        expected_action: fixture.expectedAction,
        now: NOW,
        ...overrides,
    };
}
test('APS -03 intent and policy-decision chain verifies and maps without material field loss', () => {
    const fixture = makeFixture();
    const adapter = createApsAebAdapter({
        config: fixture.config,
        trust_roots: fixture.trustRoots,
        authority_verifier: fixture.authorityVerifier,
    });
    assert.equal(adapter.id, APS_AEB_ADAPTER_ID);
    assert.equal(adapter.version, APS_AEB_ADAPTER_VERSION);
    const native = adapter.verifyNative(input(fixture));
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.acceptance, 'ACCEPTED');
    assert.deepEqual(native.reasons, []);
    assert.equal(native.replay_unit, digestAeb({
        protocol: APS_DRAFT_REVISION,
        policy_decision_receipt_id: fixture.decision.receipt_id,
    }));
    const mapped = adapter.mapAction({ ...input(fixture), profile: profile(), native });
    assert.equal(mapped.mapping, 'MATCH');
    assert.match(mapped.caid ?? '', /^caid:1:commerce\.preflight\.1:jcs-sha256:/);
    assert.equal(mapped.action_digest, digestAeb(fixture.expectedAction));
});
test('APS adapter refuses mutation of scope, nonce, issuance time, agent, or profile', () => {
    for (const mutate of [
        (value) => { value.scope_required = ['commerce:read']; },
        (value) => { value.nonce = 'f'.repeat(32); },
        (value) => { value.issued_at = '2026-08-06T12:00:00.001Z'; },
        (value) => { value.agent_id = 'did:key:z6MkOther'; },
        (value) => { value.profile = 'aps-action-ref-v1'; },
    ]) {
        const fixture = makeFixture();
        const adapter = createApsAebAdapter({
            config: fixture.config,
            trust_roots: fixture.trustRoots,
            authority_verifier: fixture.authorityVerifier,
        });
        const changed = structuredClone(fixture.expectedAction);
        mutate(changed.aps_action);
        const result = adapter.verifyNative(input(fixture, { expected_action: changed }));
        assert.notEqual(result.acceptance, 'ACCEPTED');
    }
});
test('APS adapter refuses a forged decision and a failed authority path', () => {
    const fixture = makeFixture();
    const adapter = createApsAebAdapter({
        config: fixture.config,
        trust_roots: fixture.trustRoots,
        authority_verifier: fixture.authorityVerifier,
    });
    const forged = structuredClone(input(fixture).artifact);
    forged.policy_decision.result.effective_authority_ref = '9'.repeat(64);
    const invalidSignature = adapter.verifyNative(input(fixture, { artifact: forged }));
    assert.equal(invalidSignature.native_verification, 'FAILED');
    assert.equal(invalidSignature.acceptance, 'REJECTED');
    assert.ok(invalidSignature.reasons.includes('aps:receipt_id_mismatch'));
    const refusingVerifier = {
        ...fixture.authorityVerifier,
        verify: () => ({ verified: false, reason: 'test_authority_state_invalid' }),
    };
    const authorityAdapter = createApsAebAdapter({
        config: fixture.config,
        trust_roots: fixture.trustRoots,
        authority_verifier: refusingVerifier,
    });
    const authorityResult = authorityAdapter.verifyNative(input(fixture));
    assert.equal(authorityResult.native_verification, 'FAILED');
    assert.equal(authorityResult.acceptance, 'REJECTED');
    assert.ok(authorityResult.reasons.includes('aps:test_authority_state_invalid'));
});
test('APS adapter treats permit as evidence only; consumed approval is rejected', () => {
    const fixture = makeFixture();
    const adapter = createApsAebAdapter({
        config: fixture.config,
        trust_roots: fixture.trustRoots,
        authority_verifier: fixture.authorityVerifier,
    });
    const result = adapter.verifyNative(input(fixture, {
        status: { ...input(fixture).status, consumed: true },
    }));
    assert.equal(result.native_verification, 'VERIFIED');
    assert.equal(result.acceptance, 'REJECTED');
    assert.ok(result.reasons.includes('evidence_consumed'));
});
test('APS source lock is the reviewed -03 revision', () => {
    assert.equal(APS_DRAFT_REVISION, 'draft-pidlisnyi-aps-03');
});
