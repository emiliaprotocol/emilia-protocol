// SPDX-License-Identifier: Apache-2.0
// Generated from trusted-context.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { generateKeyPairSync } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { CONTEXT_PROJECTION_COMPONENT, canonicalContextBindingDigest, canonicalContextRecordDigest, createTrustedContextAecVerifier, createTrustedContextEvaluator, signTrustedContextBinding, trustedContextPolicyDigest, verifyTrustedContextContinuity, } from './trusted-context.js';
import { createApertoMemoryContextProvider } from './apertomemory-context.js';
import { verifyAuthorizationChain } from '@emilia-protocol/verify/evidence-chain';
const VECTOR_PATH = fileURLToPath(new URL('../../interop/apertomemory-emilia/memory-projection-record.v1.vectors.json', import.meta.url));
const bundle = JSON.parse(readFileSync(VECTOR_PATH, 'utf8'));
const record = bundle.projection.record;
const HASH = (character) => `sha256:${character.repeat(64)}`;
const NOW = '2026-07-29T17:01:00.000Z';
const BINDER = generateKeyPairSync('ed25519');
const BINDER_KEY_ID = 'gate-context-binder-2026-07';
const BINDER_PUBLIC_KEY = BINDER.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
function provider(overrides = {}) {
    return createApertoMemoryContextProvider({
        adapterKeys: {
            [bundle.adapter_pin.key_id]: {
                public_key_spki_b64u: bundle.adapter_pin.public_key_spki_b64u,
                status: 'active',
                valid_from: '2026-07-29T00:00:00.000Z',
                valid_to: '2027-07-29T00:00:00.000Z',
                revoked_at: null,
            },
        },
        statusCheckedAt: '2026-07-29T17:00:30.000Z',
        ...overrides,
    });
}
function policy(overrides = {}) {
    return {
        policy_id: 'trusted-context/software-remediation/v1',
        provider_id: 'apertomemory',
        provider_profile: 'draft-ferro-apertomemory-02',
        max_projection_age_sec: 300,
        max_keyring_age_sec: 300,
        max_signer_status_age_sec: 300,
        allowed_trust: ['self', 'trusted'],
        allowed_exclusion_reasons: [
            'authentication_failed',
            'schema_invalid',
            'policy_filtered',
            'context_limit',
        ],
        max_excluded_objects: 2,
        require_current_signer_status: true,
        ...overrides,
    };
}
function baseAction(overrides = {}) {
    return {
        action_type: 'software.merge',
        repository: 'emiliaprotocol/example',
        target_ref: 'refs/heads/main',
        diff_digest: HASH('d'),
        ...overrides,
    };
}
function fixture({ projectionRecord = record, actionOverrides = {}, evidenceOverrides = {}, policyOverrides = {}, } = {}) {
    const activePolicy = policy(policyOverrides);
    const actionSubject = baseAction(actionOverrides);
    const contextBinding = signTrustedContextBinding({
        providerId: 'apertomemory',
        providerProfile: 'draft-ferro-apertomemory-02',
        projectionRecord,
        action: actionSubject,
        policyDigest: trustedContextPolicyDigest(activePolicy),
        nonce: 'ctx_nonce_01',
        issuedAt: '2026-07-29T17:00:01.000Z',
        expiresAt: '2026-07-29T17:05:01.000Z',
        binderId: 'urn:emilia:gate:context-binder:reference-01',
        keyId: BINDER_KEY_ID,
        privateKey: BINDER.privateKey,
    });
    const trustedContext = {
        provider_id: 'apertomemory',
        provider_profile: 'draft-ferro-apertomemory-02',
        projection_record_digest: canonicalContextRecordDigest(projectionRecord),
        projection_digest: projectionRecord.projection.digest,
        context_binding_digest: canonicalContextBindingDigest(contextBinding),
    };
    return {
        policy: activePolicy,
        contextBinding,
        action: { ...actionSubject, trusted_context: trustedContext },
        evidence: {
            provider_id: 'apertomemory',
            provider_profile: 'draft-ferro-apertomemory-02',
            projection_record: projectionRecord,
            context_binding: contextBinding,
            ...evidenceOverrides,
        },
    };
}
function evaluator(providerOverride = provider(), policyOverride = policy(), optionOverrides = {}) {
    return createTrustedContextEvaluator({
        providers: [providerOverride],
        policy: policyOverride,
        bindingKeys: {
            [BINDER_KEY_ID]: {
                public_key_spki_b64u: BINDER_PUBLIC_KEY,
                status: 'active',
                valid_from: '2026-07-29T00:00:00.000Z',
                valid_to: '2027-07-29T00:00:00.000Z',
                revoked_at: null,
            },
        },
        bindingStatusCheckedAt: '2026-07-29T17:00:30.000Z',
        expectedBindingNonce: 'ctx_nonce_01',
        verificationTime: NOW,
        ...optionOverrides,
    });
}
function claimsProvider(overrides) {
    const native = provider();
    return {
        providerId: native.providerId,
        profileId: native.profileId,
        verifyProjection(value, context) {
            const result = native.verifyProjection(value, context);
            if (result.state !== 'VERIFIED' || !result.claims)
                return result;
            return {
                ...result,
                claims: { ...result.claims, ...overrides },
            };
        },
    };
}
test('accepts a pinned signed projection for the exact context-bound action', () => {
    const candidate = fixture();
    const result = evaluator(provider(), candidate.policy)({
        evidence: candidate.evidence,
        action: candidate.action,
    });
    assert.equal(result.state, 'VERIFIED', JSON.stringify(result));
    assert.equal(result.reason, null);
    assert.equal(result.authorizes, false);
    assert.equal(result.projection_record_digest, canonicalContextRecordDigest(record));
    assert.equal(result.projection_digest, record.projection.digest);
    assert.match(result.action_digest, /^sha256:[0-9a-f]{64}$/);
});
test('fails closed when the action omits or changes the signed context binding', () => {
    const candidate = fixture();
    const omitted = structuredClone(candidate.action);
    delete omitted.trusted_context;
    assert.deepEqual(evaluator(provider(), candidate.policy)({ evidence: candidate.evidence, action: omitted }).state, 'NOT_VERIFIED');
    const mismatched = {
        ...candidate.action,
        trusted_context: {
            ...candidate.action.trusted_context,
            projection_record_digest: HASH('f'),
        },
    };
    const result = evaluator(provider(), candidate.policy)({ evidence: candidate.evidence, action: mismatched });
    assert.equal(result.state, 'NOT_VERIFIED');
    assert.equal(result.reason, 'action_context_binding_mismatch');
});
test('rejects altered, omitted, reordered, and signer-substituted projections', () => {
    const cases = [];
    const altered = structuredClone(record);
    altered.projection.byte_length += 1;
    cases.push(altered);
    const omitted = structuredClone(record);
    omitted.delivered.pop();
    cases.push(omitted);
    const reordered = structuredClone(record);
    [reordered.delivered[0], reordered.delivered[1]] = [reordered.delivered[1], reordered.delivered[0]];
    cases.push(reordered);
    const substituted = structuredClone(record);
    substituted.adapter.key_id = 'attacker-key';
    substituted.proof.key_id = 'attacker-key';
    cases.push(substituted);
    for (const projectionRecord of cases) {
        const candidate = fixture({ projectionRecord });
        const result = evaluator(provider(), candidate.policy)({
            evidence: candidate.evidence,
            action: candidate.action,
        });
        assert.equal(result.state, 'NOT_VERIFIED');
    }
});
test('returns INDETERMINATE for stale signer status and stale source keyring state', () => {
    const candidate = fixture();
    const staleSigner = evaluator(provider({ statusCheckedAt: '2026-07-29T16:00:00.000Z' }));
    assert.deepEqual(staleSigner({ evidence: candidate.evidence, action: candidate.action }), {
        state: 'INDETERMINATE',
        reason: 'adapter_status_stale',
        authorizes: false,
    });
    const staleKeyring = evaluator(claimsProvider({
        trust_evaluated_at: '2026-07-29T16:00:00.000Z',
    }), candidate.policy);
    assert.deepEqual(staleKeyring({ evidence: candidate.evidence, action: candidate.action }), { state: 'INDETERMINATE', reason: 'keyring_status_stale', authorizes: false });
});
test('refuses revoked signers, untrusted delivered content, and forbidden exclusions', () => {
    const candidate = fixture();
    const revoked = evaluator(provider({
        adapterKeys: {
            [bundle.adapter_pin.key_id]: {
                public_key_spki_b64u: bundle.adapter_pin.public_key_spki_b64u,
                status: 'revoked',
                valid_from: '2026-07-29T00:00:00.000Z',
                valid_to: '2027-07-29T00:00:00.000Z',
                revoked_at: '2026-07-29T17:00:45.000Z',
            },
        },
    }));
    assert.equal(revoked({ evidence: candidate.evidence, action: candidate.action }).reason, 'adapter_key_revoked');
    assert.equal(evaluator(claimsProvider({
        delivered_trust: ['unverified', 'self'],
    }), candidate.policy)({
        evidence: candidate.evidence,
        action: candidate.action,
    }).reason, 'projection_trust_policy_mismatch');
    const strictCandidate = fixture({ policyOverrides: { allowed_exclusion_reasons: ['policy_filtered'] } });
    const strictPolicy = evaluator(provider(), strictCandidate.policy);
    assert.equal(strictPolicy({ evidence: strictCandidate.evidence, action: strictCandidate.action }).reason, 'projection_exclusion_policy_mismatch');
});
test('binding signer revocation and stale status are independently fail closed', () => {
    const candidate = fixture();
    const revokedDirectory = {
        [BINDER_KEY_ID]: {
            public_key_spki_b64u: BINDER_PUBLIC_KEY,
            status: 'revoked',
            valid_from: '2026-07-29T00:00:00.000Z',
            valid_to: '2027-07-29T00:00:00.000Z',
            revoked_at: '2026-07-29T17:00:45.000Z',
        },
    };
    assert.equal(evaluator(provider(), candidate.policy, {
        bindingKeys: revokedDirectory,
    })({ evidence: candidate.evidence, action: candidate.action }).reason, 'binding_signer_revoked');
    assert.deepEqual(evaluator(provider(), candidate.policy, {
        bindingStatusCheckedAt: '2026-07-29T16:00:00.000Z',
    })({ evidence: candidate.evidence, action: candidate.action }), {
        state: 'INDETERMINATE',
        reason: 'binding_signer_status_stale',
        authorizes: false,
    });
});
test('binds the projection to the current admission nonce', () => {
    const candidate = fixture();
    assert.deepEqual(evaluator(provider(), candidate.policy, {
        expectedBindingNonce: 'ctx_nonce_for_another_admission',
    })({ evidence: candidate.evidence, action: candidate.action }), {
        state: 'NOT_VERIFIED',
        reason: 'context_binding_nonce_mismatch',
        authorizes: false,
    });
    assert.deepEqual(evaluator(provider(), candidate.policy, {
        expectedBindingNonce() {
            throw new Error('challenge store unavailable');
        },
    })({ evidence: candidate.evidence, action: candidate.action }), {
        state: 'INDETERMINATE',
        reason: 'binding_nonce_unavailable',
        authorizes: false,
    });
});
test('constructor-pinned key directories cannot be changed by caller mutation', () => {
    const candidate = fixture();
    const adapterKeys = {
        [bundle.adapter_pin.key_id]: {
            public_key_spki_b64u: bundle.adapter_pin.public_key_spki_b64u,
            status: 'active',
            valid_from: '2026-07-29T00:00:00.000Z',
            valid_to: '2027-07-29T00:00:00.000Z',
            revoked_at: null,
        },
    };
    const pinnedProvider = provider({ adapterKeys });
    adapterKeys[bundle.adapter_pin.key_id].status = 'revoked';
    adapterKeys[bundle.adapter_pin.key_id].revoked_at = '2026-07-29T17:00:45.000Z';
    const bindingKeys = {
        [BINDER_KEY_ID]: {
            public_key_spki_b64u: BINDER_PUBLIC_KEY,
            status: 'active',
            valid_from: '2026-07-29T00:00:00.000Z',
            valid_to: '2027-07-29T00:00:00.000Z',
            revoked_at: null,
        },
    };
    const configured = evaluator(pinnedProvider, candidate.policy, { bindingKeys });
    bindingKeys[BINDER_KEY_ID].status = 'revoked';
    bindingKeys[BINDER_KEY_ID].revoked_at = '2026-07-29T17:00:45.000Z';
    assert.equal(configured({ evidence: candidate.evidence, action: candidate.action }).state, 'VERIFIED');
});
test('hostile reflective inputs fail closed without escaping the verifier', () => {
    const candidate = fixture();
    const hostile = new Proxy(candidate, {
        ownKeys() {
            throw new Error('hostile proxy');
        },
    });
    assert.deepEqual(evaluator(provider(), candidate.policy)(hostile), {
        state: 'INDETERMINATE',
        reason: 'context_evaluation_unavailable',
        authorizes: false,
    });
});
test('rejects runtime trust configuration and unknown providers without invoking them', () => {
    const injectedCandidate = fixture({ evidenceOverrides: { adapterKeys: { attacker: 'key' } } });
    assert.equal(evaluator(provider(), injectedCandidate.policy)({
        evidence: injectedCandidate.evidence,
        action: injectedCandidate.action,
    }).reason, 'context_evidence_schema_invalid');
    const unknown = fixture({ evidenceOverrides: { provider_id: 'unknown-memory' } });
    assert.equal(evaluator(provider(), unknown.policy)({ evidence: unknown.evidence, action: unknown.action }).reason, 'provider_policy_mismatch');
});
test('provider failure is INDETERMINATE and never becomes authorization', () => {
    const unavailable = {
        providerId: 'apertomemory',
        profileId: 'draft-ferro-apertomemory-02',
        verifyProjection() {
            throw new Error('provider unavailable');
        },
    };
    const candidate = fixture();
    assert.deepEqual(evaluator(unavailable, candidate.policy)({ evidence: candidate.evidence, action: candidate.action }), { state: 'INDETERMINATE', reason: 'provider_verification_unavailable', authorizes: false });
});
test('AEC component establishes bounded evidence satisfaction and never authorization', () => {
    const candidate = fixture();
    const verify = createTrustedContextAecVerifier({
        evaluator: evaluator(provider(), candidate.policy),
    });
    const expectedAction = candidate.action;
    const result = verify(candidate.evidence, { action: expectedAction });
    assert.equal(result.valid, true);
    assert.equal(result.action_digest, evaluator(provider(), candidate.policy)({ evidence: candidate.evidence, action: expectedAction }).action_digest);
    assert.equal(result.detail.state, 'VERIFIED');
    assert.equal(result.detail.authorizes, false);
    assert.equal(CONTEXT_PROJECTION_COMPONENT, 'ep-memory-projection');
    const replayAction = { ...expectedAction, diff_digest: HASH('e') };
    const replay = verify(candidate.evidence, { action: replayAction });
    assert.equal(replay.valid, false);
    assert.equal(replay.detail.reason, 'action_context_binding_mismatch');
});
test('the real AEC evaluator composes memory projection as evidence, not authorization', () => {
    const candidate = fixture();
    const componentVerifier = createTrustedContextAecVerifier({
        evaluator: evaluator(provider(), candidate.policy),
    });
    const result = verifyAuthorizationChain({
        '@version': 'EP-AEC-v1',
        action: candidate.action,
        components: [{
                type: CONTEXT_PROJECTION_COMPONENT,
                evidence: candidate.evidence,
            }],
        requirement: CONTEXT_PROJECTION_COMPONENT,
    }, {
        requirement: CONTEXT_PROJECTION_COMPONENT,
        expectedAction: candidate.action,
        verifiers: { [CONTEXT_PROJECTION_COMPONENT]: componentVerifier },
    });
    assert.equal(result.satisfied, true, JSON.stringify(result));
    assert.equal(result.expected_action_bound, true);
    assert.equal(result.components[0].valid, true);
    assert.equal(result.components[0].bound, true);
    assert.equal(result.components[0].type, CONTEXT_PROJECTION_COMPONENT);
    assert.equal(result.authorized, undefined);
});
test('continuity requires the same projection, action, execution, and outcome chain', () => {
    const candidate = fixture();
    const verifiedContext = evaluator(provider(), candidate.policy)({
        evidence: candidate.evidence,
        action: candidate.action,
    });
    assert.equal(verifiedContext.state, 'VERIFIED', JSON.stringify(verifiedContext));
    const execution = {
        verified: true,
        action_digest: verifiedContext.action_digest,
        projection_record_digest: verifiedContext.projection_record_digest,
        execution_digest: HASH('7'),
    };
    const outcome = {
        verified: true,
        action_digest: verifiedContext.action_digest,
        projection_record_digest: verifiedContext.projection_record_digest,
        execution_digest: execution.execution_digest,
        outcome_digest: HASH('8'),
    };
    const continuous = verifyTrustedContextContinuity({ verifiedContext, execution, outcome });
    assert.equal(continuous.status, 'CONTINUOUS');
    assert.equal(continuous.authorizes, false);
    const broken = verifyTrustedContextContinuity({
        verifiedContext,
        execution,
        outcome: { ...outcome, execution_digest: HASH('9') },
    });
    assert.equal(broken.status, 'BROKEN');
    assert.equal(broken.reason, 'execution_outcome_binding_mismatch');
    const missing = verifyTrustedContextContinuity({ verifiedContext, execution, outcome: null });
    assert.equal(missing.status, 'INDETERMINATE');
});
