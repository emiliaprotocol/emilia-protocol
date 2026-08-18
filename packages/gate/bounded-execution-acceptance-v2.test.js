// SPDX-License-Identifier: Apache-2.0
// Generated from bounded-execution-acceptance-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-BOUNDED-EXECUTION-ACCEPTANCE-PROFILE-v2 hybrid adoption test:
// signRiskBodyV2 / verifyRiskBodyV2 (EP-RISK-HYBRID-v2) wired in additively
// via signBoundedExecutionAcceptanceProfileV2 /
// verifyBoundedExecutionAcceptanceProfileV2. Hostile matrix per
// docs/protocol/pq-hybrid-program.md: stripped leg, narrowed set,
// wrong-length signature, Ed448 masquerade, v1-refuses-v2, valid v2
// roundtrip.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY, BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_V2_VERSION, signBoundedExecutionAcceptanceProfile, signBoundedExecutionAcceptanceProfileV2, verifyBoundedExecutionAcceptanceProfile, verifyBoundedExecutionAcceptanceProfileV2, } from './bounded-execution-acceptance.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const D = (character) => `sha256:${character.repeat(64)}`;
const NOW = '2026-07-30T20:30:00.000Z';
function material() {
    const pair = generateKeyPairSync('ed25519');
    const pq = ml_dsa65.keygen(new Uint8Array(32).fill(3));
    const relyingPartyId = 'payer:example-health-plan';
    const keyId = 'key:process-acceptance-v2';
    return {
        relyingPartyId,
        keyId,
        signer: {
            issuer_id: relyingPartyId,
            key_id: keyId,
            private_key: pair.privateKey,
            pq_private_key: Buffer.from(pq.secretKey).toString('base64url'),
        },
        trusted_keys: {
            [keyId]: {
                issuer_id: relyingPartyId,
                public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
                pq_public_key: Buffer.from(pq.publicKey).toString('base64url'),
            },
        },
    };
}
function input(m) {
    return {
        profile_id: 'profile:reference-process-completion:v2',
        relying_party_id: m.relyingPartyId,
        program_id: 'program:reference',
        program_version: 1,
        program_digest: D('9'),
        valid_from: '2026-07-30T20:00:00.000Z',
        expires_at: '2026-07-31T20:00:00.000Z',
        accepted_program_statuses: ['ACTIVE'],
        max_total_unresolved: 0,
        max_total_reserved: 0,
        required_nodes: [{
                node_id: 'inspect',
                min_terminal_occurrences: 1,
                accepted_outcomes: ['COMMITTED'],
                allow_additional_terminal_outcomes: false,
            }],
    };
}
function context(m) {
    return {
        trusted_keys: m.trusted_keys,
        expected_profile_id: 'profile:reference-process-completion:v2',
        expected_relying_party_id: m.relyingPartyId,
        expected_program_id: 'program:reference',
        expected_program_version: 1,
        expected_program_digest: D('9'),
        now: NOW,
    };
}
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function');
});
test('a real hybrid acceptance profile verifies under both pinned keys', async () => {
    const m = material();
    const artifact = await signBoundedExecutionAcceptanceProfileV2(input(m), m.signer);
    assert.equal(artifact['@version'], BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_V2_VERSION);
    assert.equal(artifact.claim_boundary, BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY);
    const verified = await verifyBoundedExecutionAcceptanceProfileV2(artifact, context(m));
    assert.equal(verified.accepted, true, verified.reason ?? '');
    assert.equal(verified.verified, true);
});
test('the v1 verifier refuses a v2 profile cleanly on the version marker', async () => {
    const m = material();
    const artifact = await signBoundedExecutionAcceptanceProfileV2(input(m), m.signer);
    const verified = verifyBoundedExecutionAcceptanceProfile(artifact, context(m));
    assert.equal(verified.accepted, false);
});
test('the v1 verifier still accepts a v1 profile, unchanged', () => {
    const m = material();
    const v1Signer = { issuer_id: m.signer.issuer_id, key_id: m.signer.key_id, private_key: m.signer.private_key };
    const artifact = signBoundedExecutionAcceptanceProfile(input(m), v1Signer);
    const v1Context = {
        ...context(m),
        trusted_keys: { [m.keyId]: { issuer_id: m.relyingPartyId, public_key: m.trusted_keys[m.keyId].public_key } },
    };
    const verified = verifyBoundedExecutionAcceptanceProfile(artifact, v1Context);
    assert.equal(verified.accepted, true, verified.reason ?? '');
});
test('the v2 verifier refuses a v1 profile on the version marker', async () => {
    const m = material();
    const v1Signer = { issuer_id: m.signer.issuer_id, key_id: m.signer.key_id, private_key: m.signer.private_key };
    const artifact = signBoundedExecutionAcceptanceProfile(input(m), v1Signer);
    const verified = await verifyBoundedExecutionAcceptanceProfileV2(artifact, context(m));
    assert.equal(verified.accepted, false);
});
test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
    const m = material();
    const artifact = await signBoundedExecutionAcceptanceProfileV2(input(m), m.signer);
    const stripped = { ...artifact, proof: { ...artifact.proof, signatures: artifact.proof.signatures.filter((s) => s.alg === 'Ed25519') } };
    const verified = await verifyBoundedExecutionAcceptanceProfileV2(stripped, context(m));
    assert.equal(verified.accepted, false);
});
test('SET NARROWING: dropping the PQ leg and narrowing required_algorithms fails', async () => {
    const m = material();
    const artifact = await signBoundedExecutionAcceptanceProfileV2(input(m), m.signer);
    const narrowed = {
        ...artifact,
        proof: {
            ...artifact.proof,
            required_algorithms: ['Ed25519'],
            signatures: artifact.proof.signatures.filter((s) => s.alg === 'Ed25519'),
        },
    };
    const verified = await verifyBoundedExecutionAcceptanceProfileV2(narrowed, context(m));
    assert.equal(verified.accepted, false);
});
test('WRONG-LENGTH SIGNATURE: a truncated ML-DSA signature refuses', async () => {
    const m = material();
    const artifact = await signBoundedExecutionAcceptanceProfileV2(input(m), m.signer);
    const tampered = {
        ...artifact,
        proof: {
            ...artifact.proof,
            signatures: artifact.proof.signatures.map((s) => (s.alg === 'ML-DSA-65' ? { ...s, sig: s.sig.slice(0, -8) } : s)),
        },
    };
    const verified = await verifyBoundedExecutionAcceptanceProfileV2(tampered, context(m));
    assert.equal(verified.accepted, false);
});
test('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half refuses', async () => {
    const m = material();
    const artifact = await signBoundedExecutionAcceptanceProfileV2(input(m), m.signer);
    const ed448 = generateKeyPairSync('ed448');
    const verified = await verifyBoundedExecutionAcceptanceProfileV2(artifact, {
        ...context(m),
        trusted_keys: {
            [m.keyId]: {
                issuer_id: m.relyingPartyId,
                public_key: ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
                pq_public_key: m.trusted_keys[m.keyId].pq_public_key,
            },
        },
    });
    assert.equal(verified.accepted, false);
});
test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const m = material();
    const artifact = await signBoundedExecutionAcceptanceProfileV2(input(m), m.signer);
    const verified = await verifyBoundedExecutionAcceptanceProfileV2(artifact, {
        ...context(m),
        mldsaBackendLoader: async () => null,
    });
    assert.equal(verified.accepted, false);
});
