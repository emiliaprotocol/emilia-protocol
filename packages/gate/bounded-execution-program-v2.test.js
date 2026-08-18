// SPDX-License-Identifier: Apache-2.0
// Generated from bounded-execution-program-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-BOUNDED-EXECUTION-PROGRAM-v2 hybrid adoption test: signRiskBodyV2 /
// verifyRiskBodyV2 (EP-RISK-HYBRID-v2) wired in additively via
// signBoundedExecutionProgramV2 / verifyBoundedExecutionProgramV2. Hostile
// matrix per docs/protocol/pq-hybrid-program.md: stripped leg, narrowed set,
// wrong-length signature, Ed448 masquerade, v1-refuses-v2, valid v2
// roundtrip.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { BOUNDED_EXECUTION_PROGRAM_V2_VERSION, EXECUTION_PROGRAM_CLAIM_BOUNDARY, executionProgramDigest, signBoundedExecutionProgram, signBoundedExecutionProgramV2, verifyBoundedExecutionProgram, verifyBoundedExecutionProgramV2, } from './bounded-execution-program.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const D = (character) => `sha256:${character.repeat(64)}`;
const C = (character) => (`caid:1:devops.infrastructure-change.1:jcs-sha256:${character.repeat(43)}`);
const NOW = '2026-07-29T20:00:00.000Z';
function keyMaterial() {
    const pair = generateKeyPairSync('ed25519');
    const pq = ml_dsa65.keygen(new Uint8Array(32).fill(7));
    return {
        pair,
        pq,
        signer: {
            issuer_id: 'customer:example-security',
            key_id: 'key:customer-program-authorizer',
            private_key: pair.privateKey,
            pq_private_key: Buffer.from(pq.secretKey).toString('base64url'),
        },
        trusted_keys: {
            'key:customer-program-authorizer': {
                issuer_id: 'customer:example-security',
                public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
                pq_public_key: Buffer.from(pq.publicKey).toString('base64url'),
            },
        },
    };
}
function program() {
    return {
        program_id: 'program:production-remediation:01',
        tenant_id: 'tenant:example',
        version: 1,
        subject_id: 'agent:operations:01',
        audience: 'gate:production:01',
        objective_digest: D('1'),
        authorization_digest: D('2'),
        presentation_digest: D('3'),
        supersedes_program_digest: null,
        issued_at: '2026-07-29T19:55:00.000Z',
        valid_from: '2026-07-29T20:00:00.000Z',
        expires_at: '2026-07-29T21:00:00.000Z',
        max_total_occurrences: 3,
        max_concurrent_effects: 2,
        budgets: [
            { budget_id: 'attempts', unit: 'attempt', limit: 3 },
        ],
        nodes: [
            {
                node_id: 'inspect',
                action: { mode: 'exact', caid: C('A'), action_digest: D('a') },
                trust_program_digest: D('4'),
                depends_on: [],
                max_occurrences: 1,
                charges: [{ budget_id: 'attempts', amount: 1 }],
            },
        ],
    };
}
function verificationOptions(material) {
    return {
        trusted_keys: material.trusted_keys,
        now: NOW,
        expected_program_id: 'program:production-remediation:01',
        expected_tenant_id: 'tenant:example',
        expected_authorizer_id: 'customer:example-security',
        expected_authorization_digest: D('2'),
        expected_audience: 'gate:production:01',
    };
}
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function');
});
test('a real hybrid program verifies under both pinned keys', async () => {
    const material = keyMaterial();
    const artifact = await signBoundedExecutionProgramV2(program(), material.signer);
    assert.equal(artifact['@version'], BOUNDED_EXECUTION_PROGRAM_V2_VERSION);
    assert.equal(artifact.claim_boundary, EXECUTION_PROGRAM_CLAIM_BOUNDARY);
    const verified = await verifyBoundedExecutionProgramV2(artifact, verificationOptions(material));
    assert.equal(verified.accepted, true, verified.reason ?? '');
    assert.equal(verified.verified, true);
    assert.equal(verified.program_digest, executionProgramDigest(artifact));
});
test('the v1 verifier refuses a v2 program cleanly on the version marker', async () => {
    const material = keyMaterial();
    const artifact = await signBoundedExecutionProgramV2(program(), material.signer);
    const verified = verifyBoundedExecutionProgram(artifact, verificationOptions(material));
    assert.equal(verified.accepted, false);
    assert.notEqual(verified.reason, null);
});
test('the v1 verifier still accepts a v1 program, unchanged', () => {
    const material = keyMaterial();
    const artifact = signBoundedExecutionProgram(program(), material.signer);
    const verified = verifyBoundedExecutionProgram(artifact, verificationOptions(material));
    assert.equal(verified.accepted, true);
});
test('the v2 verifier refuses a v1 program on the version marker', async () => {
    const material = keyMaterial();
    const artifact = signBoundedExecutionProgram(program(), material.signer);
    const verified = await verifyBoundedExecutionProgramV2(artifact, verificationOptions(material));
    assert.equal(verified.accepted, false);
});
test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
    const material = keyMaterial();
    const artifact = await signBoundedExecutionProgramV2(program(), material.signer);
    const stripped = { ...artifact, proof: { ...artifact.proof, signatures: artifact.proof.signatures.filter((s) => s.alg === 'Ed25519') } };
    const verified = await verifyBoundedExecutionProgramV2(stripped, verificationOptions(material));
    assert.equal(verified.accepted, false);
});
test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const material = keyMaterial();
    const artifact = await signBoundedExecutionProgramV2(program(), material.signer);
    const stripped = { ...artifact, proof: { ...artifact.proof, signatures: artifact.proof.signatures.filter((s) => s.alg === 'ML-DSA-65') } };
    const verified = await verifyBoundedExecutionProgramV2(stripped, verificationOptions(material));
    assert.equal(verified.accepted, false);
});
test('SET NARROWING: dropping the PQ leg and narrowing required_algorithms fails', async () => {
    const material = keyMaterial();
    const artifact = await signBoundedExecutionProgramV2(program(), material.signer);
    const narrowed = {
        ...artifact,
        proof: {
            ...artifact.proof,
            required_algorithms: ['Ed25519'],
            signatures: artifact.proof.signatures.filter((s) => s.alg === 'Ed25519'),
        },
    };
    const verified = await verifyBoundedExecutionProgramV2(narrowed, verificationOptions(material));
    assert.equal(verified.accepted, false);
});
test('WRONG-LENGTH SIGNATURE: a truncated Ed25519 signature refuses', async () => {
    const material = keyMaterial();
    const artifact = await signBoundedExecutionProgramV2(program(), material.signer);
    const tampered = {
        ...artifact,
        proof: {
            ...artifact.proof,
            signatures: artifact.proof.signatures.map((s) => (s.alg === 'Ed25519' ? { ...s, sig: s.sig.slice(0, -4) } : s)),
        },
    };
    const verified = await verifyBoundedExecutionProgramV2(tampered, verificationOptions(material));
    assert.equal(verified.accepted, false);
});
test('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half refuses', async () => {
    const material = keyMaterial();
    const artifact = await signBoundedExecutionProgramV2(program(), material.signer);
    const ed448 = generateKeyPairSync('ed448');
    const options = verificationOptions(material);
    const verified = await verifyBoundedExecutionProgramV2(artifact, {
        ...options,
        trusted_keys: {
            'key:customer-program-authorizer': {
                issuer_id: 'customer:example-security',
                public_key: ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
                pq_public_key: material.trusted_keys['key:customer-program-authorizer'].pq_public_key,
            },
        },
    });
    assert.equal(verified.accepted, false);
});
test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const material = keyMaterial();
    const artifact = await signBoundedExecutionProgramV2(program(), material.signer);
    const verified = await verifyBoundedExecutionProgramV2(artifact, {
        ...verificationOptions(material),
        mldsaBackendLoader: async () => null,
    });
    assert.equal(verified.accepted, false);
});
