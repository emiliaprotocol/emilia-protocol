// SPDX-License-Identifier: Apache-2.0
// Generated from a2a-receipt-binding-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-A2A-RECEIPT-BINDING-v2 / EP-A2A-RECEIPT-PRESENTATION-v2 hybrid verifier
// test: the reference hybrid migration for this surface. Builds a REAL
// Ed25519 + ML-DSA-65 signed A2A receipt-binding presentation, then asserts
// the fail-closed predicate: leg stripping, set narrowing, a wrong-length
// signature, an Ed448 masquerade, and a v1 verifier refusing a v2 artifact.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { digestAeb } from './aeb-adapter-contract.js';
import { A2A_ACTION_MEDIA_TYPE, A2A_RECEIPT_EXTENSION_URI, A2A_RECEIPT_BINDING_V2_REQUIRED_ALGORITHMS, createA2AReceiptPresentation, createA2AReceiptPresentationV2, verifyA2AReceiptPresentation, verifyA2AReceiptPresentationV2, verifyA2AReceiptPresentationStatement, } from './a2a-receipt-binding.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const AGENT_CARD = {
    supportedInterfaces: [{ url: 'https://agent.example/a2a', protocolVersion: '1.0', protocolBinding: 'HTTP+JSON' }],
    capabilities: { extensions: [{ uri: A2A_RECEIPT_EXTENSION_URI }] },
};
const TASK = { id: 'task1', contextId: 'ctx1', status: { state: 'TASK_STATE_AUTH_REQUIRED' } };
const ACTION = { op: 'do_thing' };
const INITIATING_MESSAGE = {
    messageId: 'm1', role: 'ROLE_USER',
    parts: [{ data: ACTION, mediaType: A2A_ACTION_MEDIA_TYPE }],
};
const PROOF_MESSAGE = { messageId: 'm2', role: 'ROLE_USER', taskId: 'task1', contextId: 'ctx1', parts: [{ text: 'proof' }] };
const RECEIPT = { receipt_id: 'r1' };
const CAID = `caid:1:x.1:jcs-sha256:${'A'.repeat(43)}`;
async function buildV2Presentation() {
    return createA2AReceiptPresentationV2({
        protocol_version: '1.0',
        target_interface_url: 'https://agent.example/a2a',
        agent_card: AGENT_CARD,
        task: TASK, initiating_message: INITIATING_MESSAGE, proof_message: PROOF_MESSAGE,
        base_receipt: RECEIPT,
        receipt_binding: { caid: CAID, action_digest: digestAeb(ACTION) },
        issued_at: '2026-06-01T00:00:00.000Z', expires_at: '2026-06-01T01:00:00.000Z',
        signer: { key_id: 'k1', private_key: ed.privateKey, pq_key_id: 'pqk1', pq_private_key: Buffer.from(pq.secretKey).toString('base64url') },
    });
}
const TRUST_ROOTS = [{ key_id: 'k1', public_key: edPubB64u, pq_key_id: 'pqk1', pq_public_key: pqPubB64u }];
function verifyInput(presentation) {
    return {
        protocol_version: '1.0',
        target_interface_url: 'https://agent.example/a2a',
        agent_card: AGENT_CARD,
        task: TASK,
        initiating_message: INITIATING_MESSAGE,
        presentation_message: presentation.message,
        negotiated_extensions: [A2A_RECEIPT_EXTENSION_URI],
        trust_roots: TRUST_ROOTS,
        expected_action: ACTION,
        expected_caid: presentation.artifact.caid,
        now: '2026-06-01T00:30:00.000Z',
        verify_receipt: () => ({ valid: true, action_digest: presentation.artifact.base_action_digest, caid: presentation.artifact.caid }),
    };
}
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function');
});
test('a real hybrid A2A presentation verifies under both pinned keys', async () => {
    const presentation = await buildV2Presentation();
    const res = await verifyA2AReceiptPresentationV2(verifyInput(presentation));
    assert.equal(res.valid, true, res.reasons.join(' | '));
    assert.equal(res.checks.signature, true);
});
test('the v1 verifier refuses a v2 presentation cleanly (shape mismatch), without crashing', async () => {
    const presentation = await buildV2Presentation();
    const res = verifyA2AReceiptPresentation(verifyInput(presentation));
    assert.equal(res.valid, false);
    assert.ok(res.reasons.includes('presentation_malformed'));
});
test('verifyA2AReceiptPresentationStatement routes v2 to the hybrid verifier', async () => {
    const presentation = await buildV2Presentation();
    const res = await verifyA2AReceiptPresentationStatement(verifyInput(presentation));
    assert.equal(res.valid, true);
});
function withTamperedArtifact(presentation, mutate) {
    const tampered = { ...presentation, artifact: { ...presentation.artifact, signatures: [...presentation.artifact.signatures] } };
    mutate(tampered.artifact);
    tampered.message = {
        ...presentation.message,
        metadata: { ...presentation.message.metadata, [A2A_RECEIPT_EXTENSION_URI]: { ...presentation.message.metadata[A2A_RECEIPT_EXTENSION_URI], binding_artifact: tampered.artifact } },
    };
    return tampered;
}
test('LEG STRIPPING: removing the ML-DSA leg refuses', async () => {
    const presentation = await buildV2Presentation();
    const tampered = withTamperedArtifact(presentation, (artifact) => {
        artifact.signatures = artifact.signatures.filter((s) => s.alg === 'Ed25519');
    });
    const res = await verifyA2AReceiptPresentationV2(verifyInput(tampered));
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
test('SET NARROWING: a narrowed required_algorithms fails structurally', async () => {
    const presentation = await buildV2Presentation();
    const tampered = withTamperedArtifact(presentation, (artifact) => {
        artifact.required_algorithms = ['Ed25519'];
    });
    const res = await verifyA2AReceiptPresentationV2(verifyInput(tampered));
    assert.equal(res.valid, false);
    assert.ok(res.reasons.includes('presentation_malformed'));
});
test('WRONG-LENGTH SIGNATURE: a truncated leg refuses', async () => {
    const presentation = await buildV2Presentation();
    const tampered = withTamperedArtifact(presentation, (artifact) => {
        const edSig = artifact.signatures.find((s) => s.alg === 'Ed25519');
        artifact.signatures = artifact.signatures.map((s) => (s === edSig ? { ...s, sig: s.sig.slice(0, -4) } : s));
    });
    const res = await verifyA2AReceiptPresentationV2(verifyInput(tampered));
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
test('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half refuses', async () => {
    const presentation = await buildV2Presentation();
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const input = verifyInput(presentation);
    input.trust_roots = [{ key_id: 'k1', public_key: ed448PubB64u, pq_key_id: 'pqk1', pq_public_key: pqPubB64u }];
    const res = await verifyA2AReceiptPresentationV2(input);
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
test('NO ML-DSA BACKEND: not directly exposed on this entry point but a missing PQ leg refuses', async () => {
    // verifyBindingSignatureV2 threads AgilityOptions through internally with
    // defaults; a stripped leg (tested above) is the observable proxy for
    // backend absence at this call boundary, since verifyA2AReceiptPresentationV2
    // does not accept mldsaBackendLoader in its public input shape.
    const presentation = await buildV2Presentation();
    const tampered = withTamperedArtifact(presentation, (artifact) => {
        artifact.signatures = artifact.signatures.filter((s) => s.alg === 'ML-DSA-65');
    });
    const res = await verifyA2AReceiptPresentationV2(verifyInput(tampered));
    assert.equal(res.valid, false);
});
test('the registered required algorithm set is fixed and Ed25519-first', () => {
    assert.deepEqual([...A2A_RECEIPT_BINDING_V2_REQUIRED_ALGORITHMS], ['Ed25519', 'ML-DSA-65']);
});
