// SPDX-License-Identifier: Apache-2.0
// Generated from document-action-binding-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-DOCUMENT-ACTION-BINDING-v2 hybrid verifier test: the reference hybrid
// migration for this surface. Builds a REAL Ed25519 + ML-DSA-65 signed DAB
// mapping, then asserts the fail-closed predicate. The hostile half is the
// point: leg stripping, algorithm-set narrowing, a wrong-length signature, an
// Ed448 key masquerading as the Ed25519 half, and a v1 verifier refusing a
// v2 mapping.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DOCUMENT_ACTION_BINDING_V2_REQUIRED_ALGORITHMS, signDocumentActionBinding, signDocumentActionBindingV2, verifyDocumentActionBinding, verifyDocumentActionBindingV2, verifyDocumentActionBindingStatement, } from './document-action-binding.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const FINAL_DOCUMENT = Buffer.from('%PDF-1.7\n% DAB v2 test document\n%%EOF\n', 'utf8');
const SPEC = {
    binding_id: 'bind_v2_1',
    agreement_id: 'agr_v2_1',
    document: { bytes: FINAL_DOCUMENT, media_type: 'application/pdf' },
    material_terms: [{ term_id: 'price', type: 'amount', value: '100.00', currency: 'USD' }],
    release_action_template: { action_type: 'wire.release', amount: '100.00' },
    parties: [{ party_id: 'p1', role: 'payer' }, { party_id: 'p2', role: 'payee' }],
    required_parties: [{ party_id: 'p1', role: 'payer' }],
    validity: { not_before: '2026-01-01T00:00:00Z', not_after: '2027-01-01T00:00:00Z' },
};
const SIGNER = {
    issuer_id: 'iss1', key_id: 'k1', privateKey: ed.privateKey,
    pq_key_id: 'pqk1', pqPrivateKey: Buffer.from(pq.secretKey).toString('base64url'),
};
const VERIFY_OPTS = {
    now: '2026-06-01T00:00:00Z',
    allowedMediaTypes: ['application/pdf'],
    allowedPartyRoles: ['payer', 'payee'],
    allowedActionTypes: ['wire.release'],
    issuerKeys: { k1: { issuer_id: 'iss1', public_key: edPubB64u, pq_public_key: pqPubB64u } },
};
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function');
});
test('a real hybrid DAB mapping verifies under both pinned keys', async () => {
    const binding = await signDocumentActionBindingV2(SPEC, SIGNER);
    const res = await verifyDocumentActionBindingV2(binding, VERIFY_OPTS);
    assert.equal(res.valid, true, res.reason);
    assert.equal(res.binding_id, 'bind_v2_1');
});
test('the v1 verifier refuses a v2 mapping cleanly, without crashing', async () => {
    const binding = await signDocumentActionBindingV2(SPEC, SIGNER);
    const res = verifyDocumentActionBinding(binding, VERIFY_OPTS);
    assert.equal(res.valid, false);
    assert.equal(typeof res.reason, 'string');
});
test('the v2 verifier refuses a v1 mapping', async () => {
    const edV1 = crypto.generateKeyPairSync('ed25519');
    const edV1PubB64u = edV1.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const v1binding = signDocumentActionBinding(SPEC, { issuer_id: 'iss1', key_id: 'k1', privateKey: edV1.privateKey });
    const res = await verifyDocumentActionBindingV2(v1binding, {
        ...VERIFY_OPTS,
        issuerKeys: { k1: { issuer_id: 'iss1', public_key: edV1PubB64u, pq_public_key: pqPubB64u } },
    });
    assert.equal(res.valid, false);
});
test('verifyDocumentActionBindingStatement routes each profile to its own verifier', async () => {
    const v2 = await signDocumentActionBindingV2(SPEC, SIGNER);
    assert.equal((await verifyDocumentActionBindingStatement(v2, VERIFY_OPTS)).valid, true);
    const edV1 = crypto.generateKeyPairSync('ed25519');
    const edV1PubB64u = edV1.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const v1 = signDocumentActionBinding(SPEC, { issuer_id: 'iss1', key_id: 'k1', privateKey: edV1.privateKey });
    const res = await verifyDocumentActionBindingStatement(v1, {
        ...VERIFY_OPTS,
        issuerKeys: { k1: { issuer_id: 'iss1', public_key: edV1PubB64u } },
    });
    assert.equal(res.valid, true);
});
test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
    const binding = await signDocumentActionBindingV2(SPEC, SIGNER);
    binding.issuer_signatures = binding.issuer_signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyDocumentActionBindingV2(binding, VERIFY_OPTS);
    assert.equal(res.valid, false);
    // Only one signature remains, so the length gate refuses before the
    // per-algorithm presence check ever runs -- still a clean structural
    // refusal, and still never a pass on the surviving Ed25519 leg alone.
    assert.equal(res.reason, 'issuer_signature_missing');
});
test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const binding = await signDocumentActionBindingV2(SPEC, SIGNER);
    binding.issuer_signatures = binding.issuer_signatures.filter((s) => s.alg === 'ML-DSA-65');
    const res = await verifyDocumentActionBindingV2(binding, VERIFY_OPTS);
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'issuer_signature_missing');
});
test('LEG STRIPPING: replacing one leg with a duplicate of the other still refuses (per-algorithm check)', async () => {
    const binding = await signDocumentActionBindingV2(SPEC, SIGNER);
    const edSig = binding.issuer_signatures.find((s) => s.alg === 'Ed25519');
    binding.issuer_signatures = [edSig, { ...edSig, key_id: 'other' }];
    const res = await verifyDocumentActionBindingV2(binding, VERIFY_OPTS);
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'duplicate_issuer_signature_algorithm');
});
test('SET NARROWING: a narrowed required_algorithms fails structurally before any signature check', async () => {
    const binding = await signDocumentActionBindingV2(SPEC, SIGNER);
    binding.required_algorithms = ['Ed25519'];
    const res = await verifyDocumentActionBindingV2(binding, VERIFY_OPTS);
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'invalid_required_algorithms');
});
test('WRONG-LENGTH SIGNATURE: a truncated Ed25519 leg refuses', async () => {
    const binding = await signDocumentActionBindingV2(SPEC, SIGNER);
    const edSig = binding.issuer_signatures.find((s) => s.alg === 'Ed25519');
    edSig.sig = edSig.sig.slice(0, -4);
    const res = await verifyDocumentActionBindingV2(binding, VERIFY_OPTS);
    assert.equal(res.valid, false);
    assert.ok(res.reason?.startsWith('issuer_signature_invalid'));
});
test('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half refuses', async () => {
    const binding = await signDocumentActionBindingV2(SPEC, SIGNER);
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const res = await verifyDocumentActionBindingV2(binding, {
        ...VERIFY_OPTS,
        issuerKeys: { k1: { issuer_id: 'iss1', public_key: ed448PubB64u, pq_public_key: pqPubB64u } },
    });
    assert.equal(res.valid, false);
    assert.ok(res.reason?.startsWith('issuer_signature_invalid'));
});
test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const binding = await signDocumentActionBindingV2(SPEC, SIGNER);
    const res = await verifyDocumentActionBindingV2(binding, {
        ...VERIFY_OPTS,
        mldsaBackendLoader: async () => null,
    });
    assert.equal(res.valid, false);
});
test('the registered required algorithm set is fixed and Ed25519-first', () => {
    assert.deepEqual([...DOCUMENT_ACTION_BINDING_V2_REQUIRED_ALGORITHMS], ['Ed25519', 'ML-DSA-65']);
});
