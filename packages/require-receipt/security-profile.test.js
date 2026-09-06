// SPDX-License-Identifier: Apache-2.0
// Generated from security-profile.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Real-crypto regressions for signed human decisions and EP-RECEIPT-v1
// algorithm parity. A trusted outer issuer cannot rewrite human consent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { canonicalizeStrictJson, evaluateReceiptAssurance, makeReceiptGate, receiptAssuranceTier, verifyEmiliaReceipt, } from './index.js';
import { verifyReceipt } from '../verify/index.js';
const ACTION = 'payment.release';
const APPROVER = 'approver@example.test';
const KEY_ID = 'credential-a';
const SCOPE = {
    rpId: 'www.emiliaprotocol.ai',
    allowedOrigins: ['https://www.emiliaprotocol.ai'],
};
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest();
const spki = (key) => key.export({ type: 'spki', format: 'der' }).toString('base64url');
function mint(payloadExtra = {}, issuer = crypto.generateKeyPairSync('ed25519')) {
    const payload = {
        receipt_id: `rcpt_${crypto.randomUUID()}`,
        subject: 'agent:example',
        created_at: new Date().toISOString(),
        claim: { action_type: ACTION, outcome: 'allow_with_signoff', approver: APPROVER },
        ...payloadExtra,
    };
    const bytes = Buffer.from(canonicalizeStrictJson(payload));
    const value = crypto.sign(null, bytes, issuer.privateKey).toString('base64url');
    return {
        doc: { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value } },
        pub: spki(issuer.publicKey),
    };
}
function embeddedDecision(decision) {
    const approver = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const context = {
        nonce: 'signoff-1',
        approver: APPROVER,
        action_hash: `sha256:${'a'.repeat(64)}`,
        ...(decision === undefined ? {} : { decision }),
    };
    const clientData = Buffer.from(JSON.stringify({
        type: 'webauthn.get',
        challenge: sha256(canonicalizeStrictJson(context)).toString('base64url'),
        origin: SCOPE.allowedOrigins[0],
    }));
    const authData = Buffer.concat([sha256(SCOPE.rpId), Buffer.from([0x05, 0, 0, 0, 0])]);
    const signedBytes = Buffer.concat([authData, sha256(clientData)]);
    const signature = crypto.sign('sha256', signedBytes, approver.privateKey);
    assert.equal(crypto.verify('sha256', signedBytes, approver.publicKey, signature), true, 'negative decisions must carry a genuine valid human signature');
    const { doc, pub } = mint({
        claim: {
            action_type: ACTION,
            outcome: 'allow_with_signoff',
            approver: APPROVER,
            source_receipt_action_hash: context.action_hash,
        },
        approver_key_id: KEY_ID,
        signoff: {
            context,
            webauthn: {
                authenticator_data: authData.toString('base64url'),
                client_data_json: clientData.toString('base64url'),
                signature: signature.toString('base64url'),
            },
        },
    });
    const options = {
        ...SCOPE,
        approverKeys: {
            [KEY_ID]: { approver_id: APPROVER, key_class: 'A', public_key: spki(approver.publicKey) },
        },
    };
    return { doc, pub, options };
}
test('embedded Class-A approved decision admits one provider call and refuses replay', async () => {
    const { doc, pub, options } = embeddedDecision('approved');
    const assurance = evaluateReceiptAssurance(doc, 'class_a', options);
    assert.equal(assurance.ok, true, assurance.reason);
    assert.equal(receiptAssuranceTier(doc, options), 'class_a');
    const gate = makeReceiptGate({ action: ACTION, trustedKeys: [pub], assuranceClass: 'class_a', ...options });
    let effects = 0;
    const result = await gate.run(doc, {}, () => { effects += 1; });
    assert.equal(result.ok, true, result.body?.rejected?.reason);
    const replay = await gate.run(doc, {}, () => { effects += 1; });
    assert.equal(replay.ok, false);
    assert.equal(replay.body.rejected.reason, 'replay_refused');
    assert.equal(effects, 1);
});
test('a genuinely signed embedded denial cannot admit a provider call', async () => {
    const { doc, pub, options } = embeddedDecision('denied');
    assert.equal(verifyEmiliaReceipt(doc, { trustedKeys: [pub] }).ok, true);
    let effects = 0;
    const gate = makeReceiptGate({ action: ACTION, trustedKeys: [pub], assuranceClass: 'class_a', ...options });
    const result = await gate.run(doc, {}, () => { effects += 1; });
    assert.equal(result.ok, false);
    assert.equal(result.body.rejected.reason, 'assurance_decision_not_approved');
    assert.equal(effects, 0);
});
for (const decision of ['declined', 'amended', 'rejected', undefined, null, true, 'allow', 'APPROVED', 'unknown']) {
    test(`embedded Class-A refuses signed non-approval decision ${String(decision)}`, async () => {
        const { doc, pub, options } = embeddedDecision(decision);
        assert.equal(verifyEmiliaReceipt(doc, { trustedKeys: [pub] }).ok, true, 'the trusted outer issuer signature is valid; it does not establish human approval');
        let effects = 0;
        const gate = makeReceiptGate({ action: ACTION, trustedKeys: [pub], assuranceClass: 'class_a', ...options });
        const result = await gate.run(doc, {}, () => { effects += 1; });
        assert.equal(effects, 0, 'a signed non-approval must never invoke the provider');
        assert.equal(result.ok, false);
        assert.equal(result.body.rejected.reason, 'assurance_decision_not_approved');
        const assurance = evaluateReceiptAssurance(doc, 'class_a', options);
        assert.equal(assurance.ok, false);
        assert.equal(receiptAssuranceTier(doc, options), 'software');
    });
}
test('changing a signed denied decision to approved does not create valid Class-A proof', () => {
    const { doc, options } = embeddedDecision('denied');
    doc.payload.signoff.context.decision = 'approved';
    const result = evaluateReceiptAssurance(doc, 'class_a', options);
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'assurance_proof_invalid');
});
for (const algorithm of ['Ed25519', 'ed25519', 'ED25519']) {
    test(`core and demand verifiers accept the same Ed25519 spelling: ${algorithm}`, () => {
        const { doc, pub } = mint();
        doc.signature.algorithm = algorithm;
        assert.equal(verifyReceipt(doc, pub).valid, true);
        assert.equal(verifyEmiliaReceipt(doc, { trustedKeys: [pub] }).ok, true);
    });
}
for (const algorithm of ['none', 'null', null, undefined, '', 'ML-DSA-65', 'ES256', 'EdDSA', 42, {}, [], ' Ed25519']) {
    test(`core and demand verifiers refuse algorithm label ${JSON.stringify(algorithm)}`, async () => {
        const { doc, pub } = mint();
        if (algorithm === undefined)
            delete doc.signature.algorithm;
        else
            doc.signature.algorithm = algorithm;
        assert.equal(verifyReceipt(doc, pub).valid, false);
        assert.equal(verifyEmiliaReceipt(doc, { trustedKeys: [pub] }).ok, false);
        let effects = 0;
        const gate = makeReceiptGate({ action: ACTION, trustedKeys: [pub] });
        const result = await gate.run(doc, {}, () => { effects += 1; });
        assert.equal(result.ok, false);
        assert.equal(effects, 0);
    });
}
for (const keyType of ['ec', 'rsa']) {
    test(`core and demand verifiers refuse a valid ${keyType} signature labelled Ed25519`, async () => {
        const issuer = keyType === 'ec'
            ? crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
            : crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const { doc, pub } = mint({}, issuer);
        const validUnderActualKey = crypto.verify(null, Buffer.from(canonicalizeStrictJson(doc.payload)), issuer.publicKey, Buffer.from(doc.signature.value, 'base64url'));
        assert.equal(validUnderActualKey, true, 'the signature must be genuine under the wrong key type');
        assert.equal(verifyReceipt(doc, pub).valid, false);
        assert.equal(verifyEmiliaReceipt(doc, { trustedKeys: [pub] }).ok, false);
        let effects = 0;
        const gate = makeReceiptGate({ action: ACTION, trustedKeys: [pub] });
        const result = await gate.run(doc, {}, () => { effects += 1; });
        assert.equal(result.ok, false);
        assert.equal(effects, 0);
    });
}
test('a non-Ed25519 candidate does not prevent acceptance under a later pinned Ed25519 key', () => {
    const { doc, pub } = mint();
    const wrongKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const result = verifyEmiliaReceipt(doc, { trustedKeys: [spki(wrongKey.publicKey), pub] });
    assert.equal(result.ok, true, result.reason);
});
