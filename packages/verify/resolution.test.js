// SPDX-License-Identifier: Apache-2.0
// Generated from resolution.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { RESOLUTION_CONTEXT_TYPE, RESOLUTION_VERSION, computeBindingMomentHash, computeResolutionChallenge, computeResolutionResponseHash, verifyResolutionReceipt, } from './resolution.js';
const RP_ID = 'emiliaprotocol.ai';
const PRINCIPAL = 'ep:principal:jchen';
const KEY_ID = 'ep:key:jchen#resolution-1';
const ACTION_HASH = `sha256:${'a'.repeat(64)}`;
const NOW = '2026-07-14T05:30:00.000Z';
const bindingMoment = {
    synopsis: 'Release the staged disbursement after the second review.',
    findings: ['The payee and amount match the approved invoice.'],
    recommendations: ['Release the payment.', 'Hold for another review.'],
    offer: 'Ask for the invoice or account-change history.',
    question: {
        stem: 'Should the staged disbursement be released?',
        options: [
            { label: 'Release', reasoning: 'The verification checks passed.' },
            { label: 'Hold', reasoning: 'A further review can still be requested.' },
        ],
        recommended_idx: 0,
        hatches: { free_text: true, dialogue: true },
    },
};
function signer() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    return {
        privateKey,
        publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    };
}
const PRINCIPAL_KEY = signer();
function makeReceipt(resolution, overrides = {}) {
    const context = {
        ep_version: '1.0',
        context_type: RESOLUTION_CONTEXT_TYPE,
        envelope_hash: computeBindingMomentHash(bindingMoment),
        action_hash: ACTION_HASH,
        principal: PRINCIPAL,
        principal_key_id: KEY_ID,
        initiator: 'spiffe://operator.example/agent/7',
        nonce: 'res_8c0f0e9e7f8a4c9aa3c7',
        issued_at: '2026-07-14T05:25:00.000Z',
        expires_at: '2026-07-14T05:35:00.000Z',
        resolution,
        ...(overrides.context || {}),
    };
    const clientData = Buffer.from(JSON.stringify({
        type: 'webauthn.get',
        challenge: computeResolutionChallenge(context),
        origin: overrides.origin ?? 'https://www.emiliaprotocol.ai',
        ...(overrides.crossOrigin === undefined ? {} : { crossOrigin: overrides.crossOrigin }),
    }), 'utf8');
    const authData = Buffer.concat([
        crypto.createHash('sha256').update(RP_ID, 'utf8').digest(),
        Buffer.from([0x05]),
        Buffer.from([0, 0, 0, 1]),
    ]);
    const signed = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
    const signature = crypto.sign('sha256', signed, PRINCIPAL_KEY.privateKey).toString('base64url');
    return {
        profile: RESOLUTION_VERSION,
        signoff: {
            '@type': 'ep.signoff',
            context,
            webauthn: {
                authenticator_data: authData.toString('base64url'),
                client_data_json: clientData.toString('base64url'),
                signature,
            },
        },
    };
}
const opts = {
    bindingMoment,
    expectedActionHash: ACTION_HASH,
    expectedSelectedOption: 0,
    expectedNonce: 'res_8c0f0e9e7f8a4c9aa3c7',
    expectedInitiator: 'spiffe://operator.example/agent/7',
    evaluationTime: NOW,
    rpId: RP_ID,
    allowedOrigins: ['https://www.emiliaprotocol.ai'],
    principalKeys: { [KEY_ID]: { principal: PRINCIPAL, public_key: PRINCIPAL_KEY.publicKey } },
};
test('all four authentic outcomes verify while only approved authorizes', () => {
    const cases = [
        [{ outcome: 'approved', selected_option: 0 }, true, false],
        [{ outcome: 'declined' }, false, false],
        [{ outcome: 'amended', response_hash: computeResolutionResponseHash('Release only half.') }, false, true],
        [{ outcome: 'rejected', objection_hash: computeResolutionResponseHash('The payee identity is unresolved.') }, false, true],
    ];
    for (const [resolution, authorizes, requiresSuccessor] of cases) {
        const result = verifyResolutionReceipt(makeReceipt(resolution), opts);
        assert.equal(result.valid, true, result.reason);
        assert.equal(result.authorizes_action, authorizes);
        assert.equal(result.requires_successor, requiresSuccessor);
    }
});
test('changing a signed outcome from declined to approved fails', () => {
    const receipt = makeReceipt({ outcome: 'declined' });
    receipt.signoff.context.resolution = { outcome: 'approved', selected_option: 0 };
    const result = verifyResolutionReceipt(receipt, opts);
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'webauthn_verification_failed');
});
test('an approved receipt does not authorize until the relying party pins the option-to-action mapping', () => {
    const receipt = makeReceipt({ outcome: 'approved', selected_option: 0 });
    const withoutMapping = verifyResolutionReceipt(receipt, { ...opts, expectedSelectedOption: undefined });
    assert.equal(withoutMapping.valid, true);
    assert.equal(withoutMapping.authorizes_action, false);
    assert.equal(withoutMapping.checks.selected_option_binding, false);
    const wrongMapping = verifyResolutionReceipt(receipt, { ...opts, expectedSelectedOption: 1 });
    assert.equal(wrongMapping.valid, true);
    assert.equal(wrongMapping.authorizes_action, false);
    for (const missing of ['expectedNonce', 'expectedInitiator', 'evaluationTime']) {
        const result = verifyResolutionReceipt(receipt, { ...opts, [missing]: undefined });
        assert.equal(result.valid, true, `${missing} should not erase authentic evidence`);
        assert.equal(result.authorizes_action, false, `${missing} must be pinned before authority is credited`);
        assert.equal(result.checks.authorization_context, false);
    }
});
test('a presenter-supplied or cross-principal key cannot establish authority', () => {
    const receipt = makeReceipt({ outcome: 'approved', selected_option: 0 });
    const result = verifyResolutionReceipt(receipt, {
        ...opts,
        principalKeys: { [KEY_ID]: { principal: 'ep:principal:mallory', public_key: PRINCIPAL_KEY.publicKey } },
    });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'principal_key_not_pinned_for_role');
    const inheritedPins = Object.create({
        [KEY_ID]: { principal: PRINCIPAL, public_key: PRINCIPAL_KEY.publicKey },
    });
    const inherited = verifyResolutionReceipt(receipt, { ...opts, principalKeys: inheritedPins });
    assert.equal(inherited.valid, false);
    assert.equal(inherited.reason, 'principal_key_not_pinned_for_role');
});
test('envelope and action substitution both fail before signature credit', () => {
    const receipt = makeReceipt({ outcome: 'approved', selected_option: 0 });
    const wrongEnvelope = structuredClone(bindingMoment);
    wrongEnvelope.question.stem = 'Should a different transfer be released?';
    assert.equal(verifyResolutionReceipt(receipt, { ...opts, bindingMoment: wrongEnvelope }).reason, 'envelope_binding_mismatch');
    assert.equal(verifyResolutionReceipt(receipt, { ...opts, expectedActionHash: `sha256:${'b'.repeat(64)}` }).reason, 'action_binding_mismatch');
});
test('outcome grammar refuses semantic smuggling and self-successors', () => {
    const extraOnDecline = makeReceipt({ outcome: 'declined', successor_envelope_hash: `sha256:${'b'.repeat(64)}` });
    assert.equal(verifyResolutionReceipt(extraOnDecline, opts).reason, 'invalid_outcome_shape');
    const amendmentWithoutAnswer = makeReceipt({ outcome: 'amended' });
    assert.equal(verifyResolutionReceipt(amendmentWithoutAnswer, opts).reason, 'invalid_outcome_shape');
    const selfSuccessor = makeReceipt({
        outcome: 'rejected',
        successor_envelope_hash: computeBindingMomentHash(bindingMoment),
    });
    assert.equal(verifyResolutionReceipt(selfSuccessor, opts).reason, 'invalid_outcome_shape');
});
test('malformed envelopes and cross-language-unsafe signed values fail before digest credit', () => {
    const malformed = structuredClone(bindingMoment);
    malformed.question.hatches = { free_text: true };
    const malformedReceipt = makeReceipt({ outcome: 'rejected' }, {
        context: { envelope_hash: `sha256:${'b'.repeat(64)}` },
    });
    assert.equal(verifyResolutionReceipt(malformedReceipt, { ...opts, bindingMoment: malformed }).reason, 'malformed_binding_moment');
    const unsafe = structuredClone(bindingMoment);
    unsafe.question.recommended_idx = 9007199254740992;
    assert.equal(verifyResolutionReceipt(malformedReceipt, { ...opts, bindingMoment: unsafe }).reason, 'resolution_outside_canonicalization_profile');
});
test('missing RP ID or origin pin, stale or impossible ceremony time, malformed input, and unknown keys refuse without throwing', () => {
    const receipt = makeReceipt({ outcome: 'approved', selected_option: 0 });
    assert.equal(verifyResolutionReceipt(receipt, { ...opts, rpId: undefined }).reason, 'rp_id_required');
    assert.equal(verifyResolutionReceipt(receipt, { ...opts, allowedOrigins: undefined }).reason, 'webauthn_origin_not_allowed');
    const wrongOrigin = makeReceipt({ outcome: 'approved', selected_option: 0 }, { origin: 'https://attacker.example' });
    assert.equal(verifyResolutionReceipt(wrongOrigin, opts).reason, 'webauthn_origin_not_allowed');
    const crossed = makeReceipt({ outcome: 'approved', selected_option: 0 }, { crossOrigin: true });
    assert.equal(verifyResolutionReceipt(crossed, opts).reason, 'webauthn_verification_failed');
    assert.equal(verifyResolutionReceipt(receipt, { ...opts, evaluationTime: '2026-07-14T06:00:00.000Z' }).reason, 'resolution_outside_validity_window');
    const impossibleDate = makeReceipt({ outcome: 'approved', selected_option: 0 }, {
        context: { issued_at: '2026-02-30T05:25:00.000Z', expires_at: '2026-03-03T05:35:00.000Z' },
    });
    assert.equal(verifyResolutionReceipt(impossibleDate, { ...opts, evaluationTime: '2026-03-01T05:30:00.000Z' }).reason, 'resolution_outside_validity_window');
    assert.equal(verifyResolutionReceipt(receipt, { ...opts, principalKeys: {} }).reason, 'principal_key_not_pinned_for_role');
    assert.doesNotThrow(() => verifyResolutionReceipt(null, opts));
    assert.equal(verifyResolutionReceipt(null, opts).valid, false);
});
