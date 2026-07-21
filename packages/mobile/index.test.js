// SPDX-License-Identifier: Apache-2.0
// Generated from index.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { MOBILE_CEREMONY_VERSION, MOBILE_PRESENTATION_VERSION, buildMobileAttestationBinding, createMobileAck, createMobileChallenge, createMobileCeremonyService, createMobileExecutionRecord, createMobileRelianceProfile, hashCanonical, mobileProfileHash, toClassASignoff, verifyMobileAck, verifyMobileCeremony, verifyMobileExecutionRecord, } from './index.js';
import { createDurableChallengeStore } from '../gate/challenge-store.js';
import { createMemoryBackend } from '../gate/store.js';
import { createAtomicEvidenceLog, createMemoryAtomicEvidenceBackend } from '../gate/evidence.js';
const RP_ID = 'approve.example.gov';
const ORIGIN = 'https://approve.example.gov';
const NOW = '2026-07-14T19:02:00.000Z';
function p256() {
    const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    return {
        ...pair,
        spki: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    };
}
function fixture({ platform = 'ios', appId = platform === 'ios' ? 'gov.example.ios.approvals' : 'gov.example.android.approvals', decision = 'approved', counter = 9, flags = 0x05, origin = ORIGIN, clientDataFactory = null, key = p256(), deviceKey = p256(), registrationSignCount = 0, challengeId = `mob_${crypto.randomBytes(8).toString('hex')}`, nonce = `sig_${crypto.randomBytes(16).toString('hex')}`, actionReference = `mobile-action-${crypto.randomBytes(8).toString('hex')}`, approverIndex = 1, requiredApprovals = 1, } = {}) {
    const credentialId = crypto.randomBytes(32).toString('base64url');
    const deviceKeyId = `ep:key:mobile-${platform}-${crypto.randomBytes(4).toString('hex')}`;
    const attestationKeyId = platform === 'android'
        ? `android-keystore:sha256:${crypto.createHash('sha256').update(Buffer.from(deviceKey.spki, 'base64url')).digest('base64url')}`
        : 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eH/8=';
    const profile = createMobileRelianceProfile({
        profileId: 'gov.high-assurance.mobile.v1',
        rpId: RP_ID,
        allowedOrigins: [ORIGIN],
        acceptedApps: {
            ios: ['gov.example.ios.approvals'],
            android: ['gov.example.android.approvals'],
        },
        enrollments: [{
                device_key_id: deviceKeyId,
                credential_id: credentialId,
                public_key_spki: key.spki,
                approver_id: 'ep:approver:case-supervisor',
                platform,
                app_id: appId,
                attestation_key_id: attestationKeyId,
                status: 'active',
                valid_from: '2026-01-01T00:00:00.000Z',
                valid_to: '2027-01-01T00:00:00.000Z',
                sign_count: registrationSignCount,
            }],
    });
    const challenge = createMobileChallenge({
        actionReference,
        action: {
            action_type: 'benefit.payment_destination_change',
            case_id: 'case-9482',
            destination_last4: '4401',
            effective_date: '2026-07-15',
        },
        policy: { id: 'gov-benefits-high-risk-v1', human_approval: true },
        policyId: 'gov-benefits-high-risk-v1',
        initiatorId: 'ep:agent:benefits-assistant',
        approverId: 'ep:approver:case-supervisor',
        approverIndex,
        requiredApprovals,
        decision,
        presentation: {
            '@version': MOBILE_PRESENTATION_VERSION,
            title: 'Payment destination change',
            summary: 'Change benefit payment destination for case 9482',
            risk: 'high',
            consequence: 'Future benefit payments will be sent to the new destination.',
            material_fields: {
                action_type: 'benefit.payment_destination_change',
                case_id: 'case-9482',
                destination_last4: '4401',
                effective_date: '2026-07-15',
            },
        },
        platform,
        appId,
        deviceKeyId,
        profile,
        issuedAt: '2026-07-14T19:00:00.000Z',
        expiresAt: '2026-07-14T19:05:00.000Z',
        challengeId,
        nonce,
    });
    const clientData = Buffer.from(clientDataFactory?.(challenge) ?? JSON.stringify({
        type: 'webauthn.get',
        challenge: challenge.webauthn.challenge,
        origin,
        crossOrigin: false,
    }), 'utf8');
    const counterBytes = Buffer.alloc(4);
    counterBytes.writeUInt32BE(counter);
    const authenticatorData = Buffer.concat([
        crypto.createHash('sha256').update(RP_ID, 'utf8').digest(),
        Buffer.from([flags]),
        counterBytes,
    ]);
    const signed = Buffer.concat([
        authenticatorData,
        crypto.createHash('sha256').update(clientData).digest(),
    ]);
    const signature = crypto.sign('sha256', signed, key.privateKey);
    const response = {
        '@version': MOBILE_CEREMONY_VERSION,
        challenge_id: challenge.challenge_id,
        nonce: challenge.nonce,
        platform,
        app_id: appId,
        device_key_id: deviceKeyId,
        credential_id: credentialId,
        attestation_key_id: attestationKeyId,
        decision,
        display_hash: challenge.authorization_context.display_hash,
        signoff: {
            context: structuredClone(challenge.authorization_context),
            webauthn: {
                authenticator_data: authenticatorData.toString('base64url'),
                client_data_json: clientData.toString('base64url'),
                signature: signature.toString('base64url'),
            },
        },
        attestation: {
            format: challenge.attestation.format,
            token: Buffer.from(`verified-${platform}-attestation`).toString('base64url'),
            ...(platform === 'android' ? {
                device_key_signature: crypto.sign('sha256', Buffer.from(challenge.attestation.request_hash, 'base64url'), deviceKey.privateKey).toString('base64url'),
            } : {}),
        },
    };
    const attestationVerifier = async (request) => ({
        valid: true,
        request_hash: request.expected_request_hash,
        app_id: request.expected_app_id,
        attestation_key_id: request.expected_attestation_key_id,
        platform: request.platform,
        hardware_backed: true,
        strong_integrity: true,
        device_key_verified: request.platform === 'android',
    });
    return { profile, challenge, response, attestationVerifier, key, deviceKey, deviceKeyId };
}
function rebindAttestation(challenge) {
    const binding = buildMobileAttestationBinding(challenge);
    challenge.attestation.binding = binding;
    challenge.attestation.request_hash = Buffer
        .from(hashCanonical(binding).slice('sha256:'.length), 'hex')
        .toString('base64url');
}
test('verifies iOS and Android ceremonies as the same Class-A evidence shape', async () => {
    for (const platform of ['ios', 'android']) {
        const item = fixture({ platform });
        const result = await verifyMobileCeremony({ ...item, now: NOW });
        assert.equal(result.valid, true);
        assert.equal(result.verdict, 'verified');
        assert.equal(result.decision, 'approved');
        assert.deepEqual(result.decision_evidence, result.class_a);
        assert.notEqual(result.decision_evidence, result.class_a);
        assert.equal(result.class_a.signoff.key_class, 'A');
        assert.equal(result.class_a.context.mobile_binding.platform, platform);
        assert.deepEqual(Object.values(result.checks), Array(Object.keys(result.checks).length).fill(true));
    }
});
test('binds a mobile handshake to its true multi-approver index and threshold', async () => {
    const item = fixture({ approverIndex: 3, requiredApprovals: 2 });
    const result = await verifyMobileCeremony({ ...item, now: NOW });
    assert.equal(result.valid, true);
    assert.equal(result.class_a.context.approver_index, 3);
    assert.equal(result.class_a.context.required_approvals, 2);
});
test('signed denial is a terminal evidence outcome, not relabeled approval', async () => {
    const item = fixture({ decision: 'denied' });
    const result = await verifyMobileCeremony({ ...item, now: NOW });
    assert.equal(result.valid, true);
    assert.equal(result.decision, 'denied');
    assert.deepEqual(result.decision_evidence.context, item.challenge.authorization_context);
    assert.deepEqual(result.decision_evidence.signoff.webauthn, item.response.signoff.webauthn);
    assert.equal(result.decision_evidence.signoff.key_class, 'A');
    assert.equal(Object.hasOwn(result, 'class_a'), false);
    assert.throws(() => toClassASignoff(item.response), /approved decision/);
    item.response.decision = 'approved';
    const relabeled = await verifyMobileCeremony({ ...item, now: NOW });
    assert.equal(relabeled.valid, false);
    assert.equal(relabeled.verdict, 'refuse_action_mismatch');
});
test('refuses action, presentation, origin, app, credential, profile, and UV substitution', async () => {
    const cases = [
        ['action', (item) => { item.challenge.action.destination_last4 = '9999'; }, 'refuse_action_mismatch'],
        ['display', (item) => { item.challenge.presentation.material_fields.destination_last4 = '9999'; }, 'refuse_display_mismatch'],
        ['origin', null, 'refuse_origin', { origin: 'https://attacker.example' }],
        ['duplicate-origin', null, 'refuse_origin', {
                clientDataFactory: (challenge) => `{"type":"webauthn.get","challenge":"${challenge.webauthn.challenge}","origin":"https://attacker.example","origin":"${ORIGIN}","crossOrigin":false}`,
            }],
        ['app', (item) => { item.response.app_id = 'gov.attacker.app'; }, 'refuse_app'],
        ['device-key-id', (item) => { item.response.device_key_id = 'ep:key:mobile-attacker'; }, 'refuse_device_key'],
        ['credential-signature', (item) => {
                const attacker = p256();
                const authenticatorData = Buffer.from(item.response.signoff.webauthn.authenticator_data, 'base64url');
                const clientData = Buffer.from(item.response.signoff.webauthn.client_data_json, 'base64url');
                const signed = Buffer.concat([authenticatorData, crypto.createHash('sha256').update(clientData).digest()]);
                item.response.signoff.webauthn.signature = crypto.sign('sha256', signed, attacker.privateKey).toString('base64url');
            }, 'refuse_webauthn'],
        ['profile', (item) => {
                item.profile.enrollments[0].public_key_spki = p256().spki;
                item.profile.profile_hash = mobileProfileHash(item.profile);
            }, 'refuse_profile_mismatch'],
        ['uv', null, 'refuse_webauthn', { flags: 0x01 }],
    ];
    for (const [name, mutate, verdict, options] of cases) {
        const item = fixture(options);
        mutate?.(item);
        const result = await verifyMobileCeremony({ ...item, now: NOW });
        assert.equal(result.valid, false, name);
        assert.equal(result.verdict, verdict, name);
    }
});
test('refuses freshness laundering through a fresh outer challenge around an expired signed context', async () => {
    const item = fixture();
    item.challenge.issued_at = '2026-07-14T20:00:00.000Z';
    item.challenge.expires_at = '2026-07-14T20:05:00.000Z';
    item.challenge.webauthn.timeout_ms = 300_000;
    rebindAttestation(item.challenge);
    const result = await verifyMobileCeremony({
        ...item,
        now: '2026-07-14T20:02:00.000Z',
    });
    assert.equal(result.valid, false);
    assert.equal(result.verdict, 'refuse_challenge_expired');
});
test('refuses outer nonce and WebAuthn request metadata that diverge from the signed context', async () => {
    const nonceSwap = fixture();
    nonceSwap.challenge.nonce = 'sig_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    nonceSwap.response.nonce = nonceSwap.challenge.nonce;
    rebindAttestation(nonceSwap.challenge);
    const nonceResult = await verifyMobileCeremony({ ...nonceSwap, now: NOW });
    assert.equal(nonceResult.valid, false);
    assert.equal(nonceResult.verdict, 'refuse_action_mismatch');
    const requestSwap = fixture();
    requestSwap.challenge.webauthn.rp_id = 'attacker.example';
    requestSwap.challenge.webauthn.challenge = Buffer.alloc(32, 9).toString('base64url');
    requestSwap.challenge.webauthn.credential_ids = [Buffer.alloc(32, 8).toString('base64url')];
    requestSwap.challenge.webauthn.user_verification = 'preferred';
    rebindAttestation(requestSwap.challenge);
    const requestResult = await verifyMobileCeremony({ ...requestSwap, now: NOW });
    assert.equal(requestResult.valid, false);
    assert.equal(requestResult.verdict, 'refuse_webauthn');
});
test('refuses a signed mobile binding for a different reliance profile', async () => {
    const item = fixture();
    item.profile.profile_id = 'gov.high-assurance.mobile.v2';
    item.profile.profile_hash = mobileProfileHash(item.profile);
    item.challenge.profile_hash = item.profile.profile_hash;
    rebindAttestation(item.challenge);
    const result = await verifyMobileCeremony({ ...item, now: NOW });
    assert.equal(result.valid, false);
    assert.equal(result.verdict, 'refuse_profile_mismatch');
});
test('attestation is independently verified and client status labels carry no weight', async () => {
    const missing = fixture();
    missing.response.attestation.token = '';
    assert.equal((await verifyMobileCeremony({ ...missing, now: NOW })).verdict, 'refuse_attestation_missing');
    const selfAsserted = fixture();
    selfAsserted.response.attestation.client_claimed_strong_integrity = true;
    assert.equal((await verifyMobileCeremony({ ...selfAsserted, now: NOW })).verdict, 'refuse_malformed');
    const invalid = fixture();
    const result = await verifyMobileCeremony({
        ...invalid,
        now: NOW,
        attestationVerifier: async (request) => ({
            valid: true,
            request_hash: request.expected_request_hash,
            app_id: request.expected_app_id,
            attestation_key_id: request.expected_attestation_key_id,
            platform: request.platform,
            hardware_backed: true,
            strong_integrity: false,
        }),
    });
    assert.equal(result.valid, false);
    assert.equal(result.verdict, 'refuse_attestation');
    const formatSwap = fixture();
    formatSwap.response.attestation.format = 'play-integrity-standard';
    assert.equal((await verifyMobileCeremony({ ...formatSwap, now: NOW })).verdict, 'refuse_attestation');
});
test('refuses Android ceremony substitution without verified enrolled device-key proof', async () => {
    const item = fixture({ platform: 'android' });
    const secondDevice = p256();
    item.response.attestation.device_key_signature = crypto.sign('sha256', Buffer.from(item.challenge.attestation.request_hash, 'base64url'), secondDevice.privateKey).toString('base64url');
    const result = await verifyMobileCeremony({
        ...item,
        now: NOW,
        attestationVerifier: async () => ({ valid: false }),
    });
    assert.equal(result.valid, false);
    assert.equal(result.verdict, 'refuse_attestation');
});
test('roundtrips standard Base64 App Attest key IDs in the signed challenge context', async () => {
    const item = fixture({ platform: 'ios' });
    assert.match(item.challenge.authorization_context.mobile_binding.attestation_key_id, /[+/=]/);
    assert.equal(item.response.attestation_key_id, item.profile.enrollments[0].attestation_key_id);
    assert.equal((await verifyMobileCeremony({ ...item, now: NOW })).valid, true);
});
test('challenge creation and verification refuse incomplete, changed, extra, or nested material fields', async () => {
    const item = fixture();
    const args = {
        actionReference: item.challenge.authorization_context.action_reference,
        action: item.challenge.action,
        policy: { id: 'gov-benefits-high-risk-v1', human_approval: true },
        policyId: 'gov-benefits-high-risk-v1',
        initiatorId: 'ep:agent:benefits-assistant',
        approverId: 'ep:approver:case-supervisor',
        decision: 'approved',
        platform: 'ios',
        appId: 'gov.example.ios.approvals',
        deviceKeyId: item.deviceKeyId,
        profile: item.profile,
        issuedAt: '2026-07-14T19:00:00.000Z',
        expiresAt: '2026-07-14T19:05:00.000Z',
    };
    assert.throws(() => createMobileChallenge({
        ...args,
        presentation: { ...item.challenge.presentation, hidden_detail: 'not rendered' },
    }), /presentation/);
    const { destination_last4: _omitted, ...omittedFields } = item.challenge.presentation.material_fields;
    assert.throws(() => createMobileChallenge({
        ...args,
        presentation: {
            ...item.challenge.presentation,
            material_fields: omittedFields,
        },
    }), /exactly cover/);
    assert.throws(() => createMobileChallenge({
        ...args,
        presentation: {
            ...item.challenge.presentation,
            material_fields: { ...item.challenge.presentation.material_fields, destination_last4: '9999' },
        },
    }), /exactly cover/);
    assert.throws(() => createMobileChallenge({
        ...args,
        action: { ...item.challenge.action, service_fee_minor: 4500 },
        presentation: item.challenge.presentation,
    }), /exactly cover/);
    assert.throws(() => createMobileChallenge({
        ...args,
        action: { ...item.challenge.action, window: { not_before: '2026-07-16T20:00:00.000Z' } },
        presentation: {
            ...item.challenge.presentation,
            material_fields: { ...item.challenge.presentation.material_fields, window: '2026-07-16T20:00:00.000Z' },
        },
    }), /flat objects/);
    item.challenge.action.service_fee_minor = 4500;
    item.challenge.action_hash = hashCanonical(item.challenge.action);
    item.challenge.authorization_context.action_hash = item.challenge.action_hash;
    rebindAttestation(item.challenge);
    const result = await verifyMobileCeremony({ ...item, now: NOW });
    assert.equal(result.valid, false);
    assert.equal(result.verdict, 'refuse_action_mismatch');
});
test('hostile malformed input never throws', async () => {
    for (const value of [null, 7, [], {}, { '@version': MOBILE_CEREMONY_VERSION }]) {
        const result = await verifyMobileCeremony({ challenge: value, response: value, profile: value, now: NOW });
        assert.equal(result.valid, false);
        assert.equal(result.verdict, 'refuse_malformed');
    }
});
function durableChallengeStore() {
    const backend = createMemoryBackend();
    backend.durable = true;
    return createDurableChallengeStore(backend);
}
function durableAuditLog() {
    const backend = createMemoryAtomicEvidenceBackend();
    backend.durable = true;
    let next = 0;
    return createAtomicEvidenceLog(backend, {
        streamId: 'mobile-tests',
        recordIdFactory: () => `mobile-test-record-${String(++next).padStart(6, '0')}`,
    });
}
function monotonicCounterStore(initial = []) {
    const counters = new Map(initial);
    return {
        async advance(key, value) {
            const previous = counters.get(key) || 0;
            if (value <= previous)
                return false;
            counters.set(key, value);
            return true;
        },
    };
}
test('service registers exact bodies and only one concurrent presentation wins', async () => {
    const item = fixture();
    const service = createMobileCeremonyService({
        challengeStore: durableChallengeStore(),
        auditLog: durableAuditLog(),
        attestationVerifier: item.attestationVerifier,
        counterStore: monotonicCounterStore(),
        clock: () => NOW,
    });
    assert.equal(await service.issue({
        actionReference: item.challenge.authorization_context.action_reference,
        action: item.challenge.action,
        policy: { id: 'gov-benefits-high-risk-v1', human_approval: true },
        policyId: 'gov-benefits-high-risk-v1',
        initiatorId: 'ep:agent:benefits-assistant',
        approverId: 'ep:approver:case-supervisor',
        decision: 'approved',
        presentation: item.challenge.presentation,
        platform: 'ios',
        appId: 'gov.example.ios.approvals',
        deviceKeyId: item.deviceKeyId,
        profile: item.profile,
        issuedAt: '2026-07-14T19:00:00.000Z',
        expiresAt: '2026-07-14T19:05:00.000Z',
        challengeId: item.challenge.challenge_id,
        nonce: item.challenge.nonce,
    }).then((result) => result.ok), true);
    const results = await Promise.all([
        service.verifyAndConsume({ challenge: item.challenge, response: item.response, profile: item.profile }),
        service.verifyAndConsume({ challenge: item.challenge, response: item.response, profile: item.profile }),
    ]);
    assert.equal(results.filter((result) => result.valid).length, 1);
    assert.equal(results.filter((result) => result.verdict === 'refuse_replay').length, 1);
});
test('service fails closed on store, audit, and counter failures', async () => {
    const item = fixture();
    const stores = {
        challengeStore: {
            durable: true,
            async register() { return true; },
            async consume() { throw new Error('database unavailable'); },
        },
        auditLog: durableAuditLog(),
    };
    const unavailable = createMobileCeremonyService({
        ...stores,
        attestationVerifier: item.attestationVerifier,
        counterStore: monotonicCounterStore(),
        clock: () => NOW,
    });
    assert.equal((await unavailable.verifyAndConsume(item)).verdict, 'refuse_store_unavailable');
    const auditFailure = createMobileCeremonyService({
        challengeStore: { durable: true, async register() { return true; }, async consume() { return true; } },
        auditLog: { durable: true, strict: true, async record() { throw new Error('log unavailable'); } },
        attestationVerifier: item.attestationVerifier,
        counterStore: monotonicCounterStore(),
        clock: () => NOW,
    });
    assert.equal((await auditFailure.verifyAndConsume(item)).verdict, 'refuse_audit_unavailable');
    const counterRollback = createMobileCeremonyService({
        challengeStore: { durable: true, async register() { return true; }, async consume() { return true; } },
        auditLog: durableAuditLog(),
        attestationVerifier: item.attestationVerifier,
        counterStore: { async advance() { return false; } },
        clock: () => NOW,
    });
    assert.equal((await counterRollback.verifyAndConsume(item)).verdict, 'refuse_counter_rollback');
});
test('registration sign_count is the durable baseline and the first assertion must advance it', async () => {
    for (const counter of [7, 6]) {
        const item = fixture({ counter, registrationSignCount: 7 });
        const service = createMobileCeremonyService({
            challengeStore: { durable: true, async register() { return true; }, async consume() { return true; } },
            auditLog: durableAuditLog(),
            attestationVerifier: item.attestationVerifier,
            counterStore: monotonicCounterStore(),
            clock: () => NOW,
        });
        assert.equal((await service.verifyAndConsume(item)).verdict, 'refuse_counter_rollback');
    }
    const advanced = fixture({ counter: 8, registrationSignCount: 7 });
    const service = createMobileCeremonyService({
        challengeStore: { durable: true, async register() { return true; }, async consume() { return true; } },
        auditLog: durableAuditLog(),
        attestationVerifier: advanced.attestationVerifier,
        counterStore: monotonicCounterStore(),
        clock: () => NOW,
    });
    assert.equal((await service.verifyAndConsume(advanced)).valid, true);
});
test('service commits the protected action exactly once before reporting verified', async () => {
    const item = fixture({ counter: 1 });
    let committed = 0;
    const committedEvidence = durableAuditLog();
    const service = createMobileCeremonyService({
        challengeStore: { durable: true, async register() { return true; }, async consume() { return true; } },
        auditLog: durableAuditLog(),
        attestationVerifier: item.attestationVerifier,
        counterStore: monotonicCounterStore(),
        commitDecision: async ({ challenge, result, auditEntry }) => {
            assert.equal(challenge.challenge_id, item.challenge.challenge_id);
            assert.equal(result.decision, 'approved');
            assert.equal(auditEntry.event_type, 'mobile.ceremony.decision');
            committed += 1;
            return {
                committed: true,
                audit_record: await committedEvidence.record(auditEntry),
            };
        },
        clock: () => NOW,
    });
    const accepted = await service.verifyAndConsume(item);
    assert.equal(accepted.valid, true);
    assert.equal(committed, 1);
    assert.equal(accepted.audit_record.event_type, 'mobile.ceremony.decision');
    const splitWrite = createMobileCeremonyService({
        challengeStore: { durable: true, async register() { return true; }, async consume() { return true; } },
        auditLog: durableAuditLog(),
        attestationVerifier: item.attestationVerifier,
        counterStore: monotonicCounterStore(),
        async commitDecision() { return true; },
        clock: () => NOW,
    });
    assert.equal((await splitWrite.verifyAndConsume(item)).verdict, 'refuse_audit_unavailable');
    const conflict = createMobileCeremonyService({
        challengeStore: { durable: true, async register() { return true; }, async consume() { return true; } },
        auditLog: durableAuditLog(),
        attestationVerifier: item.attestationVerifier,
        counterStore: monotonicCounterStore(),
        async commitDecision() { return false; },
        clock: () => NOW,
    });
    assert.equal((await conflict.verifyAndConsume(item)).verdict, 'refuse_replay');
    const unavailable = createMobileCeremonyService({
        challengeStore: { durable: true, async register() { return true; }, async consume() { return true; } },
        auditLog: durableAuditLog(),
        attestationVerifier: item.attestationVerifier,
        counterStore: monotonicCounterStore(),
        async commitDecision() { throw new Error('database unavailable'); },
        clock: () => NOW,
    });
    assert.equal((await unavailable.verifyAndConsume(item)).verdict, 'refuse_store_unavailable');
});
test('signed acknowledgement is independently verifiable and tamper evident', async () => {
    const item = fixture({ counter: 0 });
    const result = await verifyMobileCeremony({ ...item, now: NOW });
    const signer = crypto.generateKeyPairSync('ed25519');
    const ack = createMobileAck({
        result,
        receiptId: 'ep:receipt:government-demo-1',
        recordedAt: NOW,
        signerPrivateKey: signer.privateKey,
        signerKeyId: 'ep:key:mobile-service-1',
    });
    const publicKey = signer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    assert.equal(verifyMobileAck(ack, publicKey), true);
    ack.decision = 'denied';
    assert.equal(verifyMobileAck(ack, publicKey), false);
});
test('execution record requires a consumed, audited result and binds the runtime record', async () => {
    const item = fixture({ counter: 1 });
    const service = createMobileCeremonyService({
        challengeStore: durableChallengeStore(),
        auditLog: durableAuditLog(),
        attestationVerifier: item.attestationVerifier,
        counterStore: monotonicCounterStore(),
        clock: () => NOW,
    });
    assert.equal((await service.issue({
        actionReference: item.challenge.authorization_context.action_reference,
        action: item.challenge.action,
        policy: { id: 'gov-benefits-high-risk-v1', human_approval: true },
        policyId: 'gov-benefits-high-risk-v1',
        initiatorId: 'ep:agent:benefits-assistant',
        approverId: 'ep:approver:case-supervisor',
        decision: 'approved',
        presentation: item.challenge.presentation,
        platform: 'ios',
        appId: 'gov.example.ios.approvals',
        deviceKeyId: item.deviceKeyId,
        profile: item.profile,
        issuedAt: '2026-07-14T19:00:00.000Z',
        expiresAt: '2026-07-14T19:05:00.000Z',
        challengeId: item.challenge.challenge_id,
        nonce: item.challenge.nonce,
    })).ok, true);
    const result = await service.verifyAndConsume({
        challenge: item.challenge,
        response: item.response,
        profile: item.profile,
    });
    const signer = crypto.generateKeyPairSync('ed25519');
    const publicKey = signer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const record = createMobileExecutionRecord({
        challenge: item.challenge,
        result,
        receiptId: 'ep:receipt:government-demo-execution-1',
        recordedAt: NOW,
        signerPrivateKey: signer.privateKey,
        signerKeyId: 'ep:key:mobile-service-execution-1',
    });
    assert.equal(record.statement_type, 'operator_runtime_attestation');
    assert.equal(record.audit_record_hash, `sha256:${result.audit_record.hash}`);
    assert.equal(verifyMobileExecutionRecord(record, publicKey), true);
    const unsignedSignatureClaim = structuredClone(record);
    unsignedSignatureClaim.signature.untrusted_status = 'verified';
    assert.equal(verifyMobileExecutionRecord(unsignedSignatureClaim, publicKey), false);
    const tampered = structuredClone(record);
    tampered.operator_assertions.challenge_consumption = 'not_consumed';
    assert.equal(verifyMobileExecutionRecord(tampered, publicKey), false);
    const pureResult = await verifyMobileCeremony({ ...item, now: NOW });
    assert.throws(() => createMobileExecutionRecord({
        challenge: item.challenge,
        result: pureResult,
        receiptId: 'ep:receipt:pure-verification-is-not-consumption',
        recordedAt: NOW,
        signerPrivateKey: signer.privateKey,
        signerKeyId: 'ep:key:mobile-service-execution-1',
    }), /durably consumed and audited/);
});
