// SPDX-License-Identifier: Apache-2.0
// Generated from enrollment.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { canonicalize } from '../verify/index.js';
import { buildMobileAndroidKeyBinding, createMobileEnrollmentService, MOBILE_ENROLLMENT_VERSION, } from './enrollment.js';
import { createDurableChallengeStore } from '../gate/challenge-store.js';
import { createMemoryBackend } from '../gate/store.js';
const ISSUED = '2026-07-14T19:00:00.000Z';
const VERIFYING = '2026-07-14T19:02:00.000Z';
const CALLER = Object.freeze({ subject: 'agency-user-42' });
function p256() {
    const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    return {
        ...pair,
        spki: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    };
}
function challengeStore() {
    const backend = createMemoryBackend();
    backend.durable = true;
    return createDurableChallengeStore(backend);
}
function service(overrides = {}) {
    let now = ISSUED;
    const passkey = p256();
    const directory = {
        durable: true,
        rows: [],
        async enrollAtomically(record) { this.rows.push(record); return true; },
    };
    const value = createMobileEnrollmentService({
        challengeStore: challengeStore(),
        directory,
        clock: () => now,
        verifyPasskeyRegistration: async () => ({
            valid: true,
            algorithm: 'ES256',
            credential_id: crypto.randomBytes(32).toString('base64url'),
            public_key_spki: passkey.spki,
            sign_count: 7,
            attestation_format: 'packed',
        }),
        verifyPlatformEnrollment: async (request) => ({
            valid: true,
            request_hash: request.expected_request_hash,
            app_id: request.expected_app_id,
            attestation_key_id: request.expected_attestation_key_id,
            platform: request.platform,
            hardware_backed: true,
            strong_integrity: true,
            platform_public_key: request.platform === 'ios'
                ? passkey.publicKey.export({ type: 'spki', format: 'pem' })
                : null,
        }),
        authorizeEnrollment: async (input) => input.caller?.subject === CALLER.subject
            && input.approver_id === 'ep:approver:case-supervisor',
        ...overrides,
    });
    return { value, directory, verifying() { now = VERIFYING; } };
}
async function issued(item) {
    const result = await item.value.issue({
        approverId: 'ep:approver:case-supervisor',
        platform: 'ios',
        appId: 'gov.example.approvals',
        rpId: 'approve.example.gov',
        origin: 'https://approve.example.gov',
        userName: 'case-supervisor@example.gov',
        displayName: 'Case Supervisor',
        caller: CALLER,
    });
    assert.equal(result.ok, true);
    item.verifying();
    return result.challenge;
}
function response(challenge) {
    return {
        '@version': MOBILE_ENROLLMENT_VERSION,
        enrollment_id: challenge.enrollment_id,
        approver_id: challenge.approver_id,
        platform: challenge.platform,
        app_id: challenge.app_id,
        platform_request_hash: challenge.platform_request_hash,
        attestation_key_id: 'appattest_enrolled_key_1',
        requested_valid_to: challenge.enrollment_valid_to,
        passkey_registration: { id: 'browser-produced-public-key-credential' },
        platform_attestation: {
            format: 'apple-app-attest-enrollment',
            token: 'opaque-token',
            request_hash: challenge.platform_request_hash,
        },
    };
}
function androidResponse(challenge, deviceKey = p256()) {
    const keyId = `android-keystore:sha256:${crypto.createHash('sha256')
        .update(Buffer.from(deviceKey.spki, 'base64url')).digest('base64url')}`;
    const binding = buildMobileAndroidKeyBinding({
        challengeRequestHash: challenge.platform_request_hash,
        keyId,
        publicKeySpki: deviceKey.spki,
    });
    const requestHash = crypto.createHash('sha256').update(canonicalize(binding), 'utf8').digest('base64url');
    return {
        '@version': MOBILE_ENROLLMENT_VERSION,
        enrollment_id: challenge.enrollment_id,
        approver_id: challenge.approver_id,
        platform: challenge.platform,
        app_id: challenge.app_id,
        platform_request_hash: challenge.platform_request_hash,
        attestation_key_id: keyId,
        requested_valid_to: challenge.enrollment_valid_to,
        passkey_registration: { id: 'android-public-key-credential' },
        platform_attestation: {
            format: 'play-integrity-standard',
            token: 'opaque-token',
            request_hash: requestHash,
            device_key: {
                algorithm: 'ES256',
                key_id: keyId,
                public_key_spki: deviceKey.spki,
                signature: crypto.sign('sha256', Buffer.from(canonicalize(binding), 'utf8'), deviceKey.privateKey)
                    .toString('base64url'),
            },
        },
    };
}
test('enrolls only after both independently verified registration rows and atomic storage', async () => {
    const item = service();
    const challenge = await issued(item);
    const result = await item.value.complete({ caller: CALLER, challenge, response: response(challenge) });
    assert.equal(result.ok, true);
    assert.equal(result.verdict, 'enrolled');
    assert.equal(result.enrollment.platform, 'ios');
    assert.equal(item.directory.rows.length, 1);
    assert.equal(item.directory.rows[0].event.device_key_id, result.enrollment.device_key_id);
    assert.match(result.enrollment.platform_public_key, /BEGIN PUBLIC KEY/);
    assert.equal(result.enrollment.sign_count, 7);
});
test('refuses enrollment binding, WebAuthn, platform, replay, and storage failures', async () => {
    const binding = service();
    const bindingChallenge = await issued(binding);
    const changed = response(bindingChallenge);
    changed.platform_request_hash = 'attacker';
    assert.equal((await binding.value.complete({ challenge: bindingChallenge, response: changed })).verdict, 'refuse_malformed');
    const webauthn = service({ verifyPasskeyRegistration: async () => ({ valid: false }) });
    const webauthnChallenge = await issued(webauthn);
    assert.equal((await webauthn.value.complete({ caller: CALLER, challenge: webauthnChallenge, response: response(webauthnChallenge) })).verdict, 'refuse_webauthn');
    const mislabeledKey = crypto.generateKeyPairSync('ed25519').publicKey
        .export({ type: 'spki', format: 'der' }).toString('base64url');
    const wrongCurve = service({
        verifyPasskeyRegistration: async () => ({
            valid: true,
            algorithm: 'ES256',
            credential_id: crypto.randomBytes(32).toString('base64url'),
            public_key_spki: mislabeledKey,
            sign_count: 0,
        }),
    });
    const wrongCurveChallenge = await issued(wrongCurve);
    assert.equal((await wrongCurve.value.complete({
        caller: CALLER,
        challenge: wrongCurveChallenge,
        response: response(wrongCurveChallenge),
    })).verdict, 'refuse_webauthn');
    const platform = service({ verifyPlatformEnrollment: async () => ({ valid: false }) });
    const platformChallenge = await issued(platform);
    assert.equal((await platform.value.complete({ caller: CALLER, challenge: platformChallenge, response: response(platformChallenge) })).verdict, 'refuse_attestation');
    const missingAppleKey = service({
        verifyPlatformEnrollment: async (request) => ({
            valid: true,
            request_hash: request.expected_request_hash,
            app_id: request.expected_app_id,
            attestation_key_id: request.expected_attestation_key_id,
            platform: 'ios',
            hardware_backed: true,
            strong_integrity: true,
        }),
    });
    const missingAppleKeyChallenge = await issued(missingAppleKey);
    assert.equal((await missingAppleKey.value.complete({
        caller: CALLER,
        challenge: missingAppleKeyChallenge,
        response: response(missingAppleKeyChallenge),
    })).verdict, 'refuse_attestation');
    const replay = service();
    const replayChallenge = await issued(replay);
    assert.equal((await replay.value.complete({ caller: CALLER, challenge: replayChallenge, response: response(replayChallenge) })).ok, true);
    assert.equal((await replay.value.complete({ caller: CALLER, challenge: replayChallenge, response: response(replayChallenge) })).verdict, 'refuse_replay');
    const unavailable = service({ directory: { durable: true, async enrollAtomically() { throw new Error('down'); } } });
    const unavailableChallenge = await issued(unavailable);
    assert.equal((await unavailable.value.complete({ caller: CALLER, challenge: unavailableChallenge, response: response(unavailableChallenge) })).verdict, 'refuse_store_unavailable');
});
test('two concurrent enrollment completions produce at most one active enrollment', async () => {
    const item = service();
    const challenge = await issued(item);
    const results = await Promise.all([
        item.value.complete({ caller: CALLER, challenge, response: response(challenge) }),
        item.value.complete({ caller: CALLER, challenge, response: response(challenge) }),
    ]);
    assert.equal(results.filter((result) => result.ok).length, 1);
    assert.equal(results.filter((result) => result.verdict === 'refuse_replay').length, 1);
});
test('refuses enrollment when the agency caller is absent or not bound to the approver', async () => {
    const item = service();
    const deniedIssue = await item.value.issue({
        approverId: 'ep:approver:case-supervisor',
        platform: 'ios',
        appId: 'gov.example.approvals',
        rpId: 'approve.example.gov',
        origin: 'https://approve.example.gov',
        userName: 'case-supervisor@example.gov',
        displayName: 'Case Supervisor',
        caller: { subject: 'different-user' },
    });
    assert.equal(deniedIssue.verdict, 'refuse_unauthorized');
    const challenge = await issued(item);
    const deniedCompletion = await item.value.complete({
        caller: { subject: 'different-user' },
        challenge,
        response: response(challenge),
    });
    assert.equal(deniedCompletion.verdict, 'refuse_unauthorized');
    assert.equal(item.directory.rows.length, 0);
});
test('accepts native Android origins and standard Apple App Attest key identifiers', async () => {
    const android = service();
    const androidIssue = await android.value.issue({
        approverId: 'ep:approver:case-supervisor',
        platform: 'android',
        appId: 'ai.emiliaprotocol.approver',
        rpId: 'www.emiliaprotocol.ai',
        origin: `android:apk-key-hash:${'a'.repeat(43)}`,
        userName: 'case-supervisor@example.gov',
        displayName: 'Case Supervisor',
        caller: CALLER,
    });
    assert.equal(androidIssue.ok, true);
    android.verifying();
    const androidKey = p256();
    const androidCompleted = await android.value.complete({
        caller: CALLER,
        challenge: androidIssue.challenge,
        response: androidResponse(androidIssue.challenge, androidKey),
    });
    assert.equal(androidCompleted.ok, true);
    assert.equal(androidCompleted.enrollment.platform_public_key, androidKey.spki);
    assert.match(androidCompleted.enrollment.attestation_key_id, /^android-keystore:sha256:/);
    assert.equal((await android.value.issue({
        approverId: 'ep:approver:case-supervisor',
        platform: 'android',
        appId: 'ai.emiliaprotocol.approver',
        rpId: 'www.emiliaprotocol.ai',
        origin: 'android:apk-key-hash:not-a-sha256-value',
        userName: 'case-supervisor@example.gov',
        displayName: 'Case Supervisor',
        caller: CALLER,
    })).verdict, 'refuse_malformed');
    const apple = service();
    const appleChallenge = await issued(apple);
    const appleResponse = response(appleChallenge);
    appleResponse.attestation_key_id = `${'A'.repeat(40)}+/=`;
    const completed = await apple.value.complete({ caller: CALLER, challenge: appleChallenge, response: appleResponse });
    assert.equal(completed.ok, true);
    assert.equal(completed.enrollment.attestation_key_id, appleResponse.attestation_key_id);
});
test('refuses a synced-passkey enrollment substituted onto a second Android device', async () => {
    const item = service();
    const issuedResult = await item.value.issue({
        approverId: 'ep:approver:case-supervisor',
        platform: 'android',
        appId: 'ai.emiliaprotocol.approver',
        rpId: 'www.emiliaprotocol.ai',
        origin: `android:apk-key-hash:${'a'.repeat(43)}`,
        userName: 'case-supervisor@example.gov',
        displayName: 'Case Supervisor',
        caller: CALLER,
    });
    item.verifying();
    const enrolledDevice = p256();
    const secondDevice = p256();
    const substituted = androidResponse(issuedResult.challenge, enrolledDevice);
    const binding = buildMobileAndroidKeyBinding({
        challengeRequestHash: issuedResult.challenge.platform_request_hash,
        keyId: substituted.attestation_key_id,
        publicKeySpki: enrolledDevice.spki,
    });
    substituted.platform_attestation.device_key.signature = crypto.sign('sha256', Buffer.from(canonicalize(binding), 'utf8'), secondDevice.privateKey).toString('base64url');
    const result = await item.value.complete({
        caller: CALLER,
        challenge: issuedResult.challenge,
        response: substituted,
    });
    assert.equal(result.ok, false);
    assert.equal(result.verdict, 'refuse_attestation');
    assert.equal(item.directory.rows.length, 0);
});
