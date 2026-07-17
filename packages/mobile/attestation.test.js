// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';

import { createAppleAppAttestVerifier, createPlayIntegrityAttestationVerifier } from './attestation.js';

const NOW = 1784070000000;
const REQUEST_HASH = Buffer.alloc(32, 7).toString('base64url');
const CERTIFICATE_DIGEST = Buffer.alloc(32, 5).toString('base64');
const ANDROID_KEY_ID = `android-keystore:sha256:${Buffer.alloc(32, 9).toString('base64url')}`;
const wrapped = (value) => Buffer.from(value, 'utf8').toString('base64url');

function playPayload(overrides = {}) {
  return {
    requestDetails: {
      requestPackageName: 'gov.example.android.approvals',
      requestHash: REQUEST_HASH,
      timestampMillis: String(NOW - 10_000),
    },
    accountDetails: { appLicensingVerdict: 'LICENSED' },
    appIntegrity: {
      appRecognitionVerdict: 'PLAY_RECOGNIZED',
      packageName: 'gov.example.android.approvals',
      certificateSha256Digest: [CERTIFICATE_DIGEST],
      versionCode: '42',
    },
    deviceIntegrity: {
      deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY', 'MEETS_STRONG_INTEGRITY'],
      deviceAttributes: { sdkVersion: 35 },
    },
    environmentDetails: {
      appAccessRiskVerdict: { appsDetected: ['KNOWN_INSTALLED'] },
      playProtectVerdict: 'NO_ISSUES',
    },
    ...overrides,
  };
}

function playVerifier(payload, options = {}) {
  return createPlayIntegrityAttestationVerifier({
    decodeToken: async (token) => token === 'opaque-play-token' ? payload : null,
    packageName: 'gov.example.android.approvals',
    certificateDigests: [CERTIFICATE_DIGEST],
    allowedVersionCodes: [42],
    minimumSdkVersion: 33,
    requirePlayProtect: true,
    clock: () => NOW,
    ...options,
  });
}

const playRequest = {
  format: 'play-integrity-standard',
  token: wrapped('opaque-play-token'),
  expected_request_hash: REQUEST_HASH,
  expected_app_id: 'gov.example.android.approvals',
  expected_attestation_key_id: ANDROID_KEY_ID,
  platform: 'android',
};

test('Play Integrity adapter pins request, app, certificate, license, freshness, and strong device state', async () => {
  const result = await playVerifier(playPayload())(playRequest);
  assert.equal(result.valid, true);
  assert.equal(result.hardware_backed, true);
  assert.equal(result.request_hash, REQUEST_HASH);
});

test('Play Integrity adapter refuses each relying-party pin failure', async () => {
  const cases = [
    playPayload({ requestDetails: { ...playPayload().requestDetails, requestHash: 'wrong' } }),
    playPayload({ requestDetails: { ...playPayload().requestDetails, timestampMillis: String(NOW - 999_000) } }),
    playPayload({ appIntegrity: { ...playPayload().appIntegrity, packageName: 'gov.attacker.app' } }),
    playPayload({ appIntegrity: { ...playPayload().appIntegrity, certificateSha256Digest: ['wrong-cert'] } }),
    playPayload({ appIntegrity: { ...playPayload().appIntegrity, versionCode: '41' } }),
    playPayload({ accountDetails: { appLicensingVerdict: 'UNLICENSED' } }),
    playPayload({ deviceIntegrity: { deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY'] } }),
    playPayload({
      deviceIntegrity: {
        ...playPayload().deviceIntegrity,
        deviceAttributes: { sdkVersion: 32 },
      },
    }),
    playPayload({
      environmentDetails: {
        ...playPayload().environmentDetails,
        playProtectVerdict: 'POSSIBLE_RISK',
      },
    }),
  ];
  for (const payload of cases) assert.equal((await playVerifier(payload)(playRequest)).valid, false);

  const capturing = playPayload({
    environmentDetails: { appAccessRiskVerdict: { appsDetected: ['UNKNOWN_CAPTURING'] } },
  });
  assert.equal((await playVerifier(capturing, { requireNoCaptureOrControl: true })(playRequest)).valid, false);

  const omittedRiskVerdict = playPayload({ environmentDetails: {} });
  assert.equal(
    (await playVerifier(omittedRiskVerdict, { requireNoCaptureOrControl: true })(playRequest)).valid,
    false,
    'a required capture/control verdict must not pass when Google omitted the evidence',
  );
});

test('Apple App Attest adapter pins request bytes and advances the hardware assertion counter', async () => {
  let counter = 0;
  const verifier = createAppleAppAttestVerifier({
    verifyAssertion: async ({ clientDataHash }) => ({
      valid: true,
      app_id: 'gov.example.ios.approvals',
      key_id: 'attest-key-1',
      environment: 'production',
      client_data_hash: clientDataHash.toString('base64url'),
      counter: 7,
    }),
    appId: 'gov.example.ios.approvals',
    attestationKeyId: 'attest-key-1',
    counterStore: {
      async advance(_key, next) {
        if (next <= counter) return false;
        counter = next;
        return true;
      },
    },
  });
  const request = {
    format: 'apple-app-attest',
    token: Buffer.from([1, 2, 3]).toString('base64url'),
    expected_request_hash: REQUEST_HASH,
    expected_app_id: 'gov.example.ios.approvals',
    expected_attestation_key_id: 'attest-key-1',
    platform: 'ios',
  };
  assert.equal((await verifier(request)).valid, true);
  assert.equal((await verifier(request)).valid, false, 'counter replay must fail closed');
});
