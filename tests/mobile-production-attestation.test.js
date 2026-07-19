// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import cbor from 'cbor';
import { Encoder } from 'cbor-x';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  verifyRegistrationResponse: vi.fn(),
  verifyAttestation: vi.fn(),
  verifyAssertion: vi.fn(),
}));

vi.mock('@simplewebauthn/server', () => ({
  verifyRegistrationResponse: (...args) => mocks.verifyRegistrationResponse(...args),
}));
vi.mock('node-app-attest', () => ({
  verifyAttestation: (...args) => mocks.verifyAttestation(...args),
  verifyAssertion: (...args) => mocks.verifyAssertion(...args),
}));

const {
  createGooglePlayIntegrityDecoder,
  createPlatformEnrollmentVerifier,
  createProductionAttestationVerifier,
  decodeAppleAuthenticatorExtensions,
  inspectAppleAppAssertion,
  inspectAppleAppAttestation,
  verifyAppleRuntimeSignals,
  verifyMobilePasskeyRegistration,
} = await import('@/lib/mobile/attestation.js');

const PLAY_CERTIFICATE = Buffer.alloc(32, 5).toString('base64url');

function appleAuthenticatorData({ category = 4, bundleVersion = '1', includeSignals = true } = {}) {
  const header = Buffer.alloc(37);
  header[32] = includeSignals ? 0x80 : 0x00;
  if (!includeSignals) return header;
  return Buffer.concat([header, cbor.encode({
    apple_validation_category_01: category,
    apple_bundle_version_01: bundleVersion,
  })]);
}

function coseP256() {
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  return new Encoder({ mapsAsObjects: false }).encode(new Map([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, Buffer.from(jwk.x, 'base64url')],
    [-3, Buffer.from(jwk.y, 'base64url')],
  ]));
}

function playPayload(requestHash, certificate = PLAY_CERTIFICATE) {
  return {
    requestDetails: {
      requestPackageName: 'ai.emiliaprotocol.approver',
      requestHash,
      timestampMillis: Date.now(),
    },
    appIntegrity: {
      appRecognitionVerdict: 'PLAY_RECOGNIZED',
      packageName: 'ai.emiliaprotocol.approver',
      certificateSha256Digest: [certificate],
      versionCode: '1',
    },
    accountDetails: { appLicensingVerdict: 'LICENSED' },
    deviceIntegrity: {
      deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY', 'MEETS_STRONG_INTEGRITY'],
      deviceAttributes: { sdkVersion: 35 },
    },
    environmentDetails: {
      appAccessRiskVerdict: { appsDetected: [] },
      playProtectVerdict: 'NO_ISSUES',
    },
  };
}

describe('mobile production attestation adapters', () => {
  beforeEach(() => vi.clearAllMocks());

  it('turns a verified P-256 passkey registration into the pinned SPKI record', async () => {
    mocks.verifyRegistrationResponse.mockResolvedValue({
      verified: true,
      registrationInfo: {
        credential: { id: 'credential-id', publicKey: coseP256(), counter: 0 },
        fmt: 'packed',
      },
    });
    const result = await verifyMobilePasskeyRegistration({
      response: { id: 'credential-id' },
      expectedChallenge: 'challenge',
      expectedOrigin: 'https://www.emiliaprotocol.ai',
      expectedRPID: 'www.emiliaprotocol.ai',
    });
    expect(result.valid).toBe(true);
    expect(result.algorithm).toBe('ES256');
    expect(crypto.createPublicKey({
      key: Buffer.from(result.public_key_spki, 'base64url'),
      format: 'der',
      type: 'spki',
    }).asymmetricKeyType).toBe('ec');
    expect(mocks.verifyRegistrationResponse).toHaveBeenCalledWith(expect.objectContaining({
      requireUserVerification: true,
      supportedAlgorithmIDs: [-7],
    }));
  });

  it('uses a short-lived service-account token only for Google server-side decode', async () => {
    const key = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
      .export({ format: 'pem', type: 'pkcs8' });
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ access_token: 'google-access', expires_in: 300 }) })
      .mockResolvedValue({ ok: true, json: async () => ({ tokenPayloadExternal: { verified: true } }) });
    const decode = createGooglePlayIntegrityDecoder({
      serviceAccount: JSON.stringify({ client_email: 'mobile@example.iam.gserviceaccount.com', private_key: key }),
      packageName: 'ai.emiliaprotocol.approver',
      fetchImpl,
      clock: () => 1_784_000_000,
    });
    expect(await decode('opaque-one')).toEqual({ verified: true });
    expect(await decode('opaque-two')).toEqual({ verified: true });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(fetchImpl.mock.calls[1][0]).toContain('ai.emiliaprotocol.approver:decodeIntegrityToken');
    expect(fetchImpl.mock.calls[1][1].headers.authorization).toBe('Bearer google-access');
  });

  it('pins every Android Play verdict during enrollment', async () => {
    const config = {
      androidCertificateDigests: [PLAY_CERTIFICATE],
      androidPackageName: 'ai.emiliaprotocol.approver',
      iosBundleId: 'ai.emiliaprotocol.approver',
      appleTeamId: '5M2Z48UQQY',
      appleEnvironment: 'production',
      appleAllowedValidationCategories: [2, 4],
      appleAllowedBundleVersions: ['1'],
      appleRequireRuntimeSignals: false,
      androidAllowedVersionCodes: [1],
      androidMinimumSdkVersion: 33,
      androidRequirePlayProtect: true,
    };
    const requestHash = 'a'.repeat(43);
    const androidKeyId = `android-keystore:sha256:${'b'.repeat(43)}`;
    const verify = createPlatformEnrollmentVerifier({
      config,
      playDecoder: async () => playPayload(requestHash),
    });
    const accepted = await verify({
      platform: 'android',
      format: 'play-integrity-standard',
      token: Buffer.from('opaque').toString('base64url'),
      expected_request_hash: requestHash,
      expected_app_id: config.androidPackageName,
      expected_attestation_key_id: androidKeyId,
    });
    expect(accepted.valid).toBe(true);
    expect(accepted.strong_integrity).toBe(true);

    const refused = await createPlatformEnrollmentVerifier({
      config,
      playDecoder: async () => playPayload(requestHash, 'attacker-cert'),
    })({
      platform: 'android',
      format: 'play-integrity-standard',
      token: Buffer.from('opaque').toString('base64url'),
      expected_request_hash: requestHash,
      expected_app_id: config.androidPackageName,
      expected_attestation_key_id: androidKeyId,
    });
    expect(refused.valid).toBe(false);
  });

  it('binds Apple enrollment to the exact canonical challenge and stores its public key', async () => {
    mocks.verifyAttestation.mockReturnValue({
      environment: 'production',
      publicKey: '-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----',
    });
    const config = {
      androidCertificateDigests: [],
      androidPackageName: 'ai.emiliaprotocol.approver',
      iosBundleId: 'ai.emiliaprotocol.approver',
      appleTeamId: '5M2Z48UQQY',
      appleEnvironment: 'production',
      appleAllowedValidationCategories: [2, 4],
      appleAllowedBundleVersions: ['1'],
      appleRequireRuntimeSignals: false,
      androidAllowedVersionCodes: [1],
      androidMinimumSdkVersion: 33,
      androidRequirePlayProtect: true,
    };
    const verify = createPlatformEnrollmentVerifier({
      config,
      playDecoder: async () => ({}),
      inspectAppleAttestation: () => ({ authenticatorData: appleAuthenticatorData() }),
    });
    const expectedBinding = { '@version': 'EP-MOBILE-ENROLLMENT-CHALLENGE-v1', challenge: 'abc' };
    const result = await verify({
      platform: 'ios',
      format: 'apple-app-attest-enrollment',
      token: Buffer.from('opaque-attestation').toString('base64url'),
      expected_request_hash: 'a'.repeat(43),
      expected_binding: expectedBinding,
      expected_app_id: config.iosBundleId,
      expected_attestation_key_id: 'apple+/=',
    });
    expect(result.valid).toBe(true);
    expect(result.platform_public_key).toContain('BEGIN PUBLIC KEY');
    expect(mocks.verifyAttestation).toHaveBeenCalledWith(expect.objectContaining({
      keyId: 'apple+/=',
      bundleIdentifier: config.iosBundleId,
      teamIdentifier: config.appleTeamId,
      allowDevelopmentEnvironment: false,
    }));
    expect(mocks.verifyAttestation.mock.calls[0][0].challenge.toString('utf8')).toBe(
      '{"@version":"EP-MOBILE-ENROLLMENT-CHALLENGE-v1","challenge":"abc"}',
    );
  });

  it('loads the enrolled App Attest key, verifies the assertion, and advances its counter', async () => {
    mocks.verifyAssertion.mockReturnValue({ signCount: 7 });
    const directory = {
      platformKey: vi.fn(async () => ({
        platform_public_key: '-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----',
        app_id: 'ai.emiliaprotocol.approver',
        status: 'active',
        valid_from: '2026-01-01T00:00:00.000Z',
        valid_to: '2027-01-01T00:00:00.000Z',
      })),
    };
    const counterStore = { advance: vi.fn(async () => true) };
    const config = {
      androidCertificateDigests: [],
      androidPackageName: 'ai.emiliaprotocol.approver',
      iosBundleId: 'ai.emiliaprotocol.approver',
      appleTeamId: '5M2Z48UQQY',
      appleEnvironment: 'production',
      appleAllowedValidationCategories: [2, 4],
      appleAllowedBundleVersions: ['1'],
      appleRequireRuntimeSignals: false,
      androidAllowedVersionCodes: [1],
      androidMinimumSdkVersion: 33,
      androidRequirePlayProtect: true,
    };
    const verifier = createProductionAttestationVerifier({
      config,
      directory,
      counterStore,
      playDecoder: async () => ({}),
      inspectAppleAssertion: () => ({ authenticatorData: appleAuthenticatorData() }),
    });
    const result = await verifier({
      platform: 'ios',
      format: 'apple-app-attest',
      token: Buffer.from('opaque-assertion').toString('base64url'),
      expected_request_hash: Buffer.alloc(32, 1).toString('base64url'),
      expected_binding: { challenge_id: 'challenge-1' },
      expected_app_id: config.iosBundleId,
      expected_attestation_key_id: 'apple-key',
    });
    expect(result.valid).toBe(true);
    expect(result.assertion_counter).toBe(7);
    expect(counterStore.advance).toHaveBeenCalledWith('apple-key', 7);
    expect(mocks.verifyAssertion).toHaveBeenCalledWith(expect.objectContaining({
      bundleIdentifier: config.iosBundleId,
      teamIdentifier: config.appleTeamId,
      signCount: 0,
    }));
  });

  it('requires the enrolled Android Keystore key signature on every Play-backed ceremony', async () => {
    const enrolledKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const secondDevice = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const publicKeySpki = enrolledKey.publicKey.export({ type: 'spki', format: 'der' });
    const keyId = `android-keystore:sha256:${crypto.createHash('sha256').update(publicKeySpki).digest('base64url')}`;
    const requestHash = Buffer.alloc(32, 3);
    const config = {
      androidCertificateDigests: [PLAY_CERTIFICATE],
      androidPackageName: 'ai.emiliaprotocol.approver',
      iosBundleId: 'ai.emiliaprotocol.approver',
      appleTeamId: '5M2Z48UQQY',
      appleEnvironment: 'production',
      appleAllowedValidationCategories: [2, 4],
      appleAllowedBundleVersions: ['1'],
      appleRequireRuntimeSignals: false,
      androidAllowedVersionCodes: [1],
      androidMinimumSdkVersion: 33,
      androidRequirePlayProtect: true,
    };
    const enrollment = {
      platform_public_key: publicKeySpki.toString('base64url'),
      app_id: config.androidPackageName,
      status: 'active',
      valid_from: '2026-01-01T00:00:00.000Z',
      valid_to: '2099-01-01T00:00:00.000Z',
    };
    const directory = { platformKey: vi.fn(async () => enrollment) };
    const verifier = createProductionAttestationVerifier({
      config,
      directory,
      counterStore: { advance: vi.fn(async () => true) },
      playDecoder: async () => playPayload(requestHash.toString('base64url')),
    });
    const input = {
      platform: 'android',
      format: 'play-integrity-standard',
      token: Buffer.from('opaque-play-token').toString('base64url'),
      expected_request_hash: requestHash.toString('base64url'),
      expected_app_id: config.androidPackageName,
      expected_attestation_key_id: keyId,
      device_key_signature: crypto.sign('sha256', requestHash, enrolledKey.privateKey).toString('base64url'),
    };
    await expect(verifier(input)).resolves.toMatchObject({ valid: true, device_key_verified: true });
    expect(directory.platformKey).toHaveBeenCalledWith(keyId, 'android');

    const substituted = {
      ...input,
      device_key_signature: crypto.sign('sha256', requestHash, secondDevice.privateKey).toString('base64url'),
    };
    await expect(verifier(substituted)).resolves.toEqual({ valid: false });
    await expect(verifier({ ...input, device_key_signature: undefined })).resolves.toEqual({ valid: false });
  });

  it('enforces Apple certificate validity and signed runtime distribution signals', () => {
    const authData = appleAuthenticatorData();
    const encoded = cbor.encode({
      fmt: 'apple-appattest',
      authData,
      attStmt: { x5c: [Buffer.from('leaf'), Buffer.from('intermediate')] },
    });
    const certificates = [
      {
        validFrom: 'Jul 01 00:00:00 2026 GMT',
        validTo: 'Aug 01 00:00:00 2026 GMT',
        ca: false,
        subject: 'CN=device',
        publicKey: { asymmetricKeyType: 'ec', asymmetricKeyDetails: { namedCurve: 'prime256v1' } },
      },
      {
        validFrom: 'Jan 01 00:00:00 2026 GMT',
        validTo: 'Jan 01 00:00:00 2030 GMT',
        ca: true,
        subject: 'CN=Apple App Attestation CA 1\nO=Apple Inc.',
        publicKey: { asymmetricKeyType: 'ec', asymmetricKeyDetails: { namedCurve: 'secp384r1' } },
      },
    ];
    let index = 0;
    expect(inspectAppleAppAttestation(encoded, {
      clock: () => Date.parse('2026-07-15T00:00:00.000Z'),
      certificateFactory: () => certificates[index++],
    }).authenticatorData).toEqual(authData);
    expect(verifyAppleRuntimeSignals(authData, {
      appleAllowedValidationCategories: [2, 4],
      appleAllowedBundleVersions: ['1'],
    })).toMatchObject({ valid: true, validation_category: 4, bundle_version: '1' });
    expect(verifyAppleRuntimeSignals(appleAuthenticatorData({ category: 3 }), {
      appleAllowedValidationCategories: [2, 4],
      appleAllowedBundleVersions: ['1'],
    }).valid).toBe(false);
    expect(verifyAppleRuntimeSignals(appleAuthenticatorData({ bundleVersion: '999' }), {
      appleAllowedValidationCategories: [2, 4],
      appleAllowedBundleVersions: ['1'],
    }).valid).toBe(false);
    expect(verifyAppleRuntimeSignals(appleAuthenticatorData({ includeSignals: false }), {
      appleAllowedValidationCategories: [2, 4],
      appleAllowedBundleVersions: ['1'],
      appleRequireRuntimeSignals: true,
    }).valid).toBe(false);
  });

  it('rejects truncated, trailing, and structurally ambiguous Apple CBOR', () => {
    expect(() => decodeAppleAuthenticatorExtensions(Buffer.alloc(36))).toThrow('malformed');
    const missingExtensions = Buffer.alloc(37);
    missingExtensions[32] = 0x80;
    expect(() => decodeAppleAuthenticatorExtensions(missingExtensions)).toThrow('extensions are missing');

    const truncatedCredential = Buffer.alloc(54);
    truncatedCredential[32] = 0xc0;
    expect(() => decodeAppleAuthenticatorExtensions(truncatedCredential)).toThrow('truncated');

    const missingCredentialKey = Buffer.alloc(55);
    missingCredentialKey[32] = 0xc0;
    missingCredentialKey.writeUInt16BE(1, 53);
    expect(() => decodeAppleAuthenticatorExtensions(missingCredentialKey)).toThrow('truncated');

    const credentialId = Buffer.from([1, 2]);
    const credentialKey = cbor.encode(new Map([[1, 2], [3, -7]]));
    const extensions = cbor.encode(new Map([
      ['apple_validation_category_01', 4],
      ['apple_bundle_version_01', '1'],
    ]));
    const withCredential = Buffer.alloc(55);
    withCredential[32] = 0xc0;
    withCredential.writeUInt16BE(credentialId.length, 53);
    const complete = Buffer.concat([withCredential, credentialId, credentialKey, extensions]);
    expect(decodeAppleAuthenticatorExtensions(complete)).toMatchObject({
      apple_validation_category_01: 4,
      apple_bundle_version_01: '1',
    });

    const trailing = Buffer.concat([appleAuthenticatorData(), Buffer.from([0])]);
    expect(verifyAppleRuntimeSignals(trailing, {
      appleAllowedValidationCategories: [4],
      appleAllowedBundleVersions: ['1'],
    })).toEqual({ valid: false, present: true });
    expect(verifyAppleRuntimeSignals(appleAuthenticatorData(), {})).toMatchObject({
      valid: false,
      present: true,
    });
    expect(verifyAppleRuntimeSignals(appleAuthenticatorData({
      category: '4',
      bundleVersion: 1,
    }), {
      appleAllowedValidationCategories: [4],
      appleAllowedBundleVersions: ['1'],
    })).toMatchObject({
      valid: false,
      validation_category: null,
      bundle_version: null,
    });
  });

  it('rejects malformed Apple attestation and assertion object profiles', () => {
    const authData = appleAuthenticatorData();
    const malformedAttestations = [
      [],
      { fmt: 'wrong', authData, attStmt: { x5c: [Buffer.from('a'), Buffer.from('b')] } },
      { fmt: 'apple-appattest', authData: 'not-bytes', attStmt: { x5c: [Buffer.from('a'), Buffer.from('b')] } },
      { fmt: 'apple-appattest', authData, attStmt: { x5c: 'not-an-array' } },
      { fmt: 'apple-appattest', authData, attStmt: { x5c: [Buffer.from('a')] } },
      { fmt: 'apple-appattest', authData, attStmt: { x5c: [Buffer.from('a'), 'not-bytes'] } },
    ];
    for (const value of malformedAttestations) {
      expect(() => inspectAppleAppAttestation(cbor.encode(value))).toThrow('malformed');
    }
    expect(() => inspectAppleAppAttestation(Buffer.concat([
      cbor.encode({ fmt: 'apple-appattest', authData, attStmt: { x5c: [Buffer.from('a'), Buffer.from('b')] } }),
      Buffer.from([0]),
    ]))).toThrow('trailing CBOR');

    expect(() => inspectAppleAppAssertion(cbor.encode({ signature: 'bad', authenticatorData: authData }))).toThrow('malformed');
    expect(() => inspectAppleAppAssertion(cbor.encode({ signature: Buffer.from('sig'), authenticatorData: 'bad' }))).toThrow('malformed');
    expect(inspectAppleAppAssertion(cbor.encode({
      signature: Buffer.from('sig'),
      authenticatorData: authData,
    })).authenticatorData).toEqual(authData);
  });

  it('rejects expired and mis-profiled Apple certificate chains one condition at a time', () => {
    const encoded = cbor.encode({
      fmt: 'apple-appattest',
      authData: appleAuthenticatorData(),
      attStmt: { x5c: [Buffer.from('leaf'), Buffer.from('intermediate')] },
    });
    const validLeaf = {
      validFrom: 'Jul 01 00:00:00 2026 GMT',
      validTo: 'Aug 01 00:00:00 2026 GMT',
      ca: false,
      subject: 'CN=device',
      publicKey: { asymmetricKeyType: 'ec', asymmetricKeyDetails: { namedCurve: 'P-256' } },
    };
    const validIntermediate = {
      validFrom: 'Jan 01 00:00:00 2026 GMT',
      validTo: 'Jan 01 00:00:00 2030 GMT',
      ca: true,
      subject: 'CN=Apple App Attestation CA 1',
      publicKey: { asymmetricKeyType: 'ec', asymmetricKeyDetails: { namedCurve: 'secp384r1' } },
    };
    const inspect = (leaf, intermediate, clock = Date.parse('2026-07-15T00:00:00.000Z')) => {
      let index = 0;
      return () => inspectAppleAppAttestation(encoded, {
        clock: () => clock,
        certificateFactory: () => [leaf, intermediate][index++],
      });
    };
    expect(inspect(validLeaf, validIntermediate, Number.NaN)).toThrow('validity window');
    expect(inspect({ ...validLeaf, validFrom: 'not-a-date' }, validIntermediate)).toThrow('validity window');
    expect(inspect({ ...validLeaf, validTo: 'not-a-date' }, validIntermediate)).toThrow('validity window');
    expect(inspect({ ...validLeaf, validFrom: 'Aug 01 00:00:00 2026 GMT' }, validIntermediate)).toThrow('validity window');
    expect(inspect({ ...validLeaf, validTo: 'Jul 01 00:00:00 2026 GMT' }, validIntermediate)).toThrow('validity window');
    expect(inspect({ ...validLeaf, ca: true }, validIntermediate)).toThrow('profile');
    expect(inspect(validLeaf, { ...validIntermediate, ca: false })).toThrow('profile');
    expect(inspect(validLeaf, { ...validIntermediate, subject: 'CN=other' })).toThrow('profile');
    expect(inspect({ ...validLeaf, publicKey: { asymmetricKeyType: 'rsa' } }, validIntermediate)).toThrow('profile');
    expect(inspect({
      ...validLeaf,
      publicKey: { asymmetricKeyType: 'ec', asymmetricKeyDetails: { namedCurve: 'secp384r1' } },
    }, validIntermediate)).toThrow('profile');
  });

  it('fails closed across Google credential, OAuth, and decode response errors', async () => {
    expect(() => createGooglePlayIntegrityDecoder()).toThrow('required');
    expect(() => createGooglePlayIntegrityDecoder({ serviceAccount: '{}' })).toThrow('malformed');

    const privateKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
      .export({ format: 'pem', type: 'pkcs8' });
    const account = { client_email: 'mobile@example.iam.gserviceaccount.com', private_key: privateKey };
    expect(() => createGooglePlayIntegrityDecoder({ serviceAccount: JSON.stringify(account) })).toThrow('packageName');
    expect(() => createGooglePlayIntegrityDecoder({
      serviceAccount: JSON.stringify(account),
      packageName: 'ai.emiliaprotocol.approver',
      fetchImpl: null,
    })).toThrow('fetchImpl');

    const make = (responses) => createGooglePlayIntegrityDecoder({
      serviceAccount: Buffer.from(JSON.stringify(account)).toString('base64'),
      packageName: 'ai.emiliaprotocol.approver',
      fetchImpl: vi.fn(async () => responses.shift()),
      clock: () => 1_784_000_000,
    });
    await expect(make([{ ok: false, status: 401 }])('token')).rejects.toThrow('Google OAuth refused');
    await expect(make([{ ok: true, json: async () => ({ access_token: 7, expires_in: 300 }) }])('token')).rejects.toThrow('malformed token');
    await expect(make([
      { ok: true, json: async () => ({ access_token: 'access', expires_in: 300 }) },
      { ok: false, status: 403 },
    ])('token')).rejects.toThrow('decode refused');
    await expect(make([
      { ok: true, json: async () => ({ access_token: 'access', expires_in: 300 }) },
      { ok: true, json: async () => ({ tokenPayloadExternal: null }) },
    ])('token')).rejects.toThrow('no verified payload');
  });

  it('refuses unverified passkeys and preserves zero-value registration defaults', async () => {
    mocks.verifyRegistrationResponse.mockResolvedValueOnce({ verified: false, registrationInfo: null });
    await expect(verifyMobilePasskeyRegistration({})).resolves.toEqual({ valid: false });
    mocks.verifyRegistrationResponse.mockResolvedValueOnce({ verified: true, registrationInfo: {} });
    await expect(verifyMobilePasskeyRegistration({})).resolves.toEqual({ valid: false });
    mocks.verifyRegistrationResponse.mockResolvedValueOnce({
      verified: true,
      registrationInfo: { credential: { id: 'credential-id', publicKey: coseP256() } },
    });
    await expect(verifyMobilePasskeyRegistration({ requireUserVerification: false })).resolves.toMatchObject({
      valid: true,
      sign_count: 0,
      attestation_format: null,
    });
    expect(mocks.verifyRegistrationResponse).toHaveBeenLastCalledWith(expect.objectContaining({
      requireUserVerification: false,
    }));
  });

  it('fails closed for every unpinned iOS enrollment boundary', async () => {
    expect(() => createPlatformEnrollmentVerifier()).toThrow('configuration');
    const base = {
      androidCertificateDigests: [],
      androidPackageName: 'ai.emiliaprotocol.approver',
      iosBundleId: 'ai.emiliaprotocol.approver',
      appleTeamId: '5M2Z48UQQY',
      appleEnvironment: 'production',
      appleAllowedValidationCategories: [4],
      appleAllowedBundleVersions: ['1'],
      appleRequireRuntimeSignals: true,
      androidAllowedVersionCodes: [1],
      androidMinimumSdkVersion: 33,
      androidRequirePlayProtect: true,
    };
    const validInput = {
      platform: 'ios',
      format: 'apple-app-attest-enrollment',
      token: Buffer.from('attestation').toString('base64url'),
      expected_request_hash: 'a'.repeat(43),
      expected_binding: { challenge: 'one' },
      expected_app_id: base.iosBundleId,
      expected_attestation_key_id: 'apple-key',
    };
    const noAndroid = createPlatformEnrollmentVerifier({ config: base, playDecoder: async () => ({}) });
    await expect(noAndroid({ ...validInput, platform: 'android' })).resolves.toEqual({ valid: false });
    for (const mutation of [
      { platform: 'web' },
      { format: 'wrong' },
      { expected_app_id: 'attacker.app' },
      { expected_binding: null },
      { expected_attestation_key_id: null },
    ]) {
      await expect(noAndroid({ ...validInput, ...mutation })).resolves.toEqual({ valid: false });
    }
    await expect(createPlatformEnrollmentVerifier({
      config: base,
      playDecoder: async () => ({}),
      inspectAppleAttestation: () => ({ authenticatorData: appleAuthenticatorData({ includeSignals: false }) }),
    })(validInput)).resolves.toEqual({ valid: false });

    mocks.verifyAttestation.mockReturnValueOnce({ environment: 'development', publicKey: 'key' });
    await expect(createPlatformEnrollmentVerifier({
      config: base,
      playDecoder: async () => ({}),
      inspectAppleAttestation: () => ({ authenticatorData: appleAuthenticatorData() }),
    })(validInput)).resolves.toEqual({ valid: false });

    mocks.verifyAttestation.mockImplementationOnce(() => { throw new Error('invalid signature'); });
    await expect(createPlatformEnrollmentVerifier({
      config: { ...base, appleEnvironment: 'development' },
      playDecoder: async () => ({}),
      inspectAppleAttestation: () => ({ authenticatorData: appleAuthenticatorData() }),
    })(validInput)).resolves.toEqual({ valid: false });
  });

  it('refuses every stale or mismatched enrolled App Attest key', async () => {
    expect(() => createProductionAttestationVerifier()).toThrow('required');
    const base = {
      androidCertificateDigests: [],
      androidPackageName: 'ai.emiliaprotocol.approver',
      iosBundleId: 'ai.emiliaprotocol.approver',
      appleTeamId: '5M2Z48UQQY',
      appleEnvironment: 'production',
      appleAllowedValidationCategories: [4],
      appleAllowedBundleVersions: ['1'],
      appleRequireRuntimeSignals: true,
      androidAllowedVersionCodes: [1],
      androidMinimumSdkVersion: 33,
      androidRequirePlayProtect: true,
    };
    const active = {
      platform_public_key: 'public-key',
      app_id: base.iosBundleId,
      status: 'active',
      valid_from: '2026-01-01T00:00:00.000Z',
      valid_to: '2027-01-01T00:00:00.000Z',
    };
    const input = {
      platform: 'ios',
      expected_attestation_key_id: 'apple-key',
      expected_binding: { challenge_id: 'one' },
      token: Buffer.from('assertion').toString('base64url'),
    };
    const make = (enrollment) => createProductionAttestationVerifier({
      config: base,
      directory: { platformKey: vi.fn(async () => enrollment) },
      counterStore: { advance: vi.fn(async () => true) },
      playDecoder: async () => ({}),
      inspectAppleAssertion: () => ({ authenticatorData: appleAuthenticatorData() }),
    });
    await expect(make(active)({ ...input, platform: 'web' })).resolves.toEqual({ valid: false });
    await expect(make(active)({ ...input, platform: 'android' })).resolves.toEqual({ valid: false });
    for (const enrollment of [
      null,
      { ...active, status: 'revoked' },
      { ...active, app_id: 'attacker.app' },
      { ...active, valid_from: '2030-01-01T00:00:00.000Z' },
      { ...active, valid_to: '2020-01-01T00:00:00.000Z' },
      { ...active, platform_public_key: null },
    ]) {
      await expect(make(enrollment)(input)).resolves.toEqual({ valid: false });
    }

    mocks.verifyAssertion.mockReturnValueOnce({ signCount: 1 });
    const invalidSignals = createProductionAttestationVerifier({
      config: base,
      directory: { platformKey: vi.fn(async () => active) },
      counterStore: { advance: vi.fn(async () => true) },
      playDecoder: async () => ({}),
      inspectAppleAssertion: () => ({ authenticatorData: appleAuthenticatorData({ includeSignals: false }) }),
    });
    await expect(invalidSignals(input)).resolves.toMatchObject({ valid: false });
  });
});
