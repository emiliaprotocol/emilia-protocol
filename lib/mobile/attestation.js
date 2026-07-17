// SPDX-License-Identifier: Apache-2.0
import { Buffer } from 'node:buffer';
import { createHash, createPublicKey, verify, X509Certificate } from 'node:crypto';
import cbor from 'cbor';
import { importPKCS8, SignJWT } from 'jose';
import { verifyAssertion, verifyAttestation } from 'node-app-attest';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { canonicalize } from '@/packages/verify/index.js';
import { coseToSpkiP256 } from '@/lib/webauthn.js';
import {
  createAppleAppAttestVerifier,
  createPlayIntegrityAttestationVerifier,
} from '@/packages/mobile/index.js';

const PLAY_SCOPE = 'https://www.googleapis.com/auth/playintegrity';
const TOKEN_AUDIENCE = 'https://oauth2.googleapis.com/token';
const APPLE_VALIDATION_CATEGORY = 'apple_validation_category_01';
const APPLE_BUNDLE_VERSION = 'apple_bundle_version_01';

function cborRecord(value) {
  if (value instanceof Map) return Object.fromEntries(value);
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function decodeOne(bytes) {
  const decoded = cbor.decodeFirstSync(bytes, { extendedResults: true });
  if (decoded.unused !== null && decoded.unused?.length !== 0) throw new Error('trailing CBOR data');
  return decoded;
}

export function decodeAppleAuthenticatorExtensions(authenticatorData) {
  if (!Buffer.isBuffer(authenticatorData) || authenticatorData.length < 37) {
    throw new Error('App Attest authenticator data is malformed');
  }
  const flags = authenticatorData[32];
  if ((flags & 0x80) === 0) return null;
  let offset = 37;
  if ((flags & 0x40) !== 0) {
    if (authenticatorData.length < 55) throw new Error('App Attest credential data is truncated');
    const credentialLength = authenticatorData.readUInt16BE(53);
    offset = 55 + credentialLength;
    if (offset >= authenticatorData.length) throw new Error('App Attest credential data is truncated');
    const credentialKey = cbor.decodeFirstSync(authenticatorData.subarray(offset), { extendedResults: true });
    offset += credentialKey.length;
  }
  if (offset >= authenticatorData.length) throw new Error('App Attest extensions are missing');
  const decoded = decodeOne(authenticatorData.subarray(offset));
  return cborRecord(decoded.value);
}

export function verifyAppleRuntimeSignals(authenticatorData, config = {}) {
  try {
    const extensions = decodeAppleAuthenticatorExtensions(authenticatorData);
    if (!extensions) {
      return { valid: config.appleRequireRuntimeSignals !== true, present: false };
    }
    const category = extensions[APPLE_VALIDATION_CATEGORY];
    const bundleVersion = extensions[APPLE_BUNDLE_VERSION];
    const allowedCategories = new Set(config.appleAllowedValidationCategories || []);
    const allowedVersions = new Set(config.appleAllowedBundleVersions || []);
    const valid = Number.isSafeInteger(category)
      && allowedCategories.has(category)
      && typeof bundleVersion === 'string'
      && allowedVersions.has(bundleVersion);
    return {
      valid,
      present: true,
      validation_category: Number.isSafeInteger(category) ? category : null,
      bundle_version: typeof bundleVersion === 'string' ? bundleVersion : null,
    };
  } catch {
    return { valid: false, present: true };
  }
}

function certificateIsCurrent(certificate, now) {
  const validFrom = Date.parse(certificate.validFrom);
  const validTo = Date.parse(certificate.validTo);
  return Number.isFinite(validFrom) && Number.isFinite(validTo) && now >= validFrom && now <= validTo;
}

export function inspectAppleAppAttestation(attestation, {
  clock = Date.now,
  certificateFactory = (raw) => new X509Certificate(raw),
} = {}) {
  const decoded = cborRecord(decodeOne(attestation).value);
  const certificates = decoded?.attStmt?.x5c;
  if (decoded?.fmt !== 'apple-appattest' || !Buffer.isBuffer(decoded.authData)
      || !Array.isArray(certificates) || certificates.length !== 2
      || certificates.some((certificate) => !Buffer.isBuffer(certificate))) {
    throw new Error('App Attest object is malformed');
  }
  const leaf = certificateFactory(certificates[0]);
  const intermediate = certificateFactory(certificates[1]);
  const now = clock();
  if (!Number.isSafeInteger(now) || !certificateIsCurrent(leaf, now)
      || !certificateIsCurrent(intermediate, now)) {
    throw new Error('App Attest certificate is outside its validity window');
  }
  if (leaf.ca !== false || intermediate.ca !== true
      || !intermediate.subject.includes('CN=Apple App Attestation CA 1')
      || leaf.publicKey?.asymmetricKeyType !== 'ec'
      || !['prime256v1', 'P-256'].includes(leaf.publicKey?.asymmetricKeyDetails?.namedCurve)) {
    throw new Error('App Attest certificate profile is invalid');
  }
  return { authenticatorData: decoded.authData };
}

export function inspectAppleAppAssertion(assertion) {
  const decoded = cborRecord(decodeOne(assertion).value);
  if (!Buffer.isBuffer(decoded?.signature) || !Buffer.isBuffer(decoded?.authenticatorData)) {
    throw new Error('App Attest assertion is malformed');
  }
  return { authenticatorData: decoded.authenticatorData };
}

function serviceAccountFromEnvironment(value) {
  if (typeof value !== 'string' || !value.trim()) throw new Error('GOOGLE_PLAY_SERVICE_ACCOUNT_JSON is required');
  const trimmed = value.trim();
  const text = trimmed.startsWith('{') ? trimmed : Buffer.from(trimmed, 'base64').toString('utf8');
  const parsed = JSON.parse(text);
  if (typeof parsed.client_email !== 'string' || typeof parsed.private_key !== 'string') {
    throw new Error('Google Play service account is malformed');
  }
  return parsed;
}

export function createGooglePlayIntegrityDecoder({
  serviceAccount,
  packageName,
  fetchImpl = fetch,
  clock = () => Math.floor(Date.now() / 1000),
} = {}) {
  const account = serviceAccountFromEnvironment(serviceAccount);
  if (typeof packageName !== 'string' || !packageName) throw new TypeError('packageName is required');
  if (typeof fetchImpl !== 'function') throw new TypeError('fetchImpl is required');
  let cached = null;

  async function accessToken() {
    const now = clock();
    if (cached && cached.expiresAt - 60 > now) return cached.value;
    const key = await importPKCS8(account.private_key, 'RS256');
    const assertion = await new SignJWT({ scope: PLAY_SCOPE })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
      .setIssuer(account.client_email)
      .setSubject(account.client_email)
      .setAudience(TOKEN_AUDIENCE)
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(key);
    const response = await fetchImpl(TOKEN_AUDIENCE, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion,
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`Google OAuth refused with HTTP ${response.status}`);
    const body = await response.json();
    if (typeof body.access_token !== 'string' || !Number.isSafeInteger(body.expires_in)) {
      throw new Error('Google OAuth returned a malformed token response');
    }
    cached = { value: body.access_token, expiresAt: now + body.expires_in };
    return cached.value;
  }

  return async function decodeIntegrityToken(integrityToken) {
    const token = await accessToken();
    const response = await fetchImpl(
      `https://playintegrity.googleapis.com/v1/${encodeURIComponent(packageName)}:decodeIntegrityToken`,
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ integrity_token: integrityToken }),
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!response.ok) throw new Error(`Play Integrity decode refused with HTTP ${response.status}`);
    const body = await response.json();
    if (!body?.tokenPayloadExternal || typeof body.tokenPayloadExternal !== 'object') {
      throw new Error('Play Integrity decode returned no verified payload');
    }
    return body.tokenPayloadExternal;
  };
}

export async function verifyMobilePasskeyRegistration({
  response,
  expectedChallenge,
  expectedOrigin,
  expectedRPID,
  requireUserVerification = true,
} = {}) {
  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    requireUserVerification,
    supportedAlgorithmIDs: [-7],
  });
  const registration = verification.registrationInfo;
  if (!verification.verified || !registration?.credential) return { valid: false };
  const spki = coseToSpkiP256(registration.credential.publicKey);
  return {
    valid: true,
    algorithm: 'ES256',
    credential_id: registration.credential.id,
    public_key_spki: spki.toString('base64url'),
    sign_count: registration.credential.counter ?? 0,
    attestation_format: registration.fmt || null,
  };
}

export function createPlatformEnrollmentVerifier({
  config,
  playDecoder,
  inspectAppleAttestation = inspectAppleAppAttestation,
} = {}) {
  if (!config) throw new TypeError('mobile configuration is required');
  const play = config.androidCertificateDigests.length > 0
    ? createPlayIntegrityAttestationVerifier({
      decodeToken: playDecoder,
      packageName: config.androidPackageName,
      certificateDigests: config.androidCertificateDigests,
      requireLicensed: true,
      requireStrongIntegrity: true,
      requireNoCaptureOrControl: true,
      requirePlayProtect: config.androidRequirePlayProtect,
      allowedVersionCodes: config.androidAllowedVersionCodes,
      minimumSdkVersion: config.androidMinimumSdkVersion,
    })
    : async () => ({ valid: false });

  return async function verifyPlatformEnrollment(input) {
    if (input.platform === 'android') return play(input);
    if (input.platform !== 'ios' || input.format !== 'apple-app-attest-enrollment'
        || input.expected_app_id !== config.iosBundleId
        || !input.expected_binding || typeof input.expected_attestation_key_id !== 'string') {
      return { valid: false };
    }
    try {
      const attestationBytes = Buffer.from(input.token, 'base64url');
      const inspected = inspectAppleAttestation(attestationBytes);
      const signals = verifyAppleRuntimeSignals(inspected.authenticatorData, config);
      if (!signals.valid) return { valid: false };
      const result = verifyAttestation({
        attestation: attestationBytes,
        challenge: Buffer.from(canonicalize(input.expected_binding), 'utf8'),
        keyId: input.expected_attestation_key_id,
        bundleIdentifier: config.iosBundleId,
        teamIdentifier: config.appleTeamId,
        allowDevelopmentEnvironment: config.appleEnvironment === 'development',
      });
      if (result.environment !== config.appleEnvironment) return { valid: false };
      return {
        valid: true,
        request_hash: input.expected_request_hash,
        app_id: config.iosBundleId,
        attestation_key_id: input.expected_attestation_key_id,
        platform: 'ios',
        hardware_backed: true,
        strong_integrity: true,
        platform_public_key: result.publicKey,
        runtime_signals: signals,
      };
    } catch {
      return { valid: false };
    }
  };
}

export function createProductionAttestationVerifier({
  config,
  directory,
  counterStore,
  playDecoder,
  inspectAppleAssertion = inspectAppleAppAssertion,
} = {}) {
  if (!config || !directory || !counterStore) throw new TypeError('config, directory, and counterStore are required');
  const play = config.androidCertificateDigests.length > 0
    ? createPlayIntegrityAttestationVerifier({
      decodeToken: playDecoder,
      packageName: config.androidPackageName,
      certificateDigests: config.androidCertificateDigests,
      requireLicensed: true,
      requireStrongIntegrity: true,
      requireNoCaptureOrControl: true,
      requirePlayProtect: config.androidRequirePlayProtect,
      allowedVersionCodes: config.androidAllowedVersionCodes,
      minimumSdkVersion: config.androidMinimumSdkVersion,
    })
    : async () => ({ valid: false });

  return async function verifyPlatformAssertion(input) {
    if (input.platform === 'android') {
      const enrolled = await directory.platformKey(input.expected_attestation_key_id, 'android');
      const now = Date.now();
      const validFrom = Date.parse(enrolled?.valid_from);
      const validTo = Date.parse(enrolled?.valid_to);
      if (!enrolled || enrolled.status !== 'active' || enrolled.app_id !== config.androidPackageName
          || !Number.isFinite(validFrom) || !Number.isFinite(validTo)
          || validFrom > now || validTo < now
          || typeof enrolled.platform_public_key !== 'string'
          || typeof input.device_key_signature !== 'string') return { valid: false };
      try {
        const publicKeyBytes = Buffer.from(enrolled.platform_public_key, 'base64url');
        const expectedKeyId = `android-keystore:sha256:${createHash('sha256').update(publicKeyBytes).digest('base64url')}`;
        const requestHash = Buffer.from(input.expected_request_hash, 'base64url');
        const publicKey = createPublicKey({ key: publicKeyBytes, format: 'der', type: 'spki' });
        if (expectedKeyId !== input.expected_attestation_key_id || requestHash.length !== 32
            || publicKey.asymmetricKeyType !== 'ec'
            || !['prime256v1', 'P-256'].includes(publicKey.asymmetricKeyDetails?.namedCurve)
            || !verify(
              'sha256',
              requestHash,
              publicKey,
              Buffer.from(input.device_key_signature, 'base64url'),
            )) return { valid: false };
      } catch {
        return { valid: false };
      }
      const result = await play(input);
      return result.valid === true ? { ...result, device_key_verified: true } : result;
    }
    if (input.platform !== 'ios') return { valid: false };
    const enrolled = await directory.platformKey(input.expected_attestation_key_id, 'ios');
    const now = Date.now();
    if (!enrolled || enrolled.status !== 'active' || enrolled.app_id !== config.iosBundleId
        || Date.parse(enrolled.valid_from) > now || Date.parse(enrolled.valid_to) < now
        || typeof enrolled.platform_public_key !== 'string') return { valid: false };
    const apple = createAppleAppAttestVerifier({
      appId: config.iosBundleId,
      attestationKeyId: input.expected_attestation_key_id,
      environment: config.appleEnvironment,
      counterStore,
      verifyAssertion: async ({ assertionObject, expectedBinding, clientDataHash, keyId, environment }) => {
        const result = verifyAssertion({
          assertion: assertionObject,
          payload: Buffer.from(canonicalize(expectedBinding), 'utf8'),
          publicKey: enrolled.platform_public_key,
          bundleIdentifier: config.iosBundleId,
          teamIdentifier: config.appleTeamId,
          signCount: 0,
        });
        const inspected = inspectAppleAssertion(assertionObject);
        const signals = verifyAppleRuntimeSignals(inspected.authenticatorData, config);
        if (!signals.valid) throw new Error('App Attest runtime signals do not satisfy the mobile profile');
        return {
          valid: true,
          app_id: config.iosBundleId,
          key_id: keyId,
          environment,
          client_data_hash: Buffer.from(clientDataHash).toString('base64url'),
          counter: result.signCount,
          integrity_signals: signals,
        };
      },
    });
    return apple(input);
  };
}
