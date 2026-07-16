// SPDX-License-Identifier: Apache-2.0
import { Buffer } from 'node:buffer';

function isRecord(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function unwrapOpaqueToken(token) {
  if (typeof token !== 'string' || !token || !/^[A-Za-z0-9_-]+$/.test(token)) {
    throw new Error('attestation token is not base64url-wrapped opaque bytes');
  }
  const bytes = Buffer.from(token, 'base64url');
  if (bytes.length === 0 || bytes.length > 128 * 1024) throw new Error('attestation token size is invalid');
  return bytes;
}

function parseMillis(value) {
  const number = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
  return Number.isSafeInteger(number) && number >= 0 ? number : null;
}

function parsePositiveInteger(value) {
  const number = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
  return Number.isSafeInteger(number) && number > 0 ? number : null;
}

/**
 * Adapt the official Google decodeIntegrityToken response into the closed
 * result consumed by verifyMobileCeremony. `decodeToken` owns OAuth and the
 * server-to-server Google call; this function owns the relying party's pins.
 */
export function createPlayIntegrityAttestationVerifier({
  decodeToken,
  packageName,
  certificateDigests,
  attestationKeyId,
  requireLicensed = true,
  requireStrongIntegrity = true,
  requireNoCaptureOrControl = false,
  requirePlayProtect = false,
  allowedVersionCodes = [],
  minimumSdkVersion = null,
  maxTokenAgeMs = 120_000,
  clock = Date.now,
} = {}) {
  if (typeof decodeToken !== 'function') throw new TypeError('decodeToken must be a function');
  if (typeof packageName !== 'string' || !packageName) throw new TypeError('packageName is required');
  if (!Array.isArray(certificateDigests) || certificateDigests.length === 0
      || certificateDigests.some((digest) => typeof digest !== 'string' || !digest)) {
    throw new TypeError('at least one pinned certificate digest is required');
  }
  if (typeof attestationKeyId !== 'string' || !attestationKeyId) throw new TypeError('attestationKeyId is required');
  if (!Array.isArray(allowedVersionCodes)
      || allowedVersionCodes.some((version) => parsePositiveInteger(version) === null)) {
    throw new TypeError('allowedVersionCodes must contain positive integer app versions');
  }
  if (minimumSdkVersion !== null && parsePositiveInteger(minimumSdkVersion) === null) {
    throw new TypeError('minimumSdkVersion must be a positive integer or null');
  }
  if (!Number.isSafeInteger(maxTokenAgeMs) || maxTokenAgeMs <= 0 || maxTokenAgeMs > 600_000) {
    throw new TypeError('maxTokenAgeMs must be a positive integer no greater than 600000');
  }
  if (typeof clock !== 'function') throw new TypeError('clock must be a function');
  const pinnedCertificates = new Set(certificateDigests);
  const pinnedVersions = new Set(allowedVersionCodes.map((version) => parsePositiveInteger(version)));

  return async function verifyPlayIntegrity({
    format,
    token,
    expected_request_hash: expectedRequestHash,
    expected_app_id: expectedAppId,
    expected_attestation_key_id: expectedAttestationKeyId,
    platform,
  } = {}) {
    try {
      if (format !== 'play-integrity-standard' || platform !== 'android'
          || expectedAppId !== packageName || expectedAttestationKeyId !== attestationKeyId) return { valid: false };
      const encodedToken = unwrapOpaqueToken(token).toString('utf8');
      const payload = await decodeToken(encodedToken);
      if (!isRecord(payload)) return { valid: false };
      const request = payload.requestDetails;
      const app = payload.appIntegrity;
      const account = payload.accountDetails;
      const device = payload.deviceIntegrity;
      if (!isRecord(request) || !isRecord(app) || !isRecord(account) || !isRecord(device)) return { valid: false };

      const tokenMillis = parseMillis(request.timestampMillis);
      const now = clock();
      const fresh = tokenMillis !== null && Number.isSafeInteger(now)
        && tokenMillis <= now && now - tokenMillis <= maxTokenAgeMs;
      const certificates = Array.isArray(app.certificateSha256Digest) ? app.certificateSha256Digest : [];
      const certificatePinned = certificates.some((digest) => pinnedCertificates.has(digest));
      const labels = Array.isArray(device.deviceRecognitionVerdict) ? device.deviceRecognitionVerdict : [];
      const meetsDevice = labels.includes('MEETS_DEVICE_INTEGRITY');
      const meetsStrong = labels.includes('MEETS_STRONG_INTEGRITY');
      const versionCode = parsePositiveInteger(app.versionCode);
      const sdkVersion = parsePositiveInteger(device.deviceAttributes?.sdkVersion);
      const accessRisk = payload.environmentDetails?.appAccessRiskVerdict;
      const playProtectVerdict = payload.environmentDetails?.playProtectVerdict;
      const detected = accessRisk?.appsDetected;
      const accessRiskPresent = isRecord(accessRisk) && Array.isArray(detected);
      const riskyEnvironment = Array.isArray(detected)
        && detected.some((label) => typeof label === 'string'
          && (label.endsWith('_CAPTURING') || label.endsWith('_CONTROLLING') || label.endsWith('_OVERLAYS')));
      const valid = request.requestPackageName === packageName
        && request.requestHash === expectedRequestHash
        && fresh
        && app.appRecognitionVerdict === 'PLAY_RECOGNIZED'
        && app.packageName === packageName
        && certificatePinned
        && (pinnedVersions.size === 0 || pinnedVersions.has(versionCode))
        && (!requireLicensed || account.appLicensingVerdict === 'LICENSED')
        && meetsDevice
        && (!requireStrongIntegrity || meetsStrong)
        && (minimumSdkVersion === null || (sdkVersion !== null && sdkVersion >= minimumSdkVersion))
        && (!requireNoCaptureOrControl || (accessRiskPresent && !riskyEnvironment));
      const protectedEnvironment = valid
        && (!requirePlayProtect || playProtectVerdict === 'NO_ISSUES');
      return {
        valid: protectedEnvironment,
        request_hash: request.requestHash,
        app_id: packageName,
        attestation_key_id: attestationKeyId,
        platform: 'android',
        hardware_backed: meetsStrong,
        strong_integrity: meetsStrong,
        version_code: versionCode,
        sdk_version: sdkVersion,
        play_protect_verdict: typeof playProtectVerdict === 'string' ? playProtectVerdict : null,
        token_timestamp_ms: tokenMillis,
      };
    } catch {
      return { valid: false };
    }
  };
}

/**
 * Adapt an App Attest cryptographic verifier. `verifyAssertion` MUST validate
 * the Apple certificate/credential chain and assertion signature against the
 * enrolled App Attest public key. This adapter pins application identity,
 * request bytes, environment, and the monotonic App Attest counter.
 */
export function createAppleAppAttestVerifier({
  verifyAssertion,
  appId,
  attestationKeyId,
  environment = 'production',
  counterStore,
} = {}) {
  if (typeof verifyAssertion !== 'function') throw new TypeError('verifyAssertion must be a cryptographic App Attest verifier');
  if (typeof appId !== 'string' || !appId || typeof attestationKeyId !== 'string' || !attestationKeyId) {
    throw new TypeError('appId and attestationKeyId are required');
  }
  if (!['development', 'production'].includes(environment)) throw new TypeError('unsupported App Attest environment');
  if (typeof counterStore?.advance !== 'function') throw new TypeError('a durable App Attest counterStore is required');

  return async function verifyAppleAppAttest({
    format,
    token,
    expected_request_hash: expectedRequestHash,
    expected_binding: expectedBinding,
    expected_app_id: expectedAppId,
    expected_attestation_key_id: expectedAttestationKeyId,
    platform,
  } = {}) {
    try {
      if (format !== 'apple-app-attest' || platform !== 'ios'
          || expectedAppId !== appId || expectedAttestationKeyId !== attestationKeyId) return { valid: false };
      const assertionObject = unwrapOpaqueToken(token);
      const clientDataHash = Buffer.from(expectedRequestHash, 'base64url');
      if (clientDataHash.length !== 32) return { valid: false };
      const result = await verifyAssertion({
        assertionObject,
        clientDataHash,
        expectedBinding,
        appId,
        keyId: attestationKeyId,
        environment,
      });
      if (!isRecord(result) || result.valid !== true
          || result.app_id !== appId || result.key_id !== attestationKeyId
          || result.environment !== environment
          || result.client_data_hash !== expectedRequestHash
          || !Number.isSafeInteger(result.counter) || result.counter < 1) return { valid: false };
      if ((await counterStore.advance(attestationKeyId, result.counter)) !== true) return { valid: false };
      return {
        valid: true,
        request_hash: expectedRequestHash,
        app_id: appId,
        attestation_key_id: attestationKeyId,
        platform: 'ios',
        hardware_backed: true,
        strong_integrity: true,
        assertion_counter: result.counter,
        integrity_signals: isRecord(result.integrity_signals) ? result.integrity_signals : null,
      };
    } catch {
      return { valid: false };
    }
  };
}

export default { createPlayIntegrityAttestationVerifier, createAppleAppAttestVerifier };
