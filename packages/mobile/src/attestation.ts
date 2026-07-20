// SPDX-License-Identifier: Apache-2.0
import { Buffer } from 'node:buffer';
type AnyRecord = Record<string, any>;

function isRecord(value: any): value is AnyRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function unwrapOpaqueToken(token: any): Buffer {
  if (typeof token !== 'string' || !token || !/^[A-Za-z0-9_-]+$/.test(token)) {
    throw new Error('attestation token is not base64url-wrapped opaque bytes');
  }
  const bytes = Buffer.from(token, 'base64url');
  if (bytes.length === 0 || bytes.length > 128 * 1024) throw new Error('attestation token size is invalid');
  return bytes;
}

function parseMillis(value: any): number | null {
  const number = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
  return Number.isSafeInteger(number) && number >= 0 ? number : null;
}

function parsePositiveInteger(value: any): number | null {
  const number = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
  return Number.isSafeInteger(number) && number > 0 ? number : null;
}

function certificateDigestBytes(value: any): Buffer | null {
  if (typeof value !== 'string' || !value) return null;
  try {
    const normalized = value.replaceAll(':', '');
    if (/^[0-9a-fA-F]{64}$/.test(normalized)) return Buffer.from(normalized, 'hex');
    if (!/^[A-Za-z0-9+/_-]{43}={0,2}$/.test(value)) return null;
    const bytes = Buffer.from(value.replaceAll('-', '+').replaceAll('_', '/'), 'base64');
    return bytes.length === 32 ? bytes : null;
  } catch {
    return null;
  }
}

/**
 * @typedef {Object} PlayIntegrityVerifierOptions
 * @property {(token: string) => Promise<any>} [decodeToken]
 * @property {string} [packageName]
 * @property {Array<string>} [certificateDigests]
 * @property {boolean} [requireLicensed]
 * @property {boolean} [requireStrongIntegrity]
 * @property {boolean} [requireNoCaptureOrControl]
 * @property {boolean} [requirePlayProtect]
 * @property {Array<number|string>} [allowedVersionCodes]
 * @property {number|string|null} [minimumSdkVersion]
 * @property {number} [maxTokenAgeMs]
 * @property {() => number} [clock]
 */

/**
 * Adapt the official Google decodeIntegrityToken response into the closed
 * result consumed by verifyMobileCeremony. `decodeToken` owns OAuth and the
 * server-to-server Google call; this function owns the relying party's pins.
 *
 * @param {PlayIntegrityVerifierOptions} [options]
 */
export function createPlayIntegrityAttestationVerifier({
  decodeToken,
  packageName,
  certificateDigests,
  requireLicensed = true,
  requireStrongIntegrity = true,
  requireNoCaptureOrControl = false,
  requirePlayProtect = false,
  allowedVersionCodes = [],
  minimumSdkVersion = null,
  maxTokenAgeMs = 120_000,
  clock = Date.now,
}: AnyRecord = {}): (input?: AnyRecord) => Promise<AnyRecord> {
  if (typeof decodeToken !== 'function') throw new TypeError('decodeToken must be a function');
  if (typeof packageName !== 'string' || !packageName) throw new TypeError('packageName is required');
  if (!Array.isArray(certificateDigests) || certificateDigests.length === 0
      || certificateDigests.some((digest: any) => certificateDigestBytes(digest) === null)) {
    throw new TypeError('at least one pinned certificate digest is required');
  }
  if (!Array.isArray(allowedVersionCodes)
      || allowedVersionCodes.some((version: any) => parsePositiveInteger(version) === null)) {
    throw new TypeError('allowedVersionCodes must contain positive integer app versions');
  }
  if (minimumSdkVersion !== null && parsePositiveInteger(minimumSdkVersion) === null) {
    throw new TypeError('minimumSdkVersion must be a positive integer or null');
  }
  if (!Number.isSafeInteger(maxTokenAgeMs) || maxTokenAgeMs <= 0 || maxTokenAgeMs > 600_000) {
    throw new TypeError('maxTokenAgeMs must be a positive integer no greater than 600000');
  }
  if (typeof clock !== 'function') throw new TypeError('clock must be a function');
  // certificateDigests was already validated above (every entry maps to a
  // non-null Buffer via certificateDigestBytes, or the constructor throws),
  // so this map can never contain null.
  const pinnedCertificates = certificateDigests.map((digest: any) => certificateDigestBytes(digest) as Buffer);
  const pinnedVersions = new Set(allowedVersionCodes.map((version) => parsePositiveInteger(version)));

  /**
   * @typedef {Object} PlayIntegrityAssertionInput
   * @property {string} [format]
   * @property {string} [token]
   * @property {string} [expected_request_hash]
   * @property {string} [expected_app_id]
   * @property {string} [expected_attestation_key_id]
   * @property {string} [platform]
   */

  /**
   * @param {PlayIntegrityAssertionInput} [input]
   */
  return async function verifyPlayIntegrity({
    format,
    token,
    expected_request_hash: expectedRequestHash,
    expected_app_id: expectedAppId,
    expected_attestation_key_id: expectedAttestationKeyId,
    platform,
  }: AnyRecord = {}): Promise<AnyRecord> {
    try {
      if (format !== 'play-integrity-standard' || platform !== 'android'
          || expectedAppId !== packageName
          || !/^android-keystore:sha256:[A-Za-z0-9_-]{43}$/.test(expectedAttestationKeyId || '')) {
        return { valid: false };
      }
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
      const certificatePinned = certificates.some((digest) => {
        const candidate = certificateDigestBytes(digest);
        return candidate !== null && pinnedCertificates.some((pin) => pin.equals(candidate));
      });
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
        attestation_key_id: expectedAttestationKeyId,
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
 * @typedef {Object} AppleAppAttestVerifierOptions
 * @property {(input: { assertionObject: Buffer, clientDataHash: Buffer, expectedBinding: unknown, appId: string, keyId: string, environment: string }) => Promise<any>} [verifyAssertion]
 * @property {string} [appId]
 * @property {string} [attestationKeyId]
 * @property {string} [environment]
 * @property {{ advance: (keyId: string, counter: number) => Promise<boolean> }} [counterStore]
 */

/**
 * Adapt an App Attest cryptographic verifier. `verifyAssertion` MUST validate
 * the Apple certificate/credential chain and assertion signature against the
 * enrolled App Attest public key. This adapter pins application identity,
 * request bytes, environment, and the monotonic App Attest counter.
 *
 * @param {AppleAppAttestVerifierOptions} [options]
 */
export function createAppleAppAttestVerifier({
  verifyAssertion,
  appId,
  attestationKeyId,
  environment = 'production',
  counterStore,
}: AnyRecord = {}): (input?: AnyRecord) => Promise<AnyRecord> {
  if (typeof verifyAssertion !== 'function') throw new TypeError('verifyAssertion must be a cryptographic App Attest verifier');
  if (typeof appId !== 'string' || !appId || typeof attestationKeyId !== 'string' || !attestationKeyId) {
    throw new TypeError('appId and attestationKeyId are required');
  }
  if (!['development', 'production'].includes(environment)) throw new TypeError('unsupported App Attest environment');
  if (typeof counterStore?.advance !== 'function') throw new TypeError('a durable App Attest counterStore is required');

  /**
   * @typedef {Object} AppleAppAttestAssertionInput
   * @property {string} [format]
   * @property {string} [token]
   * @property {string} [expected_request_hash]
   * @property {unknown} [expected_binding]
   * @property {string} [expected_app_id]
   * @property {string} [expected_attestation_key_id]
   * @property {string} [platform]
   */

  /**
   * @param {AppleAppAttestAssertionInput} [input]
   */
  return async function verifyAppleAppAttest({
    format,
    token,
    expected_request_hash: expectedRequestHash,
    expected_binding: expectedBinding,
    expected_app_id: expectedAppId,
    expected_attestation_key_id: expectedAttestationKeyId,
    platform,
  }: AnyRecord = {}): Promise<AnyRecord> {
    try {
      if (format !== 'apple-app-attest' || platform !== 'ios'
          || expectedAppId !== appId || expectedAttestationKeyId !== attestationKeyId) return { valid: false };
      const assertionObject = unwrapOpaqueToken(token);
      // expected_request_hash is optional on the input type, but a missing/
      // non-string value here throws inside Buffer.from and is caught below,
      // returning the same { valid: false } as any other malformed hash —
      // this cast only tells the compiler about that existing fail-closed path.
      const clientDataHash = Buffer.from(/** @type {string} */ (expectedRequestHash), 'base64url');
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
