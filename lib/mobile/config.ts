// SPDX-License-Identifier: Apache-2.0
import { Buffer } from 'node:buffer';

export const MOBILE_APP_ID = 'ai.emiliaprotocol.approver';
export const MOBILE_APPLE_TEAM_ID = '5M2Z48UQQY';
export const MOBILE_PROFILE_ID = 'emilia.high-assurance.mobile.v1';
export const MOBILE_RP_ID = 'www.emiliaprotocol.ai';
export const MOBILE_IOS_ORIGIN = 'https://www.emiliaprotocol.ai';
export const MOBILE_ANDROID_DEBUG_KEY_HASH = 'dLV_6w6wLHSjLKuyPiW8h8ZuK_EyeFAIsGNXeJoRgDo';

const B64U_SHA256 = /^[A-Za-z0-9_-]{43}$/;
const APP_ID = /^(?=.{3,256}$)[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9][A-Za-z0-9_-]*)+$/;
const PROFILE_ID = /^[A-Za-z0-9][A-Za-z0-9:_.-]{2,127}$/;
const RP_ID = /^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function list(value) {
  return typeof value === 'string'
    ? [...new Set(value.split(',').map((item) => item.trim()).filter(Boolean))]
    : [];
}

export function normalizeAndroidSigningCertificate(value, name = 'Android signing certificate') {
  if (typeof value !== 'string' || !value.trim()) throw new TypeError(`${name} is required`);
  const candidate = value.trim();
  let bytes;
  const hex = candidate.replaceAll(':', '');
  if (/^[0-9a-fA-F]{64}$/.test(hex)) {
    bytes = Buffer.from(hex, 'hex');
  } else if (/^[A-Za-z0-9+/_-]{43}={0,2}$/.test(candidate)) {
    bytes = Buffer.from(candidate.replaceAll('-', '+').replaceAll('_', '/'), 'base64');
  }
  if (!bytes || bytes.length !== 32) throw new TypeError(`${name} must be one SHA-256 digest`);
  const normalizedHex = bytes.toString('hex');
  return Object.freeze({
    hex: normalizedHex,
    base64: bytes.toString('base64'),
    base64url: bytes.toString('base64url'),
    assetLinks: /** @type {string[]} */ (normalizedHex.toUpperCase().match(/../g)).join(':'),
  });
}

function assertLegacyCertificatePins(env, certificate) {
  for (const [name, values] of /** @type {[string, string[]][]} */ ([
    ['MOBILE_ANDROID_APK_KEY_HASHES', list(env.MOBILE_ANDROID_APK_KEY_HASHES)],
    ['MOBILE_ANDROID_CERTIFICATE_DIGESTS', list(env.MOBILE_ANDROID_CERTIFICATE_DIGESTS)],
    ['MOBILE_ANDROID_ASSETLINKS_CERT_SHA256', list(env.MOBILE_ANDROID_ASSETLINKS_CERT_SHA256)],
  ])) {
    if (values.length === 0) continue;
    if (values.length !== 1 || normalizeAndroidSigningCertificate(values[0], name).hex !== certificate.hex) {
      throw new TypeError(`${name} does not match MOBILE_ANDROID_SIGNING_CERT_SHA256`);
    }
  }
}

function boolean(value, fallback) {
  if (value == null || value === '') return fallback;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new TypeError('mobile boolean settings must be true or false');
}

function positiveIntegerList(value, fallback) {
  const selected = value == null || String(value).trim() === '' ? fallback : value;
  const values = list(selected);
  if (values.some((item) => !/^\d+$/.test(item) || Number(item) <= 0 || !Number.isSafeInteger(Number(item)))) {
    throw new TypeError('mobile integer lists must contain positive safe integers');
  }
  return values.map(Number);
}

function boundedInteger(value, fallback, name, minimum, maximum) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new TypeError(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return parsed;
}

export function mobileAndroidOrigin(keyHash) {
  if (!B64U_SHA256.test(keyHash || '')) throw new TypeError('Android APK key hash must be an unpadded base64url SHA-256 value');
  return `android:apk-key-hash:${keyHash}`;
}

export function getMobileConfig({ env = process.env, production = env.NODE_ENV === 'production' } = {}) {
  const iosBundleId = env.MOBILE_IOS_BUNDLE_ID || MOBILE_APP_ID;
  const androidPackageName = env.MOBILE_ANDROID_PACKAGE_NAME || MOBILE_APP_ID;
  const appleTeamId = env.MOBILE_APPLE_TEAM_ID || MOBILE_APPLE_TEAM_ID;
  const profileId = env.MOBILE_PROFILE_ID || MOBILE_PROFILE_ID;
  const rpId = env.MOBILE_RP_ID || MOBILE_RP_ID;
  const iosOrigin = env.MOBILE_IOS_ORIGIN || MOBILE_IOS_ORIGIN;
  if (!APP_ID.test(iosBundleId) || !APP_ID.test(androidPackageName)) {
    throw new TypeError('mobile application identities must be reverse-domain identifiers');
  }
  if (!PROFILE_ID.test(profileId)) throw new TypeError('MOBILE_PROFILE_ID is malformed');
  if (!RP_ID.test(rpId) || rpId !== rpId.toLowerCase()) throw new TypeError('MOBILE_RP_ID must be a lowercase DNS name');
  let parsedOrigin;
  try { parsedOrigin = new URL(iosOrigin); } catch { throw new TypeError('MOBILE_IOS_ORIGIN must be an HTTPS origin'); }
  if (parsedOrigin.protocol !== 'https:' || parsedOrigin.origin !== iosOrigin || parsedOrigin.hostname !== rpId) {
    throw new TypeError('MOBILE_IOS_ORIGIN must be an HTTPS origin on MOBILE_RP_ID');
  }
  const canonicalCertificate = env.MOBILE_ANDROID_SIGNING_CERT_SHA256
    || (!production ? MOBILE_ANDROID_DEBUG_KEY_HASH : null);
  const androidSigningCertificate = normalizeAndroidSigningCertificate(
    canonicalCertificate,
    'MOBILE_ANDROID_SIGNING_CERT_SHA256',
  );
  assertLegacyCertificatePins(env, androidSigningCertificate);
  if (!/^[A-Z0-9]{10}$/.test(appleTeamId)) throw new TypeError('MOBILE_APPLE_TEAM_ID must be a 10-character Team ID');
  const appleAllowedValidationCategories = positiveIntegerList(
    env.MOBILE_APPLE_ALLOWED_VALIDATION_CATEGORIES,
    production ? '2,4' : '3',
  );
  if (appleAllowedValidationCategories.some((category) => category > 10 || [7, 8, 9].includes(category))) {
    throw new TypeError('MOBILE_APPLE_ALLOWED_VALIDATION_CATEGORIES contains a reserved or unknown category');
  }
  const appleAllowedBundleVersions = list(env.MOBILE_APPLE_ALLOWED_BUNDLE_VERSIONS || '1');
  if (appleAllowedBundleVersions.some((version) => !/^[A-Za-z0-9.-]{1,64}$/.test(version))) {
    throw new TypeError('MOBILE_APPLE_ALLOWED_BUNDLE_VERSIONS contains an invalid version');
  }
  const androidAllowedVersionCodes = positiveIntegerList(env.MOBILE_ANDROID_ALLOWED_VERSION_CODES, '1');

  return Object.freeze({
    iosBundleId,
    androidPackageName,
    appleTeamId,
    profileId,
    rpId,
    iosOrigin,
    androidSigningCertificate,
    androidSigningCertificateSha256Hex: androidSigningCertificate.hex,
    androidKeyHashes: [androidSigningCertificate.base64url],
    androidOrigins: [mobileAndroidOrigin(androidSigningCertificate.base64url)],
    androidCertificateDigests: [androidSigningCertificate.base64url],
    androidAssetLinksFingerprints: [androidSigningCertificate.assetLinks],
    androidConfigured: true,
    appleEnvironment: production ? 'production' : 'development',
    appleAllowedValidationCategories,
    appleAllowedBundleVersions,
    appleRequireRuntimeSignals: boolean(env.MOBILE_APPLE_REQUIRE_RUNTIME_SIGNALS, false),
    androidAllowedVersionCodes,
    androidMinimumSdkVersion: boundedInteger(
      env.MOBILE_ANDROID_MIN_SDK_VERSION,
      production ? 33 : 26,
      'MOBILE_ANDROID_MIN_SDK_VERSION',
      26,
      100,
    ),
    androidRequirePlayProtect: boolean(env.MOBILE_ANDROID_REQUIRE_PLAY_PROTECT, production),
    maxChallengeAgeMs: boundedInteger(
      env.MOBILE_CHALLENGE_TTL_MS, 300_000, 'MOBILE_CHALLENGE_TTL_MS', 30_000, 600_000,
    ),
    pairingTtlMs: boundedInteger(
      env.MOBILE_PAIRING_TTL_MS, 10 * 60_000, 'MOBILE_PAIRING_TTL_MS', 60_000, 3_600_000,
    ),
    sessionTtlMs: boundedInteger(
      env.MOBILE_SESSION_TTL_MS, 30 * 24 * 60 * 60_000,
      'MOBILE_SESSION_TTL_MS', 300_000, 90 * 24 * 60 * 60_000,
    ),
  });
}
