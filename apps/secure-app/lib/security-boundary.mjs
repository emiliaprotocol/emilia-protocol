// SPDX-License-Identifier: Apache-2.0

/**
 * Pure security-boundary helpers shared by the Expo shell and its Node tests.
 *
 * The Expo shell has an exportable JavaScript P-256 key. These helpers make
 * that limitation executable: software mode is allowed only by an explicit
 * policy, while hardware-provenance policies always refuse in this build.
 */

export const SOFTWARE_KEY_PROVENANCE = 'software_exportable';

const POLICY_MEMBERS = new Set(['requiredKeyProvenance', 'userVerification']);
const SESSION_MEMBERS = new Set([
  'accessToken', 'expiresAt', 'approverId', 'profileId', 'platform', 'appId',
]);
const MOBILE_TOKEN = /^ep_mobile_[A-Za-z0-9_-]{43}$/;
const APP_ID = /^[A-Za-z0-9:_.@-]{3,256}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

function exactMembers(value, members) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).length === members.size
    && Object.keys(value).every((key) => members.has(key));
}

/**
 * Require callers to choose both provenance and user-verification semantics.
 * There is deliberately no permissive default.
 */
export function normalizeSigningPolicy(policy) {
  if (!exactMembers(policy, POLICY_MEMBERS)
      || !['software_allowed', 'hardware_attested_required'].includes(policy.requiredKeyProvenance)
      || !['biometric_only', 'biometric_or_device_passcode'].includes(policy.userVerification)) {
    throw new TypeError('signing policy must explicitly choose key provenance and user verification');
  }
  return Object.freeze({
    requiredKeyProvenance: policy.requiredKeyProvenance,
    userVerification: policy.userVerification,
  });
}

/** Refuse an exportable software key whenever policy requires hardware proof. */
export function assertSoftwareSignerAllowed(policy) {
  const normalized = normalizeSigningPolicy(policy);
  if (normalized.requiredKeyProvenance !== 'software_allowed') {
    throw new Error('hardware_provenance_required: this Expo build has only an exportable software key');
  }
  return normalized;
}

/**
 * Execute the OS owner-verification policy without overstating which factor ran.
 * `biometric_only` disables device-passcode fallback and requires enrolled
 * biometric hardware. `biometric_or_device_passcode` uses the OS device-owner
 * policy; Expo does not disclose which permitted factor succeeded.
 */
export async function authenticateForPolicy(localAuthentication, policy, promptMessage = 'Authorize local signature') {
  const normalized = normalizeSigningPolicy(policy);
  if (!localAuthentication || typeof localAuthentication.authenticateAsync !== 'function') {
    return { ok: false, reason: 'authentication_unavailable' };
  }

  try {
    if (normalized.userVerification === 'biometric_only') {
      const hasHardware = await localAuthentication.hasHardwareAsync();
      const enrolled = await localAuthentication.isEnrolledAsync();
      if (!hasHardware || !enrolled) return { ok: false, reason: 'no_biometric_enrolled' };
    } else {
      const level = await localAuthentication.getEnrolledLevelAsync();
      if (!Number.isInteger(level) || level <= 0) {
        return { ok: false, reason: 'no_device_owner_authentication' };
      }
    }

    const biometricOnly = normalized.userVerification === 'biometric_only';
    const result = await localAuthentication.authenticateAsync({
      promptMessage,
      disableDeviceFallback: biometricOnly,
      fallbackLabel: biometricOnly ? '' : 'Use device passcode',
      biometricsSecurityLevel: 'strong',
    });
    if (!result?.success) return { ok: false, reason: result?.error || 'denied' };

    return {
      ok: true,
      method: biometricOnly ? 'biometric' : 'device_owner_authentication',
      policy: normalized.userVerification,
    };
  } catch {
    return { ok: false, reason: 'authentication_unavailable' };
  }
}

/** Parse only a complete, unexpired server-minted paired session. */
export function validatePairedSession(value, now = Date.now()) {
  if (!exactMembers(value, SESSION_MEMBERS)
      || !MOBILE_TOKEN.test(value.accessToken || '')
      || typeof value.expiresAt !== 'string'
      || !RFC3339_UTC.test(value.expiresAt)
      || !Number.isFinite(Date.parse(value.expiresAt))
      || Date.parse(value.expiresAt) <= now
      || typeof value.approverId !== 'string' || value.approverId.length < 1 || value.approverId.length > 256
      || typeof value.profileId !== 'string' || value.profileId.length < 1 || value.profileId.length > 256
      || !['ios', 'android'].includes(value.platform)
      || !APP_ID.test(value.appId || '')) {
    return null;
  }
  return Object.freeze({
    accessToken: value.accessToken,
    expiresAt: value.expiresAt,
    approverId: value.approverId,
    profileId: value.profileId,
    platform: value.platform,
    appId: value.appId,
  });
}

/** Bearer authorization is derived only from a validated runtime session. */
export function authorizationHeadersForSession(session, now = Date.now()) {
  const validated = validatePairedSession(session, now);
  if (!validated) throw new Error('paired_mobile_session_required');
  return { authorization: `Bearer ${validated.accessToken}` };
}

/**
 * SecureStore adapter with fail-closed corruption and expiry handling. Tests
 * inject an in-memory implementation; the app supplies expo-secure-store.
 */
export function createPairedSessionVault({
  secureStore,
  itemName = 'ep_secure_app_mobile_session_v1',
  storageOptions = {},
  now = () => Date.now(),
}) {
  if (!secureStore
      || typeof secureStore.getItemAsync !== 'function'
      || typeof secureStore.setItemAsync !== 'function'
      || typeof secureStore.deleteItemAsync !== 'function') {
    throw new TypeError('a SecureStore-compatible implementation is required');
  }

  return Object.freeze({
    async save(session) {
      const validated = validatePairedSession(session, now());
      if (!validated) throw new Error('refusing_to_store_invalid_mobile_session');
      await secureStore.setItemAsync(itemName, JSON.stringify(validated), storageOptions);
      return validated;
    },

    async load() {
      const raw = await secureStore.getItemAsync(itemName, storageOptions);
      if (!raw) return null;
      let parsed = null;
      try {
        parsed = JSON.parse(raw);
      } catch {
        // handled as an invalid record below
      }
      const validated = validatePairedSession(parsed, now());
      if (validated) return validated;
      await secureStore.deleteItemAsync(itemName, storageOptions).catch(() => undefined);
      return null;
    },

    async clear() {
      await secureStore.deleteItemAsync(itemName, storageOptions);
    },
  });
}
