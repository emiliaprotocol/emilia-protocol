// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

const verifier = await import('@emilia-protocol/verify')
  .catch(() => import('../verify/index.js'));
const { canonicalize, isCanonicalizable } = verifier;

export const MOBILE_ENROLLMENT_CHALLENGE_VERSION = 'EP-MOBILE-ENROLLMENT-CHALLENGE-v1';
export const MOBILE_ENROLLMENT_VERSION = 'EP-MOBILE-ENROLLMENT-v1';
export const MOBILE_ANDROID_KEY_BINDING_VERSION = 'EP-MOBILE-ANDROID-KEY-BINDING-v1';

const ID = /^[A-Za-z0-9:_.@-]{3,256}$/;
const ATTESTATION_KEY_ID = /^[A-Za-z0-9:._+/=-]{3,512}$/;
const ANDROID_APK_ORIGIN = /^android:apk-key-hash:[A-Za-z0-9_-]{43}$/;
const B64U = /^[A-Za-z0-9_-]+$/;
const ANDROID_KEY_ID = /^android-keystore:sha256:[A-Za-z0-9_-]{43}$/;
const ENROLLMENT_RESPONSE_MEMBERS = new Set([
  '@version', 'enrollment_id', 'approver_id', 'platform', 'app_id',
  'platform_request_hash', 'attestation_key_id', 'requested_valid_to',
  'passkey_registration', 'platform_attestation',
]);
const PLATFORM_ATTESTATION_MEMBERS = new Set(['format', 'token', 'request_hash', 'device_key']);
const ANDROID_DEVICE_KEY_MEMBERS = new Set(['algorithm', 'key_id', 'public_key_spki', 'signature']);

function record(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function exactMembers(value, allowed) {
  return record(value) && Object.keys(value).every((key) => allowed.has(key));
}

function instant(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
}

function hash(value) {
  if (!isCanonicalizable(value)) throw new TypeError('enrollment binding is not canonicalizable');
  return crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('base64url');
}

function randomId(prefix, bytes = 16) {
  return `${prefix}${crypto.randomBytes(bytes).toString('base64url')}`;
}

function boundedBase64url(value, maxBytes) {
  if (typeof value !== 'string' || !B64U.test(value)) return false;
  try {
    const bytes = Buffer.from(value, 'base64url');
    return bytes.length > 0 && bytes.length <= maxBytes;
  } catch {
    return false;
  }
}

function validEnrollmentOrigin(value) {
  if (typeof value !== 'string' || value.length > 512) return false;
  if (ANDROID_APK_ORIGIN.test(value)) return true;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && parsed.username === '' && parsed.password === '';
  } catch {
    return false;
  }
}

function isP256Spki(value) {
  if (!boundedBase64url(value, 4096)) return false;
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(value, 'base64url'), format: 'der', type: 'spki' });
    return key.asymmetricKeyType === 'ec'
      && ['prime256v1', 'P-256'].includes(key.asymmetricKeyDetails?.namedCurve);
  } catch {
    return false;
  }
}

function failure(verdict, reason) {
  return { ok: false, verdict, reason, enrollment: null };
}

export function buildMobileEnrollmentBinding(challenge) {
  return {
    '@version': MOBILE_ENROLLMENT_CHALLENGE_VERSION,
    enrollment_id: challenge.enrollment_id,
    challenge: challenge.challenge,
    approver_id: challenge.approver_id,
    platform: challenge.platform,
    app_id: challenge.app_id,
    rp_id: challenge.rp_id,
    origin: challenge.origin,
    enrollment_valid_to: challenge.enrollment_valid_to,
    issued_at: challenge.issued_at,
    expires_at: challenge.expires_at,
  };
}

/**
 * @param {{ challengeRequestHash?: string, keyId?: string, publicKeySpki?: string }} [params]
 */
export function buildMobileAndroidKeyBinding({ challengeRequestHash, keyId, publicKeySpki } = {}) {
  if (!boundedBase64url(challengeRequestHash, 32) || Buffer.from(challengeRequestHash, 'base64url').length !== 32
      || !ANDROID_KEY_ID.test(keyId || '') || !isP256Spki(publicKeySpki)) {
    throw new TypeError('Android enrollment device key binding is malformed');
  }
  return {
    '@version': MOBILE_ANDROID_KEY_BINDING_VERSION,
    challenge_request_hash: challengeRequestHash,
    algorithm: 'ES256',
    key_id: keyId,
    public_key_spki: publicKeySpki,
  };
}

function verifyAndroidDeviceKey(challenge, response) {
  const deviceKey = response.platform_attestation?.device_key;
  if (!exactMembers(deviceKey, ANDROID_DEVICE_KEY_MEMBERS)
      || deviceKey.algorithm !== 'ES256'
      || deviceKey.key_id !== response.attestation_key_id
      || !ANDROID_KEY_ID.test(deviceKey.key_id || '')
      || !isP256Spki(deviceKey.public_key_spki)
      || !boundedBase64url(deviceKey.signature, 256)) return null;
  try {
    const publicKeyBytes = Buffer.from(deviceKey.public_key_spki, 'base64url');
    const derivedKeyId = `android-keystore:sha256:${crypto.createHash('sha256').update(publicKeyBytes).digest('base64url')}`;
    if (derivedKeyId !== deviceKey.key_id) return null;
    const binding = buildMobileAndroidKeyBinding({
      challengeRequestHash: challenge.platform_request_hash,
      keyId: deviceKey.key_id,
      publicKeySpki: deviceKey.public_key_spki,
    });
    const requestHash = hash(binding);
    if (response.platform_attestation.request_hash !== requestHash) return null;
    const key = crypto.createPublicKey({ key: publicKeyBytes, format: 'der', type: 'spki' });
    const valid = crypto.verify(
      'sha256',
      Buffer.from(canonicalize(binding), 'utf8'),
      key,
      Buffer.from(deviceKey.signature, 'base64url'),
    );
    return valid ? { binding, requestHash, publicKeySpki: deviceKey.public_key_spki } : null;
  } catch {
    return null;
  }
}

/**
 * Enrollment is deliberately adapter-driven. The WebAuthn adapter must perform
 * full registration attestation verification and return an ES256/P-256 SPKI.
 * The platform adapter must verify App Attest or Play Integrity enrollment
 * evidence against the exact platform_request_hash.
 */
/**
 * @typedef {object} MobileEnrollmentServiceOptions
 * @property {{ register: (challenge: any) => Promise<boolean>, consume: (challenge: any) => Promise<boolean>, durable?: boolean }} [challengeStore]
 * @property {{ enrollAtomically: (args: any) => Promise<boolean>, durable?: boolean }} [directory]
 * @property {(args: any) => Promise<any>} [verifyPasskeyRegistration]
 * @property {(args: any) => Promise<any>} [verifyPlatformEnrollment]
 * @property {(args: any) => Promise<boolean>} [authorizeEnrollment]
 * @property {() => string} [clock]
 * @property {number} [ttlMs]
 * @property {number} [enrollmentValidityMs]
 * @property {boolean} [allowEphemeral]
 */

/**
 * @param {MobileEnrollmentServiceOptions} [params]
 */
export function createMobileEnrollmentService({
  challengeStore,
  directory,
  verifyPasskeyRegistration,
  verifyPlatformEnrollment,
  authorizeEnrollment,
  clock = () => new Date().toISOString(),
  ttlMs = 300_000,
  enrollmentValidityMs = 31_536_000_000,
  allowEphemeral = false,
} = {}) {
  if (typeof challengeStore?.register !== 'function' || typeof challengeStore?.consume !== 'function') {
    throw new TypeError('challengeStore must implement async register() and consume()');
  }
  if (typeof directory?.enrollAtomically !== 'function') {
    throw new TypeError('directory must implement async enrollAtomically()');
  }
  if (typeof verifyPasskeyRegistration !== 'function' || typeof verifyPlatformEnrollment !== 'function') {
    throw new TypeError('both enrollment verification adapters are required');
  }
  if (typeof authorizeEnrollment !== 'function') {
    throw new TypeError('authorizeEnrollment must bind the agency caller to the approver');
  }
  if (!allowEphemeral && challengeStore.durable !== true) throw new TypeError('durable challengeStore is required');
  if (!allowEphemeral && directory.durable !== true) throw new TypeError('durable enrollment directory is required');
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 60_000 || ttlMs > 900_000) {
    throw new TypeError('ttlMs must be an integer from 60000 to 900000');
  }
  if (!Number.isSafeInteger(enrollmentValidityMs)
      || enrollmentValidityMs < 86_400_000 || enrollmentValidityMs > 157_680_000_000) {
    throw new TypeError('enrollmentValidityMs must be an integer from one day to five years');
  }

  return {
    /**
     * @param {{ approverId?: string, platform?: string, appId?: string, rpId?: string, origin?: string, userName?: string, displayName?: string, caller?: any }} [params]
     */
    async issue({ approverId, platform, appId, rpId, origin, userName, displayName, caller = null } = {}) {
      if (!ID.test(approverId || '') || !['ios', 'android'].includes(platform)
          || !ID.test(appId || '') || typeof rpId !== 'string' || !rpId
          || !validEnrollmentOrigin(origin)
          || typeof userName !== 'string' || !userName
          || typeof displayName !== 'string' || !displayName) {
        return { ok: false, verdict: 'refuse_malformed', challenge: null };
      }
      try {
        if ((await authorizeEnrollment({
          operation: 'mobile.enrollment.issue',
          caller,
          approver_id: approverId,
          platform,
          app_id: appId,
          rp_id: rpId,
          origin,
        })) !== true) {
          return { ok: false, verdict: 'refuse_unauthorized', challenge: null };
        }
      } catch {
        return { ok: false, verdict: 'refuse_unauthorized', challenge: null };
      }
      const issuedAt = clock();
      const issued = instant(issuedAt);
      if (issued === null) return { ok: false, verdict: 'refuse_malformed', challenge: null };
      const challenge = {
        '@version': 'AE-CHALLENGE-v1',
        challenge_profile: MOBILE_ENROLLMENT_CHALLENGE_VERSION,
        challenge_id: randomId('enr_'),
        enrollment_id: null,
        nonce: randomId('reg_', 32),
        challenge: randomId('reg_', 32),
        approver_id: approverId,
        platform,
        app_id: appId,
        rp_id: rpId,
        origin,
        user: {
          id: Buffer.from(approverId, 'utf8').toString('base64url'),
          name: userName,
          display_name: displayName,
        },
        enrollment_valid_to: new Date(issued + enrollmentValidityMs).toISOString(),
        issued_at: issuedAt,
        expires_at: new Date(issued + ttlMs).toISOString(),
      };
      challenge.enrollment_id = challenge.challenge_id;
      const binding = buildMobileEnrollmentBinding(challenge);
      const complete = {
        ...challenge,
        webauthn: {
          rp: { id: rpId, name: 'EMILIA Government Approval' },
          challenge: challenge.challenge,
          user: { ...challenge.user },
          pub_key_cred_params: [{ type: 'public-key', alg: -7 }],
          authenticator_selection: {
            resident_key: 'preferred',
            user_verification: 'required',
          },
          attestation: 'direct',
          timeout_ms: ttlMs,
        },
        platform_binding: binding,
        platform_request_hash: hash(binding),
      };
      try {
        if ((await challengeStore.register(complete)) !== true) {
          return { ok: false, verdict: 'refuse_replay', challenge: null };
        }
      } catch {
        return { ok: false, verdict: 'refuse_store_unavailable', challenge: null };
      }
      return { ok: true, verdict: 'issued', challenge: complete };
    },

    /**
     * @param {{ challenge?: any, response?: any, caller?: any }} [params]
     */
    async complete({ challenge, response, caller = null } = {}) {
      if (!record(challenge) || challenge['@version'] !== 'AE-CHALLENGE-v1'
          || challenge.challenge_profile !== MOBILE_ENROLLMENT_CHALLENGE_VERSION
          || !exactMembers(response, ENROLLMENT_RESPONSE_MEMBERS)
          || response['@version'] !== MOBILE_ENROLLMENT_VERSION
          || response.enrollment_id !== challenge.enrollment_id
          || response.approver_id !== challenge.approver_id
          || response.platform !== challenge.platform
          || response.app_id !== challenge.app_id
          || response.platform_request_hash !== challenge.platform_request_hash
          || response.requested_valid_to !== challenge.enrollment_valid_to
          || !record(response.passkey_registration)
          || !exactMembers(response.platform_attestation, PLATFORM_ATTESTATION_MEMBERS)
          || typeof response.platform_attestation.format !== 'string'
          || !boundedBase64url(response.platform_attestation.token, 128 * 1024)
          || !boundedBase64url(response.platform_attestation.request_hash, 32)
          || !ATTESTATION_KEY_ID.test(response.attestation_key_id || '')) {
        return failure('refuse_malformed', 'enrollment response does not match the challenge');
      }
      try {
        if ((await authorizeEnrollment({
          operation: 'mobile.enrollment.complete',
          caller,
          approver_id: challenge.approver_id,
          platform: challenge.platform,
          app_id: challenge.app_id,
          rp_id: challenge.rp_id,
          origin: challenge.origin,
          enrollment_id: challenge.enrollment_id,
        })) !== true) {
          return failure('refuse_unauthorized', 'caller is not authorized to complete this enrollment');
        }
      } catch {
        return failure('refuse_unauthorized', 'caller is not authorized to complete this enrollment');
      }
      const now = instant(clock());
      if (now === null || now < instant(challenge.issued_at) || now > instant(challenge.expires_at)) {
        return failure('refuse_challenge_expired', 'enrollment challenge is not fresh');
      }
      if (hash(buildMobileEnrollmentBinding(challenge)) !== challenge.platform_request_hash) {
        return failure('refuse_action_mismatch', 'enrollment binding was changed');
      }

      const androidKey = challenge.platform === 'android'
        ? verifyAndroidDeviceKey(challenge, response)
        : null;
      if ((challenge.platform === 'android' && androidKey === null)
          || (challenge.platform === 'ios'
            && (response.platform_attestation.device_key !== undefined
              || response.platform_attestation.request_hash !== challenge.platform_request_hash))) {
        return failure('refuse_attestation', 'platform enrollment device-key binding is invalid');
      }

      let passkey;
      let platform;
      try {
        passkey = await verifyPasskeyRegistration({
          response: response.passkey_registration,
          expectedChallenge: challenge.challenge,
          expectedOrigin: challenge.origin,
          expectedRPID: challenge.rp_id,
          requireUserVerification: true,
          allowedAlgorithm: 'ES256',
        });
        platform = await verifyPlatformEnrollment({
          format: response.platform_attestation.format,
          token: response.platform_attestation.token,
          expected_request_hash: androidKey?.requestHash ?? challenge.platform_request_hash,
          expected_binding: androidKey?.binding ?? buildMobileEnrollmentBinding(challenge),
          expected_app_id: challenge.app_id,
          expected_attestation_key_id: response.attestation_key_id,
          platform: challenge.platform,
        });
      } catch {
        return failure('refuse_attestation', 'an enrollment verifier failed');
      }
      if (passkey?.valid !== true || passkey.algorithm !== 'ES256'
          || !boundedBase64url(passkey.credential_id, 2048) || !isP256Spki(passkey.public_key_spki)
          || !Number.isSafeInteger(passkey.sign_count) || passkey.sign_count < 0) {
        return failure('refuse_webauthn', 'passkey registration did not satisfy the pinned profile');
      }
      const expectedPlatformRequestHash = androidKey?.requestHash ?? challenge.platform_request_hash;
      if (platform?.valid !== true || platform.request_hash !== expectedPlatformRequestHash
          || platform.app_id !== challenge.app_id || platform.platform !== challenge.platform
          || platform.attestation_key_id !== response.attestation_key_id
          || platform.hardware_backed !== true || platform.strong_integrity !== true
          || (challenge.platform === 'ios'
            && (typeof platform.platform_public_key !== 'string'
              || platform.platform_public_key.length < 64
              || platform.platform_public_key.length > 8192
              || !platform.platform_public_key.includes('BEGIN PUBLIC KEY')))
          || (challenge.platform === 'android'
            && platform.platform_public_key != null
            && platform.platform_public_key !== androidKey.publicKeySpki)) {
        return failure('refuse_attestation', 'platform enrollment did not satisfy the pinned profile');
      }

      try {
        if ((await challengeStore.consume(challenge)) !== true) {
          return failure('refuse_replay', 'enrollment challenge was changed or already consumed');
        }
      } catch {
        return failure('refuse_store_unavailable', 'enrollment challenge store is unavailable');
      }

      const enrollment = {
        device_key_id: randomId('ep:key:mobile-'),
        credential_id: passkey.credential_id,
        public_key_spki: passkey.public_key_spki,
        approver_id: challenge.approver_id,
        platform: challenge.platform,
        app_id: challenge.app_id,
        attestation_key_id: response.attestation_key_id,
        status: 'active',
        valid_from: clock(),
        valid_to: challenge.enrollment_valid_to,
        sign_count: passkey.sign_count,
        attestation_format: passkey.attestation_format || null,
        platform_public_key: challenge.platform === 'android'
          ? androidKey.publicKeySpki
          : platform.platform_public_key,
      };
      if (instant(enrollment.valid_from) === null || instant(enrollment.valid_to) === null
          || instant(enrollment.valid_to) <= instant(enrollment.valid_from)) {
        return failure('refuse_malformed', 'enrollment validity interval is malformed');
      }
      try {
        const stored = await directory.enrollAtomically({
          enrollment,
          event: {
            event_type: 'mobile.enrollment.created',
            enrollment_id: challenge.enrollment_id,
            approver_id: challenge.approver_id,
            device_key_id: enrollment.device_key_id,
            platform: challenge.platform,
            app_id: challenge.app_id,
          },
        });
        if (stored !== true) return failure('refuse_store_unavailable', 'enrollment was not durably stored');
      } catch {
        return failure('refuse_store_unavailable', 'enrollment directory is unavailable');
      }
      return { ok: true, verdict: 'enrolled', reason: null, enrollment };
    },
  };
}

export default {
  MOBILE_ENROLLMENT_CHALLENGE_VERSION,
  MOBILE_ENROLLMENT_VERSION,
  MOBILE_ANDROID_KEY_BINDING_VERSION,
  buildMobileEnrollmentBinding,
  buildMobileAndroidKeyBinding,
  createMobileEnrollmentService,
};
