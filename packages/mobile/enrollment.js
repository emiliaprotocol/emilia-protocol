// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

const verifier = await import('@emilia-protocol/verify')
  .catch(() => import('../verify/index.js'));
const { canonicalize, isCanonicalizable } = verifier;

export const MOBILE_ENROLLMENT_CHALLENGE_VERSION = 'EP-MOBILE-ENROLLMENT-CHALLENGE-v1';
export const MOBILE_ENROLLMENT_VERSION = 'EP-MOBILE-ENROLLMENT-v1';

const ID = /^[A-Za-z0-9:_.@-]{3,256}$/;
const B64U = /^[A-Za-z0-9_-]+$/;

function record(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
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
 * Enrollment is deliberately adapter-driven. The WebAuthn adapter must perform
 * full registration attestation verification and return an ES256/P-256 SPKI.
 * The platform adapter must verify App Attest or Play Integrity enrollment
 * evidence against the exact platform_request_hash.
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
    async issue({ approverId, platform, appId, rpId, origin, userName, displayName, caller = null } = {}) {
      if (!ID.test(approverId || '') || !['ios', 'android'].includes(platform)
          || !ID.test(appId || '') || typeof rpId !== 'string' || !rpId
          || typeof origin !== 'string' || !origin.startsWith('https://')
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
          user: challenge.user,
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

    async complete({ challenge, response, caller = null } = {}) {
      if (!record(challenge) || challenge['@version'] !== 'AE-CHALLENGE-v1'
          || challenge.challenge_profile !== MOBILE_ENROLLMENT_CHALLENGE_VERSION
          || !record(response) || response['@version'] !== MOBILE_ENROLLMENT_VERSION
          || response.enrollment_id !== challenge.enrollment_id
          || response.approver_id !== challenge.approver_id
          || response.platform !== challenge.platform
          || response.app_id !== challenge.app_id
          || response.platform_request_hash !== challenge.platform_request_hash
          || response.requested_valid_to !== challenge.enrollment_valid_to
          || !record(response.passkey_registration)
          || !record(response.platform_attestation)
          || !ID.test(response.attestation_key_id || '')) {
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
          expected_request_hash: challenge.platform_request_hash,
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
      if (platform?.valid !== true || platform.request_hash !== challenge.platform_request_hash
          || platform.app_id !== challenge.app_id || platform.platform !== challenge.platform
          || platform.attestation_key_id !== response.attestation_key_id
          || platform.hardware_backed !== true || platform.strong_integrity !== true) {
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
  buildMobileEnrollmentBinding,
  createMobileEnrollmentService,
};
