// SPDX-License-Identifier: Apache-2.0
/**
 * @emilia-protocol/mobile
 *
 * A native-mobile ceremony profile over EP's existing Class-A WebAuthn
 * primitive. The passkey assertion remains independently verifiable offline.
 * Apple App Attest or Google Play Integrity is an additional, separately
 * verified evidence row bound to the same context hash; it is not a new trust
 * root and is never accepted from client-supplied status labels.
 */
import crypto from 'node:crypto';
import {
  createAppleAppAttestVerifier,
  createPlayIntegrityAttestationVerifier,
} from './attestation.js';
import { createGovernmentMobileController } from './government.js';
import { createMobileHttpHandler } from './http.js';
import { strictJsonGate } from './strict-json.js';
import {
  MOBILE_PRESENTATION_VERSION,
  normalizeControlledMobilePresentation,
  normalizeMobilePresentation,
  projectMobileAction,
  validControlledMobilePresentation,
  validMobilePresentation,
} from './presentation.js';
import {
  buildMobileAndroidKeyBinding,
  buildMobileEnrollmentBinding,
  createMobileEnrollmentService,
  MOBILE_ANDROID_KEY_BINDING_VERSION,
  MOBILE_ENROLLMENT_CHALLENGE_VERSION,
  MOBILE_ENROLLMENT_VERSION,
} from './enrollment.js';

const verifier = await import('@emilia-protocol/verify')
  .catch(() => import('../verify/index.js'));
const { canonicalize, isCanonicalizable, verifyWebAuthnSignoff } = verifier;

export const MOBILE_CHALLENGE_VERSION = 'EP-MOBILE-CHALLENGE-v1';
export const MOBILE_CEREMONY_VERSION = 'EP-MOBILE-CEREMONY-v1';
export const MOBILE_PROFILE_VERSION = 'EP-MOBILE-RELIANCE-PROFILE-v1';
export const MOBILE_ATTESTATION_BINDING_VERSION = 'EP-MOBILE-ATTESTATION-BINDING-v1';
export const MOBILE_ACK_VERSION = 'EP-MOBILE-ACK-v1';
export const MOBILE_EXECUTION_RECORD_VERSION = 'EP-MOBILE-EXECUTION-RECORD-v1';
export {
  MOBILE_PRESENTATION_VERSION,
  normalizeControlledMobilePresentation,
  normalizeMobilePresentation,
  projectMobileAction,
  validControlledMobilePresentation,
  validMobilePresentation,
};

const MOBILE_CHECK_NAMES = Object.freeze([
  'profile',
  'freshness',
  'action',
  'presentation',
  'signed_context',
  'platform',
  'app',
  'device_key',
  'origin',
  'webauthn',
  'attestation',
]);

export { createPlayIntegrityAttestationVerifier, createAppleAppAttestVerifier };
export { createGovernmentMobileController };
export { createMobileHttpHandler };
export {
  buildMobileAndroidKeyBinding,
  buildMobileEnrollmentBinding,
  createMobileEnrollmentService,
  MOBILE_ANDROID_KEY_BINDING_VERSION,
  MOBILE_ENROLLMENT_CHALLENGE_VERSION,
  MOBILE_ENROLLMENT_VERSION,
};

export const MOBILE_VERDICTS = Object.freeze([
  'verified',
  'refuse_malformed',
  'refuse_unauthorized',
  'refuse_profile_mismatch',
  'refuse_challenge_expired',
  'refuse_action_mismatch',
  'refuse_display_mismatch',
  'refuse_platform',
  'refuse_app',
  'refuse_device_key',
  'refuse_origin',
  'refuse_webauthn',
  'refuse_attestation_missing',
  'refuse_attestation',
  'refuse_counter_rollback',
  'refuse_replay',
  'refuse_rate_limited',
  'refuse_store_unavailable',
  'refuse_audit_unavailable',
]);

const PLATFORM_ATTESTATION_FORMAT = Object.freeze({
  ios: 'apple-app-attest',
  android: 'play-integrity-standard',
});
const HEX_256 = /^(?:sha256:)?[0-9a-f]{64}$/;
const B64U = /^[A-Za-z0-9_-]+$/;
const ID = /^[A-Za-z0-9:_.@-]{3,256}$/;
const ATTESTATION_KEY_ID = /^[A-Za-z0-9:._+/=-]{3,512}$/;
const ANDROID_APK_ORIGIN = /^android:apk-key-hash:[A-Za-z0-9_-]{43}$/;
const CANONICAL_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CONTEXT_MEMBERS = new Set([
  'ep_version', 'context_type', 'action_hash', 'policy_id', 'policy_hash',
  'initiator', 'approver', 'approver_index', 'required_approvals', 'nonce',
  'issued_at', 'expires_at', 'decision', 'display_hash', 'mobile_binding',
]);
const MOBILE_BINDING_MEMBERS = new Set([
  'profile', 'profile_hash', 'platform', 'app_id', 'device_key_id',
  'credential_id', 'attestation_key_id',
]);
const CHALLENGE_MEMBERS = new Set([
  '@version', 'challenge_profile', 'challenge_id', 'nonce', 'action', 'action_hash',
  'profile_hash', 'authorization_context', 'webauthn', 'presentation', 'issued_at',
  'expires_at', 'attestation',
]);
const WEBAUTHN_REQUEST_MEMBERS = new Set([
  'rp_id', 'challenge', 'credential_ids', 'user_verification', 'timeout_ms',
]);
const CHALLENGE_ATTESTATION_MEMBERS = new Set(['required', 'format', 'binding', 'request_hash']);
const RESPONSE_MEMBERS = new Set([
  '@version', 'challenge_id', 'nonce', 'platform', 'app_id', 'device_key_id',
  'credential_id', 'attestation_key_id', 'decision', 'display_hash', 'signoff', 'attestation',
]);
const SIGNOFF_MEMBERS = new Set(['context', 'webauthn']);
const WEBAUTHN_ASSERTION_MEMBERS = new Set(['authenticator_data', 'client_data_json', 'signature']);
const RESPONSE_ATTESTATION_MEMBERS = new Set(['format', 'token', 'device_key_signature']);

function isRecord(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function own(value, key) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function exactMembers(value, allowed) {
  return isRecord(value) && Object.keys(value).every((key) => allowed.has(key));
}

function hashBytes(value) {
  return crypto.createHash('sha256').update(value).digest();
}

function hashCanonicalBytes(value) {
  return hashBytes(Buffer.from(canonicalize(value), 'utf8'));
}

export function hashCanonical(value) {
  if (!isCanonicalizable(value)) throw new TypeError('value is outside the EP canonicalization profile');
  return `sha256:${hashCanonicalBytes(value).toString('hex')}`;
}

function equalCanonical(left, right) {
  try {
    return isCanonicalizable(left) && isCanonicalizable(right)
      && canonicalize(left) === canonicalize(right);
  } catch {
    return false;
  }
}

function parseInstant(value) {
  if (typeof value !== 'string' || !CANONICAL_INSTANT.test(value)) return null;
  const millis = Date.parse(value);
  if (!Number.isFinite(millis) || new Date(millis).toISOString() !== value) return null;
  return millis;
}

function validHash(value) {
  return typeof value === 'string' && HEX_256.test(value);
}

function normalizeHash(value) {
  return typeof value === 'string' ? value.toLowerCase().replace(/^sha256:/, '') : '';
}

function validId(value) {
  return typeof value === 'string' && ID.test(value);
}

function validAttestationKeyId(value) {
  return typeof value === 'string' && ATTESTATION_KEY_ID.test(value);
}

function validOrigin(value) {
  if (typeof value !== 'string' || value.length > 512) return false;
  if (ANDROID_APK_ORIGIN.test(value)) return true;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && parsed.username === '' && parsed.password === '';
  } catch {
    return false;
  }
}

function validB64u(value, maxBytes = 64 * 1024) {
  if (typeof value !== 'string' || !value || value.length > Math.ceil(maxBytes * 4 / 3) + 4 || !B64U.test(value)) return false;
  try {
    return Buffer.from(value, 'base64url').length > 0;
  } catch {
    return false;
  }
}

function randomId(prefix, bytes = 16) {
  return `${prefix}${crypto.randomBytes(bytes).toString('hex')}`;
}

function profileBody(profile) {
  if (!isRecord(profile)) return null;
  const { profile_hash: ignored, ...body } = profile;
  return body;
}

export function mobileProfileHash(profile) {
  const body = profileBody(profile);
  if (!body || !isCanonicalizable(body)) throw new TypeError('mobile profile is not canonicalizable');
  return hashCanonical(body);
}

function normalizeEnrollment(enrollment) {
  if (!isRecord(enrollment)) throw new TypeError('every enrollment must be an object');
  const normalized = {
    device_key_id: enrollment.device_key_id,
    credential_id: enrollment.credential_id,
    public_key_spki: enrollment.public_key_spki,
    approver_id: enrollment.approver_id,
    platform: enrollment.platform,
    app_id: enrollment.app_id,
    attestation_key_id: enrollment.attestation_key_id,
    status: enrollment.status || 'active',
    valid_from: enrollment.valid_from,
    valid_to: enrollment.valid_to,
    sign_count: enrollment.sign_count ?? 0,
  };
  if (!validId(normalized.device_key_id)
      || !validB64u(normalized.credential_id, 2048)
      || !validB64u(normalized.public_key_spki, 4096)
      || !validId(normalized.approver_id)
      || !['ios', 'android'].includes(normalized.platform)
      || !validId(normalized.app_id)
      || !validAttestationKeyId(normalized.attestation_key_id)
      || !['active', 'revoked'].includes(normalized.status)
      || parseInstant(normalized.valid_from) === null
      || parseInstant(normalized.valid_to) === null
      || parseInstant(normalized.valid_from) >= parseInstant(normalized.valid_to)
      || !Number.isSafeInteger(normalized.sign_count) || normalized.sign_count < 0) {
    throw new TypeError('mobile enrollment is malformed');
  }
  return normalized;
}

export function createMobileRelianceProfile({
  profileId,
  rpId,
  allowedOrigins,
  acceptedApps,
  enrollments,
  attestationRequired = true,
  hardwareBackedRequired = true,
  strongIntegrityRequired = true,
  maxChallengeAgeMs = 300_000,
  counterPolicy = 'registration_baseline',
} = {}) {
  if (!validId(profileId) || typeof rpId !== 'string' || !rpId || rpId.length > 253) {
    throw new TypeError('profileId and rpId are required');
  }
  if (!Array.isArray(allowedOrigins) || allowedOrigins.length === 0
      || allowedOrigins.some((origin) => !validOrigin(origin))) {
    throw new TypeError('allowedOrigins must contain HTTPS or pinned Android APK origins');
  }
  if (!isRecord(acceptedApps)
      || !Array.isArray(acceptedApps.ios)
      || !Array.isArray(acceptedApps.android)
      || [...acceptedApps.ios, ...acceptedApps.android].length === 0
      || [...acceptedApps.ios, ...acceptedApps.android].some((appId) => !validId(appId))) {
    throw new TypeError('acceptedApps must contain ios and android arrays');
  }
  if (!Array.isArray(enrollments) || enrollments.length === 0) {
    throw new TypeError('at least one enrollment is required');
  }
  if (!Number.isSafeInteger(maxChallengeAgeMs) || maxChallengeAgeMs < 10_000 || maxChallengeAgeMs > 900_000) {
    throw new TypeError('maxChallengeAgeMs must be an integer from 10000 to 900000');
  }
  if (!['ignore', 'monotonic_if_nonzero', 'registration_baseline'].includes(counterPolicy)) {
    throw new TypeError('unsupported counterPolicy');
  }
  const normalizedEnrollments = enrollments.map(normalizeEnrollment)
    .sort((a, b) => a.device_key_id.localeCompare(b.device_key_id));
  if (new Set(normalizedEnrollments.map((item) => item.device_key_id)).size !== normalizedEnrollments.length) {
    throw new TypeError('device_key_id must be unique');
  }
  const profile = {
    '@version': MOBILE_PROFILE_VERSION,
    profile_id: profileId,
    rp_id: rpId,
    allowed_origins: [...new Set(allowedOrigins)].sort(),
    accepted_apps: {
      ios: [...new Set(acceptedApps.ios)].sort(),
      android: [...new Set(acceptedApps.android)].sort(),
    },
    requirements: {
      attestation_required: attestationRequired === true,
      hardware_backed_required: hardwareBackedRequired === true,
      strong_integrity_required: strongIntegrityRequired === true,
      max_challenge_age_ms: maxChallengeAgeMs,
      counter_policy: counterPolicy,
    },
    enrollments: normalizedEnrollments,
  };
  return { ...profile, profile_hash: mobileProfileHash(profile) };
}

function assertProfile(profile) {
  let normalized;
  try {
    normalized = createMobileRelianceProfile({
      profileId: profile?.profile_id,
      rpId: profile?.rp_id,
      allowedOrigins: profile?.allowed_origins,
      acceptedApps: profile?.accepted_apps,
      enrollments: profile?.enrollments,
      attestationRequired: profile?.requirements?.attestation_required,
      hardwareBackedRequired: profile?.requirements?.hardware_backed_required,
      strongIntegrityRequired: profile?.requirements?.strong_integrity_required,
      maxChallengeAgeMs: profile?.requirements?.max_challenge_age_ms,
      counterPolicy: profile?.requirements?.counter_policy,
    });
  } catch {
    normalized = null;
  }
  if (!normalized || !equalCanonical(profile, normalized)) {
    throw new TypeError('mobile reliance profile is malformed or its hash is stale');
  }
  return profile;
}

function enrollmentFor(profile, deviceKeyId) {
  return profile.enrollments.find((item) => item.device_key_id === deviceKeyId) || null;
}

function actionHash(action) {
  if (!isRecord(action) || !isCanonicalizable(action)) throw new TypeError('action must be a canonicalizable object');
  return hashCanonical(action);
}

function displayHash(presentation) {
  if (!isRecord(presentation) || !isCanonicalizable(presentation)) {
    throw new TypeError('presentation must be a canonicalizable object');
  }
  return hashCanonical(presentation);
}

function contextHash(context) {
  return hashCanonical(context);
}

export function buildMobileAuthorizationContext({
  actionHash,
  policyId = null,
  policyHash = null,
  initiatorId,
  approverId,
  approverIndex = 1,
  requiredApprovals = 1,
  nonce,
  issuedAt,
  expiresAt,
  decision,
  displayHash,
  profileHash,
  platform,
  appId,
  deviceKeyId,
  credentialId,
  attestationKeyId,
} = {}) {
  if (!validHash(actionHash) || (policyHash !== null && !validHash(policyHash))
      || !validId(initiatorId) || !validId(approverId)
      || !Number.isSafeInteger(approverIndex) || approverIndex < 1 || approverIndex > 1024
      || !Number.isSafeInteger(requiredApprovals) || requiredApprovals < 1 || requiredApprovals > 1024
      || !validId(nonce)
      || parseInstant(issuedAt) === null || parseInstant(expiresAt) === null
      || parseInstant(issuedAt) >= parseInstant(expiresAt)
      || !['approved', 'denied'].includes(decision) || !validHash(displayHash)
      || !validHash(profileHash) || !['ios', 'android'].includes(platform)
      || !validId(appId) || !validId(deviceKeyId) || !validB64u(credentialId, 2048)
      || !validAttestationKeyId(attestationKeyId)) {
    throw new TypeError('mobile authorization context input is malformed');
  }
  return {
    ep_version: '1.0',
    context_type: 'ep.signoff.v1',
    action_hash: actionHash,
    policy_id: policyId,
    policy_hash: policyHash,
    initiator: initiatorId,
    approver: approverId,
    approver_index: approverIndex,
    required_approvals: requiredApprovals,
    nonce,
    issued_at: issuedAt,
    expires_at: expiresAt,
    decision,
    display_hash: displayHash,
    mobile_binding: {
      profile: MOBILE_CHALLENGE_VERSION,
      profile_hash: profileHash,
      platform,
      app_id: appId,
      device_key_id: deviceKeyId,
      credential_id: credentialId,
      attestation_key_id: attestationKeyId,
    },
  };
}

export function buildMobileAttestationBinding(challenge) {
  const context = challenge?.authorization_context;
  if (!isRecord(context)) throw new TypeError('challenge authorization_context is required');
  return {
    '@version': MOBILE_ATTESTATION_BINDING_VERSION,
    challenge_id: challenge.challenge_id,
    nonce: challenge.nonce,
    action_hash: challenge.action_hash,
    context_hash: contextHash(context),
    profile_hash: challenge.profile_hash,
    rp_id: challenge.webauthn?.rp_id,
    platform: context.mobile_binding?.platform,
    app_id: context.mobile_binding?.app_id,
    device_key_id: context.mobile_binding?.device_key_id,
    attestation_key_id: context.mobile_binding?.attestation_key_id,
  };
}

export function createMobileChallenge({
  action,
  policy = null,
  policyId = null,
  initiatorId,
  approverId,
  approverIndex = 1,
  requiredApprovals = 1,
  decision,
  presentation,
  platform,
  appId,
  deviceKeyId,
  profile,
  issuedAt,
  expiresAt,
  challengeId = randomId('mob_'),
  nonce = randomId('sig_'),
} = {}) {
  assertProfile(profile);
  const enrollment = enrollmentFor(profile, deviceKeyId);
  if (!enrollment || enrollment.status !== 'active'
      || enrollment.platform !== platform || enrollment.app_id !== appId
      || enrollment.approver_id !== approverId) {
    throw new TypeError('active enrollment does not match the requested approver, platform, or app');
  }
  if (!profile.accepted_apps[platform]?.includes(appId)) throw new TypeError('app is not accepted by the profile');
  const issued = parseInstant(issuedAt);
  const expires = parseInstant(expiresAt);
  if (issued === null || expires === null || expires <= issued
      || expires - issued > profile.requirements.max_challenge_age_ms) {
    throw new TypeError('challenge validity window is malformed or exceeds the profile maximum');
  }
  if (!validId(challengeId) || !validId(nonce)) throw new TypeError('challengeId and nonce are malformed');

  const computedActionHash = actionHash(action);
  const normalizedPresentation = normalizeControlledMobilePresentation(action, presentation);
  const computedDisplayHash = displayHash(normalizedPresentation);
  const computedPolicyHash = policy === null ? null : hashCanonical(policy);
  const authorizationContext = buildMobileAuthorizationContext({
    actionHash: computedActionHash,
    policyId,
    policyHash: computedPolicyHash,
    initiatorId,
    approverId,
    approverIndex,
    requiredApprovals,
    nonce,
    issuedAt,
    expiresAt,
    decision,
    displayHash: computedDisplayHash,
    profileHash: profile.profile_hash,
    platform,
    appId,
    deviceKeyId,
    credentialId: enrollment.credential_id,
    attestationKeyId: enrollment.attestation_key_id,
  });
  const webauthnChallenge = hashCanonicalBytes(authorizationContext).toString('base64url');
  const base = {
    '@version': 'AE-CHALLENGE-v1',
    challenge_profile: MOBILE_CHALLENGE_VERSION,
    challenge_id: challengeId,
    nonce,
    action,
    action_hash: computedActionHash,
    profile_hash: profile.profile_hash,
    authorization_context: authorizationContext,
    webauthn: {
      rp_id: profile.rp_id,
      challenge: webauthnChallenge,
      credential_ids: [enrollment.credential_id],
      user_verification: 'required',
      timeout_ms: expires - issued,
    },
    presentation: normalizedPresentation,
    issued_at: issuedAt,
    expires_at: expiresAt,
  };
  const binding = buildMobileAttestationBinding(base);
  return {
    ...base,
    attestation: {
      required: profile.requirements.attestation_required,
      format: PLATFORM_ATTESTATION_FORMAT[platform],
      binding,
      request_hash: hashCanonicalBytes(binding).toString('base64url'),
    },
  };
}

function malformed(reason, checks = {}) {
  return { valid: false, verdict: 'refuse_malformed', decision: null, checks, reason };
}

function refused(verdict, reason, checks, extra = {}) {
  return { valid: false, verdict, decision: null, checks, reason, ...extra };
}

function parseClientData(signoff) {
  try {
    const bytes = Buffer.from(signoff.webauthn.client_data_json, 'base64url');
    if (bytes.length === 0 || bytes.length > 16 * 1024) return null;
    const text = bytes.toString('utf8');
    if (!strictJsonGate(text).ok) return null;
    const parsed = JSON.parse(text);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function parseSignCount(signoff) {
  try {
    const bytes = Buffer.from(signoff.webauthn.authenticator_data, 'base64url');
    return bytes.length >= 37 ? bytes.readUInt32BE(33) : null;
  } catch {
    return null;
  }
}

function validContextShape(context) {
  return isRecord(context)
    && isCanonicalizable(context)
    && Object.keys(context).every((key) => CONTEXT_MEMBERS.has(key))
    && context.ep_version === '1.0'
    && context.context_type === 'ep.signoff.v1'
    && Number.isSafeInteger(context.approver_index)
    && Number.isSafeInteger(context.required_approvals)
    && context.approver_index >= 1
    && context.required_approvals >= 1
    && context.approver_index <= 1024
    && context.required_approvals <= 1024
    && ['approved', 'denied'].includes(context.decision)
    && isRecord(context.mobile_binding)
    && Object.keys(context.mobile_binding).every((key) => MOBILE_BINDING_MEMBERS.has(key))
    && context.mobile_binding.profile === MOBILE_CHALLENGE_VERSION;
}

function validChallengeShape(challenge) {
  return exactMembers(challenge, CHALLENGE_MEMBERS)
    && exactMembers(challenge.webauthn, WEBAUTHN_REQUEST_MEMBERS)
    && exactMembers(challenge.attestation, CHALLENGE_ATTESTATION_MEMBERS)
    && validMobilePresentation(challenge.presentation);
}

function validResponseShape(response) {
  return exactMembers(response, RESPONSE_MEMBERS)
    && exactMembers(response.signoff, SIGNOFF_MEMBERS)
    && exactMembers(response.signoff?.webauthn, WEBAUTHN_ASSERTION_MEMBERS)
    && exactMembers(response.attestation, RESPONSE_ATTESTATION_MEMBERS)
    && typeof response.attestation?.format === 'string'
    && typeof response.attestation?.token === 'string';
}

function profileEnrollmentValidAt(enrollment, instant) {
  const at = parseInstant(instant);
  return enrollment.status === 'active'
    && at !== null
    && at >= parseInstant(enrollment.valid_from)
    && at <= parseInstant(enrollment.valid_to);
}

/**
 * Pure verification. It does not establish that the challenge was registered
 * or unused; use createMobileCeremonyService for durable one-time processing.
 */
export async function verifyMobileCeremony({
  challenge,
  response,
  profile,
  now,
  attestationVerifier,
} = {}) {
  const checks = {
    profile: false,
    freshness: false,
    action: false,
    presentation: false,
    signed_context: false,
    platform: false,
    app: false,
    device_key: false,
    origin: false,
    webauthn: false,
    attestation: false,
  };
  try {
    assertProfile(profile);
    if (!validChallengeShape(challenge)) {
      return malformed('mobile challenge shape or presentation is malformed', checks);
    }
    checks.profile = challenge['@version'] === 'AE-CHALLENGE-v1'
      && challenge.challenge_profile === MOBILE_CHALLENGE_VERSION
      && normalizeHash(challenge.profile_hash) === normalizeHash(profile.profile_hash);
    if (!checks.profile) return refused('refuse_profile_mismatch', 'challenge does not name the pinned profile', checks);
    if (!validResponseShape(response) || response['@version'] !== MOBILE_CEREMONY_VERSION
        || !validContextShape(challenge.authorization_context)
        || !isRecord(response.signoff) || !isRecord(response.signoff.webauthn)
        || !isRecord(response.attestation)) {
      return malformed('mobile ceremony or challenge shape is malformed', checks);
    }

    const nowMillis = parseInstant(now);
    const issued = parseInstant(challenge.issued_at);
    const expires = parseInstant(challenge.expires_at);
    const contextIssued = parseInstant(challenge.authorization_context.issued_at);
    const contextExpires = parseInstant(challenge.authorization_context.expires_at);
    checks.freshness = nowMillis !== null && issued !== null && expires !== null
      && issued <= nowMillis && nowMillis <= expires
      && expires - issued <= profile.requirements.max_challenge_age_ms
      && contextIssued === issued && contextExpires === expires;
    if (!checks.freshness) return refused('refuse_challenge_expired', 'challenge is not fresh under the pinned profile', checks);

    const context = challenge.authorization_context;
    if (normalizeHash(context.mobile_binding?.profile_hash) !== normalizeHash(profile.profile_hash)) {
      return refused('refuse_profile_mismatch', 'signed context does not name the pinned profile', checks);
    }
    checks.action = isRecord(challenge.action)
      && normalizeHash(actionHash(challenge.action)) === normalizeHash(challenge.action_hash)
      && normalizeHash(context.action_hash) === normalizeHash(challenge.action_hash);
    if (!checks.action) return refused('refuse_action_mismatch', 'action bytes do not match the signed action hash', checks);

    checks.presentation = validControlledMobilePresentation(challenge.action, challenge.presentation)
      && normalizeHash(displayHash(challenge.presentation)) === normalizeHash(context.display_hash)
      && response.display_hash === context.display_hash;
    if (!checks.presentation) return refused('refuse_display_mismatch', 'presentation bytes do not match the signed display hash', checks);

    checks.signed_context = equalCanonical(response.signoff.context, context)
      && response.challenge_id === challenge.challenge_id
      && response.nonce === challenge.nonce
      && context.nonce === challenge.nonce
      && response.decision === context.decision;
    if (!checks.signed_context) return refused('refuse_action_mismatch', 'response substituted signed context, nonce, or decision', checks);

    const binding = context.mobile_binding;
    checks.platform = ['ios', 'android'].includes(binding.platform)
      && response.platform === binding.platform;
    if (!checks.platform) return refused('refuse_platform', 'platform does not match the signed context', checks);

    checks.app = profile.accepted_apps[binding.platform]?.includes(binding.app_id)
      && response.app_id === binding.app_id;
    if (!checks.app) return refused('refuse_app', 'app is not accepted by the pinned profile', checks);

    const enrollment = enrollmentFor(profile, binding.device_key_id);
    checks.device_key = Boolean(enrollment
      && profileEnrollmentValidAt(enrollment, context.issued_at)
      && enrollment.platform === binding.platform
      && enrollment.app_id === binding.app_id
      && enrollment.approver_id === context.approver
      && enrollment.credential_id === binding.credential_id
      && enrollment.attestation_key_id === binding.attestation_key_id
      && response.device_key_id === binding.device_key_id
      && response.credential_id === binding.credential_id
      && response.attestation_key_id === binding.attestation_key_id);
    if (!checks.device_key) return refused('refuse_device_key', 'no active pinned enrollment matches the signed mobile binding', checks);

    const expectedWebAuthnChallenge = hashCanonicalBytes(context).toString('base64url');
    const requestCredentialIds = challenge.webauthn?.credential_ids;
    const requestMetadataValid = challenge.webauthn?.rp_id === profile.rp_id
      && challenge.webauthn?.challenge === expectedWebAuthnChallenge
      && Array.isArray(requestCredentialIds)
      && requestCredentialIds.length === 1
      && requestCredentialIds[0] === enrollment.credential_id
      && challenge.webauthn?.user_verification === 'required'
      && Number.isSafeInteger(challenge.webauthn?.timeout_ms)
      && challenge.webauthn.timeout_ms === expires - issued;
    if (!requestMetadataValid) {
      return refused('refuse_webauthn', 'WebAuthn request metadata diverges from the signed context or pinned profile', checks);
    }

    const clientData = parseClientData(response.signoff);
    checks.origin = Boolean(clientData
      && profile.allowed_origins.includes(clientData.origin)
      && clientData.crossOrigin !== true);
    if (!checks.origin) return refused('refuse_origin', 'WebAuthn origin is not pinned by the reliance profile', checks);

    const webauthn = verifyWebAuthnSignoff(response.signoff, enrollment.public_key_spki, {
      rpId: profile.rp_id,
      allowedOrigins: profile.allowed_origins,
    });
    checks.webauthn = webauthn.valid === true;
    if (!checks.webauthn) return refused('refuse_webauthn', 'Class-A assertion failed offline verification', checks, { webauthn });

    const expectedBinding = buildMobileAttestationBinding(challenge);
    const expectedRequestHash = hashCanonicalBytes(expectedBinding).toString('base64url');
    if (challenge.attestation?.request_hash !== expectedRequestHash
        || !equalCanonical(challenge.attestation?.binding, expectedBinding)
        || challenge.attestation?.format !== PLATFORM_ATTESTATION_FORMAT[binding.platform]
        || challenge.attestation?.required !== profile.requirements.attestation_required) {
      return refused('refuse_attestation', 'attestation request binding is malformed', checks);
    }

    if (profile.requirements.attestation_required && !validB64u(response.attestation.token, 128 * 1024)) {
      return refused('refuse_attestation_missing', 'a platform attestation token is required', checks);
    }
    if (response.attestation.format !== challenge.attestation.format) {
      return refused('refuse_attestation', 'response attestation format does not match the challenge', checks);
    }
    if ((binding.platform === 'android' && !validB64u(response.attestation.device_key_signature, 256))
        || (binding.platform === 'ios' && own(response.attestation, 'device_key_signature'))) {
      return refused('refuse_attestation', 'device-key ceremony signature does not match the enrolled platform', checks);
    }
    if (profile.requirements.attestation_required && typeof attestationVerifier !== 'function') {
      return refused('refuse_attestation_missing', 'no pinned platform attestation verifier was supplied', checks);
    }
    if (profile.requirements.attestation_required) {
      let attested;
      try {
        attested = await attestationVerifier({
          format: challenge.attestation.format,
          token: response.attestation.token,
          expected_request_hash: expectedRequestHash,
          expected_binding: expectedBinding,
          expected_app_id: binding.app_id,
          expected_attestation_key_id: binding.attestation_key_id,
          device_key_signature: response.attestation.device_key_signature,
          platform: binding.platform,
        });
      } catch {
        return refused('refuse_attestation', 'platform attestation verifier failed', checks);
      }
      checks.attestation = Boolean(attested?.valid === true
        && attested.request_hash === expectedRequestHash
        && attested.app_id === binding.app_id
        && attested.attestation_key_id === binding.attestation_key_id
        && attested.platform === binding.platform
        && (binding.platform !== 'android' || attested.device_key_verified === true)
        && (!profile.requirements.hardware_backed_required || attested.hardware_backed === true)
        && (!profile.requirements.strong_integrity_required || attested.strong_integrity === true));
      if (!checks.attestation) return refused('refuse_attestation', 'platform attestation did not satisfy the pinned profile', checks);
    } else {
      checks.attestation = true;
    }

    return {
      valid: true,
      verdict: 'verified',
      decision: context.decision,
      checks,
      reason: null,
      context_hash: contextHash(context),
      sign_count: parseSignCount(response.signoff),
      approver_id: context.approver,
      device_key_id: binding.device_key_id,
      class_a: toClassASignoff(response),
    };
  } catch (error) {
    return malformed(error instanceof Error ? error.message : 'malformed mobile ceremony', checks);
  }
}

export function toClassASignoff(response) {
  if (!isRecord(response?.signoff?.context) || !isRecord(response.signoff.webauthn)) {
    throw new TypeError('verified mobile response with signoff is required');
  }
  const context = structuredClone(response.signoff.context);
  const digest = hashCanonicalBytes(context);
  return {
    context,
    signoff: {
      context_hash: `sha256:${digest.toString('hex')}`,
      key_class: 'A',
      approver_key_id: context.mobile_binding.device_key_id,
      signed_at: context.issued_at,
      webauthn: structuredClone(response.signoff.webauthn),
    },
  };
}

function decisionRecord(challenge, result) {
  return {
    event_type: 'mobile.ceremony.decision',
    challenge_id: challenge?.challenge_id || null,
    action_hash: challenge?.action_hash || null,
    profile_hash: challenge?.profile_hash || null,
    verdict: result.verdict,
    decision: result.decision,
    approver_id: result.approver_id || null,
    device_key_id: result.device_key_id || null,
    context_hash: result.context_hash || null,
  };
}

/**
 * Durable service boundary. Registration and consumption use the exact
 * AE-CHALLENGE body, so any changed action, profile, display, or expiry is a
 * different body and cannot consume the registered challenge.
 */
export function createMobileCeremonyService({
  challengeStore,
  auditLog,
  attestationVerifier,
  counterStore = null,
  commitDecision = null,
  clock = () => new Date().toISOString(),
  allowEphemeral = false,
} = {}) {
  if (typeof challengeStore?.register !== 'function' || typeof challengeStore?.consume !== 'function') {
    throw new TypeError('challengeStore must implement async register() and consume()');
  }
  if (typeof auditLog?.record !== 'function') throw new TypeError('auditLog must implement async record()');
  if (!allowEphemeral && challengeStore.durable !== true) throw new TypeError('durable challengeStore is required');
  if (!allowEphemeral && !(auditLog.durable === true && auditLog.strict === true)) {
    throw new TypeError('durable strict auditLog is required');
  }
  if (commitDecision !== null && typeof commitDecision !== 'function') {
    throw new TypeError('commitDecision must be a function when provided');
  }
  if (typeof clock !== 'function') throw new TypeError('clock must be a function');

  async function recordOrRefuse(challenge, result) {
    try {
      const record = await auditLog.record(decisionRecord(challenge, result));
      return { ...result, audit_record: record };
    } catch {
      return {
        valid: false,
        verdict: 'refuse_audit_unavailable',
        decision: null,
        checks: result.checks || {},
        reason: 'durable audit record could not be written',
      };
    }
  }

  return {
    async issue(args) {
      const challenge = createMobileChallenge(args);
      try {
        if ((await challengeStore.register(challenge)) !== true) {
          return { ok: false, verdict: 'refuse_replay', challenge: null };
        }
      } catch {
        return { ok: false, verdict: 'refuse_store_unavailable', challenge: null };
      }
      return { ok: true, verdict: 'issued', challenge };
    },

    async verifyAndConsume({ challenge, response, profile }) {
      let result = await verifyMobileCeremony({
        challenge,
        response,
        profile,
        now: clock(),
        attestationVerifier,
      });
      if (!result.valid) return recordOrRefuse(challenge, result);

      try {
        if ((await challengeStore.consume(challenge)) !== true) {
          result = refused('refuse_replay', 'challenge was not registered, was changed, or was already consumed', result.checks);
          return recordOrRefuse(challenge, result);
        }
      } catch {
        result = refused('refuse_store_unavailable', 'challenge consumption store is unavailable', result.checks);
        return recordOrRefuse(challenge, result);
      }

      const counterRequired = profile.requirements.counter_policy === 'registration_baseline'
        || (profile.requirements.counter_policy === 'monotonic_if_nonzero'
          && Number.isSafeInteger(result.sign_count) && result.sign_count > 0);
      if (counterRequired) {
        if (!Number.isSafeInteger(result.sign_count) || result.sign_count < 0) {
          result = refused('refuse_counter_rollback', 'authenticator counter is missing or malformed', result.checks);
          return recordOrRefuse(challenge, result);
        }
        const registrationBaseline = enrollmentFor(profile, result.device_key_id)?.sign_count;
        if (profile.requirements.counter_policy === 'registration_baseline'
            && (!Number.isSafeInteger(registrationBaseline) || result.sign_count <= registrationBaseline)) {
          result = refused('refuse_counter_rollback', 'authenticator counter did not advance its registration baseline', result.checks);
          return recordOrRefuse(challenge, result);
        }
        if (typeof counterStore?.advance !== 'function') {
          result = refused('refuse_store_unavailable', 'counter store is required by the pinned authenticator policy', result.checks);
          return recordOrRefuse(challenge, result);
        }
        try {
          if ((await counterStore.advance(result.device_key_id, result.sign_count)) !== true) {
            result = refused('refuse_counter_rollback', 'authenticator counter did not advance', result.checks);
            return recordOrRefuse(challenge, result);
          }
        } catch {
          result = refused('refuse_store_unavailable', 'authenticator counter store is unavailable', result.checks);
          return recordOrRefuse(challenge, result);
        }
      }

      if (commitDecision !== null) {
        const auditEntry = decisionRecord(challenge, result);
        let committed;
        try {
          committed = await commitDecision({ challenge, result, auditEntry });
          if (committed === false) {
            result = refused(
              'refuse_replay',
              'the protected action was already decided or is not bound to this challenge',
              result.checks,
            );
            return recordOrRefuse(challenge, result);
          }
        } catch {
          result = refused(
            'refuse_store_unavailable',
            'the protected action decision could not be committed',
            result.checks,
          );
          return recordOrRefuse(challenge, result);
        }

        const atomicallyAudited = {
          ...result,
          audit_record: committed?.audit_record,
        };
        if (committed?.committed !== true || !auditRecordMatches(challenge, atomicallyAudited)) {
          return {
            valid: false,
            verdict: 'refuse_audit_unavailable',
            decision: null,
            checks: result.checks,
            reason: 'the protected action and portable evidence were not committed atomically',
          };
        }
        return atomicallyAudited;
      }

      return recordOrRefuse(challenge, result);
    },
  };
}

export function createMobileAck({ result, receiptId = null, recordedAt, signerPrivateKey, signerKeyId } = {}) {
  if (result?.valid !== true || result.verdict !== 'verified' || !['approved', 'denied'].includes(result.decision)) {
    throw new TypeError('a verified mobile ceremony result is required');
  }
  if (parseInstant(recordedAt) === null || !validId(signerKeyId) || !signerPrivateKey) {
    throw new TypeError('recordedAt, signerKeyId, and signerPrivateKey are required');
  }
  const body = {
    '@version': MOBILE_ACK_VERSION,
    verdict: 'verified',
    decision: result.decision,
    context_hash: result.context_hash,
    approver_id: result.approver_id,
    device_key_id: result.device_key_id,
    receipt_id: receiptId,
    recorded_at: recordedAt,
    signer_key_id: signerKeyId,
  };
  const signature = crypto.sign(null, Buffer.from(canonicalize(body), 'utf8'), signerPrivateKey).toString('base64url');
  return { ...body, signature: { algorithm: 'Ed25519', value: signature } };
}

export function verifyMobileAck(ack, publicKeySpkiB64u) {
  try {
    if (!isRecord(ack) || ack['@version'] !== MOBILE_ACK_VERSION
        || !isRecord(ack.signature) || ack.signature.algorithm !== 'Ed25519'
        || !validB64u(ack.signature.value) || !validB64u(publicKeySpkiB64u, 4096)) return false;
    const { signature, ...body } = ack;
    const key = crypto.createPublicKey({ key: Buffer.from(publicKeySpkiB64u, 'base64url'), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(canonicalize(body), 'utf8'), key, Buffer.from(signature.value, 'base64url'));
  } catch {
    return false;
  }
}

function auditRecordMatches(challenge, result) {
  const record = result?.audit_record;
  if (!isRecord(record)
      || !Number.isSafeInteger(record.seq) || record.seq < 0
      || typeof record.record_id !== 'string' || record.record_id.length < 16 || record.record_id.length > 256
      || (record.prev_hash !== 'genesis' && !validHash(record.prev_hash))
      || !validHash(record.hash)) return false;
  const { hash, ...body } = record;
  if (normalizeHash(hashCanonical(body)) !== normalizeHash(hash)) return false;
  const expected = decisionRecord(challenge, result);
  return Object.entries(expected).every(([key, value]) => equalCanonical(record[key], value));
}

/**
 * Sign the operator's runtime statement after the durable ceremony service has
 * consumed the challenge and appended its atomic audit record. This statement
 * is deliberately separate from the Class-A signoff: its signature proves what
 * the operator attested, not that Apple/Google, storage, or physical execution
 * can be independently reconstructed offline.
 */
export function createMobileExecutionRecord({
  challenge,
  result,
  receiptId,
  recordedAt,
  signerPrivateKey,
  signerKeyId,
} = {}) {
  const context = challenge?.authorization_context;
  const binding = context?.mobile_binding;
  if (!validChallengeShape(challenge)
      || result?.valid !== true || result.verdict !== 'verified'
      || !['approved', 'denied'].includes(result.decision)
      || !isRecord(result.checks)
      || !MOBILE_CHECK_NAMES.every((name) => result.checks[name] === true)
      || result.context_hash !== contextHash(context)
      || result.approver_id !== context?.approver
      || result.device_key_id !== binding?.device_key_id
      || !auditRecordMatches(challenge, result)
      || !validId(receiptId) || parseInstant(recordedAt) === null
      || !validId(signerKeyId) || !signerPrivateKey) {
    throw new TypeError('a durably consumed and audited mobile ceremony result is required');
  }
  const body = {
    '@version': MOBILE_EXECUTION_RECORD_VERSION,
    statement_type: 'operator_runtime_attestation',
    verdict: 'verified',
    decision: result.decision,
    challenge_id: challenge.challenge_id,
    action_hash: challenge.action_hash,
    profile_hash: challenge.profile_hash,
    context_hash: result.context_hash,
    approver_id: result.approver_id,
    device_key_id: result.device_key_id,
    platform: binding.platform,
    app_id: binding.app_id,
    attestation_format: challenge.attestation.format,
    receipt_id: receiptId,
    audit_record_id: result.audit_record.record_id,
    audit_record_hash: `sha256:${normalizeHash(result.audit_record.hash)}`,
    online_checks: Object.fromEntries(MOBILE_CHECK_NAMES.map((name) => [name, true])),
    operator_assertions: {
      platform_attestation: 'verified_at_execution',
      challenge_consumption: 'consumed_before_audit_record',
      durable_audit: 'recorded',
    },
    recorded_at: recordedAt,
    signer_key_id: signerKeyId,
  };
  const signature = crypto.sign(null, Buffer.from(canonicalize(body), 'utf8'), signerPrivateKey).toString('base64url');
  return { ...body, signature: { algorithm: 'Ed25519', value: signature } };
}

/** Verify only the execution-record signature and closed wire shape. */
export function verifyMobileExecutionRecord(record, publicKeySpkiB64u) {
  try {
    if (!isRecord(record) || record['@version'] !== MOBILE_EXECUTION_RECORD_VERSION
        || record.statement_type !== 'operator_runtime_attestation'
        || record.verdict !== 'verified' || !['approved', 'denied'].includes(record.decision)
        || !validId(record.challenge_id) || !validHash(record.action_hash)
        || !validHash(record.profile_hash) || !validHash(record.context_hash)
        || !validId(record.approver_id) || !validId(record.device_key_id)
        || !['ios', 'android'].includes(record.platform) || !validId(record.app_id)
        || !['apple-app-attest', 'play-integrity-standard'].includes(record.attestation_format)
        || !validId(record.receipt_id)
        || typeof record.audit_record_id !== 'string' || record.audit_record_id.length < 16
        || record.audit_record_id.length > 256 || !validHash(record.audit_record_hash)
        || !isRecord(record.online_checks)
        || Object.keys(record.online_checks).length !== MOBILE_CHECK_NAMES.length
        || !MOBILE_CHECK_NAMES.every((name) => record.online_checks[name] === true)
        || !equalCanonical(record.operator_assertions, {
          platform_attestation: 'verified_at_execution',
          challenge_consumption: 'consumed_before_audit_record',
          durable_audit: 'recorded',
        })
        || parseInstant(record.recorded_at) === null || !validId(record.signer_key_id)
        || !isRecord(record.signature) || record.signature.algorithm !== 'Ed25519'
        || Object.keys(record.signature).length !== 2
        || !Object.keys(record.signature).every((key) => ['algorithm', 'value'].includes(key))
        || !validB64u(record.signature.value) || !validB64u(publicKeySpkiB64u, 4096)) return false;
    const allowed = new Set([
      '@version', 'statement_type', 'verdict', 'decision', 'challenge_id', 'action_hash',
      'profile_hash', 'context_hash', 'approver_id', 'device_key_id', 'platform',
      'app_id', 'attestation_format', 'receipt_id', 'audit_record_id',
      'audit_record_hash', 'online_checks', 'operator_assertions', 'recorded_at',
      'signer_key_id', 'signature',
    ]);
    if (!Object.keys(record).every((key) => allowed.has(key))) return false;
    const { signature, ...body } = record;
    const key = crypto.createPublicKey({ key: Buffer.from(publicKeySpkiB64u, 'base64url'), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(canonicalize(body), 'utf8'), key, Buffer.from(signature.value, 'base64url'));
  } catch {
    return false;
  }
}

export default {
  MOBILE_CHALLENGE_VERSION,
  MOBILE_CEREMONY_VERSION,
  MOBILE_PROFILE_VERSION,
  MOBILE_ATTESTATION_BINDING_VERSION,
  MOBILE_ACK_VERSION,
  MOBILE_EXECUTION_RECORD_VERSION,
  MOBILE_PRESENTATION_VERSION,
  MOBILE_VERDICTS,
  hashCanonical,
  mobileProfileHash,
  createMobileRelianceProfile,
  projectMobileAction,
  normalizeControlledMobilePresentation,
  normalizeMobilePresentation,
  validControlledMobilePresentation,
  validMobilePresentation,
  buildMobileAuthorizationContext,
  buildMobileAttestationBinding,
  createMobileChallenge,
  verifyMobileCeremony,
  createMobileCeremonyService,
  toClassASignoff,
  createMobileAck,
  verifyMobileAck,
  createMobileExecutionRecord,
  verifyMobileExecutionRecord,
  createPlayIntegrityAttestationVerifier,
  createAppleAppAttestVerifier,
  createGovernmentMobileController,
  createMobileHttpHandler,
  buildMobileEnrollmentBinding,
  buildMobileAndroidKeyBinding,
  createMobileEnrollmentService,
  MOBILE_ANDROID_KEY_BINDING_VERSION,
  MOBILE_ENROLLMENT_CHALLENGE_VERSION,
  MOBILE_ENROLLMENT_VERSION,
};
