// SPDX-License-Identifier: Apache-2.0

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { coseToSpkiP256, getRpConfig } from '../webauthn.js';
import {
  RELEASE_LOCK_CHALLENGE_TTL_MS,
  RELEASE_LOCK_CREDENTIAL_ID_PATTERN,
} from './constants.js';
import { releaseLockRefusal } from './errors.js';

function rpPolicy(value = getRpConfig()) {
  const rpID = value?.rpID;
  const origin = value?.origin;
  const rpName = value?.rpName || 'EMILIA Protocol';
  if (typeof rpID !== 'string' || rpID.length === 0 || rpID.length > 253
      || typeof origin !== 'string' || origin.length === 0 || origin.length > 512
      || typeof rpName !== 'string' || rpName.length === 0 || rpName.length > 128) {
    throw releaseLockRefusal(
      503,
      'webauthn_policy_unconfigured',
      'Release Lock WebAuthn RP policy is not configured.',
    );
  }
  return { rpID, origin, rpName };
}

export async function createReleaseLockRegistrationOptions({
  session,
  existingCredentials = [],
  now = Date.now,
  rpConfig,
} = {}) {
  if (!session?.lock_id || !session?.role || !session?.contact_binding_id) {
    throw releaseLockRefusal(401, 'session_invalid', 'Release Lock session is invalid.');
  }
  const policy = rpPolicy(rpConfig);
  const userHandle = `release-lock:${session.lock_id}:${session.role}:${session.contact_binding_id}`;
  const options = await generateRegistrationOptions({
    rpName: policy.rpName,
    rpID: policy.rpID,
    userID: Buffer.from(userHandle, 'utf8'),
    userName: `${session.role}@${session.lock_id}`,
    userDisplayName: `${session.role} approval for ${session.lock_id}`,
    attestationType: 'direct',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
    },
    supportedAlgorithmIDs: [-7],
    excludeCredentials: existingCredentials.map((credential) => ({
      id: credential.credential_id,
      transports: credential.transports || undefined,
    })),
  });
  const nowMs = typeof now === 'function' ? now() : now;
  const expiresAt = new Date(Math.min(
    nowMs + RELEASE_LOCK_CHALLENGE_TTL_MS,
    Date.parse(session.expires_at),
    Date.parse(session.lock_expires_at),
  )).toISOString();
  return Object.freeze({
    options,
    challenge: options.challenge,
    rpId: policy.rpID,
    origin: policy.origin,
    expiresAt,
  });
}

export async function verifyReleaseLockRegistration({
  challenge,
  attestation,
  rpConfig,
} = {}) {
  if (!challenge?.challenge || !challenge?.rp_id || !challenge?.origin || !attestation) {
    throw releaseLockRefusal(400, 'registration_invalid', 'Registration response is malformed.');
  }
  const policy = rpPolicy(rpConfig);
  if (policy.rpID !== challenge.rp_id || policy.origin !== challenge.origin) {
    throw releaseLockRefusal(
      409,
      'webauthn_policy_mismatch',
      'Stored registration policy does not match the active RP policy.',
    );
  }
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: attestation,
      expectedChallenge: challenge.challenge,
      expectedOrigin: challenge.origin,
      expectedRPID: challenge.rp_id,
      requireUserVerification: true,
    });
  } catch {
    throw releaseLockRefusal(400, 'attestation_invalid', 'Passkey registration did not verify.');
  }
  if (!verification.verified || !verification.registrationInfo) {
    throw releaseLockRefusal(400, 'attestation_invalid', 'Passkey registration did not verify.');
  }
  const {
    credential,
    credentialDeviceType,
    credentialBackedUp,
    fmt,
  } = verification.registrationInfo;
  if (!RELEASE_LOCK_CREDENTIAL_ID_PATTERN.test(credential.id || '')) {
    throw releaseLockRefusal(400, 'credential_id_invalid', 'Registered credential identifier is invalid.');
  }
  let spki;
  try {
    spki = coseToSpkiP256(credential.publicKey);
  } catch {
    throw releaseLockRefusal(
      400,
      'unsupported_credential_key',
      'Release Lock requires an ES256 P-256 credential.',
    );
  }
  return Object.freeze({
    credentialId: credential.id,
    publicKeyCose: Buffer.from(credential.publicKey).toString('base64url'),
    publicKeySpki: spki.toString('base64url'),
    signCount: credential.counter ?? 0,
    transports: credential.transports || null,
    deviceType: credentialDeviceType || null,
    backedUp: credentialBackedUp === true,
    attestationFormat: fmt || null,
    rpId: challenge.rp_id,
    origin: challenge.origin,
  });
}

export const releaseLockRegistrationInternals = Object.freeze({ rpPolicy });
