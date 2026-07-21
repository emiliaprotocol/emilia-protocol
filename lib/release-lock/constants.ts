// SPDX-License-Identifier: Apache-2.0

export const RELEASE_LOCK_CO_ACTION_VERSION = 'EP-RELEASE-LOCK-CO-ACTION-v1';
export const RELEASE_LOCK_DRAW_ACTION_VERSION = 'EP-RELEASE-LOCK-DRAW-ACTION-v1';
export const RELEASE_LOCK_ACTION_CHECK_VERSION = 'EP-RELEASE-LOCK-ACTION-CHECK-v1';
export const RELEASE_LOCK_EVIDENCE_VERSION = 'EP-RELEASE-LOCK-EVIDENCE-v1';
export const RELEASE_LOCK_EFFECT_VERSION = 'EP-RELEASE-LOCK-EFFECT-v1';
export const RELEASE_LOCK_ACCEPTANCE_VERSION = 'EP-RELEASE-LOCK-ROUND-ACCEPTANCE-v1';

export const RELEASE_LOCK_ROLES: readonly string[] = Object.freeze(['contractor', 'customer']);
export const RELEASE_LOCK_ROUNDS: readonly string[] = Object.freeze([
  'CO_ACCEPTED',
  'DRAW_RELEASE',
]);

export const RELEASE_LOCK_COOKIE = '__Host-ep_release_lock_session';
export const RELEASE_LOCK_TOKEN_BYTES = 32;
export const RELEASE_LOCK_CHALLENGE_TTL_MS = 5 * 60 * 1000;
export const RELEASE_LOCK_PAIRING_TTL_MS = 5 * 60 * 1000;
export const RELEASE_LOCK_MIRROR_SESSION_TTL_MS = 30 * 60 * 1000;
export const RELEASE_LOCK_MAX_BODY_BYTES = 256 * 1024;
export const RELEASE_LOCK_MAX_ACTION_BYTES = 128 * 1024;
export const RELEASE_LOCK_MAX_MATERIAL_FIELDS_BYTES = 32 * 1024;
export const RELEASE_LOCK_MAX_LIFETIME_MS = 90 * 24 * 60 * 60 * 1000;
export const RELEASE_LOCK_MIN_LIFETIME_MS = 5 * 60 * 1000;

export const RELEASE_LOCK_LIMITATIONS: readonly string[] = Object.freeze([
  'EMILIA does not hold or move funds.',
  'CO_ACCEPTED records acceptance of one exact retained change order and never authorizes payment.',
  'Only a complete DRAW_RELEASE round can make its exact custodian instruction eligible for execution.',
  'Production invitation secrets are delivered to each verified contact channel and are never returned to the creating party.',
  'This bundle does not establish workmanship, completion, legal enforceability, civil identity, comprehension, or voluntariness.',
  'Contact-channel verification binds an invitation to a verified channel reference; it is not a civil-identity claim.',
  'Role separation requires two distinct subjects under one pinned external authority; that authority remains responsible for identity proofing and subject uniqueness.',
  'Passkey evidence proves verification under the recorded WebAuthn policy; it does not establish biometrics, device ownership, or device-bound identity.',
  'Action Mirror handoff uses a single-use, short-lived capability scoped to one lock, role, and approval round.',
  'Custodian state is limited to the configured provider adapter and may remain indeterminate pending authoritative reconciliation.',
  'The outer content digest detects transport corruption only; evidence authenticity requires re-verifying every signed component under relying-party-pinned keys.',
]);

export const RELEASE_LOCK_ID_PATTERN = /^rlk_[a-f0-9]{32}$/;
export const RELEASE_LOCK_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
export const RELEASE_LOCK_HMAC_PATTERN = /^hmac-sha256:[0-9a-f]{64}$/;
export const RELEASE_LOCK_CREDENTIAL_ID_PATTERN = /^[A-Za-z0-9_-]{16,2048}$/;
