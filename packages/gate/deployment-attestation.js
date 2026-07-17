// SPDX-License-Identifier: Apache-2.0
/**
 * Relying-party evaluation of evidence that an expected Gate workload is
 * running. This module introduces no attestation format and no trust root: the
 * profile pins a verifier selected by the relying party, and that verifier may
 * consume EAT/RATS, App Attest, Play Integrity, TPM, confidential-compute, or
 * workload-identity evidence.
 */
import { canonicalize, hashCanonical } from './execution-binding.js';

export const DEPLOYMENT_PROFILE_VERSION = 'EP-GATE-DEPLOYMENT-PROFILE-v1';
export const DEPLOYMENT_ATTESTATION_VERDICTS = Object.freeze([
  'attested',
  'refuse_profile_invalid',
  'refuse_verifier_unpinned',
  'refuse_evidence_invalid',
  'refuse_verifier_error',
  'refuse_context_mismatch',
  'refuse_measurement_mismatch',
  'refuse_stale',
]);

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function strictInstantMs(value) {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339);
  if (!match) return NaN;
  const [, y, m, d, h, min, s] = match;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(y), Number(m) - 1, Number(d));
  calendar.setUTCHours(Number(h), Number(min), Number(s), 0);
  if (calendar.toISOString().slice(0, 19) !== `${y}-${m}-${d}T${h}:${min}:${s}`) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function string(value, max = 512) {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
}

function digest(value) {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function exactKeys(value, allowed) {
  return isPlainObject(value) && Object.keys(value).every((key) => allowed.has(key));
}

function validateProfile(profile) {
  if (!exactKeys(profile, new Set([
    '@version', 'profile_id', 'verifier_id', 'evidence_type', 'gate_id', 'environment_id',
    'audience', 'nonce', 'max_age_sec', 'max_future_skew_sec', 'required_measurements',
  ]))) return 'profile_shape_invalid';
  if (profile['@version'] !== DEPLOYMENT_PROFILE_VERSION) return 'profile_version_invalid';
  for (const field of ['profile_id', 'verifier_id', 'evidence_type', 'gate_id', 'environment_id', 'audience']) {
    if (!string(profile[field])) return `profile_${field}_invalid`;
  }
  if (!string(profile.nonce, 1024)) return 'profile_nonce_invalid';
  if (!Number.isSafeInteger(profile.max_age_sec) || profile.max_age_sec < 1 || profile.max_age_sec > 86_400) {
    return 'profile_max_age_invalid';
  }
  if (!Number.isSafeInteger(profile.max_future_skew_sec)
      || profile.max_future_skew_sec < 0 || profile.max_future_skew_sec > 300) {
    return 'profile_future_skew_invalid';
  }
  if (!isPlainObject(profile.required_measurements)
      || Object.keys(profile.required_measurements).length === 0
      || Object.keys(profile.required_measurements).length > 32) return 'profile_measurements_invalid';
  for (const [name, value] of Object.entries(profile.required_measurements)) {
    if (!string(name, 128) || !digest(value)) return 'profile_measurements_invalid';
  }
  try { canonicalize(profile); } catch { return 'profile_canonicalization_invalid'; }
  return null;
}

export function deploymentProfileDigest(profile) {
  const invalid = validateProfile(profile);
  if (invalid) throw new TypeError(invalid);
  return `sha256:${hashCanonical(profile)}`;
}

function fail(verdict, profileHash = null, extra = {}) {
  return {
    accepted: false,
    verified: false,
    verdict,
    profile_hash: profileHash,
    checks: {
      profile: verdict !== 'refuse_profile_invalid',
      verifier: false,
      evidence: false,
      context: false,
      freshness: false,
      measurements: false,
      ...extra,
    },
  };
}

function verifierFor(verifiers, verifierId) {
  let verifier;
  if (verifiers instanceof Map) verifier = verifiers.get(verifierId);
  else if (isPlainObject(verifiers) && Object.hasOwn(verifiers, verifierId)) {
    verifier = verifiers[verifierId];
  }
  return typeof verifier === 'function' ? verifier : null;
}

/**
 * Verify deployment evidence under a relying-party-pinned profile.
 *
 * The selected verifier is taken from `profile.verifier_id`, which is a trusted
 * input. A presenter cannot select its own verifier by labeling the evidence.
 * The verifier returns normalized claims; this kernel independently compares
 * every context and measurement claim with the profile.
 */
export async function verifyDeploymentAttestation(evidence, options = {}) {
  let profile;
  let invalid;
  try {
    invalid = validateProfile(options.profile);
    profile = invalid ? options.profile : JSON.parse(canonicalize(options.profile));
  } catch {
    invalid = 'profile_hostile_input';
    profile = null;
  }
  if (invalid) return { ...fail('refuse_profile_invalid'), reason: invalid };
  const profileHash = deploymentProfileDigest(profile);
  const verifier = verifierFor(options.verifiers, profile.verifier_id);
  if (typeof verifier !== 'function') {
    return { ...fail('refuse_verifier_unpinned', profileHash, { profile: true }), reason: 'pinned_verifier_missing' };
  }

  let claims;
  try {
    claims = await verifier(evidence, Object.freeze({
      evidence_type: profile.evidence_type,
      audience: profile.audience,
      nonce: profile.nonce,
      gate_id: profile.gate_id,
      environment_id: profile.environment_id,
    }));
  } catch {
    return {
      ...fail('refuse_verifier_error', profileHash, { profile: true, verifier: true }),
      reason: 'pinned_verifier_threw',
    };
  }
  if (!isPlainObject(claims) || claims.verified !== true || !isPlainObject(claims.measurements)) {
    return {
      ...fail('refuse_evidence_invalid', profileHash, { profile: true, verifier: true }),
      reason: 'attestation_not_verified',
    };
  }
  try { claims = JSON.parse(canonicalize(claims)); } catch {
    return {
      ...fail('refuse_evidence_invalid', profileHash, { profile: true, verifier: true }),
      reason: 'attestation_claims_not_canonical_json',
    };
  }

  const contextMatches = claims.verifier_id === profile.verifier_id
    && claims.evidence_type === profile.evidence_type
    && claims.gate_id === profile.gate_id
    && claims.environment_id === profile.environment_id
    && claims.audience === profile.audience
    && claims.nonce === profile.nonce;
  if (!contextMatches) {
    return {
      ...fail('refuse_context_mismatch', profileHash, {
        profile: true, verifier: true, evidence: true,
      }),
      reason: 'attestation_context_mismatch',
    };
  }

  const now = options.now === undefined ? Date.now() : Number(options.now);
  const issuedAt = strictInstantMs(claims.issued_at);
  const expiresAt = strictInstantMs(claims.expires_at);
  if (!Number.isFinite(now) || !Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)
      || expiresAt < issuedAt
      || issuedAt > now + (profile.max_future_skew_sec * 1000)
      || now - issuedAt > profile.max_age_sec * 1000
      || now >= expiresAt) {
    return {
      ...fail('refuse_stale', profileHash, {
        profile: true, verifier: true, evidence: true, context: true,
      }),
      reason: 'attestation_outside_freshness_window',
    };
  }

  const mismatched = [];
  const missing = [];
  for (const [name, expected] of Object.entries(profile.required_measurements)) {
    if (!Object.hasOwn(claims.measurements, name)) missing.push(name);
    else if (claims.measurements[name] !== expected) mismatched.push(name);
  }
  if (missing.length || mismatched.length) {
    return {
      ...fail('refuse_measurement_mismatch', profileHash, {
        profile: true, verifier: true, evidence: true, context: true, freshness: true,
      }),
      reason: 'attestation_measurement_mismatch',
      missing_measurements: missing,
      mismatched_measurements: mismatched,
    };
  }

  return {
    accepted: true,
    verified: true,
    verdict: 'attested',
    reason: null,
    profile_hash: profileHash,
    verifier_id: profile.verifier_id,
    evidence_type: profile.evidence_type,
    gate_id: profile.gate_id,
    environment_id: profile.environment_id,
    issued_at: claims.issued_at,
    expires_at: claims.expires_at,
    measurements: Object.freeze({ ...profile.required_measurements }),
    checks: {
      profile: true,
      verifier: true,
      evidence: true,
      context: true,
      freshness: true,
      measurements: true,
    },
    limitation: 'Attestation proves the expected workload measurements, not that every consequential route is forced through that workload.',
  };
}

export default {
  DEPLOYMENT_PROFILE_VERSION,
  DEPLOYMENT_ATTESTATION_VERDICTS,
  deploymentProfileDigest,
  verifyDeploymentAttestation,
};
