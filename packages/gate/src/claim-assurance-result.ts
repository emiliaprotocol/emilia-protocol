// SPDX-License-Identifier: Apache-2.0
/**
 * Closed validation for the Claim Assurance result consumed by Gate and
 * preserved by the reliance packet. This module intentionally has no runtime
 * dependency on @emilia-protocol/verify so the executor-side boundary remains
 * independently packageable.
 */
import { canonicalize } from './execution-binding.js';

export const CLAIM_ASSURANCE_ADMISSIBILITY_RESULT_VERSION =
  'EP-CLAIM-ASSURANCE-ADMISSIBILITY-v1' as const;

const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/;
const CANONICAL_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const PROFILE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/;
const TOP_LEVEL_KEYS = Object.freeze([
  '@type',
  'action_digest',
  'admissibility_profile',
  'as_of',
  'assurance_record_digest',
  'authorizes_action',
  'claim_assurance_verdict',
  'claim_case_digest',
  'evaluated_at',
  'profile_hash',
  'profile_satisfied',
  'reasons',
  'replay_digest',
  'verdict',
].sort());
const PROFILE_KEYS = Object.freeze(['id', 'version']);
const CLAIM_VERDICTS = Object.freeze([
  'VERIFIED', 'UNVERIFIED', 'DIVERGED', 'INDETERMINATE',
]);
const ADMISSIBILITY_VERDICTS = Object.freeze([
  'admissible', 'missing_evidence', 'stale', 'conflicted', 'unverifiable',
]);

type JsonObject = Record<string, unknown>;

export interface ClaimAssuranceResultValidationOptions {
  expectedProfile?: { id: string; profile_hash: string } | null;
  expectedActionDigest?: string | null;
  requireAdmissible?: boolean;
}

export type ClaimAssuranceResultValidation =
  | { ok: true; reason: null; block: Readonly<JsonObject> }
  | { ok: false; reason: string; block: null };

function fail(reason: string): ClaimAssuranceResultValidation {
  return { ok: false, reason, block: null };
}

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function sameKeys(value: JsonObject, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

function strictClone(value: unknown): unknown {
  return JSON.parse(canonicalize(value));
}

function validDigest(value: unknown): value is string {
  return typeof value === 'string' && SHA256_DIGEST.test(value);
}

function instantMilliseconds(value: unknown): number | null {
  if (typeof value !== 'string' || !CANONICAL_INSTANT.test(value)) return null;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return null;
  return new Date(milliseconds).toISOString().replace('.000Z', 'Z') === value
    ? milliseconds
    : null;
}

/**
 * Return the nested/direct result only when it explicitly identifies itself as
 * Claim Assurance. Accessor properties and malformed containers are ignored;
 * the strict validator will reject malformed direct Claim Assurance values.
 */
export function claimAssuranceResultCandidate(value: unknown): unknown | null {
  if (!isObject(value)) return null;
  try {
    const nestedDescriptor = Object.getOwnPropertyDescriptor(value, 'admissibility');
    if (nestedDescriptor
        && (nestedDescriptor.enumerable !== true || !Object.hasOwn(nestedDescriptor, 'value'))) {
      return value;
    }
    const candidate = nestedDescriptor ? nestedDescriptor.value : value;
    if (!isObject(candidate)) return null;
    const typeDescriptor = Object.getOwnPropertyDescriptor(candidate, '@type');
    if (!typeDescriptor) return null;
    if (typeDescriptor.enumerable !== true || !Object.hasOwn(typeDescriptor, 'value')) return candidate;
    return typeDescriptor.value === CLAIM_ASSURANCE_ADMISSIBILITY_RESULT_VERSION ? candidate : null;
  } catch {
    return value;
  }
}

/**
 * Strictly clone and validate the closed Claim Assurance result contract.
 * Success returns a deeply frozen plain-data snapshot, closing post-validation
 * mutation and getter/proxy-shaped result attacks.
 */
export function validateClaimAssuranceAdmissibilityResult(
  value: unknown,
  {
    expectedProfile = null,
    expectedActionDigest = null,
    requireAdmissible = false,
  }: ClaimAssuranceResultValidationOptions = {},
): ClaimAssuranceResultValidation {
  let block: unknown;
  try {
    block = strictClone(value);
  } catch {
    return fail('not_strict_canonical_json');
  }
  if (!isObject(block)) return fail('result_not_object');
  if (!sameKeys(block, TOP_LEVEL_KEYS)) return fail('result_shape_not_closed');
  if (block['@type'] !== CLAIM_ASSURANCE_ADMISSIBILITY_RESULT_VERSION) {
    return fail('result_version_mismatch');
  }

  const profile = block.admissibility_profile;
  if (!isObject(profile) || !sameKeys(profile, PROFILE_KEYS)) {
    return fail('profile_shape_not_closed');
  }
  if (typeof profile.id !== 'string'
      || profile.id.length < 1
      || profile.id.length > 128
      || !PROFILE_ID.test(profile.id)) {
    return fail('profile_id_invalid');
  }
  if (profile.version !== '1') return fail('profile_version_invalid');
  if (!validDigest(block.profile_hash)) return fail('profile_hash_invalid');

  for (const field of [
    'replay_digest', 'assurance_record_digest', 'claim_case_digest', 'action_digest',
  ] as const) {
    if (!validDigest(block[field])) return fail(`${field}_invalid`);
  }
  if (expectedProfile
      && (profile.id !== expectedProfile.id
        || block.profile_hash !== expectedProfile.profile_hash)) {
    return fail('profile_pin_mismatch');
  }
  if (expectedActionDigest !== null && block.action_digest !== expectedActionDigest) {
    return fail('action_digest_mismatch');
  }

  if (typeof block.verdict !== 'string'
      || !ADMISSIBILITY_VERDICTS.includes(block.verdict)) {
    return fail('admissibility_verdict_invalid');
  }
  if (typeof block.claim_assurance_verdict !== 'string'
      || !CLAIM_VERDICTS.includes(block.claim_assurance_verdict)) {
    return fail('claim_assurance_verdict_invalid');
  }
  if (typeof block.profile_satisfied !== 'boolean') return fail('profile_satisfied_invalid');
  if (block.authorizes_action !== false) return fail('authorizes_action_must_be_false');

  const asOf = instantMilliseconds(block.as_of);
  const evaluatedAt = instantMilliseconds(block.evaluated_at);
  if (asOf === null) return fail('as_of_invalid');
  if (evaluatedAt === null) return fail('evaluated_at_invalid');
  if (asOf > evaluatedAt) return fail('as_of_after_evaluated_at');

  if (!Array.isArray(block.reasons)
      || block.reasons.length > 256
      || block.reasons.some((reason) => typeof reason !== 'string'
        || reason.length < 1
        || reason.length > 256)) {
    return fail('reasons_invalid');
  }
  const reasons = block.reasons as string[];
  if (new Set(reasons).size !== reasons.length
      || reasons.some((reason, index) => index > 0 && reasons[index - 1] > reason)) {
    return fail('reasons_not_unique_sorted');
  }

  const claimVerified = block.claim_assurance_verdict === 'VERIFIED';
  if (block.profile_satisfied !== claimVerified) {
    return fail('profile_satisfaction_claim_verdict_mismatch');
  }
  const permittedAdmissibilityByClaim: Record<string, readonly string[]> = {
    VERIFIED: ['admissible', 'stale'],
    DIVERGED: ['conflicted'],
    UNVERIFIED: ['unverifiable'],
    INDETERMINATE: ['missing_evidence', 'stale', 'unverifiable'],
  };
  if (!permittedAdmissibilityByClaim[block.claim_assurance_verdict as string]
    ?.includes(block.verdict as string)) {
    return fail('claim_and_admissibility_verdict_mismatch');
  }
  if (requireAdmissible && block.verdict !== 'admissible') {
    return fail('result_not_admissible');
  }

  return { ok: true, reason: null, block: deepFreeze(block) };
}
