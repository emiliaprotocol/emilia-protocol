// SPDX-License-Identifier: Apache-2.0
/**
 * AEB-EXECUTION-CONDITIONS-v1 — execution-boundary condition evaluation.
 *
 * This is an internal AEB profile, not a policy language and not a new receipt
 * format. It compares opaque, human-approved commitments with normalized
 * resolver results under a relying-party-owned resolver profile. Native
 * resolver authentication happens outside this module; this evaluator refuses
 * any source, trust digest, freshness rule, or enforcement strength that the
 * relying party did not pin.
 *
 * MATCH means only that an accepted resolver reported a match. It does not
 * establish physical or world truth. `observed` and `leased` results can satisfy
 * a condition profile but cannot claim prevention. Only a compare-and-set or
 * provider-enforced result carrying enforcement evidence can support that
 * narrower claim. An ADMIT result covers this conditions axis only; it is not a
 * substitute for AEB evidence verification, local authorization, or atomic
 * authority consumption.
 */
import { digestAeb, type AebDigest } from './aeb-adapter-contract.js';

type Obj = Record<string, unknown>;

export const AEB_EXECUTION_CONDITIONS_VERSION = 'AEB-EXECUTION-CONDITIONS-v1';
export const AEB_EXECUTION_RESOLVER_PROFILE_VERSION = 'AEB-EXECUTION-RESOLVER-PROFILE-v1';
export const AEB_EXECUTION_CONDITION_RESOLUTION_VERSION = 'AEB-EXECUTION-CONDITION-RESOLUTION-v1';

export const AEB_EXECUTION_CONDITIONS_SCOPE = Object.freeze({
  decision_scope: 'execution_conditions_only',
  authorization_established: false,
  physical_truth_established: false,
  prevention_capable_strengths: Object.freeze(['compare-and-set', 'provider-enforced']),
} as const);

export type AebExecutionConditionOutcome =
  | 'ADMIT'
  | 'PREDICATE_FAILED'
  | 'INDETERMINATE'
  | 'INVALID';
export type AebExecutionEnforcementStrength =
  | 'observed'
  | 'leased'
  | 'compare-and-set'
  | 'provider-enforced';
export type AebExecutionResolutionVerdict =
  | 'MATCH'
  | 'MISMATCH'
  | 'UNAVAILABLE'
  | 'CONFLICTING';
export type AebExecutionBasisVerdict = 'CURRENT' | 'EXPIRED' | 'REVOKED' | 'UNAVAILABLE';

export interface AebExecutionResolverSourcePin {
  source_id: string;
  trust_digest: AebDigest;
  required_strength: AebExecutionEnforcementStrength;
}

export interface AebExecutionResolverProfile {
  '@version': typeof AEB_EXECUTION_RESOLVER_PROFILE_VERSION;
  profile_id: string;
  version: number;
  relying_party_id: string;
  max_resolution_age_seconds: number;
  max_future_skew_seconds: number;
  sources: AebExecutionResolverSourcePin[];
  profile_digest: AebDigest;
}

export type AebExecutionResolverProfileInput = Omit<AebExecutionResolverProfile, 'profile_digest'>;

export interface AebExecutionApprovedBasis {
  /** Digest of the independently verified human-authorization artifact. */
  authorization_evidence_digest: AebDigest;
  /** Opaque approved rationale/basis commitment; this module never interprets it. */
  basis_digest: AebDigest;
  /** Opaque approved predicate-set commitment; this module defines no predicate language. */
  predicate_set_digest: AebDigest;
  presentation_method: string;
  /** Digest of the exact presentation bound into the human authorization. */
  presentation_digest: AebDigest;
}

export interface AebExecutionConditionsProfile {
  '@version': typeof AEB_EXECUTION_CONDITIONS_VERSION;
  profile_id: string;
  version: number;
  relying_party_id: string;
  action_digest: AebDigest;
  approved_basis: AebExecutionApprovedBasis;
  resolver_profile_id: string;
  resolver_profile_digest: AebDigest;
  profile_digest: AebDigest;
}

export type AebExecutionConditionsProfileInput = Omit<AebExecutionConditionsProfile, 'profile_digest'>;

export interface AebExecutionBasisStatus {
  verdict: AebExecutionBasisVerdict;
  checked_at: string;
  /** Currency of this status lookup, not an extension of the approval itself. */
  status_valid_until: string;
}

export interface AebExecutionConditionResolution {
  '@version': typeof AEB_EXECUTION_CONDITION_RESOLUTION_VERSION;
  source_id: string;
  source_trust_digest: AebDigest;
  source_record_digest: AebDigest;
  resolver_profile_digest: AebDigest;
  action_digest: AebDigest;
  authorization_evidence_digest: AebDigest;
  basis_digest: AebDigest;
  predicate_set_digest: AebDigest;
  presentation_method: string;
  presentation_digest: AebDigest;
  verdict: AebExecutionResolutionVerdict;
  strength: AebExecutionEnforcementStrength;
  resolved_at: string;
  valid_until: string;
  lease_expires_at: string | null;
  enforcement_evidence_digest: AebDigest | null;
  prevention_claimed: boolean;
}

export interface AebExecutionConditionsEvaluationOptions {
  /** Relying-party-pinned digest; the presented profile is never self-authorizing. */
  expected_profile_digest: AebDigest;
  resolver_profile: AebExecutionResolverProfile;
  action_digest: AebDigest;
  approved_basis: AebExecutionApprovedBasis;
  basis_status: AebExecutionBasisStatus;
  resolutions: readonly AebExecutionConditionResolution[];
  evaluated_at: string;
}

export type AebExecutionConditionReason =
  | 'profile_invalid'
  | 'profile_digest_mismatch'
  | 'resolver_profile_invalid'
  | 'resolver_profile_digest_mismatch'
  | 'resolver_profile_id_mismatch'
  | 'relying_party_mismatch'
  | 'exact_action_mismatch'
  | 'authorization_evidence_mismatch'
  | 'basis_digest_mismatch'
  | 'predicate_set_digest_mismatch'
  | 'presentation_method_mismatch'
  | 'presentation_digest_mismatch'
  | 'basis_status_invalid'
  | 'basis_status_stale'
  | 'basis_status_unavailable'
  | 'basis_expired'
  | 'basis_revoked'
  | 'resolution_invalid'
  | 'resolution_missing'
  | 'resolution_conflicting'
  | 'resolution_unavailable'
  | 'resolution_stale'
  | 'resolution_from_future'
  | 'resolution_source_unpinned'
  | 'resolution_source_trust_mismatch'
  | 'resolution_resolver_mismatch'
  | 'resolution_action_mismatch'
  | 'resolution_authorization_mismatch'
  | 'resolution_basis_mismatch'
  | 'resolution_predicate_set_mismatch'
  | 'resolution_presentation_mismatch'
  | 'resolution_strength_mismatch'
  | 'lease_expired'
  | 'prevention_claim_not_supported'
  | 'enforcement_evidence_missing'
  | 'predicate_failed';

export interface AebExecutionConditionsResult {
  outcome: AebExecutionConditionOutcome;
  binding: 'MATCH' | 'MISMATCH' | 'INVALID';
  basis_status: 'CURRENT' | 'EXPIRED' | 'REVOKED' | 'INDETERMINATE' | 'INVALID';
  resolution_status: 'MATCH' | 'MISMATCH' | 'INDETERMINATE' | 'INVALID';
  conditions_satisfied: boolean;
  prevention_established: boolean;
  authorization_established: false;
  physical_truth_established: false;
  decision_scope: 'execution_conditions_only';
  profile_digest: AebDigest | null;
  resolver_profile_digest: AebDigest | null;
  reasons: AebExecutionConditionReason[];
}

export interface AebExecutionProfileVerification {
  valid: boolean;
  profile_digest: AebDigest | null;
  reasons: ('profile_invalid' | 'profile_digest_mismatch')[];
}

export interface AebExecutionResolverProfileVerification {
  valid: boolean;
  profile_digest: AebDigest | null;
  reasons: ('resolver_profile_invalid' | 'resolver_profile_digest_mismatch')[];
}

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const IDENT_RE = /^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$/;
const METHOD_RE = /^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$/;
const RFC3339_SECOND_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;
const STRENGTHS = new Set<AebExecutionEnforcementStrength>([
  'observed', 'leased', 'compare-and-set', 'provider-enforced',
]);
const RESOLUTION_VERDICTS = new Set<AebExecutionResolutionVerdict>([
  'MATCH', 'MISMATCH', 'UNAVAILABLE', 'CONFLICTING',
]);
const BASIS_VERDICTS = new Set<AebExecutionBasisVerdict>([
  'CURRENT', 'EXPIRED', 'REVOKED', 'UNAVAILABLE',
]);
const RESOLVER_KEYS = new Set([
  '@version', 'profile_id', 'version', 'relying_party_id',
  'max_resolution_age_seconds', 'max_future_skew_seconds', 'sources', 'profile_digest',
]);
const SOURCE_KEYS = new Set(['source_id', 'trust_digest', 'required_strength']);
const PROFILE_KEYS = new Set([
  '@version', 'profile_id', 'version', 'relying_party_id', 'action_digest',
  'approved_basis', 'resolver_profile_id', 'resolver_profile_digest', 'profile_digest',
]);
const BASIS_KEYS = new Set([
  'authorization_evidence_digest', 'basis_digest', 'predicate_set_digest',
  'presentation_method', 'presentation_digest',
]);
const BASIS_STATUS_KEYS = new Set(['verdict', 'checked_at', 'status_valid_until']);
const RESOLUTION_KEYS = new Set([
  '@version', 'source_id', 'source_trust_digest', 'source_record_digest',
  'resolver_profile_digest', 'action_digest', 'authorization_evidence_digest',
  'basis_digest', 'predicate_set_digest', 'presentation_method', 'presentation_digest',
  'verdict', 'strength', 'resolved_at', 'valid_until', 'lease_expires_at',
  'enforcement_evidence_digest', 'prevention_claimed',
]);

function isRecord(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Obj, keys: ReadonlySet<string>): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.size && actual.every((key) => keys.has(key));
}

function validDigest(value: unknown): value is AebDigest {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function validIdentifier(value: unknown): value is string {
  return typeof value === 'string' && IDENT_RE.test(value);
}

function parseInstant(value: unknown): number {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_SECOND_RE);
  if (!match) return NaN;
  const [, y, mo, d, h, mi, s] = match;
  const date = new Date(0);
  date.setUTCFullYear(Number(y), Number(mo) - 1, Number(d));
  date.setUTCHours(Number(h), Number(mi), Number(s), 0);
  if (date.toISOString() !== `${value.slice(0, -1)}.000Z`) return NaN;
  return date.getTime();
}

function sortedUnique<T extends string>(values: readonly T[]): T[] {
  return [...new Set(values)].sort() as T[];
}

function freezeDeep<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Obj)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}

function sourceKey(source: AebExecutionResolverSourcePin): string {
  return `${source.source_id}\u0000${source.trust_digest}\u0000${source.required_strength}`;
}

function validApprovedBasis(value: unknown): value is AebExecutionApprovedBasis {
  return isRecord(value) && exactKeys(value, BASIS_KEYS)
    && validDigest(value.authorization_evidence_digest)
    && validDigest(value.basis_digest)
    && validDigest(value.predicate_set_digest)
    && typeof value.presentation_method === 'string' && METHOD_RE.test(value.presentation_method)
    && validDigest(value.presentation_digest);
}

function resolverShapeValid(profile: unknown): profile is AebExecutionResolverProfile {
  if (!isRecord(profile) || !exactKeys(profile, RESOLVER_KEYS)
      || profile['@version'] !== AEB_EXECUTION_RESOLVER_PROFILE_VERSION
      || !validIdentifier(profile.profile_id)
      || !Number.isSafeInteger(profile.version) || Number(profile.version) < 1
      || !validIdentifier(profile.relying_party_id)
      || !Number.isSafeInteger(profile.max_resolution_age_seconds)
      || Number(profile.max_resolution_age_seconds) < 1
      || Number(profile.max_resolution_age_seconds) > 86_400
      || !Number.isSafeInteger(profile.max_future_skew_seconds)
      || Number(profile.max_future_skew_seconds) < 0
      || Number(profile.max_future_skew_seconds) > 300
      || !validDigest(profile.profile_digest)
      || !Array.isArray(profile.sources)
      || profile.sources.length === 0 || profile.sources.length > 32) return false;

  const parsed: AebExecutionResolverSourcePin[] = [];
  for (const source of profile.sources) {
    if (!isRecord(source) || !exactKeys(source, SOURCE_KEYS)
        || !validIdentifier(source.source_id)
        || !validDigest(source.trust_digest)
        || typeof source.required_strength !== 'string'
        || !STRENGTHS.has(source.required_strength as AebExecutionEnforcementStrength)) return false;
    parsed.push(source as unknown as AebExecutionResolverSourcePin);
  }
  const ids = parsed.map((source) => source.source_id);
  const keys = parsed.map(sourceKey);
  return ids.length === new Set(ids).size
    && JSON.stringify(keys) === JSON.stringify([...keys].sort());
}

function conditionsShapeValid(profile: unknown): profile is AebExecutionConditionsProfile {
  return isRecord(profile) && exactKeys(profile, PROFILE_KEYS)
    && profile['@version'] === AEB_EXECUTION_CONDITIONS_VERSION
    && validIdentifier(profile.profile_id)
    && Number.isSafeInteger(profile.version) && Number(profile.version) >= 1
    && validIdentifier(profile.relying_party_id)
    && validDigest(profile.action_digest)
    && validApprovedBasis(profile.approved_basis)
    && validIdentifier(profile.resolver_profile_id)
    && validDigest(profile.resolver_profile_digest)
    && validDigest(profile.profile_digest);
}

function withoutDigest<T extends { profile_digest: AebDigest }>(profile: T): Omit<T, 'profile_digest'> {
  const copy = structuredClone(profile) as T;
  delete (copy as Partial<T>).profile_digest;
  return copy;
}

export function computeAebExecutionResolverProfileDigest(
  profile: AebExecutionResolverProfile,
): AebDigest {
  return digestAeb(withoutDigest(profile));
}

export function verifyAebExecutionResolverProfile(
  profile: unknown,
  expectedDigest?: AebDigest,
): AebExecutionResolverProfileVerification {
  if (!resolverShapeValid(profile)) {
    return { valid: false, profile_digest: null, reasons: ['resolver_profile_invalid'] };
  }
  let computed: AebDigest;
  try {
    computed = computeAebExecutionResolverProfileDigest(profile);
  } catch {
    return { valid: false, profile_digest: null, reasons: ['resolver_profile_invalid'] };
  }
  if (computed !== profile.profile_digest
      || (expectedDigest !== undefined && profile.profile_digest !== expectedDigest)) {
    return { valid: false, profile_digest: computed, reasons: ['resolver_profile_digest_mismatch'] };
  }
  return { valid: true, profile_digest: computed, reasons: [] };
}

export function defineAebExecutionResolverProfile(
  input: AebExecutionResolverProfileInput,
): AebExecutionResolverProfile {
  const sources = [...structuredClone(input.sources)].sort((a, b) => sourceKey(a).localeCompare(sourceKey(b)));
  const profile = {
    ...structuredClone(input),
    sources,
    profile_digest: digestAeb(null),
  } as AebExecutionResolverProfile;
  if (!resolverShapeValid(profile)) throw new TypeError('resolver_profile_invalid');
  profile.profile_digest = computeAebExecutionResolverProfileDigest(profile);
  return freezeDeep(profile);
}

export function computeAebExecutionConditionsProfileDigest(
  profile: AebExecutionConditionsProfile,
): AebDigest {
  return digestAeb(withoutDigest(profile));
}

export function verifyAebExecutionConditionsProfile(
  profile: unknown,
  expectedDigest?: AebDigest,
): AebExecutionProfileVerification {
  if (!conditionsShapeValid(profile)) {
    return { valid: false, profile_digest: null, reasons: ['profile_invalid'] };
  }
  let computed: AebDigest;
  try {
    computed = computeAebExecutionConditionsProfileDigest(profile);
  } catch {
    return { valid: false, profile_digest: null, reasons: ['profile_invalid'] };
  }
  if (computed !== profile.profile_digest
      || (expectedDigest !== undefined && profile.profile_digest !== expectedDigest)) {
    return { valid: false, profile_digest: computed, reasons: ['profile_digest_mismatch'] };
  }
  return { valid: true, profile_digest: computed, reasons: [] };
}

export function defineAebExecutionConditionsProfile(
  input: AebExecutionConditionsProfileInput,
): AebExecutionConditionsProfile {
  const profile = {
    ...structuredClone(input),
    profile_digest: digestAeb(null),
  } as AebExecutionConditionsProfile;
  if (!conditionsShapeValid(profile)) throw new TypeError('profile_invalid');
  profile.profile_digest = computeAebExecutionConditionsProfileDigest(profile);
  return freezeDeep(profile);
}

function result(
  outcome: AebExecutionConditionOutcome,
  reasons: AebExecutionConditionReason[],
  details: Partial<Pick<AebExecutionConditionsResult,
    'binding' | 'basis_status' | 'resolution_status' | 'prevention_established'>> = {},
  profileDigest: AebDigest | null = null,
  resolverProfileDigest: AebDigest | null = null,
): AebExecutionConditionsResult {
  return {
    outcome,
    binding: details.binding ?? (outcome === 'INVALID' ? 'INVALID' : 'MATCH'),
    basis_status: details.basis_status ?? 'CURRENT',
    resolution_status: details.resolution_status
      ?? (outcome === 'PREDICATE_FAILED' ? 'MISMATCH'
        : outcome === 'INDETERMINATE' ? 'INDETERMINATE'
          : outcome === 'INVALID' ? 'INVALID' : 'MATCH'),
    conditions_satisfied: outcome === 'ADMIT',
    prevention_established: outcome === 'ADMIT' && details.prevention_established === true,
    authorization_established: false,
    physical_truth_established: false,
    decision_scope: 'execution_conditions_only',
    profile_digest: profileDigest,
    resolver_profile_digest: resolverProfileDigest,
    reasons: sortedUnique(reasons),
  };
}

function basisMismatchReasons(
  expected: AebExecutionApprovedBasis,
  presented: unknown,
): AebExecutionConditionReason[] {
  if (!validApprovedBasis(presented)) return ['profile_invalid'];
  const reasons: AebExecutionConditionReason[] = [];
  if (presented.authorization_evidence_digest !== expected.authorization_evidence_digest) {
    reasons.push('authorization_evidence_mismatch');
  }
  if (presented.basis_digest !== expected.basis_digest) reasons.push('basis_digest_mismatch');
  if (presented.predicate_set_digest !== expected.predicate_set_digest) {
    reasons.push('predicate_set_digest_mismatch');
  }
  if (presented.presentation_method !== expected.presentation_method) {
    reasons.push('presentation_method_mismatch');
  }
  if (presented.presentation_digest !== expected.presentation_digest) {
    reasons.push('presentation_digest_mismatch');
  }
  return reasons;
}

function validBasisStatus(value: unknown): value is AebExecutionBasisStatus {
  return isRecord(value) && exactKeys(value, BASIS_STATUS_KEYS)
    && typeof value.verdict === 'string'
    && BASIS_VERDICTS.has(value.verdict as AebExecutionBasisVerdict)
    && Number.isFinite(parseInstant(value.checked_at))
    && Number.isFinite(parseInstant(value.status_valid_until));
}

function resolutionShapeReasons(
  resolution: unknown,
): AebExecutionConditionReason[] {
  if (!isRecord(resolution) || !exactKeys(resolution, RESOLUTION_KEYS)
      || resolution['@version'] !== AEB_EXECUTION_CONDITION_RESOLUTION_VERSION
      || !validIdentifier(resolution.source_id)
      || !validDigest(resolution.source_trust_digest)
      || !validDigest(resolution.source_record_digest)
      || !validDigest(resolution.resolver_profile_digest)
      || !validDigest(resolution.action_digest)
      || !validDigest(resolution.authorization_evidence_digest)
      || !validDigest(resolution.basis_digest)
      || !validDigest(resolution.predicate_set_digest)
      || typeof resolution.presentation_method !== 'string'
      || !METHOD_RE.test(resolution.presentation_method)
      || !validDigest(resolution.presentation_digest)
      || typeof resolution.verdict !== 'string'
      || !RESOLUTION_VERDICTS.has(resolution.verdict as AebExecutionResolutionVerdict)
      || typeof resolution.strength !== 'string'
      || !STRENGTHS.has(resolution.strength as AebExecutionEnforcementStrength)
      || !Number.isFinite(parseInstant(resolution.resolved_at))
      || !Number.isFinite(parseInstant(resolution.valid_until))
      || typeof resolution.prevention_claimed !== 'boolean'
      || !(resolution.lease_expires_at === null
        || Number.isFinite(parseInstant(resolution.lease_expires_at)))
      || !(resolution.enforcement_evidence_digest === null
        || validDigest(resolution.enforcement_evidence_digest))) return ['resolution_invalid'];

  const typed = resolution as unknown as AebExecutionConditionResolution;
  const protective = typed.strength === 'compare-and-set' || typed.strength === 'provider-enforced';
  const reasons: AebExecutionConditionReason[] = [];
  if (!protective && typed.prevention_claimed) reasons.push('prevention_claim_not_supported');
  if (protective && typed.enforcement_evidence_digest === null) reasons.push('enforcement_evidence_missing');
  if (typed.strength === 'leased' && typed.lease_expires_at === null) reasons.push('resolution_invalid');
  if (typed.strength !== 'leased' && typed.lease_expires_at !== null) reasons.push('resolution_invalid');
  if (!protective && typed.enforcement_evidence_digest !== null) reasons.push('resolution_invalid');
  return reasons;
}

function evaluateInner(
  profile: unknown,
  options: AebExecutionConditionsEvaluationOptions,
): AebExecutionConditionsResult {
  const checkedProfile = verifyAebExecutionConditionsProfile(profile, options.expected_profile_digest);
  const profileDigest = checkedProfile.profile_digest;
  if (!checkedProfile.valid) {
    return result('INVALID', checkedProfile.reasons, {}, profileDigest, null);
  }
  const typedProfile = profile as AebExecutionConditionsProfile;
  const checkedResolver = verifyAebExecutionResolverProfile(
    options.resolver_profile,
    typedProfile.resolver_profile_digest,
  );
  const resolverDigest = checkedResolver.profile_digest;
  if (!checkedResolver.valid) {
    return result('INVALID', checkedResolver.reasons, {}, profileDigest, resolverDigest);
  }
  if (options.resolver_profile.profile_id !== typedProfile.resolver_profile_id) {
    return result('INVALID', ['resolver_profile_id_mismatch'], {}, profileDigest, resolverDigest);
  }
  if (options.resolver_profile.relying_party_id !== typedProfile.relying_party_id) {
    return result('INVALID', ['relying_party_mismatch'], {}, profileDigest, resolverDigest);
  }
  if (!validDigest(options.action_digest) || options.action_digest !== typedProfile.action_digest) {
    return result('INVALID', ['exact_action_mismatch'], { binding: 'MISMATCH' }, profileDigest, resolverDigest);
  }
  const basisReasons = basisMismatchReasons(typedProfile.approved_basis, options.approved_basis);
  if (basisReasons.length > 0) {
    return result('INVALID', basisReasons, { binding: 'MISMATCH' }, profileDigest, resolverDigest);
  }

  if (!validBasisStatus(options.basis_status)) {
    return result('INVALID', ['basis_status_invalid'], { basis_status: 'INVALID' }, profileDigest, resolverDigest);
  }
  const evaluatedAt = parseInstant(options.evaluated_at);
  if (!Number.isFinite(evaluatedAt)) {
    return result('INVALID', ['basis_status_invalid'], { basis_status: 'INVALID' }, profileDigest, resolverDigest);
  }
  if (options.basis_status.verdict === 'EXPIRED') {
    return result('INVALID', ['basis_expired'], { basis_status: 'EXPIRED' }, profileDigest, resolverDigest);
  }
  if (options.basis_status.verdict === 'REVOKED') {
    return result('INVALID', ['basis_revoked'], { basis_status: 'REVOKED' }, profileDigest, resolverDigest);
  }
  if (options.basis_status.verdict === 'UNAVAILABLE') {
    return result('INDETERMINATE', ['basis_status_unavailable'], {
      basis_status: 'INDETERMINATE', resolution_status: 'INDETERMINATE',
    }, profileDigest, resolverDigest);
  }
  const basisCheckedAt = parseInstant(options.basis_status.checked_at);
  const basisStatusValidUntil = parseInstant(options.basis_status.status_valid_until);
  const futureSkewMs = options.resolver_profile.max_future_skew_seconds * 1000;
  if (basisCheckedAt > evaluatedAt + futureSkewMs || basisStatusValidUntil < evaluatedAt) {
    return result('INDETERMINATE', ['basis_status_stale'], {
      basis_status: 'INDETERMINATE', resolution_status: 'INDETERMINATE',
    }, profileDigest, resolverDigest);
  }

  if (!Array.isArray(options.resolutions) || options.resolutions.length > 64) {
    return result('INVALID', ['resolution_invalid'], {}, profileDigest, resolverDigest);
  }
  const pins = new Map(options.resolver_profile.sources.map((pin) => [pin.source_id, pin]));
  const bySource = new Map<string, AebExecutionConditionResolution[]>();
  for (const raw of options.resolutions) {
    const shapeReasons = resolutionShapeReasons(raw);
    if (shapeReasons.length > 0) {
      return result('INVALID', shapeReasons, {}, profileDigest, resolverDigest);
    }
    const resolution = raw as AebExecutionConditionResolution;
    const pin = pins.get(resolution.source_id);
    if (!pin) {
      return result('INVALID', ['resolution_source_unpinned'], {}, profileDigest, resolverDigest);
    }
    const bindingReasons: AebExecutionConditionReason[] = [];
    if (resolution.source_trust_digest !== pin.trust_digest) {
      bindingReasons.push('resolution_source_trust_mismatch');
    }
    if (resolution.strength !== pin.required_strength) bindingReasons.push('resolution_strength_mismatch');
    if (resolution.resolver_profile_digest !== typedProfile.resolver_profile_digest) {
      bindingReasons.push('resolution_resolver_mismatch');
    }
    if (resolution.action_digest !== typedProfile.action_digest) bindingReasons.push('resolution_action_mismatch');
    if (resolution.authorization_evidence_digest
        !== typedProfile.approved_basis.authorization_evidence_digest) {
      bindingReasons.push('resolution_authorization_mismatch');
    }
    if (resolution.basis_digest !== typedProfile.approved_basis.basis_digest) {
      bindingReasons.push('resolution_basis_mismatch');
    }
    if (resolution.predicate_set_digest !== typedProfile.approved_basis.predicate_set_digest) {
      bindingReasons.push('resolution_predicate_set_mismatch');
    }
    if (resolution.presentation_method !== typedProfile.approved_basis.presentation_method
        || resolution.presentation_digest !== typedProfile.approved_basis.presentation_digest) {
      bindingReasons.push('resolution_presentation_mismatch');
    }
    if (bindingReasons.length > 0) {
      return result('INVALID', bindingReasons, { binding: 'MISMATCH' }, profileDigest, resolverDigest);
    }
    const entries = bySource.get(resolution.source_id) ?? [];
    entries.push(resolution);
    bySource.set(resolution.source_id, entries);
  }

  const missing = options.resolver_profile.sources.some((pin) => !bySource.has(pin.source_id));
  if (missing) {
    return result('INDETERMINATE', ['resolution_missing'], {}, profileDigest, resolverDigest);
  }
  if ([...bySource.values()].some((entries) => entries.length !== 1)) {
    return result('INDETERMINATE', ['resolution_conflicting'], {}, profileDigest, resolverDigest);
  }

  const resolutions = [...bySource.values()].map(([entry]) => entry);
  const maxAgeMs = options.resolver_profile.max_resolution_age_seconds * 1000;
  for (const resolution of resolutions) {
    const resolvedAt = parseInstant(resolution.resolved_at);
    const validUntil = parseInstant(resolution.valid_until);
    if (validUntil < resolvedAt) {
      return result('INVALID', ['resolution_invalid'], {}, profileDigest, resolverDigest);
    }
    if (resolvedAt > evaluatedAt + futureSkewMs) {
      return result('INDETERMINATE', ['resolution_from_future'], {}, profileDigest, resolverDigest);
    }
    if (evaluatedAt - resolvedAt > maxAgeMs || evaluatedAt > validUntil) {
      return result('INDETERMINATE', ['resolution_stale'], {}, profileDigest, resolverDigest);
    }
    if (resolution.strength === 'leased'
        && evaluatedAt > parseInstant(resolution.lease_expires_at)) {
      return result('INDETERMINATE', ['lease_expired'], {}, profileDigest, resolverDigest);
    }
  }

  if (resolutions.some((resolution) => resolution.verdict === 'CONFLICTING')) {
    return result('INDETERMINATE', ['resolution_conflicting'], {}, profileDigest, resolverDigest);
  }
  if (resolutions.some((resolution) => resolution.verdict === 'UNAVAILABLE')) {
    return result('INDETERMINATE', ['resolution_unavailable'], {}, profileDigest, resolverDigest);
  }
  if (resolutions.some((resolution) => resolution.verdict === 'MISMATCH')) {
    return result('PREDICATE_FAILED', ['predicate_failed'], {}, profileDigest, resolverDigest);
  }

  const preventionEstablished = resolutions.every((resolution) =>
    (resolution.strength === 'compare-and-set' || resolution.strength === 'provider-enforced')
      && resolution.prevention_claimed
      && resolution.enforcement_evidence_digest !== null);
  return result('ADMIT', [], { prevention_established: preventionEstablished }, profileDigest, resolverDigest);
}

export function evaluateAebExecutionConditions(
  profile: unknown,
  options: AebExecutionConditionsEvaluationOptions,
): AebExecutionConditionsResult {
  try {
    return evaluateInner(profile, options);
  } catch {
    return result('INVALID', ['profile_invalid']);
  }
}
