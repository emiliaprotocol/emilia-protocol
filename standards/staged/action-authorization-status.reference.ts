// SPDX-License-Identifier: Apache-2.0
/**
 * Implementation-neutral action-authorization status coding for incident,
 * claims, and underwriting records. This module validates a classification;
 * it does not decide authorization, causation, liability, or coverage.
 */

import crypto from 'node:crypto';

export const ACTION_AUTHORIZATION_STATUS_VERSION = 'ACTION-AUTHORIZATION-STATUS-v1' as const;

export const AUTHORIZATION_REQUIREMENTS = [
  'exact_action',
  'bounded_program',
  'standing_scope',
  'none',
  'unknown',
] as const;

export const AUTHORITY_STATES = [
  'valid',
  'invalid',
  'revoked',
  'stale',
  'indeterminate',
  'not_evaluated',
] as const;

export const ACTION_BINDINGS = [
  'exact_action',
  'within_bound',
  'outside_bound',
  'none',
  'indeterminate',
  'not_evaluated',
] as const;

export const ADMISSION_STATES = [
  'admitted',
  'refused',
  'bypassed',
  'indeterminate',
  'not_observed',
] as const;

export const EFFECT_STATES = [
  'executed',
  'failed',
  'not_executed',
  'indeterminate',
  'unknown',
] as const;

export const AUTHORIZATION_EVIDENCE_CLASSES = [
  'E0_NONE',
  'E1_SELF_ASSERTED',
  'E2_OPERATOR_RECORDED',
  'E3_ACTION_BOUND_SIGNED',
  'E4_OFFLINE_PINNED_VERIFIABLE',
  'E5_RECONCILED_NAMED_POPULATION',
] as const;

export const BOUNDARY_ROLES = [
  'credential_broker',
  'resource_server',
  'provider_gateway',
  'execution_service',
  'other',
] as const;

export const POPULATION_BASES = [
  'single_action',
  'declared_population',
  'reconciled_named_systems',
  'independent_observation',
] as const;

export const ARTIFACT_VERIFICATION_STATES = [
  'verified',
  'failed',
  'not_checked',
  'indeterminate',
] as const;

export interface ActionAuthorizationStatusValidation {
  valid: boolean;
  errors: string[];
  digest?: string;
}

const MAX_CANONICAL_DEPTH = 64;

function hasUnpairedUtf16Surrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function canonicalDomainError(path: string, reason: string): TypeError {
  return new TypeError(`value is outside the strict canonical JSON domain at ${path}: ${reason}`);
}

function canonicalizeValue(value: unknown, path: string, ancestors: Set<object>, depth: number): string {
  if (depth > MAX_CANONICAL_DEPTH) throw canonicalDomainError(path, 'nesting depth exceeded');
  if (value === null) return 'null';
  if (typeof value === 'string') {
    if (hasUnpairedUtf16Surrogate(value)) throw canonicalDomainError(path, 'unpaired Unicode surrogate');
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw canonicalDomainError(path, 'numbers must be safe integers');
    return JSON.stringify(value);
  }
  if (typeof value !== 'object') throw canonicalDomainError(path, `${typeof value} is not a JSON value`);

  const object = value as object;
  if (ancestors.has(object)) throw canonicalDomainError(path, 'cyclic reference');
  ancestors.add(object);
  try {
    if (Array.isArray(value)) {
      const ownKeys = Reflect.ownKeys(value);
      const expectedKeys = new Set(['length', ...Array.from({ length: value.length }, (_, index) => String(index))]);
      if (ownKeys.some((key) => typeof key !== 'string')
          || ownKeys.length !== expectedKeys.size
          || ownKeys.some((key) => !expectedKeys.has(key as string))) {
        throw canonicalDomainError(path, 'sparse arrays and extra members are not permitted');
      }
      const entries: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !('value' in descriptor)) {
          throw canonicalDomainError(`${path}[${index}]`, 'array holes and accessors are not permitted');
        }
        entries.push(canonicalizeValue(descriptor.value, `${path}[${index}]`, ancestors, depth + 1));
      }
      return `[${entries.join(',')}]`;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw canonicalDomainError(path, 'only plain objects are permitted');
    }
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some((key) => typeof key !== 'string')) throw canonicalDomainError(path, 'symbol members are not JSON');
    const members: string[] = [];
    for (const key of (ownKeys as string[]).sort()) {
      if (hasUnpairedUtf16Surrogate(key)) throw canonicalDomainError(`${path}.${key}`, 'invalid member name');
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor)) {
        throw canonicalDomainError(`${path}.${key}`, 'non-enumerable members and accessors are not permitted');
      }
      members.push(`${JSON.stringify(key)}:${canonicalizeValue(descriptor.value, `${path}.${key}`, ancestors, depth + 1)}`);
    }
    return `{${members.join(',')}}`;
  } finally {
    ancestors.delete(object);
  }
}

function canonicalizeStrictJson(value: unknown): string {
  return canonicalizeValue(value, '$', new Set<object>(), 0);
}

export type AuthorizationRequirement = typeof AUTHORIZATION_REQUIREMENTS[number];
export type AuthorityState = typeof AUTHORITY_STATES[number];
export type ActionBinding = typeof ACTION_BINDINGS[number];
export type AdmissionState = typeof ADMISSION_STATES[number];
export type EffectState = typeof EFFECT_STATES[number];
export type AuthorizationEvidenceClass = typeof AUTHORIZATION_EVIDENCE_CLASSES[number];
export type BoundaryRole = typeof BOUNDARY_ROLES[number];
export type PopulationBasis = typeof POPULATION_BASES[number];
export type ArtifactVerificationState = typeof ARTIFACT_VERIFICATION_STATES[number];

export interface ActionAuthorizationStatusRecord {
  '@version': typeof ACTION_AUTHORIZATION_STATUS_VERSION;
  action: {
    reference: { scheme: string; value: string };
    type: string;
    occurred_at: string;
  };
  boundary: {
    id: string;
    role: BoundaryRole;
  };
  classification: {
    requirement: AuthorizationRequirement;
    authority: AuthorityState;
    binding: ActionBinding;
    admission: AdmissionState;
    effect: EffectState;
  };
  evidence: {
    class: AuthorizationEvidenceClass;
    as_of: string;
    population_basis: PopulationBasis;
    source_systems: string[];
    verification_profile: {
      id: string;
      digest: string;
    } | null;
    artifacts: Array<{
      type: string;
      digest: string;
      verification: ArtifactVerificationState;
    }>;
    limitations: string[];
  };
  classified_at: string;
  classifier: {
    id: string;
    method: 'manual' | 'ruleset' | 'mixed';
    ruleset_digest: string;
  };
}

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/+\-]{0,511}$/;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isOneOf<T extends readonly string[]>(value: unknown, values: T): value is T[number] {
  return typeof value === 'string' && values.includes(value as T[number]);
}

function timestampMillis(value: unknown): number | null {
  if (typeof value !== 'string' || !UTC_TIMESTAMP.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function add(errors: string[], condition: boolean, code: string): void {
  if (!condition) errors.push(code);
}

function uniqueStrings(value: unknown): value is string[] {
  return Array.isArray(value)
    && value.every((entry) => typeof entry === 'string' && IDENTIFIER.test(entry))
    && new Set(value).size === value.length;
}

function digestStrictRecord(record: unknown): string {
  const canonical = canonicalizeStrictJson(record);
  return `sha256:${crypto.createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
}

export function validateActionAuthorizationStatus(record: unknown): ActionAuthorizationStatusValidation {
  const errors: string[] = [];
  try {
    canonicalizeStrictJson(record);
  } catch {
    return { valid: false, errors: ['record_outside_strict_json_domain'] };
  }

  if (!isObject(record)) return { valid: false, errors: ['record_must_be_object'] };
  add(errors, hasExactKeys(record, [
    '@version', 'action', 'boundary', 'classification', 'evidence', 'classified_at', 'classifier',
  ]), 'record_members_not_closed');
  add(errors, record['@version'] === ACTION_AUTHORIZATION_STATUS_VERSION, 'unsupported_version');

  const action = record.action;
  if (!isObject(action)) {
    errors.push('invalid_action');
  } else {
    add(errors, hasExactKeys(action, ['reference', 'type', 'occurred_at']), 'action_members_not_closed');
    const reference = action.reference;
    if (!isObject(reference)) {
      errors.push('invalid_action_reference');
    } else {
      add(errors, hasExactKeys(reference, ['scheme', 'value']), 'action_reference_members_not_closed');
      add(errors, typeof reference.scheme === 'string' && IDENTIFIER.test(reference.scheme), 'invalid_action_reference_scheme');
      add(errors, typeof reference.value === 'string' && reference.value.length > 0 && reference.value.length <= 2048, 'invalid_action_reference_value');
    }
    add(errors, typeof action.type === 'string' && IDENTIFIER.test(action.type), 'invalid_action_type');
    add(errors, timestampMillis(action.occurred_at) !== null, 'invalid_action_timestamp');
  }

  const boundary = record.boundary;
  if (!isObject(boundary)) {
    errors.push('invalid_boundary');
  } else {
    add(errors, hasExactKeys(boundary, ['id', 'role']), 'boundary_members_not_closed');
    add(errors, typeof boundary.id === 'string' && IDENTIFIER.test(boundary.id), 'invalid_boundary_id');
    add(errors, isOneOf(boundary.role, BOUNDARY_ROLES), 'invalid_boundary_role');
  }

  const classification = record.classification;
  if (!isObject(classification)) {
    errors.push('invalid_classification');
  } else {
    add(errors, hasExactKeys(classification, ['requirement', 'authority', 'binding', 'admission', 'effect']), 'classification_members_not_closed');
    add(errors, isOneOf(classification.requirement, AUTHORIZATION_REQUIREMENTS), 'invalid_requirement');
    add(errors, isOneOf(classification.authority, AUTHORITY_STATES), 'invalid_authority_state');
    add(errors, isOneOf(classification.binding, ACTION_BINDINGS), 'invalid_action_binding');
    add(errors, isOneOf(classification.admission, ADMISSION_STATES), 'invalid_admission_state');
    add(errors, isOneOf(classification.effect, EFFECT_STATES), 'invalid_effect_state');

    if (classification.requirement === 'none') {
      add(errors, classification.authority === 'not_evaluated', 'no_requirement_requires_authority_not_evaluated');
      add(errors, classification.binding === 'not_evaluated', 'no_requirement_requires_binding_not_evaluated');
    }
    if (classification.requirement === 'unknown') {
      add(errors, classification.authority === 'indeterminate', 'unknown_requirement_requires_indeterminate_authority');
      add(errors, classification.binding === 'indeterminate', 'unknown_requirement_requires_indeterminate_binding');
    }
  }

  const evidence = record.evidence;
  if (!isObject(evidence)) {
    errors.push('invalid_evidence');
  } else {
    add(errors, hasExactKeys(evidence, [
      'class', 'as_of', 'population_basis', 'source_systems', 'verification_profile',
      'artifacts', 'limitations',
    ]), 'evidence_members_not_closed');
    add(errors, isOneOf(evidence.class, AUTHORIZATION_EVIDENCE_CLASSES), 'invalid_evidence_class');
    add(errors, timestampMillis(evidence.as_of) !== null, 'invalid_evidence_timestamp');
    add(errors, isOneOf(evidence.population_basis, POPULATION_BASES), 'invalid_population_basis');
    add(errors, uniqueStrings(evidence.source_systems), 'invalid_source_systems');
    const verificationProfile = evidence.verification_profile;
    if (verificationProfile !== null) {
      if (!isObject(verificationProfile)) {
        errors.push('invalid_verification_profile');
      } else {
        add(errors, hasExactKeys(verificationProfile, ['id', 'digest']), 'verification_profile_members_not_closed');
        add(errors, typeof verificationProfile.id === 'string' && IDENTIFIER.test(verificationProfile.id), 'invalid_verification_profile_id');
        add(errors, typeof verificationProfile.digest === 'string' && DIGEST.test(verificationProfile.digest), 'invalid_verification_profile_digest');
      }
    }
    add(errors, Array.isArray(evidence.limitations)
      && evidence.limitations.length > 0
      && evidence.limitations.length <= 32
      && evidence.limitations.every((entry) => typeof entry === 'string' && entry.length > 0 && entry.length <= 2048), 'invalid_limitations');

    const artifacts = evidence.artifacts;
    if (!Array.isArray(artifacts) || artifacts.length > 64) {
      errors.push('invalid_artifacts');
    } else {
      const artifactDigests: string[] = [];
      for (const artifact of artifacts) {
        if (!isObject(artifact)) {
          errors.push('invalid_artifact');
          continue;
        }
        add(errors, hasExactKeys(artifact, ['type', 'digest', 'verification']), 'artifact_members_not_closed');
        add(errors, typeof artifact.type === 'string' && IDENTIFIER.test(artifact.type), 'invalid_artifact_type');
        add(errors, typeof artifact.digest === 'string' && DIGEST.test(artifact.digest), 'invalid_artifact_digest');
        add(errors, isOneOf(artifact.verification, ARTIFACT_VERIFICATION_STATES), 'invalid_artifact_verification');
        if (typeof artifact.digest === 'string') artifactDigests.push(artifact.digest);
      }
      add(errors, new Set(artifactDigests).size === artifactDigests.length, 'duplicate_artifact_digest');
      if (evidence.class === 'E0_NONE') {
        add(errors, artifacts.length === 0, 'e0_forbids_artifacts');
      } else if (isOneOf(evidence.class, AUTHORIZATION_EVIDENCE_CLASSES)) {
        add(errors, artifacts.length > 0, 'evidence_class_requires_artifact');
      }
      if (evidence.class === 'E3_ACTION_BOUND_SIGNED'
          || evidence.class === 'E4_OFFLINE_PINNED_VERIFIABLE'
          || evidence.class === 'E5_RECONCILED_NAMED_POPULATION') {
        add(errors, artifacts.some((artifact) => isObject(artifact) && artifact.verification === 'verified'), 'signed_class_requires_verified_artifact');
      }
      if (evidence.class === 'E4_OFFLINE_PINNED_VERIFIABLE'
          || evidence.class === 'E5_RECONCILED_NAMED_POPULATION') {
        add(errors, isObject(verificationProfile), 'verified_class_requires_verification_profile');
        add(errors, !artifacts.some((artifact) => isObject(artifact) && artifact.verification === 'failed'), 'verified_class_forbids_failed_artifact');
      }
      if (evidence.class === 'E5_RECONCILED_NAMED_POPULATION') {
        add(errors, evidence.population_basis === 'reconciled_named_systems', 'e5_requires_reconciled_population_basis');
        add(errors, Array.isArray(evidence.source_systems) && evidence.source_systems.length > 0, 'e5_requires_named_source_systems');
      }
    }
  }

  const classifier = record.classifier;
  if (!isObject(classifier)) {
    errors.push('invalid_classifier');
  } else {
    add(errors, hasExactKeys(classifier, ['id', 'method', 'ruleset_digest']), 'classifier_members_not_closed');
    add(errors, typeof classifier.id === 'string' && IDENTIFIER.test(classifier.id), 'invalid_classifier_id');
    add(errors, isOneOf(classifier.method, ['manual', 'ruleset', 'mixed'] as const), 'invalid_classifier_method');
    add(errors, typeof classifier.ruleset_digest === 'string' && DIGEST.test(classifier.ruleset_digest), 'invalid_ruleset_digest');
  }

  const occurredAt = isObject(action) ? timestampMillis(action.occurred_at) : null;
  const evidenceAsOf = isObject(evidence) ? timestampMillis(evidence.as_of) : null;
  const classifiedAt = timestampMillis(record.classified_at);
  add(errors, classifiedAt !== null, 'invalid_classified_at');
  if (occurredAt !== null && evidenceAsOf !== null) {
    add(errors, evidenceAsOf >= occurredAt, 'evidence_precedes_action');
  }
  if (evidenceAsOf !== null && classifiedAt !== null) {
    add(errors, classifiedAt >= evidenceAsOf, 'classification_precedes_evidence');
  }

  const uniqueErrors = [...new Set(errors)];
  if (uniqueErrors.length > 0) return { valid: false, errors: uniqueErrors };
  return { valid: true, errors: [], digest: digestStrictRecord(record) };
}

export function authorizationStatusDigest(record: unknown): string {
  const result = validateActionAuthorizationStatus(record);
  if (!result.valid || !result.digest) {
    throw new TypeError(`invalid action authorization status: ${result.errors.join(',')}`);
  }
  return result.digest;
}

const actionAuthorizationStatus = {
  ACTION_AUTHORIZATION_STATUS_VERSION,
  AUTHORIZATION_REQUIREMENTS,
  AUTHORITY_STATES,
  ACTION_BINDINGS,
  ADMISSION_STATES,
  EFFECT_STATES,
  AUTHORIZATION_EVIDENCE_CLASSES,
  BOUNDARY_ROLES,
  POPULATION_BASES,
  ARTIFACT_VERIFICATION_STATES,
  validateActionAuthorizationStatus,
  authorizationStatusDigest,
};

export default actionAuthorizationStatus;
