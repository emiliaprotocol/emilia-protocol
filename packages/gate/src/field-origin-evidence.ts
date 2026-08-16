// SPDX-License-Identifier: Apache-2.0
/**
 * Signed per-field provenance evidence for one executor-observed action.
 *
 * The artifact authenticates a pinned issuer's assertions about where each
 * exact field came from and whether it was a snapshot of mutable state. It is
 * evaluated before admission. It does not prove the asserted origin is true,
 * detect prompt injection, authorize the action, or prove an external effect.
 */
import { createPublicKey } from 'node:crypto';

import {
  RISK_DIGEST,
  riskClone,
  riskDigest,
  riskExact,
  riskFreeze,
  riskIdentifier,
  riskRecord,
  signRiskBody,
  verifyRiskBody,
  type RiskRecord,
  type TrustedRiskKeys,
} from './reliance-risk-crypto.js';
import { canonicalizeStrictJson } from './strict-json.js';

export const FIELD_ORIGIN_EVIDENCE_VERSION = 'EP-FIELD-ORIGIN-v0.1';
export const FIELD_ORIGIN_CLAIM_BOUNDARY =
  'pinned_issuer_asserted_field_provenance_bound_to_exact_action_at_admission_not_source_truth_not_prompt_injection_detection_not_authorization_not_effect_truth';

const PROFILE_KEYS = [
  'profile_id', 'relying_party_id', 'action_type', 'fields', 'transforms',
] as const;
const FIELD_RULE_KEYS = [
  'path', 'role', 'required', 'allowed_origins', 'snapshot_policy',
  'max_snapshot_age_sec', 'allowed_transform_ids',
] as const;
const TRANSFORM_KEYS = ['transform_id', 'version', 'digest'] as const;
const INPUT_KEYS = [
  'evidence_id', 'profile', 'observed_action', 'observed_at', 'annotations',
] as const;
const ANNOTATION_KEYS = ['path', 'origin_class', 'snapshot', 'transform'] as const;
const FIELD_KEYS = [
  'path', 'value_digest', 'origin_class', 'snapshot', 'transform',
] as const;
const SNAPSHOT_KEYS = ['kind', 'observed_at', 'source_version'] as const;
const BODY_KEYS = [
  '@version', 'evidence_id', 'profile_id', 'profile_digest',
  'relying_party_id', 'action_type', 'action_digest', 'observed_at',
  'fields', 'claim_boundary', 'issuer',
] as const;
const CONTEXT_KEYS = [
  'trusted_keys', 'pinned_profile', 'expected_relying_party_id',
  'observed_action', 'now',
] as const;
const ISSUER_KEYS = ['id', 'key_id'] as const;
const SIGNER_KEYS = ['issuer_id', 'key_id', 'private_key'] as const;
const TRUSTED_KEY_KEYS = ['issuer_id', 'public_key'] as const;

const ORIGIN_CLASSES = new Set([
  'operator_pinned',
  'approver_supplied',
  'untrusted_bounded',
  'derived_via_versioned_transform',
  'unknown',
]);
const PROFILE_ORIGIN_CLASSES = new Set([
  'operator_pinned',
  'approver_supplied',
  'untrusted_bounded',
  'derived_via_versioned_transform',
]);
const FIELD_ROLES = new Set(['control', 'bounded_data']);
const SNAPSHOT_POLICIES = new Set(['immutable', 'mutable_snapshot', 'either']);
const MAX_FIELDS = 256;
const MAX_TRANSFORMS = 64;
const MAX_SNAPSHOT_AGE_SEC = 31_536_000;

export interface FieldOriginVerificationContext {
  trusted_keys: TrustedRiskKeys;
  pinned_profile: RiskRecord;
  expected_relying_party_id: string;
  observed_action: RiskRecord;
  now: string;
}

export class FieldOriginValidationError extends TypeError {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'FieldOriginValidationError';
    this.code = code;
  }
}

function refuse(code: string, message: string): never {
  throw new FieldOriginValidationError(code, message);
}

function strictJsonClone(value: unknown): any {
  return JSON.parse(canonicalizeStrictJson(value));
}

function byteOrder(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function safeInteger(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum;
}

function canonicalInstant(value: unknown, field: string): string {
  if (typeof value !== 'string') refuse('field_origin_instant_invalid', `${field} must be canonical RFC 3339`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    refuse('field_origin_instant_invalid', `${field} must be canonical RFC 3339`);
  }
  return value;
}

function validPointer(path: unknown): path is string {
  return typeof path === 'string'
    && path.startsWith('/')
    && Buffer.byteLength(path, 'utf8') <= 512
    && !/~(?:[^01]|$)/.test(path);
}

function decodePointer(path: string): string[] {
  if (!validPointer(path)) refuse('field_origin_path_invalid', 'field path must be a bounded JSON Pointer');
  return path.slice(1).split('/').map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'));
}

function encodePointerPart(part: string): string {
  return part.replace(/~/g, '~0').replace(/\//g, '~1');
}

function actionLeafPaths(value: unknown, base = ''): string[] {
  if (Array.isArray(value) || !riskRecord(value) || Object.keys(value).length === 0) {
    return base ? [base] : [];
  }
  const paths: string[] = [];
  for (const key of Object.keys(value).sort(byteOrder)) {
    const next = `${base}/${encodePointerPart(key)}`;
    paths.push(...actionLeafPaths(value[key], next));
  }
  return paths;
}

function valueAtPointer(value: unknown, path: string): { found: boolean; value: unknown } {
  let current = value;
  for (const part of decodePointer(path)) {
    if (Array.isArray(current)) {
      if (!/^(0|[1-9][0-9]*)$/.test(part)) return { found: false, value: null };
      const index = Number(part);
      if (!Number.isSafeInteger(index) || index >= current.length) return { found: false, value: null };
      current = current[index];
      continue;
    }
    if (!riskRecord(current) || !Object.hasOwn(current, part)) return { found: false, value: null };
    current = current[part];
  }
  return { found: true, value: current };
}

function normalizeStringSet(
  value: unknown,
  allowed: ReadonlySet<string> | null,
  field: string,
  maximum: number,
): string[] {
  if (!Array.isArray(value) || value.length > maximum
      || value.some((entry) => typeof entry !== 'string'
        || !riskIdentifier(entry)
        || (allowed !== null && !allowed.has(entry)))
      || new Set(value).size !== value.length) {
    refuse(`field_origin_${field}_invalid`, `${field} is invalid`);
  }
  return [...value].sort(byteOrder);
}

function normalizeTransform(value: unknown): RiskRecord {
  if (!riskExact(value, TRANSFORM_KEYS)
      || !riskIdentifier(value.transform_id)
      || !riskIdentifier(value.version)
      || typeof value.digest !== 'string'
      || !RISK_DIGEST.test(value.digest)) {
    refuse('field_origin_transform_invalid', 'transform is invalid');
  }
  return {
    transform_id: value.transform_id,
    version: value.version,
    digest: value.digest,
  };
}

function normalizeProfile(value: unknown): RiskRecord {
  if (!riskExact(value, PROFILE_KEYS)
      || !riskIdentifier(value.profile_id)
      || !riskIdentifier(value.relying_party_id)
      || !riskIdentifier(value.action_type)
      || !Array.isArray(value.fields)
      || value.fields.length < 1
      || value.fields.length > MAX_FIELDS
      || !Array.isArray(value.transforms)
      || value.transforms.length > MAX_TRANSFORMS) {
    refuse('field_origin_profile_invalid', 'field-origin profile is not a closed v0.1 object');
  }

  const transforms = value.transforms.map(normalizeTransform);
  const transformIds = new Set<string>();
  for (const transform of transforms) {
    if (transformIds.has(transform.transform_id)) {
      refuse('field_origin_transform_duplicated', 'transform id is duplicated');
    }
    transformIds.add(transform.transform_id);
  }

  const paths = new Set<string>();
  const fields = value.fields.map((entry) => {
    if (!riskExact(entry, FIELD_RULE_KEYS)
        || !validPointer(entry.path)
        || typeof entry.role !== 'string'
        || !FIELD_ROLES.has(entry.role)
        || typeof entry.required !== 'boolean'
        || typeof entry.snapshot_policy !== 'string'
        || !SNAPSHOT_POLICIES.has(entry.snapshot_policy)) {
      refuse('field_origin_field_rule_invalid', 'field-origin rule is invalid');
    }
    if (paths.has(entry.path)) refuse('field_origin_path_duplicated', 'field path is duplicated');
    paths.add(entry.path);

    const allowedOrigins = normalizeStringSet(
      entry.allowed_origins,
      PROFILE_ORIGIN_CLASSES,
      'allowed_origins',
      PROFILE_ORIGIN_CLASSES.size,
    );
    if (allowedOrigins.length < 1) {
      refuse('field_origin_allowed_origins_invalid', 'allowed_origins must not be empty');
    }
    if (entry.role === 'control' && allowedOrigins.includes('untrusted_bounded')) {
      refuse('field_origin_control_profile_widening', 'control fields cannot allow untrusted_bounded');
    }
    const allowedTransformIds = normalizeStringSet(
      entry.allowed_transform_ids,
      null,
      'allowed_transform_ids',
      MAX_TRANSFORMS,
    );
    if (allowedOrigins.includes('derived_via_versioned_transform') !== (allowedTransformIds.length > 0)) {
      refuse('field_origin_transform_policy_invalid', 'derived origin and allowed transforms must be declared together');
    }
    for (const transformId of allowedTransformIds) {
      if (!transformIds.has(transformId)) {
        refuse('field_origin_transform_unresolved', 'field rule names an unknown transform');
      }
    }
    if (entry.snapshot_policy === 'immutable') {
      if (entry.max_snapshot_age_sec !== null) {
        refuse('field_origin_snapshot_policy_invalid', 'immutable fields cannot declare snapshot age');
      }
    } else if (!safeInteger(entry.max_snapshot_age_sec, 1, MAX_SNAPSHOT_AGE_SEC)) {
      refuse('field_origin_snapshot_policy_invalid', 'mutable or either fields require bounded snapshot age');
    }
    return {
      path: entry.path,
      role: entry.role,
      required: entry.required,
      allowed_origins: allowedOrigins,
      snapshot_policy: entry.snapshot_policy,
      max_snapshot_age_sec: entry.max_snapshot_age_sec,
      allowed_transform_ids: allowedTransformIds,
    };
  }).sort((left, right) => byteOrder(left.path, right.path));

  return {
    profile_id: value.profile_id,
    relying_party_id: value.relying_party_id,
    action_type: value.action_type,
    fields,
    transforms: transforms.sort((left, right) => byteOrder(left.transform_id, right.transform_id)),
  };
}

function normalizeTrustedKeys(value: unknown): TrustedRiskKeys {
  if (!riskRecord(value) || Object.keys(value).length < 1) {
    refuse('field_origin_trusted_keys_invalid', 'field-origin trust keys must be a nonempty closed map');
  }
  const normalized: TrustedRiskKeys = {};
  for (const [keyId, pin] of Object.entries(value).sort(([left], [right]) => byteOrder(left, right))) {
    if (!riskIdentifier(keyId)
        || !riskExact(pin, TRUSTED_KEY_KEYS)
        || !riskIdentifier(pin.issuer_id)
        || typeof pin.public_key !== 'string'
        || !/^[A-Za-z0-9_-]+$/.test(pin.public_key)) {
      refuse('field_origin_trusted_keys_invalid', 'field-origin trust key pin is invalid');
    }
    try {
      const keyBytes = Buffer.from(pin.public_key, 'base64url');
      const key = createPublicKey({ key: keyBytes, type: 'spki', format: 'der' });
      if (keyBytes.toString('base64url') !== pin.public_key || key.asymmetricKeyType !== 'ed25519') {
        refuse('field_origin_trusted_keys_invalid', 'field-origin trust key must be canonical Ed25519 SPKI');
      }
    } catch (error) {
      if (error instanceof FieldOriginValidationError) throw error;
      refuse('field_origin_trusted_keys_invalid', 'field-origin trust key must be canonical Ed25519 SPKI');
    }
    normalized[keyId] = { issuer_id: pin.issuer_id, public_key: pin.public_key };
  }
  return normalized;
}

function normalizeSnapshot(value: unknown): RiskRecord {
  if (!riskExact(value, SNAPSHOT_KEYS)
      || (value.kind !== 'immutable' && value.kind !== 'mutable_snapshot')
      || (value.source_version !== null && !riskIdentifier(value.source_version))) {
    refuse('field_origin_snapshot_invalid', 'snapshot caveat is invalid');
  }
  if (value.kind === 'immutable') {
    if (value.observed_at !== null || value.source_version !== null) {
      refuse('field_origin_snapshot_invalid', 'immutable snapshot caveat must not carry mutable-state metadata');
    }
    return { kind: 'immutable', observed_at: null, source_version: null };
  }
  return {
    kind: 'mutable_snapshot',
    observed_at: canonicalInstant(value.observed_at, 'snapshot.observed_at'),
    source_version: value.source_version,
  };
}

function normalizeAnnotation(value: unknown): RiskRecord {
  if (!riskExact(value, ANNOTATION_KEYS)
      || !validPointer(value.path)
      || typeof value.origin_class !== 'string'
      || !ORIGIN_CLASSES.has(value.origin_class)) {
    refuse('field_origin_annotation_invalid', 'field annotation is invalid');
  }
  return {
    path: value.path,
    origin_class: value.origin_class,
    snapshot: normalizeSnapshot(value.snapshot),
    transform: value.transform === null ? null : normalizeTransform(value.transform),
  };
}

function normalizeField(value: unknown): RiskRecord {
  if (!riskExact(value, FIELD_KEYS)
      || !validPointer(value.path)
      || typeof value.value_digest !== 'string'
      || !RISK_DIGEST.test(value.value_digest)
      || typeof value.origin_class !== 'string'
      || !ORIGIN_CLASSES.has(value.origin_class)) {
    refuse('field_origin_field_invalid', 'field evidence is invalid');
  }
  return {
    path: value.path,
    value_digest: value.value_digest,
    origin_class: value.origin_class,
    snapshot: normalizeSnapshot(value.snapshot),
    transform: value.transform === null ? null : normalizeTransform(value.transform),
  };
}

function normalizeFields(value: unknown, fieldNormalizer: (entry: unknown) => RiskRecord): RiskRecord[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_FIELDS) {
    refuse('field_origin_fields_invalid', 'field evidence must be a bounded nonempty array');
  }
  const paths = new Set<string>();
  const fields = value.map(fieldNormalizer);
  for (const field of fields) {
    if (paths.has(field.path)) refuse('field_origin_path_duplicated', 'field path is duplicated');
    paths.add(field.path);
  }
  return fields.sort((left, right) => byteOrder(left.path, right.path));
}

function normalizeBody(value: unknown): RiskRecord {
  if (!riskExact(value, BODY_KEYS)
      || value['@version'] !== FIELD_ORIGIN_EVIDENCE_VERSION
      || !riskIdentifier(value.evidence_id)
      || !riskIdentifier(value.profile_id)
      || typeof value.profile_digest !== 'string'
      || !RISK_DIGEST.test(value.profile_digest)
      || !riskIdentifier(value.relying_party_id)
      || !riskIdentifier(value.action_type)
      || typeof value.action_digest !== 'string'
      || !RISK_DIGEST.test(value.action_digest)
      || value.claim_boundary !== FIELD_ORIGIN_CLAIM_BOUNDARY
      || !riskExact(value.issuer, ISSUER_KEYS)
      || !riskIdentifier(value.issuer.id)
      || !riskIdentifier(value.issuer.key_id)) {
    refuse('field_origin_evidence_invalid', 'field-origin evidence body is invalid');
  }
  const observedAt = canonicalInstant(value.observed_at, 'observed_at');
  if (value.issuer.id !== value.relying_party_id) {
    refuse('field_origin_issuer_mismatch', 'field-origin issuer must be the relying party');
  }
  return {
    '@version': FIELD_ORIGIN_EVIDENCE_VERSION,
    evidence_id: value.evidence_id,
    profile_id: value.profile_id,
    profile_digest: value.profile_digest,
    relying_party_id: value.relying_party_id,
    action_type: value.action_type,
    action_digest: value.action_digest,
    observed_at: observedAt,
    fields: normalizeFields(value.fields, normalizeField),
    claim_boundary: FIELD_ORIGIN_CLAIM_BOUNDARY,
    issuer: riskClone(value.issuer),
  };
}

function normalizeContext(value: unknown): FieldOriginVerificationContext | null {
  let context: unknown;
  try { context = strictJsonClone(value); } catch { return null; }
  if (!riskExact(context, CONTEXT_KEYS)
      || !riskRecord(context.trusted_keys)
      || !riskRecord(context.pinned_profile)
      || !riskIdentifier(context.expected_relying_party_id)
      || !riskRecord(context.observed_action)) return null;
  try {
    canonicalInstant(context.now, 'now');
    return {
      ...context,
      trusted_keys: normalizeTrustedKeys(context.trusted_keys),
      pinned_profile: normalizeProfile(context.pinned_profile),
    } as FieldOriginVerificationContext;
  } catch {
    return null;
  }
}

export function pinFieldOriginProfile(profile: unknown): RiskRecord {
  let snapshot: unknown;
  try { snapshot = strictJsonClone(profile); } catch {
    refuse('field_origin_profile_invalid', 'field-origin profile must be strict canonical JSON data');
  }
  return riskFreeze(normalizeProfile(snapshot));
}

export function pinFieldOriginTrustedKeys(keys: unknown): TrustedRiskKeys {
  let snapshot: unknown;
  try { snapshot = strictJsonClone(keys); } catch {
    refuse('field_origin_trusted_keys_invalid', 'field-origin trust keys must be strict canonical JSON data');
  }
  return riskFreeze(normalizeTrustedKeys(snapshot));
}

export function fieldOriginProfileDigest(profile: unknown): string {
  return riskDigest(pinFieldOriginProfile(profile));
}

export function signFieldOriginEvidence(
  input: unknown,
  signer: { issuer_id: string; key_id: string; private_key: any },
): RiskRecord {
  let snapshot: unknown;
  try { snapshot = strictJsonClone(input); } catch {
    refuse('field_origin_input_invalid', 'field-origin input must be strict canonical JSON data');
  }
  if (!riskExact(snapshot, INPUT_KEYS)
      || !riskIdentifier(snapshot.evidence_id)
      || !riskRecord(snapshot.observed_action)
      || !Array.isArray(snapshot.annotations)) {
    refuse('field_origin_input_invalid', 'field-origin input is not a closed v0.1 object');
  }
  const profile = normalizeProfile(snapshot.profile);
  if (snapshot.observed_action.action_type !== profile.action_type) {
    refuse('field_origin_action_type_mismatch', 'observed action type does not match profile');
  }
  const observedAt = canonicalInstant(snapshot.observed_at, 'observed_at');
  const annotations = normalizeFields(snapshot.annotations, normalizeAnnotation);
  const leafPaths = actionLeafPaths(snapshot.observed_action).sort(byteOrder);
  if (leafPaths.length !== annotations.length
      || leafPaths.some((path, index) => path !== annotations[index].path)) {
    refuse('field_origin_annotation_coverage_invalid', 'every observed action field requires exactly one annotation');
  }
  const fields = annotations.map((annotation) => {
    const resolved = valueAtPointer(snapshot.observed_action, annotation.path);
    if (!resolved.found) refuse('field_origin_annotation_coverage_invalid', 'annotation path is absent from observed action');
    return {
      path: annotation.path,
      value_digest: riskDigest(resolved.value),
      origin_class: annotation.origin_class,
      snapshot: riskClone(annotation.snapshot),
      transform: annotation.transform === null ? null : riskClone(annotation.transform),
    };
  });
  if (!riskExact(signer, SIGNER_KEYS)
      || !riskIdentifier(signer.issuer_id)
      || !riskIdentifier(signer.key_id)) {
    refuse('field_origin_signer_invalid', 'field-origin signer must be a closed Ed25519 signer');
  }
  if (signer.issuer_id !== profile.relying_party_id) {
    refuse('field_origin_issuer_mismatch', 'field-origin signer must be the relying party');
  }
  return signRiskBody(
    FIELD_ORIGIN_EVIDENCE_VERSION,
    {
      '@version': FIELD_ORIGIN_EVIDENCE_VERSION,
      evidence_id: snapshot.evidence_id,
      profile_id: profile.profile_id,
      profile_digest: riskDigest(profile),
      relying_party_id: profile.relying_party_id,
      action_type: profile.action_type,
      action_digest: riskDigest(snapshot.observed_action),
      observed_at: observedAt,
      fields,
      claim_boundary: FIELD_ORIGIN_CLAIM_BOUNDARY,
    },
    signer,
  );
}

export function verifyFieldOriginEvidence(
  artifact: unknown,
  rawContext?: FieldOriginVerificationContext,
): RiskRecord {
  const fail = (
    reason: string,
    verified = false,
    artifactDigest: string | null = null,
  ) => riskFreeze({
    accepted: false,
    verified,
    reason,
    artifact_digest: artifactDigest,
    profile_digest: null,
    action_digest: null,
    field_count: 0,
    claim_boundary: FIELD_ORIGIN_CLAIM_BOUNDARY,
  });
  const context = normalizeContext(rawContext);
  if (!context) return fail('field_origin_verification_context_required');
  let snapshot: unknown;
  try { snapshot = strictJsonClone(artifact); } catch {
    return fail('field_origin_evidence_invalid');
  }
  const signed = verifyRiskBody(snapshot, FIELD_ORIGIN_EVIDENCE_VERSION, context.trusted_keys);
  if (!signed.valid || !signed.body || !signed.artifact_digest) {
    return fail(`field_origin_${signed.reason ?? 'signature_invalid'}`);
  }
  let body: RiskRecord;
  try { body = normalizeBody(signed.body); } catch (error) {
    return fail(
      error instanceof FieldOriginValidationError ? error.code : 'field_origin_evidence_invalid',
      true,
      signed.artifact_digest,
    );
  }
  const profile = normalizeProfile(context.pinned_profile);
  const profileDigest = riskDigest(profile);
  if (body.relying_party_id !== context.expected_relying_party_id
      || profile.relying_party_id !== context.expected_relying_party_id) {
    return fail('field_origin_relying_party_mismatch', true, signed.artifact_digest);
  }
  if (body.profile_id !== profile.profile_id || body.profile_digest !== profileDigest) {
    return fail('field_origin_profile_mismatch', true, signed.artifact_digest);
  }
  if (body.action_type !== profile.action_type
      || context.observed_action.action_type !== profile.action_type) {
    return fail('field_origin_action_type_mismatch', true, signed.artifact_digest);
  }
  const actionDigest = riskDigest(context.observed_action);
  if (body.action_digest !== actionDigest) {
    return fail('field_origin_action_mismatch', true, signed.artifact_digest);
  }
  const now = Date.parse(context.now);
  if (Date.parse(body.observed_at) > now) {
    return fail('field_origin_evidence_from_future', true, signed.artifact_digest);
  }

  const rules = new Map<string, RiskRecord>(profile.fields.map((rule: RiskRecord) => [rule.path, rule]));
  const transforms = new Map<string, RiskRecord>(
    profile.transforms.map((transform: RiskRecord) => [transform.transform_id, transform]),
  );
  const fields = new Map<string, RiskRecord>(body.fields.map((field: RiskRecord) => [field.path, field]));
  const leafPaths = actionLeafPaths(context.observed_action).sort(byteOrder);

  for (const path of leafPaths) {
    if (!rules.has(path)) return fail(`field_origin_field_unprofiled:${path}`, true, signed.artifact_digest);
    if (!fields.has(path)) return fail(`field_origin_unknown:${path}`, true, signed.artifact_digest);
  }
  for (const rule of profile.fields) {
    const resolved = valueAtPointer(context.observed_action, rule.path);
    const field = fields.get(rule.path);
    if (!resolved.found) {
      if (rule.required) return fail(`field_origin_field_missing:${rule.path}`, true, signed.artifact_digest);
      if (field) return fail(`field_origin_field_unobserved:${rule.path}`, true, signed.artifact_digest);
      continue;
    }
    if (!field) return fail(`field_origin_unknown:${rule.path}`, true, signed.artifact_digest);
    if (field.value_digest !== riskDigest(resolved.value)) {
      return fail(`field_origin_value_mismatch:${rule.path}`, true, signed.artifact_digest);
    }
    if (field.origin_class === 'unknown') {
      return fail(`field_origin_unknown:${rule.path}`, true, signed.artifact_digest);
    }
    if (rule.role === 'control' && field.origin_class === 'untrusted_bounded') {
      return fail(`field_origin_control_untrusted:${rule.path}`, true, signed.artifact_digest);
    }
    if (!rule.allowed_origins.includes(field.origin_class)) {
      return fail(`field_origin_origin_not_allowed:${rule.path}`, true, signed.artifact_digest);
    }
    if (field.origin_class === 'derived_via_versioned_transform') {
      if (!field.transform) return fail(`field_origin_transform_required:${rule.path}`, true, signed.artifact_digest);
      const pinned = transforms.get(field.transform.transform_id);
      if (!pinned
          || !rule.allowed_transform_ids.includes(field.transform.transform_id)
          || riskDigest(pinned) !== riskDigest(field.transform)) {
        return fail(`field_origin_transform_unpinned:${rule.path}`, true, signed.artifact_digest);
      }
    } else if (field.transform !== null) {
      return fail(`field_origin_transform_unexpected:${rule.path}`, true, signed.artifact_digest);
    }
    if (rule.snapshot_policy === 'immutable' && field.snapshot.kind !== 'immutable') {
      return fail(`field_origin_snapshot_policy_mismatch:${rule.path}`, true, signed.artifact_digest);
    }
    if (rule.snapshot_policy === 'mutable_snapshot' && field.snapshot.kind !== 'mutable_snapshot') {
      return fail(`field_origin_snapshot_policy_mismatch:${rule.path}`, true, signed.artifact_digest);
    }
    if (field.snapshot.kind === 'mutable_snapshot') {
      const snapshotAt = Date.parse(field.snapshot.observed_at);
      if (snapshotAt > Date.parse(body.observed_at)) {
        return fail(`field_origin_snapshot_after_evidence:${rule.path}`, true, signed.artifact_digest);
      }
      const ageMs = now - snapshotAt;
      if (ageMs < 0) return fail(`field_origin_snapshot_from_future:${rule.path}`, true, signed.artifact_digest);
      if (safeInteger(rule.max_snapshot_age_sec, 1, MAX_SNAPSHOT_AGE_SEC)
          && ageMs > rule.max_snapshot_age_sec * 1000) {
        return fail(`field_origin_snapshot_stale:${rule.path}`, true, signed.artifact_digest);
      }
    }
  }
  if (fields.size !== leafPaths.length) {
    return fail('field_origin_field_set_mismatch', true, signed.artifact_digest);
  }
  return riskFreeze({
    accepted: true,
    verified: true,
    reason: null,
    artifact_digest: signed.artifact_digest,
    profile_digest: profileDigest,
    action_digest: actionDigest,
    field_count: fields.size,
    fields: riskClone(body.fields),
    claim_boundary: FIELD_ORIGIN_CLAIM_BOUNDARY,
  });
}
