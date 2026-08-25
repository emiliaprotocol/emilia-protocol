// SPDX-License-Identifier: Apache-2.0
/**
 * Profile-neutral authorization-artifact hook for AADP compositions.
 *
 * This module records independently verified evidence. It never issues an
 * AADP wire verdict, consumes an AADP approval, or authorizes execution.
 */
import {
  AUTHORIZATION_BUNDLE_VERSION,
  verifyAuthorizationBundle,
  type AuthorizationBundleVerificationOptions,
  type AuthorizationBundleVerificationResult,
} from './authorization-bundle.js';
import { canonicalizeAeb, digestAeb, type AebDigest } from './aeb-adapter-contract.js';

export const AADP_AUTHORIZATION_ARTIFACT_VERSION =
  'AADP-AUTHORIZATION-ARTIFACT-v1';
export const AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE =
  'EP-AADP-AUTHORIZATION-ARTIFACT-v1';
export const AADP_ACTION_MAPPING_CONFIG_VERSION =
  'AADP-ACTION-MAPPING-CONFIG-v1';
export const AADP_ACTION_MAPPING_RECORD_VERSION =
  'AADP-ACTION-MAPPING-RECORD-v1';
export const AADP_NATIVE_VERIFIER_DESCRIPTOR_VERSION =
  'AADP-NATIVE-VERIFIER-DESCRIPTOR-v1';
export const AADP_NATIVE_VERIFICATION_RECORD_VERSION =
  'AADP-NATIVE-VERIFICATION-RECORD-v1';

export type AadpNativeVerificationOutcome =
  | 'VERIFIED'
  | 'REFUSED'
  | 'UNAVAILABLE'
  | 'NOT_RUN';

export type AadpEvidenceSatisfaction =
  | 'SATISFIED'
  | 'REFUSE'
  | 'INDETERMINATE'
  | 'NOT_EVALUATED';

export interface AadpPinnedImplementation {
  id: string;
  version: string;
  digest: AebDigest;
}

export interface AadpMappingResolver {
  id: string;
  version: string;
  digest: AebDigest;
}

export interface AadpMaterialFieldMap {
  source_param: string;
  mapped_path: string;
}

export interface AadpActionMappingConfiguration {
  profile: typeof AADP_ACTION_MAPPING_CONFIG_VERSION;
  mapping_profile: string;
  source_action_type: string;
  mapped_action_type: string;
  implementation: AadpPinnedImplementation;
  resolver: AadpMappingResolver;
  material_field_map: AadpMaterialFieldMap[];
  no_material_field_loss: true;
}

export interface AadpActionMappingRecord {
  profile: typeof AADP_ACTION_MAPPING_RECORD_VERSION;
  mapping_profile: string;
  implementation: AadpPinnedImplementation;
  resolver: AadpMappingResolver & { configuration_digest: AebDigest };
  source_action_digest: AebDigest;
  mapped_action_digest: AebDigest;
  no_material_field_loss: true;
}

export interface AadpNativeVerifierDescriptor {
  profile: typeof AADP_NATIVE_VERIFIER_DESCRIPTOR_VERSION;
  artifact_profile: typeof AUTHORIZATION_BUNDLE_VERSION;
  implementation: AadpPinnedImplementation;
}

export interface AadpNativeVerificationRecord {
  profile: typeof AADP_NATIVE_VERIFICATION_RECORD_VERSION;
  artifact_profile: typeof AUTHORIZATION_BUNDLE_VERSION;
  artifact_digest: AebDigest | null;
  native_verification: Exclude<AadpNativeVerificationOutcome, 'NOT_RUN'>;
  evidence_satisfaction: Exclude<AadpEvidenceSatisfaction, 'NOT_EVALUATED'>;
  verifier: AadpPinnedImplementation;
  trust_configuration_digest: AebDigest;
  status_policy_digest: AebDigest;
  source_action_digest: AebDigest;
  mapped_action_digest: AebDigest;
  verification_result_digest: AebDigest;
  record_digest: AebDigest;
}

export interface AadpAuthorizationArtifact {
  profile: typeof AADP_AUTHORIZATION_ARTIFACT_VERSION;
  artifact_profile: string;
  artifact_digest: AebDigest;
  native_verification: Exclude<AadpNativeVerificationOutcome, 'NOT_RUN'>;
  evidence_satisfaction: Exclude<AadpEvidenceSatisfaction, 'NOT_EVALUATED'>;
  verification_record_digest: AebDigest;
  action_mapping: AadpActionMappingRecord;
}

export type AadpAuthorizationArtifactMatchVerdict =
  | 'MATCH'
  | 'MISMATCH'
  | 'INDETERMINATE';

export interface AadpAuthorizationArtifactMatchResult {
  verdict: AadpAuthorizationArtifactMatchVerdict;
  artifact: AadpAuthorizationArtifact | null;
  reason: string | null;
}

export interface AadpAction {
  action_type: string;
  params: Record<string, unknown>;
}

export interface DeriveAadpEpAuthorizationArtifactInput {
  bundle: unknown;
  artifactReferenceDigest?: AebDigest;
  aadpAction: unknown;
  mapping: unknown;
  verifier: unknown;
  bundleOptions: Omit<AuthorizationBundleVerificationOptions, 'expectedAction'>;
}

export interface AadpEpAuthorizationArtifactResult {
  verdict: 'VERIFIED' | 'REFUSE' | 'INDETERMINATE';
  native_verification: AadpNativeVerificationOutcome;
  evidence_satisfaction: AadpEvidenceSatisfaction;
  artifact: AadpAuthorizationArtifact | null;
  verification_record: AadpNativeVerificationRecord | null;
  mapped_action: unknown | null;
  authorization_decision: false;
  reasons: string[];
}

type Obj = Record<string, unknown>;

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const TOKEN_RE = /^[A-Za-z_][A-Za-z0-9_.:-]*$/;
const MATERIAL_PARAM_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MAPPED_PATH_RE = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/;

const IMPLEMENTATION_KEYS = new Set(['id', 'version', 'digest']);
const RESOLVER_KEYS = new Set(['id', 'version', 'digest']);
const MAPPING_ENTRY_KEYS = new Set(['source_param', 'mapped_path']);
const MAPPING_CONFIG_KEYS = new Set([
  'profile',
  'mapping_profile',
  'source_action_type',
  'mapped_action_type',
  'implementation',
  'resolver',
  'material_field_map',
  'no_material_field_loss',
]);
const MAPPING_RECORD_KEYS = new Set([
  'profile',
  'mapping_profile',
  'implementation',
  'resolver',
  'source_action_digest',
  'mapped_action_digest',
  'no_material_field_loss',
]);
const RESOLVER_RECORD_KEYS = new Set(['id', 'version', 'digest', 'configuration_digest']);
const VERIFIER_DESCRIPTOR_KEYS = new Set(['profile', 'artifact_profile', 'implementation']);
const ARTIFACT_KEYS = new Set([
  'profile',
  'artifact_profile',
  'artifact_digest',
  'native_verification',
  'evidence_satisfaction',
  'verification_record_digest',
  'action_mapping',
]);
const BUNDLE_OPTION_KEYS = new Set([
  'now',
  'audience',
  'approverKeys',
  'expectedApprovers',
  'acceptedKeyClasses',
  'currentPolicy',
  'expectedAuthorizationInstance',
  'expectedAuthorizationBinding',
  'requireAuthorizationBinding',
  'currentStatus',
  'requireCurrentStatus',
  'verifyClassASignoff',
  'verifyKeyProofs',
  'verifyPresentationEvidence',
  'requirePresentationEvidence',
]);
const UNBOUND_VERIFIER_HOOKS = [
  'verifyClassASignoff',
  'verifyKeyProofs',
  'verifyPresentationEvidence',
] as const;
const NATIVE_CHECKS = [
  'closed_shape',
  'action',
  'contexts',
  'signatures',
  'approver_selection',
  'separation_of_duties',
  'windows',
  'audience',
  'authorization_instance',
  'authorization_binding',
  'key_proofs',
  'presentation',
  'current_status',
] as const;
const RESERVED_MAPPING_PATH_SEGMENTS = new Set([
  '__proto__',
  'constructor',
  'prototype',
]);

function dataRecord(value: unknown): Obj | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== 'string')) return null;
    const record: Obj = Object.create(null);
    for (const key of keys as string[]) {
      const descriptor = descriptors[key];
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      record[key] = descriptor.value;
    }
    return record;
  } catch {
    return null;
  }
}

function exactKeys(record: Obj, expected: ReadonlySet<string>): boolean {
  const keys = Object.keys(record);
  return keys.length === expected.size && keys.every((key) => expected.has(key));
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function absoluteUri(value: unknown): value is string {
  if (!nonEmptyString(value)) return false;
  try {
    return new URL(value).protocol.length > 1;
  } catch {
    return false;
  }
}

function validDigest(value: unknown): value is AebDigest {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function canonicalCopy<T>(value: T): T | null {
  try {
    return JSON.parse(canonicalizeAeb(value)) as T;
  } catch {
    return null;
  }
}

function safeDigest(value: unknown): AebDigest | null {
  try {
    return digestAeb(value);
  } catch {
    return null;
  }
}

function parseImplementation(value: unknown): AadpPinnedImplementation | null {
  const record = dataRecord(value);
  if (!record
      || !exactKeys(record, IMPLEMENTATION_KEYS)
      || !absoluteUri(record.id)
      || !nonEmptyString(record.version)
      || !validDigest(record.digest)) return null;
  return {
    id: record.id,
    version: record.version,
    digest: record.digest,
  };
}

function parseResolver(value: unknown): AadpMappingResolver | null {
  const record = dataRecord(value);
  if (!record
      || !exactKeys(record, RESOLVER_KEYS)
      || !absoluteUri(record.id)
      || !nonEmptyString(record.version)
      || !validDigest(record.digest)) return null;
  return { id: record.id, version: record.version, digest: record.digest };
}

function parseMappingConfiguration(value: unknown): AadpActionMappingConfiguration | null {
  const record = dataRecord(value);
  if (!record
      || !exactKeys(record, MAPPING_CONFIG_KEYS)
      || record.profile !== AADP_ACTION_MAPPING_CONFIG_VERSION
      || !absoluteUri(record.mapping_profile)
      || !nonEmptyString(record.source_action_type)
      || !TOKEN_RE.test(record.source_action_type)
      || !nonEmptyString(record.mapped_action_type)
      || !TOKEN_RE.test(record.mapped_action_type)
      || record.no_material_field_loss !== true
      || !Array.isArray(record.material_field_map)
      || record.material_field_map.length === 0) return null;
  const implementation = parseImplementation(record.implementation);
  const resolver = parseResolver(record.resolver);
  if (!implementation || !resolver) return null;

  const materialFieldMap: AadpMaterialFieldMap[] = [];
  const sources = new Set<string>();
  const targets = new Set<string>();
  for (const candidate of record.material_field_map) {
    const entry = dataRecord(candidate);
    if (!entry
        || !exactKeys(entry, MAPPING_ENTRY_KEYS)
        || typeof entry.source_param !== 'string'
        || typeof entry.mapped_path !== 'string') return null;
    const sourceParam = entry.source_param;
    const mappedPath = entry.mapped_path;
    if (!MATERIAL_PARAM_RE.test(sourceParam)
        || RESERVED_MAPPING_PATH_SEGMENTS.has(sourceParam)
        || !MAPPED_PATH_RE.test(mappedPath)
        || mappedPath.split('.').some((segment) => RESERVED_MAPPING_PATH_SEGMENTS.has(segment))
        || mappedPath === 'action_type'
        || sources.has(sourceParam)
        || targets.has(mappedPath)
        || [...targets].some((target) => target.startsWith(`${mappedPath}.`)
          || mappedPath.startsWith(`${target}.`))) return null;
    sources.add(sourceParam);
    targets.add(mappedPath);
    materialFieldMap.push({
      source_param: sourceParam,
      mapped_path: mappedPath,
    });
  }
  return {
    profile: AADP_ACTION_MAPPING_CONFIG_VERSION,
    mapping_profile: record.mapping_profile,
    source_action_type: record.source_action_type,
    mapped_action_type: record.mapped_action_type,
    implementation,
    resolver,
    material_field_map: materialFieldMap,
    no_material_field_loss: true,
  };
}

function parseVerifierDescriptor(value: unknown): AadpNativeVerifierDescriptor | null {
  const record = dataRecord(value);
  if (!record
      || !exactKeys(record, VERIFIER_DESCRIPTOR_KEYS)
      || record.profile !== AADP_NATIVE_VERIFIER_DESCRIPTOR_VERSION
      || record.artifact_profile !== AUTHORIZATION_BUNDLE_VERSION) return null;
  const implementation = parseImplementation(record.implementation);
  if (!implementation) return null;
  return {
    profile: AADP_NATIVE_VERIFIER_DESCRIPTOR_VERSION,
    artifact_profile: AUTHORIZATION_BUNDLE_VERSION,
    implementation,
  };
}

function parseAadpAction(value: unknown): AadpAction | null {
  const record = dataRecord(value);
  if (!record
      || Object.keys(record).length !== 2
      || !Object.hasOwn(record, 'action_type')
      || !Object.hasOwn(record, 'params')
      || !nonEmptyString(record.action_type)) return null;
  const params = dataRecord(record.params);
  if (!params) return null;
  const copied = canonicalCopy(params);
  if (!copied) return null;
  return { action_type: record.action_type, params: copied };
}

function parseMappingRecord(value: unknown): AadpActionMappingRecord | null {
  const record = dataRecord(value);
  if (!record
      || !exactKeys(record, MAPPING_RECORD_KEYS)
      || record.profile !== AADP_ACTION_MAPPING_RECORD_VERSION
      || !absoluteUri(record.mapping_profile)
      || !validDigest(record.source_action_digest)
      || !validDigest(record.mapped_action_digest)
      || record.no_material_field_loss !== true) return null;
  const implementation = parseImplementation(record.implementation);
  const resolverRecord = dataRecord(record.resolver);
  if (!implementation
      || !resolverRecord
      || !exactKeys(resolverRecord, RESOLVER_RECORD_KEYS)
      || !absoluteUri(resolverRecord.id)
      || !nonEmptyString(resolverRecord.version)
      || !validDigest(resolverRecord.digest)
      || !validDigest(resolverRecord.configuration_digest)) return null;
  return {
    profile: AADP_ACTION_MAPPING_RECORD_VERSION,
    mapping_profile: record.mapping_profile,
    implementation,
    resolver: {
      id: resolverRecord.id,
      version: resolverRecord.version,
      digest: resolverRecord.digest,
      configuration_digest: resolverRecord.configuration_digest,
    },
    source_action_digest: record.source_action_digest,
    mapped_action_digest: record.mapped_action_digest,
    no_material_field_loss: true,
  };
}

/** Return a safe normalized copy of the closed, profile-neutral hook. */
export function parseAadpAuthorizationArtifact(
  value: unknown,
): AadpAuthorizationArtifact | null {
  const record = dataRecord(value);
  if (!record
      || !exactKeys(record, ARTIFACT_KEYS)
      || record.profile !== AADP_AUTHORIZATION_ARTIFACT_VERSION
      || !nonEmptyString(record.artifact_profile)
      || !validDigest(record.artifact_digest)
      || !['VERIFIED', 'REFUSED', 'UNAVAILABLE'].includes(record.native_verification as string)
      || !['SATISFIED', 'REFUSE', 'INDETERMINATE'].includes(record.evidence_satisfaction as string)
      || !validDigest(record.verification_record_digest)) return null;
  const actionMapping = parseMappingRecord(record.action_mapping);
  if (!actionMapping) return null;
  return {
    profile: AADP_AUTHORIZATION_ARTIFACT_VERSION,
    artifact_profile: record.artifact_profile,
    artifact_digest: record.artifact_digest,
    native_verification: record.native_verification as AadpAuthorizationArtifact['native_verification'],
    evidence_satisfaction: record.evidence_satisfaction as AadpAuthorizationArtifact['evidence_satisfaction'],
    verification_record_digest: record.verification_record_digest,
    action_mapping: actionMapping,
  };
}

/**
 * Compare a presented AADP hook with one independently derived by the PDP.
 * Missing native verification is indeterminate. Malformed or unequal
 * presenter input is a hard mismatch.
 */
export function matchAadpAuthorizationArtifact(
  presented: unknown,
  expected: unknown,
): AadpAuthorizationArtifactMatchResult {
  const actual = parseAadpAuthorizationArtifact(presented);
  if (!actual) {
    return { verdict: 'MISMATCH', artifact: null, reason: 'authorization_artifact_malformed' };
  }
  const derived = parseAadpAuthorizationArtifact(expected);
  if (!derived) {
    return {
      verdict: 'INDETERMINATE',
      artifact: null,
      reason: 'native_authorization_artifact_unavailable',
    };
  }
  try {
    if (canonicalizeAeb(actual) !== canonicalizeAeb(derived)) {
      return { verdict: 'MISMATCH', artifact: null, reason: 'authorization_artifact_mismatch' };
    }
  } catch {
    return { verdict: 'MISMATCH', artifact: null, reason: 'authorization_artifact_malformed' };
  }
  return { verdict: 'MATCH', artifact: derived, reason: null };
}

function result(
  verdict: AadpEpAuthorizationArtifactResult['verdict'],
  nativeVerification: AadpNativeVerificationOutcome,
  evidenceSatisfaction: AadpEvidenceSatisfaction,
  reasons: string[],
  overrides: Partial<AadpEpAuthorizationArtifactResult> = {},
): AadpEpAuthorizationArtifactResult {
  return {
    verdict,
    native_verification: nativeVerification,
    evidence_satisfaction: evidenceSatisfaction,
    artifact: null,
    verification_record: null,
    mapped_action: null,
    authorization_decision: false,
    reasons,
    ...overrides,
  };
}

function valueAtPath(value: unknown, path: string): unknown {
  let current: unknown = value;
  for (const segment of path.split('.')) {
    const record = dataRecord(current);
    if (!record || !Object.hasOwn(record, segment)) return undefined;
    current = record[segment];
  }
  return current;
}

function setValueAtPath(target: Obj, path: string, value: unknown): boolean {
  const segments = path.split('.');
  let current = target;
  for (let index = 0; index < segments.length - 1; index += 1) {
    const segment = segments[index];
    if (!Object.hasOwn(current, segment)) current[segment] = {};
    const next = dataRecord(current[segment]);
    if (!next) return false;
    current[segment] = next;
    current = next;
  }
  const leaf = segments.at(-1);
  if (!leaf || Object.hasOwn(current, leaf)) return false;
  current[leaf] = value;
  return true;
}

function sameCanonical(left: unknown, right: unknown): boolean {
  try {
    return canonicalizeAeb(left) === canonicalizeAeb(right);
  } catch {
    return false;
  }
}

function validateAndMapAction(
  action: AadpAction,
  mapping: AadpActionMappingConfiguration,
): {
  verdict: 'MAPPED' | 'REFUSE' | 'INDETERMINATE';
  mappedAction: Obj | null;
  reason: string | null;
} {
  if (action.action_type !== mapping.source_action_type) {
    return { verdict: 'REFUSE', mappedAction: null, reason: 'aadp_action_type_not_mapped' };
  }
  const expectedParams = mapping.material_field_map.map((entry) => entry.source_param).sort();
  const actualParams = Object.keys(action.params).sort();
  const missing = expectedParams.filter((key) => !actualParams.includes(key));
  const unknown = actualParams.filter((key) => !expectedParams.includes(key));
  if (missing.length > 0 || unknown.length > 0) {
    return {
      verdict: 'REFUSE',
      mappedAction: null,
      reason: `aadp_action_material_fields_unmapped:${[...missing, ...unknown].sort().join(',')}`,
    };
  }
  const mappedRecord: Obj = { action_type: mapping.mapped_action_type };
  for (const field of mapping.material_field_map) {
    if (!setValueAtPath(mappedRecord, field.mapped_path, action.params[field.source_param])) {
      return { verdict: 'REFUSE', mappedAction: null, reason: 'mapped_action_malformed' };
    }
    if (!sameCanonical(action.params[field.source_param], valueAtPath(mappedRecord, field.mapped_path))) {
      return {
        verdict: 'REFUSE',
        mappedAction: null,
        reason: `aadp_action_material_field_lost:${field.source_param}`,
      };
    }
  }
  const copied = canonicalCopy(mappedRecord);
  return copied
    ? { verdict: 'MAPPED', mappedAction: copied, reason: null }
    : { verdict: 'REFUSE', mappedAction: null, reason: 'mapped_action_malformed' };
}

function digestVerifierInputs(
  optionsValue: unknown,
): {
  options: Omit<AuthorizationBundleVerificationOptions, 'expectedAction'> | null;
  trustDigest: AebDigest | null;
  statusPolicyDigest: AebDigest | null;
  reason: string | null;
} {
  const options = dataRecord(optionsValue);
  if (!options) {
    return { options: null, trustDigest: null, statusPolicyDigest: null, reason: 'native_verifier_options_malformed' };
  }
  const unknown = Object.keys(options).filter((key) => !BUNDLE_OPTION_KEYS.has(key)).sort();
  if (unknown.length > 0) {
    return {
      options: null,
      trustDigest: null,
      statusPolicyDigest: null,
      reason: `native_verifier_options_unknown:${unknown.join(',')}`,
    };
  }
  const unboundHook = UNBOUND_VERIFIER_HOOKS.find((key) => Object.hasOwn(options, key));
  if (unboundHook) {
    return {
      options: null,
      trustDigest: null,
      statusPolicyDigest: null,
      reason: `native_verifier_extension_unbound:${unboundHook}`,
    };
  }
  const now = options.now instanceof Date ? options.now.toISOString() : options.now;
  const trustConfiguration = {
    audience: options.audience ?? null,
    approverKeys: options.approverKeys ?? null,
    expectedApprovers: options.expectedApprovers ?? null,
    acceptedKeyClasses: options.acceptedKeyClasses ?? null,
    expectedAuthorizationInstance: options.expectedAuthorizationInstance ?? null,
    expectedAuthorizationBinding: options.expectedAuthorizationBinding ?? null,
    requireAuthorizationBinding: options.requireAuthorizationBinding === true,
    requirePresentationEvidence: options.requirePresentationEvidence === true,
  };
  const statusPolicy = {
    now: now ?? null,
    currentPolicy: options.currentPolicy ?? null,
    currentStatus: options.currentStatus ?? null,
    requireCurrentStatus: options.requireCurrentStatus === true,
  };
  const trustDigest = safeDigest(trustConfiguration);
  const statusPolicyDigest = safeDigest(statusPolicy);
  if (!trustDigest || !statusPolicyDigest) {
    return {
      options: null,
      trustDigest: null,
      statusPolicyDigest: null,
      reason: 'native_verifier_configuration_not_canonicalizable',
    };
  }
  return {
    options: options as unknown as Omit<AuthorizationBundleVerificationOptions, 'expectedAction'>,
    trustDigest,
    statusPolicyDigest,
    reason: null,
  };
}

function classifyNativeVerification(
  verification: AuthorizationBundleVerificationResult,
): Exclude<AadpNativeVerificationOutcome, 'NOT_RUN'> {
  if (NATIVE_CHECKS.every((key) => verification.checks[key] === true)) return 'VERIFIED';
  if (verification.verdict === 'INDETERMINATE') return 'UNAVAILABLE';
  return 'REFUSED';
}

function buildMappingRecord(
  mapping: AadpActionMappingConfiguration,
  sourceActionDigest: AebDigest,
  mappedActionDigest: AebDigest,
): AadpActionMappingRecord | null {
  const configurationDigest = safeDigest(mapping);
  if (!configurationDigest) return null;
  return {
    profile: AADP_ACTION_MAPPING_RECORD_VERSION,
    mapping_profile: mapping.mapping_profile,
    implementation: mapping.implementation,
    resolver: {
      ...mapping.resolver,
      configuration_digest: configurationDigest,
    },
    source_action_digest: sourceActionDigest,
    mapped_action_digest: mappedActionDigest,
    no_material_field_loss: true,
  };
}

function buildVerificationRecord(
  descriptor: AadpNativeVerifierDescriptor,
  artifactDigest: AebDigest | null,
  nativeVerification: Exclude<AadpNativeVerificationOutcome, 'NOT_RUN'>,
  verification: AuthorizationBundleVerificationResult,
  trustConfigurationDigest: AebDigest,
  statusPolicyDigest: AebDigest,
  sourceActionDigest: AebDigest,
  mappedActionDigest: AebDigest,
): AadpNativeVerificationRecord | null {
  const base = {
    profile: AADP_NATIVE_VERIFICATION_RECORD_VERSION,
    artifact_profile: AUTHORIZATION_BUNDLE_VERSION,
    artifact_digest: artifactDigest,
    native_verification: nativeVerification,
    evidence_satisfaction: verification.verdict,
    verifier: descriptor.implementation,
    trust_configuration_digest: trustConfigurationDigest,
    status_policy_digest: statusPolicyDigest,
    source_action_digest: sourceActionDigest,
    mapped_action_digest: mappedActionDigest,
    verification_result_digest: digestAeb(verification),
  } as const;
  const recordDigest = safeDigest(base);
  return recordDigest ? { ...base, record_digest: recordDigest } : null;
}

/**
 * Derive the generic AADP hook from an EP Authorization Bundle.
 *
 * Mapping and verifier descriptors are relying-party configuration, never
 * presenter input. Source material parameters are closed and every declared
 * value must survive at its exact mapped path before EP verification runs.
 */
export function deriveAadpEpAuthorizationArtifact(
  input: DeriveAadpEpAuthorizationArtifactInput,
): AadpEpAuthorizationArtifactResult {
  try {
    const envelope = dataRecord(input);
    if (!envelope) {
      return result('REFUSE', 'NOT_RUN', 'NOT_EVALUATED', ['aadp_profile_input_malformed']);
    }
    const action = parseAadpAction(envelope.aadpAction);
    if (!action) {
      return result('REFUSE', 'NOT_RUN', 'NOT_EVALUATED', ['aadp_action_malformed']);
    }
    const mapping = parseMappingConfiguration(envelope.mapping);
    if (!mapping) {
      return result('INDETERMINATE', 'NOT_RUN', 'NOT_EVALUATED', ['aadp_action_mapping_unavailable']);
    }
    const mapped = validateAndMapAction(action, mapping);
    if (mapped.verdict !== 'MAPPED' || !mapped.mappedAction) {
      return result(
        mapped.verdict === 'REFUSE' ? 'REFUSE' : 'INDETERMINATE',
        'NOT_RUN',
        'NOT_EVALUATED',
        [mapped.reason ?? 'aadp_action_mapping_unavailable'],
      );
    }
    const sourceActionDigest = digestAeb(action);
    const mappedActionDigest = digestAeb(mapped.mappedAction);
    const mappingRecord = buildMappingRecord(mapping, sourceActionDigest, mappedActionDigest);
    if (!mappingRecord) {
      return result('INDETERMINATE', 'NOT_RUN', 'NOT_EVALUATED', ['aadp_action_mapping_unavailable']);
    }

    const verifier = parseVerifierDescriptor(envelope.verifier);
    if (!verifier) {
      return result('INDETERMINATE', 'UNAVAILABLE', 'NOT_EVALUATED', ['native_verifier_unavailable'], {
        mapped_action: mapped.mappedAction,
      });
    }
    const verifierInputs = digestVerifierInputs(envelope.bundleOptions);
    if (!verifierInputs.options || !verifierInputs.trustDigest || !verifierInputs.statusPolicyDigest) {
      return result('REFUSE', 'NOT_RUN', 'NOT_EVALUATED', [
        verifierInputs.reason ?? 'native_verifier_options_malformed',
      ], { mapped_action: mapped.mappedAction });
    }

    const artifactDigest = safeDigest(envelope.bundle)
      ?? (validDigest(envelope.artifactReferenceDigest) ? envelope.artifactReferenceDigest : null);
    const verification = verifyAuthorizationBundle(envelope.bundle, {
      ...verifierInputs.options,
      expectedAction: mapped.mappedAction,
    });
    const nativeVerification = classifyNativeVerification(verification);
    const verificationRecord = buildVerificationRecord(
      verifier,
      artifactDigest,
      nativeVerification,
      verification,
      verifierInputs.trustDigest,
      verifierInputs.statusPolicyDigest,
      sourceActionDigest,
      mappedActionDigest,
    );
    if (!verificationRecord) {
      return result('INDETERMINATE', 'UNAVAILABLE', verification.verdict, [
        'native_verification_record_unavailable',
      ], { mapped_action: mapped.mappedAction });
    }

    const artifact = artifactDigest === null ? null : {
      profile: AADP_AUTHORIZATION_ARTIFACT_VERSION,
      artifact_profile: AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE,
      artifact_digest: artifactDigest,
      native_verification: nativeVerification,
      evidence_satisfaction: verification.verdict,
      verification_record_digest: verificationRecord.record_digest,
      action_mapping: mappingRecord,
    } satisfies AadpAuthorizationArtifact;

    if (verification.verdict !== 'SATISFIED' || artifact === null) {
      return result(
        verification.verdict === 'REFUSE' ? 'REFUSE' : 'INDETERMINATE',
        nativeVerification,
        verification.verdict,
        verification.reasons.length > 0
          ? verification.reasons
          : ['native_authorization_artifact_unavailable'],
        {
          artifact,
          verification_record: verificationRecord,
          mapped_action: mapped.mappedAction,
        },
      );
    }

    return result('VERIFIED', nativeVerification, 'SATISFIED', [], {
      artifact,
      verification_record: verificationRecord,
      mapped_action: mapped.mappedAction,
    });
  } catch {
    return result('INDETERMINATE', 'UNAVAILABLE', 'NOT_EVALUATED', [
      'native_authorization_artifact_unavailable',
    ]);
  }
}

/** Derive the native EP hook and compare it to a presenter-supplied AADP hook. */
export function verifyAadpEpAuthorizationArtifact(
  presented: unknown,
  input: DeriveAadpEpAuthorizationArtifactInput,
): AadpEpAuthorizationArtifactResult {
  const derived = deriveAadpEpAuthorizationArtifact(input);
  if (derived.verdict !== 'VERIFIED') return derived;
  const matched = matchAadpAuthorizationArtifact(presented, derived.artifact);
  if (matched.verdict === 'MATCH') return derived;
  return result(
    matched.verdict === 'MISMATCH' ? 'REFUSE' : 'INDETERMINATE',
    derived.native_verification,
    derived.evidence_satisfaction,
    [matched.reason ?? 'authorization_artifact_mismatch'],
    {
      verification_record: derived.verification_record,
      mapped_action: derived.mapped_action,
    },
  );
}

export default Object.freeze({
  AADP_AUTHORIZATION_ARTIFACT_VERSION,
  AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE,
  AADP_ACTION_MAPPING_CONFIG_VERSION,
  AADP_ACTION_MAPPING_RECORD_VERSION,
  AADP_NATIVE_VERIFIER_DESCRIPTOR_VERSION,
  AADP_NATIVE_VERIFICATION_RECORD_VERSION,
  parseAadpAuthorizationArtifact,
  matchAadpAuthorizationArtifact,
  deriveAadpEpAuthorizationArtifact,
  verifyAadpEpAuthorizationArtifact,
});
