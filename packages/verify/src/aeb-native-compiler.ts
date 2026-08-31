// SPDX-License-Identifier: Apache-2.0
/**
 * A neutral compiler surface for AEB-ADAPTER-v1.
 *
 * Native bytes remain native. The compiler asks the relying-party-pinned
 * adapters to verify and map those bytes, composes their results through the
 * existing AEB evaluator and AEC engine, and projects one closed report. It
 * performs no network access, credential issuance, consumption, provider
 * entry, execution, or outcome reconciliation.
 *
 * The report is evidence, not a bearer credential or an authorization result.
 * A caller-supplied policy input is preserved as input only. Gate or another
 * local runtime must evaluate authorization and reserve authority before
 * provider entry.
 */
import { AEC_VERSION } from './evidence-chain.js';
import {
  AEB_ADAPTER_VERSION,
  aebNativeReplayKeys,
  canonicalizeAeb,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  type Acceptance,
  type AebAdapter,
  type AebDigest,
  type AebEvidenceLegInput,
  type AebEvidenceSubject,
  type AebFreshness,
  type AebLegVerdict,
  type AebPinnedConfig,
  type AebPinnedProfile,
  type AebRequirement,
  type AebVerdict,
  type MappingVerdict,
  type NativeVerification,
} from './aeb-adapter-contract.js';

export const AEB_NATIVE_COMPILER_VERSION = 'EP-AEB-NATIVE-COMPILER-v1';
export const AEB_NATIVE_DESCRIPTOR_VERSION = 'EP-AEB-NATIVE-DESCRIPTOR-v1';

export type AebNativeCompilerVerified = NativeVerification | 'INDETERMINATE';
export type AebNativeCompilerPolicyInputDecision = 'ALLOW' | 'DENY' | 'INDETERMINATE';
export type AebNativeCompilerInputProvenance = 'RELYING_PARTY_INPUT';
export type AebSemanticLossStatus = 'NONE' | 'NON_MATERIAL_ONLY' | 'MATERIAL' | 'UNKNOWN';
export type AebSemanticOmissionClassification = 'material' | 'non_material' | 'unknown';
export type AebSemanticOmissionDeclaration =
  | 'omitted_material_fields'
  | 'omitted_nonmaterial_fields'
  | 'profile_semantics_unavailable'
  | 'native_profile_binding_unestablished';
export type AebNativeCompilerNotEvaluated = 'NOT_EVALUATED';
export type AebNativeCompilerNotEstablished = 'NOT_ESTABLISHED';

export interface AebNativeDescriptor {
  '@version': typeof AEB_NATIVE_DESCRIPTOR_VERSION;
  protocol: {
    id: string;
    revision: string;
  };
  /** A closed source descriptor. At least one of media_type or schema is required. */
  source: {
    media_type: string | null;
    schema: { id: string; revision: string } | null;
  };
  /** This is a relying-party pin, not proof that running code was measured. */
  verifier: {
    implementation_id: string;
    implementation_revision: string;
    implementation_digest: AebDigest;
  };
  adapter: {
    id: string;
    revision: string;
  };
  mapping_profile: {
    id: string;
    revision: string;
    digest: AebDigest;
  };
  target_action_type: string;
  replay_scope: string;
  /** Digest of descriptor_id plus every field above. */
  descriptor_digest: AebDigest;
}

export interface AebNativeDescriptorSet {
  /** Out-of-band relying-party digest pins, keyed by descriptor ID. */
  pins: Record<string, AebDigest>;
  /** Closed descriptor bodies, independently checked against pins. */
  registry: Record<string, AebNativeDescriptor>;
}

export interface AebNativeCompilerLegInput extends AebEvidenceLegInput {
  native_descriptor_id: string;
}

export interface AebNativeCompilerExpectedAction {
  caid: string;
  /** Exact action value supplied by the relying party for comparison. */
  value: unknown;
}

export interface AebNativeCompilerRequirement {
  ref: string;
  /** Must be byte-equivalent to the requirement under the relying-party pins. */
  definition: AebRequirement;
}

export interface AebNativeCompilerLocalPolicyInput {
  policy_id: string;
  policy_version: string;
  decision: 'ALLOW' | 'DENY';
  reasons: readonly string[];
}

export interface AebNativeCompilerInput {
  /** Complete AEB-ADAPTER-v1 relying-party pins. */
  pins: AebPinnedConfig;
  /** Pure, offline adapter implementations selected by adapter ID. */
  adapters: Record<string, AebAdapter>;
  /** Compiler-local source and verifier metadata, pinned by digest. */
  native_descriptors: AebNativeDescriptorSet;
  native_legs: AebNativeCompilerLegInput[];
  expected_action: AebNativeCompilerExpectedAction;
  requirement: AebNativeCompilerRequirement;
  initiator_id: string;
  executor_id?: string;
  evaluated_at: string;
  /** Unverified policy input. The compiler preserves it but does not authorize. */
  local_policy_input: AebNativeCompilerLocalPolicyInput;
}

export interface AebNativeCompilerAxis<T extends string> {
  result: T;
  reasons: string[];
}

export interface AebSemanticLossReport {
  status: AebSemanticLossStatus;
  profile_pinned: boolean;
  omitted_material_fields: string[];
  omitted_nonmaterial_fields: string[];
  omissions: AebSemanticOmission[];
}

export interface AebSemanticOmission {
  /** Exact stable path declared by the profile; `$` means the whole unknown projection. */
  path: string;
  classification: AebSemanticOmissionClassification;
  basis: {
    profile_id: string;
    profile_digest: AebDigest;
    profile_pinned: boolean;
    declaration: AebSemanticOmissionDeclaration;
    /** Commits the omission and classification to the profile digest above. */
    binding_digest: AebDigest;
  };
}

export interface AebNativeCompilerLegReport {
  artifact_ref: string;
  native_descriptor: {
    id: string;
    digest: AebDigest;
    pinned: boolean;
    protocol: { id: string; revision: string };
    source: {
      media_type: string | null;
      schema: { id: string; revision: string } | null;
    };
    verifier: {
      implementation_id: string;
      implementation_revision: string;
      implementation_digest: AebDigest;
    };
    target_action_type: string;
    replay_scope: string;
  };
  native_profile: {
    adapter_id: string;
    adapter_revision: string;
    mapping_profile_id: string;
    mapping_profile_revision: string;
  };
  artifact_digest: AebDigest;
  native_result: {
    verification: NativeVerification;
    acceptance: Acceptance;
  };
  pins: {
    adapter_config_digest: AebDigest;
    profile_digest: AebDigest;
    mapper_id: string;
    resolver: {
      id: string;
      revision: string;
      implementation_digest: AebDigest;
    };
  };
  action: {
    /** Compiler-effective relation. Lossy or unknown semantics force this closed. */
    mapping: MappingVerdict;
    caid: string | null;
    normalized_action_digest: AebDigest | null;
    /** Raw output from the native mapper, retained only for diagnostics. */
    native_raw_mapping: MappingVerdict;
    native_raw_caid: string | null;
    native_raw_normalized_action_digest: AebDigest | null;
  };
  evidence: {
    role: string;
    subject: AebEvidenceSubject | null;
    freshness: AebFreshness;
  };
  replay_unit: AebDigest;
  semantic_loss: AebSemanticLossReport;
  verdict: AebLegVerdict;
  reasons: string[];
}

export interface AebNativeCompilerReport {
  '@version': typeof AEB_NATIVE_COMPILER_VERSION;
  relying_party_id: string;
  evaluated_at: string;
  engine: {
    evaluator: typeof AEB_ADAPTER_VERSION;
    composition: typeof AEC_VERSION;
    signed_evaluation: false;
  };
  requirement: {
    ref: string;
    digest: AebDigest;
    pinned: boolean;
  };
  expected_action: {
    caid: string;
    /** Detached exact value supplied by the relying party. */
    value: unknown;
    digest: AebDigest;
    provenance: AebNativeCompilerInputProvenance;
  };
  local_policy_input: {
    policy_id: string;
    policy_version: string;
    decision: AebNativeCompilerPolicyInputDecision;
    reasons: string[];
    provenance: AebNativeCompilerInputProvenance;
    /** The compiler has not authenticated or executed this decision. */
    verification: AebNativeCompilerNotEvaluated;
    input_digest: AebDigest;
  };
  legs: AebNativeCompilerLegReport[];
  /** Stable across changes to AEB artifact_ref wrapper identifiers. */
  replay_unit: AebDigest;
  semantic_loss: {
    status: AebSemanticLossStatus;
    material_present: boolean;
    unknown_present: boolean;
    profiles: Array<{ profile_id: string; report: AebSemanticLossReport }>;
  };
  axes: {
    verified: AebNativeCompilerAxis<AebNativeCompilerVerified>;
    accepted: AebNativeCompilerAxis<Acceptance>;
    match: AebNativeCompilerAxis<MappingVerdict>;
    satisfied: AebNativeCompilerAxis<AebVerdict>;
    policy_input: AebNativeCompilerAxis<AebNativeCompilerPolicyInputDecision>;
    local_authorization: AebNativeCompilerAxis<AebNativeCompilerNotEvaluated>;
  };
  lifecycle: {
    reservation: AebNativeCompilerAxis<AebNativeCompilerNotEvaluated>;
    consumption: AebNativeCompilerAxis<AebNativeCompilerNotEvaluated>;
    provider_entry: AebNativeCompilerAxis<AebNativeCompilerNotEstablished>;
    provider_outcome: AebNativeCompilerAxis<AebNativeCompilerNotEstablished>;
    observed_effect: AebNativeCompilerAxis<AebNativeCompilerNotEstablished>;
    retry: AebNativeCompilerAxis<AebNativeCompilerNotEvaluated>;
    reconciliation: AebNativeCompilerAxis<AebNativeCompilerNotEvaluated>;
  };
  claims: {
    local_authorization_established: false;
    provider_entry_established: false;
    execution_established: false;
    outcome_established: false;
    verifier_runtime_measurement_established: false;
  };
  /** A digest is not a credential, signature, reservation, or execution permit. */
  report_is_credential: false;
  reasons: string[];
  report_digest: AebDigest;
}

const ZERO_DIGEST = `sha256:${'0'.repeat(64)}` as AebDigest;
const UNSIGNED_EVALUATION_REASON = 'evaluation_signature_required';
const SEMANTIC_OMISSION_BASIS_VERSION = 'EP-AEB-SEMANTIC-OMISSION-BASIS-v1';
const CAID = /^caid:[A-Za-z0-9._:-]+$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const LOCAL_POLICY_INPUT_KEYS = new Set(['policy_id', 'policy_version', 'decision', 'reasons']);
const DESCRIPTOR_KEYS = new Set([
  '@version', 'protocol', 'source', 'verifier', 'adapter', 'mapping_profile',
  'target_action_type', 'replay_scope', 'descriptor_digest',
]);
const PROTOCOL_KEYS = new Set(['id', 'revision']);
const SOURCE_KEYS = new Set(['media_type', 'schema']);
const SCHEMA_KEYS = new Set(['id', 'revision']);
const VERIFIER_KEYS = new Set([
  'implementation_id', 'implementation_revision', 'implementation_digest',
]);
const ADAPTER_KEYS = new Set(['id', 'revision']);
const MAPPING_PROFILE_KEYS = new Set(['id', 'revision', 'digest']);

function isRecord(value: unknown): value is Record<string, any> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Record<string, any>, keys: ReadonlySet<string>): boolean {
  return Object.keys(value).length === keys.size
    && Object.keys(value).every((key) => keys.has(key));
}

function exactString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function tryDigest(value: unknown): AebDigest | null {
  try {
    return digestAeb(value);
  } catch {
    return null;
  }
}

function tryCanonicalClone(value: unknown): { ok: true; value: unknown } | { ok: false; value: null } {
  try {
    return { ok: true, value: JSON.parse(canonicalizeAeb(value)) as unknown };
  } catch {
    return { ok: false, value: null };
  }
}

/** Digest rule for the compiler-local, relying-party-pinned native descriptor. */
export function aebNativeDescriptorDigest(
  descriptorId: string,
  descriptor: Omit<AebNativeDescriptor, 'descriptor_digest'> | AebNativeDescriptor,
): AebDigest {
  const { descriptor_digest: _ignored, ...body } = descriptor as AebNativeDescriptor;
  return digestAeb({ descriptor_id: descriptorId, descriptor: body });
}

function descriptorShapeValid(value: unknown): value is AebNativeDescriptor {
  if (!isRecord(value) || !exactKeys(value, DESCRIPTOR_KEYS)
      || value['@version'] !== AEB_NATIVE_DESCRIPTOR_VERSION
      || !isRecord(value.protocol) || !exactKeys(value.protocol, PROTOCOL_KEYS)
      || !exactString(value.protocol.id) || !exactString(value.protocol.revision)
      || !isRecord(value.source) || !exactKeys(value.source, SOURCE_KEYS)
      || !(value.source.media_type === null || exactString(value.source.media_type))
      || !(value.source.schema === null
        || (isRecord(value.source.schema) && exactKeys(value.source.schema, SCHEMA_KEYS)
          && exactString(value.source.schema.id) && exactString(value.source.schema.revision)))
      || (value.source.media_type === null && value.source.schema === null)
      || !isRecord(value.verifier) || !exactKeys(value.verifier, VERIFIER_KEYS)
      || !exactString(value.verifier.implementation_id)
      || !exactString(value.verifier.implementation_revision)
      || typeof value.verifier.implementation_digest !== 'string'
      || !DIGEST.test(value.verifier.implementation_digest)
      || !isRecord(value.adapter) || !exactKeys(value.adapter, ADAPTER_KEYS)
      || !exactString(value.adapter.id) || !exactString(value.adapter.revision)
      || !isRecord(value.mapping_profile) || !exactKeys(value.mapping_profile, MAPPING_PROFILE_KEYS)
      || !exactString(value.mapping_profile.id) || !exactString(value.mapping_profile.revision)
      || typeof value.mapping_profile.digest !== 'string' || !DIGEST.test(value.mapping_profile.digest)
      || !exactString(value.target_action_type) || !exactString(value.replay_scope)
      || typeof value.descriptor_digest !== 'string' || !DIGEST.test(value.descriptor_digest)) return false;
  return true;
}

function emptyDescriptorReport(id: string): AebNativeCompilerLegReport['native_descriptor'] {
  return {
    id,
    digest: ZERO_DIGEST,
    pinned: false,
    protocol: { id: '', revision: '' },
    source: { media_type: null, schema: null },
    verifier: {
      implementation_id: '', implementation_revision: '', implementation_digest: ZERO_DIGEST,
    },
    target_action_type: '',
    replay_scope: '',
  };
}

function validateNativeDescriptor(
  leg: AebNativeCompilerLegInput | undefined,
  descriptors: AebNativeDescriptorSet | undefined,
  pins: AebPinnedConfig,
  expectedAction: unknown,
): { valid: boolean; report: AebNativeCompilerLegReport['native_descriptor']; reasons: string[] } {
  const id = exactString(leg?.native_descriptor_id) ? leg.native_descriptor_id : '';
  if (!id) {
    return {
      valid: false,
      report: emptyDescriptorReport(''),
      reasons: ['native_descriptor_id_required'],
    };
  }
  const descriptor = isRecord(descriptors?.registry) ? descriptors.registry[id] : undefined;
  if (descriptor === undefined) {
    return {
      valid: false,
      report: emptyDescriptorReport(id),
      reasons: [`native_descriptor_not_registered:${id}`],
    };
  }
  if (!descriptorShapeValid(descriptor)) {
    return {
      valid: false,
      report: emptyDescriptorReport(id),
      reasons: [`native_descriptor_invalid:${id}`],
    };
  }
  const report: AebNativeCompilerLegReport['native_descriptor'] = {
    id,
    digest: descriptor.descriptor_digest,
    pinned: false,
    protocol: { ...descriptor.protocol },
    source: {
      media_type: descriptor.source.media_type,
      schema: descriptor.source.schema === null ? null : { ...descriptor.source.schema },
    },
    verifier: { ...descriptor.verifier },
    target_action_type: descriptor.target_action_type,
    replay_scope: descriptor.replay_scope,
  };
  const reasons: string[] = [];
  let recomputed: AebDigest | null = null;
  try {
    recomputed = aebNativeDescriptorDigest(id, descriptor);
  } catch {
    // The closed shape above makes this unusual, but it remains fail closed.
  }
  if (recomputed === null || recomputed !== descriptor.descriptor_digest) {
    reasons.push(`native_descriptor_digest_mismatch:${id}`);
  }
  const expectedPin = isRecord(descriptors?.pins) ? descriptors.pins[id] : undefined;
  if (typeof expectedPin !== 'string' || !DIGEST.test(expectedPin)) {
    reasons.push(`native_descriptor_not_pinned:${id}`);
  } else if (expectedPin !== descriptor.descriptor_digest) {
    reasons.push(`native_descriptor_pin_mismatch:${id}`);
  }
  const adapterPin = pins.adapters?.[leg?.adapter_id ?? ''];
  if (!leg || descriptor.adapter.id !== leg.adapter_id
      || descriptor.adapter.revision !== adapterPin?.version) {
    reasons.push(`native_descriptor_adapter_binding_mismatch:${id}`);
  }
  const profile = pins.profiles?.[leg?.profile_id ?? ''];
  if (!leg || descriptor.mapping_profile.id !== leg.profile_id
      || descriptor.mapping_profile.revision !== profile?.version
      || descriptor.mapping_profile.digest !== profile?.profile_digest) {
    reasons.push(`native_descriptor_profile_binding_mismatch:${id}`);
  }
  const actionType = isRecord(expectedAction) && exactString(expectedAction.action_type)
    ? expectedAction.action_type : null;
  if (actionType === null || descriptor.target_action_type !== actionType) {
    reasons.push(`native_descriptor_target_action_type_mismatch:${id}`);
  }
  const valid = reasons.length === 0;
  report.pinned = valid;
  return { valid, report, reasons: sortedUnique(reasons) };
}

function compilerLifecycle(): AebNativeCompilerReport['lifecycle'] {
  return {
    reservation: { result: 'NOT_EVALUATED', reasons: ['compiler_does_not_reserve_authority'] },
    consumption: { result: 'NOT_EVALUATED', reasons: ['compiler_does_not_consume_authority'] },
    provider_entry: { result: 'NOT_ESTABLISHED', reasons: ['compiler_has_no_provider_entry_evidence'] },
    provider_outcome: { result: 'NOT_ESTABLISHED', reasons: ['compiler_has_no_provider_outcome_evidence'] },
    observed_effect: { result: 'NOT_ESTABLISHED', reasons: ['compiler_has_no_observed_effect_evidence'] },
    retry: { result: 'NOT_EVALUATED', reasons: ['compiler_does_not_determine_retry'] },
    reconciliation: { result: 'NOT_EVALUATED', reasons: ['compiler_does_not_reconcile_outcomes'] },
  };
}

function localPolicyInputValid(value: unknown): value is AebNativeCompilerLocalPolicyInput {
  return isRecord(value)
    && exactKeys(value, LOCAL_POLICY_INPUT_KEYS)
    && exactString(value.policy_id)
    && exactString(value.policy_version)
    && (value.decision === 'ALLOW' || value.decision === 'DENY')
    && Array.isArray(value.reasons)
    && value.reasons.every(exactString)
    && new Set(value.reasons).size === value.reasons.length;
}

function profileIsPinned(
  profileId: string,
  profile: AebPinnedProfile | undefined,
  pins: AebPinnedConfig,
): profile is AebPinnedProfile {
  if (!profile) return false;
  let digest: AebDigest | null = null;
  try {
    digest = mappingProfileDigest(profileId, profile);
  } catch {
    return false;
  }
  const entry = pins.registry?.entries?.[profile.registry_entry_ref];
  return digest === profile.profile_digest
    && Array.isArray(pins.accepted_mappers)
    && pins.accepted_mappers.includes(profile.mapper_id)
    && entry?.kind === 'mapping-profile'
    && entry.status === 'active'
    && isRecord(entry.definition)
    && entry.definition.profile_digest === profile.profile_digest;
}

function semanticOmission(
  profileId: string,
  profileDigest: AebDigest,
  profilePinned: boolean,
  path: string,
  classification: AebSemanticOmissionClassification,
  declaration: AebSemanticOmissionDeclaration,
): AebSemanticOmission {
  const basis = {
    profile_id: profileId,
    profile_digest: profileDigest,
    profile_pinned: profilePinned,
    declaration,
  };
  return {
    path,
    classification,
    basis: {
      ...basis,
      binding_digest: digestAeb({
        '@version': SEMANTIC_OMISSION_BASIS_VERSION,
        path,
        classification,
        ...basis,
      }),
    },
  };
}

function unknownSemanticLoss(
  profileId: string,
  pins: AebPinnedConfig,
  declaration: Extract<
    AebSemanticOmissionDeclaration,
    'profile_semantics_unavailable' | 'native_profile_binding_unestablished'
  > = 'profile_semantics_unavailable',
): AebSemanticLossReport {
  const profile = pins.profiles?.[profileId];
  const candidateDigest = profile?.profile_digest;
  const profileDigest = typeof candidateDigest === 'string' && DIGEST.test(candidateDigest)
    ? candidateDigest : ZERO_DIGEST;
  const profilePinned = profileIsPinned(profileId, profile, pins);
  return {
    status: 'UNKNOWN',
    profile_pinned: profilePinned,
    omitted_material_fields: [],
    omitted_nonmaterial_fields: [],
    omissions: [semanticOmission(
      profileId,
      profileDigest,
      profilePinned,
      '$',
      'unknown',
      declaration,
    )],
  };
}

function semanticLossForProfile(
  profileId: string,
  pins: AebPinnedConfig,
): AebSemanticLossReport {
  const profile = pins.profiles?.[profileId];
  if (!profileIsPinned(profileId, profile, pins)
      || !isRecord(profile.semantic_equivalence)
      || profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
      || profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
      || !Array.isArray(profile.semantic_equivalence.omitted_material_fields)
      || !profile.semantic_equivalence.omitted_material_fields.every(exactString)
      || !Array.isArray(profile.semantic_equivalence.omitted_nonmaterial_fields)
      || !profile.semantic_equivalence.omitted_nonmaterial_fields.every(exactString)) {
    return unknownSemanticLoss(profileId, pins);
  }
  const material = sortedUnique([...profile.semantic_equivalence.omitted_material_fields]);
  const nonmaterial = sortedUnique([...profile.semantic_equivalence.omitted_nonmaterial_fields]);
  return {
    status: material.length > 0 ? 'MATERIAL'
      : nonmaterial.length > 0 ? 'NON_MATERIAL_ONLY' : 'NONE',
    profile_pinned: true,
    omitted_material_fields: material,
    omitted_nonmaterial_fields: nonmaterial,
    omissions: [
      ...material.map((path) => semanticOmission(
        profileId,
        profile.profile_digest,
        true,
        path,
        'material',
        'omitted_material_fields',
      )),
      ...nonmaterial.map((path) => semanticOmission(
        profileId,
        profile.profile_digest,
        true,
        path,
        'non_material',
        'omitted_nonmaterial_fields',
      )),
    ],
  };
}

function failureReasonsForLegs(
  legs: readonly AebNativeCompilerLegReport[],
  predicate: (leg: AebNativeCompilerLegReport) => boolean,
): string[] {
  return sortedUnique(legs.filter(predicate).flatMap((leg) => leg.reasons));
}

function aggregateVerified(legs: readonly AebNativeCompilerLegReport[]): AebNativeCompilerAxis<AebNativeCompilerVerified> {
  if (legs.length === 0) return { result: 'INDETERMINATE', reasons: ['native_legs_required'] };
  if (legs.some((leg) => leg.native_result.verification === 'FAILED')) {
    return {
      result: 'FAILED',
      reasons: failureReasonsForLegs(legs, (leg) => leg.native_result.verification === 'FAILED'),
    };
  }
  return { result: 'VERIFIED', reasons: [] };
}

function aggregateAccepted(legs: readonly AebNativeCompilerLegReport[]): AebNativeCompilerAxis<Acceptance> {
  if (legs.length === 0) return { result: 'INDETERMINATE', reasons: ['native_legs_required'] };
  if (legs.some((leg) => leg.native_result.acceptance === 'REJECTED')) {
    return {
      result: 'REJECTED',
      reasons: failureReasonsForLegs(legs, (leg) => leg.native_result.acceptance === 'REJECTED'),
    };
  }
  if (legs.some((leg) => leg.native_result.acceptance === 'INDETERMINATE')) {
    return {
      result: 'INDETERMINATE',
      reasons: failureReasonsForLegs(legs, (leg) => leg.native_result.acceptance === 'INDETERMINATE'),
    };
  }
  return { result: 'ACCEPTED', reasons: [] };
}

function aggregateMatch(legs: readonly AebNativeCompilerLegReport[]): AebNativeCompilerAxis<MappingVerdict> {
  if (legs.length === 0) return { result: 'INDETERMINATE', reasons: ['native_legs_required'] };
  const semanticRelationUnknown = legs.some((leg) => (
    leg.semantic_loss.status === 'MATERIAL' || leg.semantic_loss.status === 'UNKNOWN'
  ));
  if (semanticRelationUnknown) {
    return {
      result: 'INDETERMINATE',
      reasons: failureReasonsForLegs(legs, (leg) => (
        leg.semantic_loss.status === 'MATERIAL' || leg.semantic_loss.status === 'UNKNOWN'
      )),
    };
  }
  if (legs.some((leg) => leg.action.mapping === 'MISMATCH')) {
    return {
      result: 'MISMATCH',
      reasons: failureReasonsForLegs(legs, (leg) => leg.action.mapping === 'MISMATCH'),
    };
  }
  if (legs.some((leg) => leg.action.mapping === 'INDETERMINATE')) {
    return {
      result: 'INDETERMINATE',
      reasons: failureReasonsForLegs(legs, (leg) => leg.action.mapping === 'INDETERMINATE'),
    };
  }
  return { result: 'MATCH', reasons: [] };
}

function aggregateLoss(legs: readonly AebNativeCompilerLegReport[]): AebNativeCompilerReport['semantic_loss'] {
  const profiles = legs.map((leg) => ({
    profile_id: leg.native_profile.mapping_profile_id,
    report: leg.semantic_loss,
  }));
  if (profiles.length === 0) {
    return {
      status: 'UNKNOWN', material_present: false, unknown_present: true, profiles,
    };
  }
  const material = profiles.some(({ report }) => report.status === 'MATERIAL');
  const unknown = profiles.some(({ report }) => report.status === 'UNKNOWN');
  const nonmaterial = profiles.some(({ report }) => report.status === 'NON_MATERIAL_ONLY');
  return {
    status: material ? 'MATERIAL' : unknown ? 'UNKNOWN' : nonmaterial ? 'NON_MATERIAL_ONLY' : 'NONE',
    material_present: material,
    unknown_present: unknown,
    profiles,
  };
}

function buildReportCore(input: AebNativeCompilerInput): Omit<AebNativeCompilerReport, 'report_digest'> {
  const actionDigest = tryDigest(input.expected_action?.value) ?? ZERO_DIGEST;
  const expectedActionValue = tryCanonicalClone(input.expected_action?.value);
  const suppliedRequirementDigest = tryDigest(input.requirement?.definition) ?? ZERO_DIGEST;
  const pinnedRequirement = input.pins?.requirements?.[input.requirement?.ref];
  const pinnedRequirementDigest = tryDigest(pinnedRequirement);
  const requirementPinned = exactString(input.requirement?.ref)
    && pinnedRequirementDigest !== null
    && suppliedRequirementDigest !== ZERO_DIGEST
    && pinnedRequirementDigest === suppliedRequirementDigest;
  const expectedActionValid = isRecord(input.expected_action)
    && exactKeys(input.expected_action, new Set(['caid', 'value']))
    && exactString(input.expected_action.caid)
    && CAID.test(input.expected_action.caid)
    && actionDigest !== ZERO_DIGEST
    && expectedActionValue.ok;
  const legsInput = Array.isArray(input.native_legs) ? input.native_legs : [];
  const wrapperSeed = digestAeb({
    '@version': AEB_NATIVE_COMPILER_VERSION,
    relying_party_id: input.pins?.relying_party_id ?? '',
    requirement_ref: input.requirement?.ref ?? '',
    requirement_digest: suppliedRequirementDigest,
    action: { caid: input.expected_action?.caid ?? '', digest: actionDigest },
    native_artifacts: legsInput.map((leg) => ({
      native_descriptor_id: leg?.native_descriptor_id,
      native_descriptor_pin: isRecord(input.native_descriptors?.pins)
        ? input.native_descriptors.pins[leg?.native_descriptor_id] ?? null : null,
      adapter_id: leg?.adapter_id,
      profile_id: leg?.profile_id,
      artifact_digest: tryDigest(leg?.artifact) ?? ZERO_DIGEST,
    })),
  });
  const evaluation = evaluateAebEvidence({
    config: input.pins,
    adapters: input.adapters,
    operation_id: `compile:${wrapperSeed.slice('sha256:'.length)}`,
    consumption_nonce: `compile-only:${wrapperSeed.slice('sha256:'.length)}`,
    initiator_id: input.initiator_id,
    ...(input.executor_id !== undefined ? { executor_id: input.executor_id } : {}),
    requirement_ref: input.requirement?.ref ?? '',
    caid: input.expected_action?.caid ?? '',
    expected_action: input.expected_action?.value,
    legs: legsInput,
    evaluated_at: input.evaluated_at,
    // This identifies the unsigned local derivation. It is not a key or a
    // credential, and the compiler never returns the unsigned AEB record as one.
    evaluator_key_id: 'aeb-native-compiler:unsigned-v1',
  });
  const legs: AebNativeCompilerLegReport[] = evaluation.record.legs.map((leg, index) => {
    const adapterPin = input.pins?.adapters?.[leg.adapter_id];
    const profile = input.pins?.profiles?.[leg.profile_id];
    const descriptor = validateNativeDescriptor(
      legsInput[index],
      input.native_descriptors,
      input.pins,
      input.expected_action?.value,
    );
    const semanticLoss = descriptor.valid
      ? semanticLossForProfile(leg.profile_id, input.pins)
      : unknownSemanticLoss(leg.profile_id, input.pins, 'native_profile_binding_unestablished');
    const semanticLossReasons = semanticLoss.status === 'MATERIAL'
      ? [`semantic_loss_material:${leg.profile_id}`]
      : semanticLoss.status === 'UNKNOWN'
        ? [`semantic_loss_unknown:${leg.profile_id}`]
        : [];
    const effectiveActionEstablished = descriptor.valid
      && semanticLoss.status !== 'MATERIAL'
      && semanticLoss.status !== 'UNKNOWN';
    const reasons = sortedUnique([
      ...leg.reasons,
      ...descriptor.reasons,
      ...semanticLossReasons,
    ]);
    return {
      artifact_ref: leg.artifact_ref,
      native_descriptor: descriptor.report,
      native_profile: {
        adapter_id: leg.adapter_id,
        adapter_revision: leg.adapter_version,
        mapping_profile_id: leg.profile_id,
        mapping_profile_revision: leg.profile_version,
      },
      artifact_digest: leg.evidence_digest,
      native_result: {
        verification: leg.native_verification,
        acceptance: descriptor.valid || leg.acceptance === 'REJECTED'
          ? leg.acceptance : 'INDETERMINATE',
      },
      pins: {
        adapter_config_digest: adapterPin?.config_digest ?? ZERO_DIGEST,
        profile_digest: leg.profile_digest,
        mapper_id: leg.mapper_id,
        resolver: {
          id: profile?.resolver?.id ?? '',
          revision: profile?.resolver?.version ?? '',
          implementation_digest: leg.resolver_digest,
        },
      },
      action: {
        mapping: effectiveActionEstablished ? leg.mapping : 'INDETERMINATE',
        caid: effectiveActionEstablished ? leg.caid : null,
        normalized_action_digest: effectiveActionEstablished ? leg.action_digest : null,
        native_raw_mapping: leg.mapping,
        native_raw_caid: leg.caid,
        native_raw_normalized_action_digest: leg.action_digest,
      },
      evidence: {
        role: leg.evidence_role,
        subject: leg.subject,
        freshness: { ...leg.freshness },
      },
      replay_unit: leg.replay_unit,
      semantic_loss: semanticLoss,
      verdict: effectiveActionEstablished ? leg.verdict : 'INDETERMINATE',
      reasons,
    };
  });
  const verified = aggregateVerified(legs);
  const accepted = aggregateAccepted(legs);
  const match = aggregateMatch(legs);
  const semanticLoss = aggregateLoss(legs);
  const engineReasons = evaluation.record.reasons.filter((reason) => reason !== UNSIGNED_EVALUATION_REASON);
  const compilerReasons: string[] = [];
  if (!requirementPinned) compilerReasons.push('requirement_not_pinned');
  if (!expectedActionValid) compilerReasons.push('expected_action_invalid');
  for (const { profile_id: profileId, report } of semanticLoss.profiles) {
    if (report.status === 'MATERIAL') compilerReasons.push(`semantic_loss_material:${profileId}`);
    if (report.status === 'UNKNOWN') compilerReasons.push(`semantic_loss_unknown:${profileId}`);
  }
  compilerReasons.push(...legs.flatMap((leg) => (
    leg.native_descriptor.pinned
      ? [] : leg.reasons.filter((reason) => reason.startsWith('native_descriptor_'))
  )));

  let satisfactionResult = evaluation.record.verdict;
  if (!requirementPinned || !expectedActionValid || semanticLoss.unknown_present) {
    satisfactionResult = 'INDETERMINATE';
  } else if (semanticLoss.material_present) {
    satisfactionResult = 'UNSATISFIED';
  }
  const satisfactionReasons = satisfactionResult === 'SATISFIED'
    ? []
    : sortedUnique([...engineReasons, ...compilerReasons]);
  const satisfied: AebNativeCompilerAxis<AebVerdict> = {
    result: satisfactionResult,
    reasons: satisfactionReasons,
  };

  const policyInputValid = localPolicyInputValid(input.local_policy_input);
  const policyInput: AebNativeCompilerAxis<AebNativeCompilerPolicyInputDecision> = policyInputValid
    ? {
      result: input.local_policy_input.decision,
      reasons: sortedUnique([...input.local_policy_input.reasons]),
    }
    : { result: 'INDETERMINATE', reasons: ['local_policy_input_invalid'] };
  const localAuthorization: AebNativeCompilerAxis<AebNativeCompilerNotEvaluated> = {
    result: 'NOT_EVALUATED',
    reasons: ['compiler_does_not_evaluate_local_authorization'],
  };
  const nativeReplayKeys = aebNativeReplayKeys(evaluation.record);
  const replayUnit = nativeReplayKeys.length > 0
    ? digestAeb({
      version: AEB_NATIVE_COMPILER_VERSION,
      relying_party_id: input.pins?.relying_party_id ?? '',
      native_replay_keys: nativeReplayKeys,
    })
    : ZERO_DIGEST;
  const policy: AebNativeCompilerLocalPolicyInput = policyInputValid
    ? {
      policy_id: input.local_policy_input.policy_id,
      policy_version: input.local_policy_input.policy_version,
      decision: input.local_policy_input.decision,
      reasons: sortedUnique([...input.local_policy_input.reasons]),
    }
    : { policy_id: '', policy_version: '', decision: 'DENY', reasons: [] };
  const topReasons = sortedUnique([
    ...compilerReasons,
    ...(verified.result === 'VERIFIED' ? [] : verified.reasons),
    ...(accepted.result === 'ACCEPTED' ? [] : accepted.reasons),
    ...(match.result === 'MATCH' ? [] : match.reasons),
    ...(satisfied.result === 'SATISFIED' ? [] : satisfied.reasons),
    ...(!policyInputValid ? ['local_policy_input_invalid'] : []),
  ]);
  return {
    '@version': AEB_NATIVE_COMPILER_VERSION,
    relying_party_id: input.pins?.relying_party_id ?? '',
    evaluated_at: input.evaluated_at,
    engine: {
      evaluator: AEB_ADAPTER_VERSION,
      composition: evaluation.record.composition.engine,
      signed_evaluation: false,
    },
    requirement: {
      ref: input.requirement?.ref ?? '',
      digest: suppliedRequirementDigest,
      pinned: requirementPinned,
    },
    expected_action: {
      caid: input.expected_action?.caid ?? '',
      value: expectedActionValue.ok ? expectedActionValue.value : null,
      digest: actionDigest,
      provenance: 'RELYING_PARTY_INPUT',
    },
    local_policy_input: {
      policy_id: policy.policy_id,
      policy_version: policy.policy_version,
      decision: policyInput.result,
      reasons: [...policyInput.reasons],
      provenance: 'RELYING_PARTY_INPUT',
      verification: 'NOT_EVALUATED',
      input_digest: tryDigest(input.local_policy_input) ?? ZERO_DIGEST,
    },
    legs,
    replay_unit: replayUnit,
    semantic_loss: semanticLoss,
    axes: {
      verified,
      accepted,
      match,
      satisfied,
      policy_input: policyInput,
      local_authorization: localAuthorization,
    },
    lifecycle: compilerLifecycle(),
    claims: {
      local_authorization_established: false,
      provider_entry_established: false,
      execution_established: false,
      outcome_established: false,
      verifier_runtime_measurement_established: false,
    },
    report_is_credential: false,
    reasons: topReasons,
  };
}

function failureReport(input: unknown): Omit<AebNativeCompilerReport, 'report_digest'> {
  const value = isRecord(input) ? input : {};
  const expected = isRecord(value.expected_action) ? value.expected_action : {};
  const requirement = isRecord(value.requirement) ? value.requirement : {};
  const expectedActionValue = tryCanonicalClone(expected.value);
  const policyInputValid = localPolicyInputValid(value.local_policy_input);
  const policy = policyInputValid
    ? value.local_policy_input
    : { policy_id: '', policy_version: '', decision: 'DENY' as const, reasons: [] };
  const policyInput: AebNativeCompilerAxis<AebNativeCompilerPolicyInputDecision> = policyInputValid
    ? { result: policy.decision, reasons: sortedUnique([...policy.reasons]) }
    : { result: 'INDETERMINATE', reasons: ['local_policy_input_invalid'] };
  return {
    '@version': AEB_NATIVE_COMPILER_VERSION,
    relying_party_id: isRecord(value.pins) && exactString(value.pins.relying_party_id)
      ? value.pins.relying_party_id : '',
    evaluated_at: exactString(value.evaluated_at) ? value.evaluated_at : '',
    engine: { evaluator: AEB_ADAPTER_VERSION, composition: AEC_VERSION, signed_evaluation: false },
    requirement: {
      ref: exactString(requirement.ref) ? requirement.ref : '',
      digest: tryDigest(requirement.definition) ?? ZERO_DIGEST,
      pinned: false,
    },
    expected_action: {
      caid: exactString(expected.caid) ? expected.caid : '',
      value: expectedActionValue.ok ? expectedActionValue.value : null,
      digest: tryDigest(expected.value) ?? ZERO_DIGEST,
      provenance: 'RELYING_PARTY_INPUT',
    },
    local_policy_input: {
      policy_id: policy.policy_id,
      policy_version: policy.policy_version,
      decision: policyInput.result,
      reasons: [...policyInput.reasons],
      provenance: 'RELYING_PARTY_INPUT',
      verification: 'NOT_EVALUATED',
      input_digest: tryDigest(value.local_policy_input) ?? ZERO_DIGEST,
    },
    legs: [],
    replay_unit: ZERO_DIGEST,
    semantic_loss: {
      status: 'UNKNOWN', material_present: false, unknown_present: true, profiles: [],
    },
    axes: {
      verified: { result: 'INDETERMINATE', reasons: ['compiler_input_invalid'] },
      accepted: { result: 'INDETERMINATE', reasons: ['compiler_input_invalid'] },
      match: { result: 'INDETERMINATE', reasons: ['compiler_input_invalid'] },
      satisfied: { result: 'INDETERMINATE', reasons: ['compiler_input_invalid'] },
      policy_input: policyInput,
      local_authorization: {
        result: 'NOT_EVALUATED',
        reasons: ['compiler_does_not_evaluate_local_authorization'],
      },
    },
    lifecycle: compilerLifecycle(),
    claims: {
      local_authorization_established: false,
      provider_entry_established: false,
      execution_established: false,
      outcome_established: false,
      verifier_runtime_measurement_established: false,
    },
    report_is_credential: false,
    reasons: ['compiler_input_invalid'],
  };
}

/**
 * Compile native evidence into a deterministic, fail-closed AEB report.
 *
 * The function is intentionally synchronous and side-effect free. Any runtime
 * input or adapter error returns an INDETERMINATE report instead of widening
 * authority or throwing through an authorization boundary.
 */
export function compileAebNativeEvidence(input: AebNativeCompilerInput): AebNativeCompilerReport {
  let core: Omit<AebNativeCompilerReport, 'report_digest'>;
  try {
    core = buildReportCore(input);
  } catch {
    core = failureReport(input);
  }
  return { ...core, report_digest: digestAeb(core) };
}
