// SPDX-License-Identifier: Apache-2.0

/**
 * Pure FIDO/AP2-to-Gate builders.
 *
 * This module re-verifies and binds a signed two-leg AEB evaluation from
 * relying-party-pinned configuration, exact artifacts, and current statuses.
 * It never reserves authority, enters a provider, reconciles an outcome, or
 * reads an ambient clock. Admission custody remains the AdmissionStore's job.
 */

import crypto from 'node:crypto';
import {
  createAebNativeVerificationAttestationAdapter,
  digestAeb,
  verifyAebEvaluation,
  type AebPinnedConfig,
  type AebStatusInput,
} from '@emilia-protocol/verify/aeb-adapter-contract';
import {
  createFidoAp2AebAdapter,
  createFidoAp2NativeSourceBinding,
  projectFidoAp2PaymentAction,
  FIDO_AP2_AEB_ADAPTER_ID,
  FIDO_AP2_NATIVE_PROTOCOL_ID,
  type FidoAp2SignCountPolicy,
  type FidoAp2NativeSourceBindingInput,
} from '@emilia-protocol/verify/fido-ap2-bridge';

import {
  createAdmissionSnapshot,
  type AdmissionDigest,
  type AdmissionInput,
  type AdmissionResourceReservationInput,
  type AdmissionSnapshot,
  type AdmissionSnapshotInput,
} from './admission-store.js';
import type { GateQualificationBundleV2 } from './gate-qualification-v2.js';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const BRIDGE_DOMAIN = 'EP-FIDO-AP2-GATE-BRIDGE-v1';
const AEB_ARTIFACT_TYPE = 'aeb.fido-ap2-human-authorization';
const AP2_SOURCE_REVISION =
  'google-agentic-commerce/AP2@e1ea56db72a6385bce3e5c1112b3a56ce60acb43';
const HUMAN_ARTIFACT_VERSION = 'EP-FIDO-AP2-EVIDENCE-v1';
const HUMAN_ROLE = 'human_authorization';
const AP2_NATIVE_ROLE = 'ap2-native-authorization';
const REQUIRED_COMPOSITION = `${AP2_NATIVE_ROLE} AND ${HUMAN_ROLE}`;
const INPUT_KEYS = new Set([
  'evaluation',
  'humanArtifact',
  'nativeAttestation',
  'bindings',
]);
const BINDING_KEYS = new Set([
  'tenant_id',
  'relying_party_id',
  'audience',
  'admission_id',
  'operation_id',
  'caid',
  'action_digest',
  'effect_request_digest',
  'provider',
  'candidate_manifest_digest',
  'runtime_measurement_digest',
  'candidate_custody',
  'assignment_digest',
  'qualification_policy_digest',
  'test_result_payload_digests',
  'agent_evaluation_evidence_payload_digests',
  'qualification_statement_payload_digest',
  'qualification_status',
  'executor_adapter_digest',
  'idempotency_key',
  'authorization_policy_digest',
  'trust_epoch',
  'trust_configuration_digest',
  'configuration_epoch',
  'configuration_digest',
  'inputs',
  'expires_at',
  'supersedes_admission_id',
  'remedy_for',
]);
const HUMAN_ARTIFACT_KEYS = new Set([
  '@version',
  'source_revision',
  'tenant_id',
  'relying_party_id',
  'audience',
  'operation_id',
  'effect_request_digest',
  'provider',
  'source_commitments',
  'normalized_action',
  'disclosure',
  'signoff',
]);
const SOURCE_COMMITMENT_KEYS = new Set([
  'checkout_mandate_token_digest',
  'payment_mandate_token_digest',
  'native_verification_attestation_digest',
]);
const SIGNOFF_KEYS = new Set(['context', 'webauthn']);
const CONTEXT_KEYS = new Set([
  'source_revision',
  'tenant_id',
  'relying_party_id',
  'audience',
  'operation_id',
  'effect_request_digest',
  'provider',
  'source_commitments',
  'normalized_action_digest',
  'caid',
  'disclosure_digest',
  'approver_id',
  'nonce',
  'expires_at',
]);
const WEBAUTHN_KEYS = new Set([
  'credential_id',
  'authenticator_data',
  'client_data_json',
  'signature',
]);
const ACTION_KEYS = new Set([
  'action_type', 'checkout_mandate_digest', 'payment_mandate_digest',
  'checkout_payload_jwt_digest', 'transaction_id', 'amount_minor', 'currency',
  'payee_id', 'payee_name', 'payee_website_digest', 'pisp_digest',
  'payment_instrument_id', 'payment_instrument_type',
  'payment_instrument_description_digest', 'risk_data_digest', 'execution',
  'source_expires_at',
]);
const DISCLOSURE_KEYS = new Set([
  'checkout_commitment', 'payment_commitment',
  'checkout_payload_jwt_commitment', 'transaction_id',
  'amount_minor', 'currency', 'payee_id', 'payee_name',
  'payment_instrument_id', 'payment_instrument_type', 'execution',
  'source_expires_at',
]);
const NATIVE_ATTESTATION_KEYS = new Set([
  '@version', 'protocol_id', 'audience', 'native_artifact_ref',
  'native_artifact_digest', 'evidence_role', 'subject', 'verified_at',
  'expires_at', 'mapping', 'signature',
]);
const NATIVE_SUBJECT_KEYS = new Set(['id', 'kind']);
const NATIVE_MAPPING_KEYS = new Set([
  'profile_digest', 'mapper_id', 'resolver_digest', 'caid',
  'normalized_action_digest',
]);
const NATIVE_SIGNATURE_KEYS = new Set(['alg', 'key_id', 'value']);
const AUTHENTICATED_STATUS_KEYS = new Set([
  'artifact_ref', 'evidence_digest', 'replay_unit', 'authority_id',
  'sequence', 'head_digest', 'status',
]);
const PROVIDER_KEYS = new Set([
  'provider_id',
  'account_id',
  'environment',
]);
const ADMISSION_INPUT_KEYS = new Set([
  'role',
  'artifact_type',
  'subject',
  'payload_digest',
  'profile_digest',
  'verifier_id',
  'trust_configuration_digest',
  'valid_until',
]);
const QUALIFICATION_BUNDLE_INPUT_KEYS = new Set([
  'bridgeInput',
  'qualification',
  'aec',
  'localPolicy',
]);

type Obj = Record<string, unknown>;
const MAX_INPUT_DEPTH = 64;

export interface FidoAp2AuthenticatedStatus {
  artifact_ref: string;
  evidence_digest: AdmissionDigest;
  replay_unit: AdmissionDigest;
  authority_id: string;
  sequence: number;
  head_digest: AdmissionDigest;
  status: AebStatusInput;
}

export interface FidoAp2Provider {
  provider_id: string;
  account_id: string;
  environment: string;
}

export interface FidoAp2ProviderRequestVerifier {
  id: string;
  version: string;
  implementation_digest: AdmissionDigest;
  verify(input: Readonly<{
    effect_request_bytes: Uint8Array;
    payment_mandate_token: string;
    payment_mandate_token_digest: AdmissionDigest;
    provider: Readonly<FidoAp2Provider>;
  }>): boolean;
}

/** Server-owned dependencies. None of these values may come from the request. */
export interface FidoAp2TrustedAdmissionControls {
  now(): number | string | Date;
  pinned_config: AebPinnedConfig;
  resolve_current_statuses(input: Readonly<{
    artifact_refs: readonly [string, string];
    evidence_digests: readonly [AdmissionDigest, AdmissionDigest];
    replay_units: readonly [AdmissionDigest, AdmissionDigest];
    now: string;
  }>): readonly [FidoAp2AuthenticatedStatus, FidoAp2AuthenticatedStatus];
  tenant_id: string;
  relying_party_id: string;
  audience: string;
  operation_id: string;
  initiator_id: string;
  executor_id: string;
  provider: Readonly<FidoAp2Provider>;
  gate_trust_configuration_digest: AdmissionDigest;
  executor_adapter_digest: AdmissionDigest;
  /** Server-owned current WebAuthn signature-counter head for this credential. */
  webauthn_counter_head: number;
  ap2_source: FidoAp2NativeSourceBindingInput;
  effect_request_bytes: Uint8Array;
  provider_request_verifier: FidoAp2ProviderRequestVerifier;
}

type ValidatedProvider = FidoAp2Provider;

interface ValidatedHumanArtifact {
  sourceRevision: string;
  tenantId: string;
  relyingPartyId: string;
  audience: string;
  operationId: string;
  effectRequestDigest: AdmissionDigest;
  provider: ValidatedProvider;
  caid: string;
  actionDigest: AdmissionDigest;
  checkoutMandateTokenDigest: AdmissionDigest;
  paymentMandateTokenDigest: AdmissionDigest;
  nativeVerificationAttestationDigest: AdmissionDigest;
  disclosureDigest: AdmissionDigest;
  artifactDigest: AdmissionDigest;
  approverId: string;
  credentialId: string;
  signCount: number;
  sourceExpiresAt: string;
  sourceExpiresAtMs: number;
  expiresAt: string;
  expiresAtMs: number;
}

interface ValidatedNativeAttestation {
  attestationDigest: AdmissionDigest;
  nativeArtifactDigest: AdmissionDigest;
  subjectId: string;
  subjectKind: string;
  verifiedAtMs: number;
  expiresAt: string;
  expiresAtMs: number;
}

interface ResolvedStatuses {
  current: Record<string, AebStatusInput>;
  leases: AdmissionResourceReservationInput[];
}

interface ValidatedEvaluation {
  operationId: string;
  consumptionNonce: string;
  initiatorId: string;
  executorId: string;
  relyingPartyId: string;
  evaluatorKeyId: string;
  pinnedConfigDigest: AdmissionDigest;
  requirementRef: string;
  requirementDigest: AdmissionDigest;
  caid: string;
  actionDigest: AdmissionDigest;
  evidenceDigest: AdmissionDigest;
  recordDigest: AdmissionDigest;
  humanId: string;
  humanEvidenceDigest: AdmissionDigest;
  nativeEvidenceDigest: AdmissionDigest;
  nativeSubjectId: string;
  nativeSubjectKind: string;
  humanAdapterId: string;
  humanArtifactRef: string;
  humanReplayUnit: AdmissionDigest;
  nativeAdapterId: string;
  nativeAdapterVersion: string;
  nativeArtifactRef: string;
  nativeReplayUnit: AdmissionDigest;
  legExpiresAt: string;
  legExpiresAtMs: number;
}

function fail(message: string): never {
  throw new TypeError(`FIDO/AP2 bridge: ${message}`);
}

function object(value: unknown, name: string): Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${name} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail(`${name} must be a plain object`);
  }
  return value as Obj;
}

function strictJsonInput(
  value: unknown,
  seen = new WeakSet<object>(),
  depth = 0,
): boolean {
  if (depth > MAX_INPUT_DEPTH) return false;
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return true;
  }
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value !== 'object' || seen.has(value)) return false;
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) return false;
      const keys = Reflect.ownKeys(value);
      if (keys.length !== value.length + 1
          || keys.some((key) => typeof key === 'symbol'
          || (key !== 'length' && (!/^(0|[1-9][0-9]*)$/.test(String(key))
            || Number(key) >= value.length)))) {
        return false;
      }
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !Object.hasOwn(descriptor, 'value')
            || !strictJsonInput(descriptor.value, seen, depth + 1)) return false;
      }
      return true;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return false;
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string') return false;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')
          || !strictJsonInput(descriptor.value, seen, depth + 1)) return false;
    }
    return true;
  } finally {
    seen.delete(value);
  }
}

function cloneStrictJsonInput(value: unknown, name: string): unknown {
  if (!strictJsonInput(value)) fail(`${name} is outside the strict JSON domain`);
  let cloned: unknown;
  try {
    // structuredClone rejects Proxy objects. That closes the validation/use
    // gap where a proxy can expose safe property descriptors and later return
    // different values from its get trap.
    cloned = structuredClone(value);
  } catch {
    return fail(`${name} must be inert structured data`);
  }
  if (!strictJsonInput(cloned)) fail(`${name} is outside the strict JSON domain`);
  return cloned;
}

function freezeStrictJson<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value as Record<string, unknown>)) {
      freezeStrictJson(child);
    }
    Object.freeze(value);
  }
  return value;
}

function closed(value: Obj, allowed: ReadonlySet<string>, name: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(`${name}.${key} is not allowed`);
  }
}

function string(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512) {
    fail(`${name} is invalid`);
  }
  return value;
}

function digest(value: unknown, name: string): AdmissionDigest {
  if (typeof value !== 'string' || !DIGEST.test(value)) {
    fail(`${name} is not a SHA-256 digest`);
  }
  return value as AdmissionDigest;
}

function base64urlBytes(value: unknown, name: string, maxBytes: number): Buffer {
  const encoded = string(value, name);
  if (encoded.length > Math.ceil(maxBytes * 4 / 3) + 2
      || !/^[A-Za-z0-9_-]+$/.test(encoded)
      || encoded.length % 4 === 1) fail(`${name} is invalid`);
  const bytes = Buffer.from(encoded, 'base64url');
  if (bytes.length === 0 || bytes.length > maxBytes
      || bytes.toString('base64url') !== encoded) fail(`${name} is invalid`);
  return bytes;
}

function instant(value: unknown, name: string): { iso: string; ms: number } {
  if (typeof value !== 'string') fail(`${name} is invalid`);
  const ms = Date.parse(value as string);
  if (!Number.isFinite(ms)) fail(`${name} is invalid`);
  return { iso: new Date(ms).toISOString(), ms };
}

function emptyReasons(value: unknown, name: string): void {
  if (!Array.isArray(value) || value.length !== 0) {
    fail(`${name} must be empty`);
  }
}

function exact(value: unknown, expected: unknown, name: string): void {
  if (value !== expected) fail(`${name} does not match`);
}

function bridgeDigest(domain: string, ...parts: readonly string[]): AdmissionDigest {
  const hash = crypto.createHash('sha256');
  hash.update(BRIDGE_DOMAIN, 'utf8');
  hash.update('\0', 'utf8');
  hash.update(domain, 'utf8');
  for (const part of parts) {
    hash.update('\0', 'utf8');
    hash.update(String(Buffer.byteLength(part, 'utf8')), 'utf8');
    hash.update(':', 'utf8');
    hash.update(part, 'utf8');
  }
  return `sha256:${hash.digest('hex')}`;
}

export function digestFidoAp2EffectRequest(value: Uint8Array): AdmissionDigest {
  if (!(value instanceof Uint8Array) || value.byteLength === 0
      || value.byteLength > 8 * 1024 * 1024) {
    fail('effect request bytes are outside the closed v1 limit');
  }
  const bytes = Buffer.from(value);
  const hash = crypto.createHash('sha256');
  hash.update('EP-FIDO-AP2-PROVIDER-REQUEST-v1\0', 'utf8');
  hash.update(String(bytes.length), 'utf8');
  hash.update(':', 'utf8');
  hash.update(bytes);
  return `sha256:${hash.digest('hex')}`;
}

function trustedNow(controls: FidoAp2TrustedAdmissionControls): { iso: string; ms: number } {
  if (!controls || typeof controls !== 'object' || typeof controls.now !== 'function') {
    fail('server-owned admission controls are required');
  }
  let value: unknown;
  try {
    value = controls.now();
  } catch {
    return fail('trusted clock is unavailable');
  }
  const ms = value instanceof Date ? value.getTime()
    : typeof value === 'number' ? value : Date.parse(String(value));
  if (!Number.isFinite(ms)) fail('trusted clock returned an invalid instant');
  return { iso: new Date(ms).toISOString(), ms };
}

function validateProvider(raw: unknown, name: string): ValidatedProvider {
  const provider = object(raw, name);
  closed(provider, PROVIDER_KEYS, name);
  return {
    provider_id: string(provider.provider_id, `${name}.provider_id`),
    account_id: string(provider.account_id, `${name}.account_id`),
    environment: string(provider.environment, `${name}.environment`),
  };
}

function sameProvider(
  left: ValidatedProvider,
  right: ValidatedProvider,
  name: string,
): void {
  exact(left.provider_id, right.provider_id, `${name}.provider_id`);
  exact(left.account_id, right.account_id, `${name}.account_id`);
  exact(left.environment, right.environment, `${name}.environment`);
}

function validateEvaluation(
  raw: unknown,
  admittedAtMs: number,
): ValidatedEvaluation {
  const recordDigest = aebDigest(raw, 'evaluation record');
  const record = object(raw, 'evaluation');
  exact(record['@type'], 'AEB-EVALUATION-v1', 'evaluation.record.@type');
  exact(record.verdict, 'SATISFIED', 'evaluation.record.verdict');
  emptyReasons(record.reasons, 'evaluation.record.reasons');

  const operationId = string(record.operation_id, 'evaluation.record.operation_id');
  const consumptionNonce = string(
    record.consumption_nonce,
    'evaluation.record.consumption_nonce',
  );
  const initiatorId = string(record.initiator_id, 'evaluation.record.initiator_id');
  const executorId = string(record.executor_id, 'evaluation.record.executor_id');
  const requirementRef = string(
    record.requirement_ref,
    'evaluation.record.requirement_ref',
  );
  const requirementDigest = digest(
    record.requirement_digest,
    'evaluation.record.requirement_digest',
  );
  digest(record.registry_digest, 'evaluation.record.registry_digest');
  const caid = string(record.caid, 'evaluation.record.caid');
  const evidenceDigest = digest(
    record.evidence_digest,
    'evaluation.record.evidence_digest',
  );

  const evaluator = object(record.evaluator, 'evaluation.record.evaluator');
  const relyingPartyId = string(evaluator.id, 'evaluation.record.evaluator.id');
  const evaluatorKeyId = string(
    evaluator.key_id,
    'evaluation.record.evaluator.key_id',
  );
  const pinnedConfigDigest = digest(
    evaluator.pinned_config_digest,
    'evaluation.record.evaluator.pinned_config_digest',
  );

  const signature = object(record.signature, 'evaluation.record.signature');
  exact(signature.alg, 'Ed25519', 'evaluation.record.signature.alg');
  exact(signature.key_id, evaluatorKeyId, 'evaluation.record.signature.key_id');
  string(signature.value, 'evaluation.record.signature.value');

  if (!Array.isArray(record.legs) || record.legs.length !== 2) {
    fail('evaluation must contain exactly two evidence legs');
  }
  const byRole = new Map<string, Obj>();
  for (const [index, value] of record.legs.entries()) {
    const leg = object(value, `evaluation.record.legs[${index}]`);
    const role = string(leg.evidence_role, `AEB leg ${index} evidence_role`);
    if (byRole.has(role)) fail(`duplicate AEB evidence role ${role}`);
    byRole.set(role, leg);
    exact(leg.native_verification, 'VERIFIED', `AEB leg ${role} native verification`);
    exact(leg.acceptance, 'ACCEPTED', `AEB leg ${role} acceptance`);
    exact(leg.mapping, 'MATCH', `AEB leg ${role} mapping`);
    exact(leg.verdict, 'SATISFIED', `AEB leg ${role} verdict`);
    emptyReasons(leg.reasons, `AEB leg ${role} reasons`);
    string(leg.adapter_id, `AEB leg ${role} adapter_id`);
    string(leg.adapter_version, `AEB leg ${role} adapter_version`);
    string(leg.profile_id, `AEB leg ${role} profile_id`);
    string(leg.profile_version, `AEB leg ${role} profile_version`);
    digest(leg.profile_digest, `AEB leg ${role} profile_digest`);
    string(leg.artifact_ref, `AEB leg ${role} artifact_ref`);
    digest(leg.evidence_digest, `AEB leg ${role} evidence_digest`);
    digest(leg.status_digest, `AEB leg ${role} status_digest`);
    string(leg.mapper_id, `AEB leg ${role} mapper_id`);
    digest(leg.resolver_digest, `AEB leg ${role} resolver_digest`);
    digest(leg.replay_unit, `AEB leg ${role} replay_unit`);
    exact(leg.caid, caid, `AEB leg ${role} CAID`);
    digest(leg.action_digest, `AEB leg ${role} action_digest`);
  }
  const humanLeg = byRole.get(HUMAN_ROLE);
  const nativeLeg = byRole.get(AP2_NATIVE_ROLE);
  if (!humanLeg || !nativeLeg || byRole.size !== 2) {
    fail('evaluation must contain AP2-native and human-authorization legs');
  }
  const actionDigest = digest(humanLeg.action_digest, 'human AEB action_digest');
  exact(nativeLeg.action_digest, actionDigest, 'AEB leg action agreement');
  const humanAdapterId = string(humanLeg.adapter_id, 'human AEB adapter id');
  exact(humanAdapterId, FIDO_AP2_AEB_ADAPTER_ID, 'human AEB adapter id');
  const humanArtifactRef = string(
    humanLeg.artifact_ref,
    'human AEB artifact reference',
  );
  const nativeAdapterId = string(nativeLeg.adapter_id, 'native AEB adapter id');
  if (nativeAdapterId === humanAdapterId) {
    fail('native and human AEB adapters must be distinct');
  }
  const nativeAdapterVersion = string(
    nativeLeg.adapter_version,
    'native AEB adapter version',
  );
  const nativeArtifactRef = string(
    nativeLeg.artifact_ref,
    'native AEB artifact reference',
  );
  if (nativeArtifactRef === humanArtifactRef) {
    fail('native and human AEB artifact references must be distinct');
  }
  const humanReplayUnit = digest(humanLeg.replay_unit, 'human AEB replay_unit');
  const nativeReplayUnit = digest(nativeLeg.replay_unit, 'native AEB replay_unit');

  const humanSubject = object(humanLeg.subject, 'human AEB leg subject');
  exact(humanSubject.kind, 'human', 'human AEB leg subject kind');
  const humanId = string(humanSubject.id, 'human AEB leg subject id');
  if (humanId === initiatorId || humanId === executorId) {
    fail('human authorizer must be distinct from initiator and executor');
  }
  const nativeSubject = object(nativeLeg.subject, 'native AP2 AEB leg subject');
  if (!['system', 'organization'].includes(String(nativeSubject.kind))) {
    fail('native AP2 verifier subject kind is invalid');
  }
  const nativeSubjectId = string(nativeSubject.id, 'native AP2 verifier subject id');
  const nativeSubjectKind = String(nativeSubject.kind);

  const composition = object(record.composition, 'evaluation.record.composition');
  exact(composition.engine, 'EP-AEC-v1', 'evaluation composition engine');
  exact(
    composition.requirement_expression,
    REQUIRED_COMPOSITION,
    'evaluation composition requirement',
  );
  exact(composition.satisfied, true, 'evaluation composition satisfaction');
  // AEB's composition digest is the AEC digest of {caid,
  // normalized_action_digest}; the Gate action digest is the normalized action
  // digest carried by both verified legs. Signature verification and
  // re-derivation below bind the two without collapsing their domains.
  digest(composition.action_digest, 'evaluation composition action');

  const constraints = object(
    record.authority_constraints,
    'evaluation.record.authority_constraints',
  );
  for (const constraint of [
    'initiator_exclusion',
    'executor_exclusion',
    'one_time_consumption',
  ]) {
    if (constraints[constraint] !== true) {
      fail(`evaluation authority constraint ${constraint} is not satisfied`);
    }
  }

  const evaluatedAt = instant(record.evaluated_at, 'evaluation.record.evaluated_at');
  if (evaluatedAt.ms > admittedAtMs) {
    fail('evaluation occurs after admission time');
  }
  const expirations: Array<{ iso: string; ms: number }> = [];
  for (const [role, leg] of byRole) {
    const freshness = object(leg.freshness, `AEB leg ${role} freshness`);
    if (freshness.revocation_checked !== true
        || freshness.revoked !== false
        || freshness.consumed !== false
        || freshness.unavailable !== false
        || freshness.fresh !== true) {
      fail(`AEB leg ${role} is not fresh and available for one-time admission`);
    }
    const checkedAt = instant(freshness.checked_at, `AEB leg ${role} freshness.checked_at`);
    const expires = instant(freshness.expires_at, `AEB leg ${role} freshness.expires_at`);
    if (checkedAt.ms > evaluatedAt.ms || expires.ms <= admittedAtMs) {
      fail(`AEB leg ${role} freshness interval does not cover admission`);
    }
    if (typeof freshness.age_seconds !== 'number'
        || !Number.isFinite(freshness.age_seconds)
        || freshness.age_seconds < 0
        || Math.abs(
          freshness.age_seconds - ((evaluatedAt.ms - checkedAt.ms) / 1_000),
        ) > 0.001) {
      fail(`AEB leg ${role} freshness age is invalid`);
    }
    expirations.push(expires);
  }
  expirations.sort((left, right) => left.ms - right.ms);
  const legExpires = expirations[0];

  return {
    operationId,
    consumptionNonce,
    initiatorId,
    executorId,
    relyingPartyId,
    evaluatorKeyId,
    pinnedConfigDigest,
    requirementRef,
    requirementDigest,
    caid,
    actionDigest,
    evidenceDigest,
    recordDigest,
    humanId,
    humanEvidenceDigest: digest(humanLeg.evidence_digest, 'human AEB evidence_digest'),
    nativeEvidenceDigest: digest(nativeLeg.evidence_digest, 'native AP2 AEB evidence_digest'),
    nativeSubjectId,
    nativeSubjectKind,
    humanAdapterId,
    humanArtifactRef,
    humanReplayUnit,
    nativeAdapterId,
    nativeAdapterVersion,
    nativeArtifactRef,
    nativeReplayUnit,
    legExpiresAt: legExpires.iso,
    legExpiresAtMs: legExpires.ms,
  };
}

function verifyEvaluationAtAdmission(
  record: unknown,
  pinnedConfigRaw: unknown,
  currentStatuses: Record<string, AebStatusInput>,
  humanArtifact: unknown,
  nativeAttestation: unknown,
  expectedAction: unknown,
  admittedAt: string,
  evaluation: ValidatedEvaluation,
): AebPinnedConfig {
  const pinnedConfigObject = object(
    cloneStrictJsonInput(pinnedConfigRaw, 'trusted pinnedConfig'),
    'trusted pinnedConfig',
  );
  const relyingPartyId = string(
    pinnedConfigObject.relying_party_id,
    'pinnedConfig.relying_party_id',
  );
  exact(
    relyingPartyId,
    evaluation.relyingPartyId,
    'pinned AEB relying-party binding',
  );
  exact(
    aebDigest(pinnedConfigObject, 'trusted pinnedConfig'),
    evaluation.pinnedConfigDigest,
    'signed AEB pinned-config digest',
  );

  const humanAdapter = createFidoAp2AebAdapter();
  exact(humanAdapter.id, evaluation.humanAdapterId, 'human AEB adapter binding');
  const nativeAdapter = createAebNativeVerificationAttestationAdapter({
    id: evaluation.nativeAdapterId,
    version: evaluation.nativeAdapterVersion,
  });
  const verification = verifyAebEvaluation(record, {
    mode: 'execution',
    config: pinnedConfigObject as unknown as AebPinnedConfig,
    adapters: {
      [humanAdapter.id]: humanAdapter,
      [nativeAdapter.id]: nativeAdapter,
    },
    artifacts: {
      [evaluation.humanArtifactRef]: humanArtifact,
      [evaluation.nativeArtifactRef]: nativeAttestation,
    },
    current_statuses: currentStatuses,
    expected_action: expectedAction,
    now: admittedAt,
  });
  if (!verification.valid || !verification.execution_authorizing) {
    const reasons = verification.reasons.length > 0
      ? verification.reasons.join(',')
      : 'verification_failed';
    fail(`signed AEB evaluation is not execution-authorizing: ${reasons}`);
  }
  return pinnedConfigObject as unknown as AebPinnedConfig;
}

function resolveTrustedStatuses(
  controls: FidoAp2TrustedAdmissionControls,
  evaluation: ValidatedEvaluation,
  now: { iso: string; ms: number },
): ResolvedStatuses {
  if (typeof controls.resolve_current_statuses !== 'function') {
    fail('authenticated current-status resolver is required');
  }
  let resolved: readonly [FidoAp2AuthenticatedStatus, FidoAp2AuthenticatedStatus];
  try {
    resolved = controls.resolve_current_statuses({
      artifact_refs: [evaluation.nativeArtifactRef, evaluation.humanArtifactRef],
      evidence_digests: [evaluation.nativeEvidenceDigest, evaluation.humanEvidenceDigest],
      replay_units: [evaluation.nativeReplayUnit, evaluation.humanReplayUnit],
      now: now.iso,
    });
  } catch {
    return fail('authenticated current-status resolution failed');
  }
  const cloned = cloneStrictJsonInput(resolved, 'authenticated statuses');
  if (!Array.isArray(cloned) || cloned.length !== 2) {
    fail('authenticated status resolver must return exactly two statuses');
  }
  const expected = new Map([
    [evaluation.nativeArtifactRef, {
      evidence: evaluation.nativeEvidenceDigest,
      replay: evaluation.nativeReplayUnit,
    }],
    [evaluation.humanArtifactRef, {
      evidence: evaluation.humanEvidenceDigest,
      replay: evaluation.humanReplayUnit,
    }],
  ]);
  const current: Record<string, AebStatusInput> = {};
  const leases: AdmissionResourceReservationInput[] = [];
  for (const [index, raw] of cloned.entries()) {
    const entry = object(raw, `authenticated statuses[${index}]`);
    closed(entry, AUTHENTICATED_STATUS_KEYS, `authenticated statuses[${index}]`);
    const ref = string(entry.artifact_ref, `authenticated statuses[${index}].artifact_ref`);
    const match = expected.get(ref);
    if (!match || Object.hasOwn(current, ref)) fail('authenticated status identity mismatch');
    exact(entry.evidence_digest, match.evidence, 'authenticated status evidence digest');
    exact(entry.replay_unit, match.replay, 'authenticated status replay unit');
    const authority = string(entry.authority_id, 'authenticated status authority');
    if (!Number.isSafeInteger(entry.sequence) || Number(entry.sequence) < 0) {
      fail('authenticated status sequence is invalid');
    }
    const head = digest(entry.head_digest, 'authenticated status head');
    const status = object(entry.status, 'authenticated status value');
    const expires = instant(status.expires_at, 'authenticated status expires_at');
    if (expires.ms <= now.ms) fail('authenticated status is expired');
    current[ref] = structuredClone(status) as unknown as AebStatusInput;
    const resourceId = `aeb-status-head:${bridgeDigest('status-head-id', authority, ref)}`;
    leases.push({
      kind: 'external_lease',
      resource_id: resourceId,
      reservation_id: `fido-ap2-reservation:${bridgeDigest('status-head-reservation', authority, ref, String(entry.sequence))}`,
      digest: head,
      expires_at: expires.iso,
    });
    expected.delete(ref);
  }
  if (expected.size !== 0) fail('authenticated status set is incomplete');
  return { current, leases };
}

function aebDigest(value: unknown, name: string): AdmissionDigest {
  try {
    return digestAeb(value) as AdmissionDigest;
  } catch {
    return fail(`${name} is outside the strict AEB JSON domain`);
  }
}

function validateHumanArtifact(raw: unknown): ValidatedHumanArtifact {
  const artifactDigest = aebDigest(raw, 'humanArtifact');
  const artifact = object(raw, 'humanArtifact');
  closed(artifact, HUMAN_ARTIFACT_KEYS, 'humanArtifact');
  exact(artifact['@version'], HUMAN_ARTIFACT_VERSION, 'humanArtifact.@version');
  exact(artifact.source_revision, AP2_SOURCE_REVISION, 'humanArtifact.source_revision');
  const tenantId = string(artifact.tenant_id, 'humanArtifact.tenant_id');
  const relyingPartyId = string(
    artifact.relying_party_id,
    'humanArtifact.relying_party_id',
  );
  const audience = string(artifact.audience, 'humanArtifact.audience');
  const operationId = string(artifact.operation_id, 'humanArtifact.operation_id');
  const effectRequestDigest = digest(
    artifact.effect_request_digest,
    'humanArtifact.effect_request_digest',
  );
  const provider = validateProvider(artifact.provider, 'humanArtifact.provider');
  const commitments = object(
    artifact.source_commitments,
    'humanArtifact.source_commitments',
  );
  closed(commitments, SOURCE_COMMITMENT_KEYS, 'humanArtifact.source_commitments');
  const checkoutMandateTokenDigest = digest(
    commitments.checkout_mandate_token_digest,
    'humanArtifact.source_commitments.checkout_mandate_token_digest',
  );
  const paymentMandateTokenDigest = digest(
    commitments.payment_mandate_token_digest,
    'humanArtifact.source_commitments.payment_mandate_token_digest',
  );
  const nativeVerificationAttestationDigest = digest(
    commitments.native_verification_attestation_digest,
    'humanArtifact.source_commitments.native_verification_attestation_digest',
  );

  const action = object(artifact.normalized_action, 'humanArtifact.normalized_action');
  closed(action, ACTION_KEYS, 'humanArtifact.normalized_action');
  exact(action.action_type, 'payment.purchase.1', 'humanArtifact action type');
  exact(action.checkout_mandate_digest, checkoutMandateTokenDigest, 'humanArtifact checkout source binding');
  exact(action.payment_mandate_digest, paymentMandateTokenDigest, 'humanArtifact payment source binding');
  for (const field of [
    'checkout_payload_jwt_digest', 'payee_website_digest', 'pisp_digest',
    'payment_instrument_description_digest', 'risk_data_digest',
  ]) digest(action[field], `humanArtifact action ${field}`);
  string(action.transaction_id, 'humanArtifact action transaction_id');
  if (!Number.isSafeInteger(action.amount_minor) || Number(action.amount_minor) <= 0) {
    fail('humanArtifact action amount_minor is invalid');
  }
  const currency = string(action.currency, 'humanArtifact action currency');
  if (!/^[A-Z]{3}$/.test(currency)) fail('humanArtifact action currency is invalid');
  for (const field of [
    'payee_id', 'payee_name', 'payment_instrument_id',
    'payment_instrument_type',
  ]) {
    string(action[field], `humanArtifact action ${field}`);
  }
  exact(action.execution, 'immediate', 'humanArtifact action execution');
  const sourceExpires = instant(
    action.source_expires_at,
    'humanArtifact action source_expires_at',
  );
  const actionDigest = aebDigest(action, 'humanArtifact normalized action');

  const disclosure = object(artifact.disclosure, 'humanArtifact.disclosure');
  closed(disclosure, DISCLOSURE_KEYS, 'humanArtifact.disclosure');
  for (const field of [
    'transaction_id', 'amount_minor', 'currency', 'payee_id', 'payee_name',
    'payment_instrument_id', 'payment_instrument_type', 'execution',
    'source_expires_at',
  ]) {
    exact(disclosure[field], action[field], `humanArtifact disclosure ${field}`);
  }
  exact(disclosure.checkout_commitment, checkoutMandateTokenDigest, 'humanArtifact checkout disclosure');
  exact(disclosure.payment_commitment, paymentMandateTokenDigest, 'humanArtifact payment disclosure');
  exact(
    disclosure.checkout_payload_jwt_commitment,
    action.checkout_payload_jwt_digest,
    'humanArtifact checkout payload disclosure',
  );
  const disclosureDigest = aebDigest(disclosure, 'humanArtifact disclosure');

  const signoff = object(artifact.signoff, 'humanArtifact.signoff');
  closed(signoff, SIGNOFF_KEYS, 'humanArtifact.signoff');
  const context = object(signoff.context, 'humanArtifact.signoff.context');
  closed(context, CONTEXT_KEYS, 'humanArtifact.signoff.context');
  exact(context.source_revision, AP2_SOURCE_REVISION, 'humanArtifact context source revision');
  exact(context.tenant_id, tenantId, 'humanArtifact context tenant');
  exact(context.relying_party_id, relyingPartyId, 'humanArtifact context relying party');
  exact(context.audience, audience, 'humanArtifact context audience');
  exact(context.operation_id, operationId, 'humanArtifact context operation');
  exact(
    context.effect_request_digest,
    effectRequestDigest,
    'humanArtifact context effect request',
  );
  sameProvider(
    validateProvider(context.provider, 'humanArtifact context provider'),
    provider,
    'humanArtifact context provider',
  );
  exact(
    aebDigest(context.source_commitments, 'humanArtifact context source commitments'),
    aebDigest(commitments, 'humanArtifact source commitments'),
    'humanArtifact context source commitments',
  );
  exact(context.normalized_action_digest, actionDigest, 'humanArtifact context action digest');
  const caid = string(context.caid, 'humanArtifact context CAID');
  exact(context.disclosure_digest, disclosureDigest, 'humanArtifact context disclosure digest');
  const approverId = string(context.approver_id, 'humanArtifact context approver');
  const nonce = string(context.nonce, 'humanArtifact context nonce');
  const expires = instant(context.expires_at, 'humanArtifact context expires_at');

  const webauthn = object(signoff.webauthn, 'humanArtifact.signoff.webauthn');
  closed(webauthn, WEBAUTHN_KEYS, 'humanArtifact.signoff.webauthn');
  const credentialId = string(
    webauthn.credential_id,
    'humanArtifact WebAuthn credential_id',
  );
  const authenticatorData = base64urlBytes(
    webauthn.authenticator_data,
    'humanArtifact WebAuthn authenticator_data',
    64,
  );
  if (authenticatorData.length !== 37) {
    fail('humanArtifact WebAuthn authenticator_data is outside closed v1');
  }
  base64urlBytes(
    webauthn.client_data_json,
    'humanArtifact WebAuthn client_data_json',
    8 * 1024,
  );
  base64urlBytes(
    webauthn.signature,
    'humanArtifact WebAuthn signature',
    128,
  );
  const signCount = authenticatorData.readUInt32BE(33);

  return {
    sourceRevision: AP2_SOURCE_REVISION,
    tenantId,
    relyingPartyId,
    audience,
    operationId,
    effectRequestDigest,
    provider,
    caid,
    actionDigest,
    checkoutMandateTokenDigest,
    paymentMandateTokenDigest,
    nativeVerificationAttestationDigest,
    disclosureDigest,
    artifactDigest,
    approverId,
    credentialId,
    signCount,
    sourceExpiresAt: sourceExpires.iso,
    sourceExpiresAtMs: sourceExpires.ms,
    expiresAt: expires.iso,
    expiresAtMs: expires.ms,
  };
}

function validateNativeAttestation(
  raw: unknown,
  artifact: ValidatedHumanArtifact,
  expectedNativeArtifactDigest: AdmissionDigest,
): ValidatedNativeAttestation {
  const attestationDigest = aebDigest(raw, 'nativeAttestation');
  const attestation = object(raw, 'nativeAttestation');
  closed(attestation, NATIVE_ATTESTATION_KEYS, 'nativeAttestation');
  exact(
    attestation['@version'],
    'EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v1',
    'nativeAttestation.@version',
  );
  exact(
    attestation.protocol_id,
    FIDO_AP2_NATIVE_PROTOCOL_ID,
    'nativeAttestation.protocol_id',
  );
  exact(attestation.audience, artifact.audience, 'nativeAttestation audience');
  string(attestation.native_artifact_ref, 'nativeAttestation artifact_ref');
  const nativeArtifactDigest = digest(
    attestation.native_artifact_digest,
    'nativeAttestation native_artifact_digest',
  );
  exact(
    nativeArtifactDigest,
    expectedNativeArtifactDigest,
    'nativeAttestation source commitment binding',
  );
  exact(attestation.evidence_role, AP2_NATIVE_ROLE, 'nativeAttestation evidence role');
  const subject = object(attestation.subject, 'nativeAttestation.subject');
  closed(subject, NATIVE_SUBJECT_KEYS, 'nativeAttestation.subject');
  const subjectId = string(subject.id, 'nativeAttestation subject id');
  const subjectKind = string(subject.kind, 'nativeAttestation subject kind');
  if (!['system', 'organization'].includes(subjectKind)) {
    fail('nativeAttestation subject kind is invalid');
  }
  const verifiedAt = instant(attestation.verified_at, 'nativeAttestation verified_at');
  const expiresAt = instant(attestation.expires_at, 'nativeAttestation expires_at');
  if (verifiedAt.ms >= expiresAt.ms) fail('nativeAttestation interval is invalid');
  const mapping = object(attestation.mapping, 'nativeAttestation.mapping');
  closed(mapping, NATIVE_MAPPING_KEYS, 'nativeAttestation.mapping');
  digest(mapping.profile_digest, 'nativeAttestation mapping profile');
  string(mapping.mapper_id, 'nativeAttestation mapping mapper');
  digest(mapping.resolver_digest, 'nativeAttestation mapping resolver');
  exact(mapping.caid, artifact.caid, 'nativeAttestation mapping CAID');
  exact(
    mapping.normalized_action_digest,
    artifact.actionDigest,
    'nativeAttestation mapping action',
  );
  const signature = object(attestation.signature, 'nativeAttestation.signature');
  closed(signature, NATIVE_SIGNATURE_KEYS, 'nativeAttestation.signature');
  exact(signature.alg, 'Ed25519', 'nativeAttestation signature algorithm');
  string(signature.key_id, 'nativeAttestation signature key');
  const signatureValue = string(signature.value, 'nativeAttestation signature value');
  if (!/^[A-Za-z0-9_-]+$/.test(signatureValue)) {
    fail('nativeAttestation signature is invalid');
  }
  exact(
    attestationDigest,
    artifact.nativeVerificationAttestationDigest,
    'human/native attestation digest binding',
  );
  return {
    attestationDigest,
    nativeArtifactDigest,
    subjectId,
    subjectKind,
    verifiedAtMs: verifiedAt.ms,
    expiresAt: expiresAt.iso,
    expiresAtMs: expiresAt.ms,
  };
}

function validateTrustedControls(
  controls: FidoAp2TrustedAdmissionControls,
): {
  tenantId: string;
  relyingPartyId: string;
  audience: string;
  operationId: string;
  initiatorId: string;
  executorId: string;
  provider: ValidatedProvider;
  gateTrustConfigurationDigest: AdmissionDigest;
  executorAdapterDigest: AdmissionDigest;
  source: ReturnType<typeof createFidoAp2NativeSourceBinding>;
  effectRequestDigest: AdmissionDigest;
  webauthnCounterHead: number;
} {
  if (!controls || typeof controls !== 'object') {
    fail('server-owned admission controls are required');
  }
  const tenantId = string(controls.tenant_id, 'trusted tenant_id');
  const relyingPartyId = string(controls.relying_party_id, 'trusted relying_party_id');
  const audience = string(controls.audience, 'trusted audience');
  const operationId = string(controls.operation_id, 'trusted operation_id');
  const initiatorId = string(controls.initiator_id, 'trusted initiator_id');
  const executorId = string(controls.executor_id, 'trusted executor_id');
  const provider = validateProvider(controls.provider, 'trusted provider');
  const gateTrustConfigurationDigest = digest(
    controls.gate_trust_configuration_digest,
    'trusted Gate trust configuration',
  );
  const executorAdapterDigest = digest(
    controls.executor_adapter_digest,
    'trusted executor adapter digest',
  );
  if (!Number.isSafeInteger(controls.webauthn_counter_head)
      || controls.webauthn_counter_head < 0
      || controls.webauthn_counter_head > 0xffffffff) {
    fail('trusted WebAuthn counter head is invalid');
  }
  const webauthnCounterHead = controls.webauthn_counter_head;
  let source: ReturnType<typeof createFidoAp2NativeSourceBinding>;
  try {
    source = createFidoAp2NativeSourceBinding(controls.ap2_source);
  } catch {
    return fail('trusted AP2 source tokens are invalid');
  }
  if (!(controls.effect_request_bytes instanceof Uint8Array)) {
    fail('trusted provider request bytes are required');
  }
  const requestBytes = Uint8Array.from(controls.effect_request_bytes);
  const effectRequestDigest = digestFidoAp2EffectRequest(requestBytes);
  const verifier = controls.provider_request_verifier;
  if (!verifier || typeof verifier !== 'object'
      || typeof verifier.verify !== 'function') {
    fail('pinned provider-request verifier is required');
  }
  string(verifier.id, 'provider-request verifier id');
  string(verifier.version, 'provider-request verifier version');
  exact(
    digest(verifier.implementation_digest, 'provider-request verifier implementation'),
    executorAdapterDigest,
    'provider-request verifier implementation binding',
  );
  const callbackBytes = Uint8Array.from(requestBytes);
  const before = digestFidoAp2EffectRequest(callbackBytes);
  let accepted = false;
  try {
    accepted = verifier.verify({
      effect_request_bytes: callbackBytes,
      payment_mandate_token: controls.ap2_source.payment_mandate_token,
      payment_mandate_token_digest: source.payment_mandate_token_digest as AdmissionDigest,
      provider: Object.freeze({ ...provider }),
    });
  } catch {
    return fail('provider-request verification failed');
  }
  if (digestFidoAp2EffectRequest(callbackBytes) !== before) {
    fail('provider-request verifier mutated its input');
  }
  if (accepted !== true) {
    fail('exact AP2 payment token is not bound into the provider request');
  }
  return {
    tenantId,
    relyingPartyId,
    audience,
    operationId,
    initiatorId,
    executorId,
    provider,
    gateTrustConfigurationDigest,
    executorAdapterDigest,
    source,
    effectRequestDigest,
    webauthnCounterHead,
  };
}

function pinnedSignCountPolicy(
  pinnedConfig: AebPinnedConfig,
  evaluation: ValidatedEvaluation,
): FidoAp2SignCountPolicy {
  const pin = object(
    pinnedConfig.adapters[evaluation.humanAdapterId],
    'pinnedConfig human adapter',
  );
  const config = object(pin.config, 'pinnedConfig human adapter config');
  if (config.sign_count_policy !== 'above-enrollment-and-one-time'
      && config.sign_count_policy !== 'not-relied-upon') {
    fail('pinned WebAuthn counter policy is invalid');
  }
  return config.sign_count_policy;
}

function resourceDigestParts(
  bindings: Obj,
  artifact: ValidatedHumanArtifact,
  provider: ValidatedProvider,
  evaluation: ValidatedEvaluation,
): string[] {
  return [
    string(bindings.tenant_id, 'bindings.tenant_id'),
    string(bindings.admission_id, 'bindings.admission_id'),
    string(bindings.operation_id, 'bindings.operation_id'),
    artifact.relyingPartyId,
    artifact.audience,
    artifact.caid,
    artifact.actionDigest,
    digest(bindings.effect_request_digest, 'bindings.effect_request_digest'),
    provider.provider_id,
    provider.account_id,
    provider.environment,
    artifact.sourceRevision,
    artifact.disclosureDigest,
    artifact.artifactDigest,
    evaluation.recordDigest,
    evaluation.consumptionNonce,
    evaluation.initiatorId,
    evaluation.executorId,
    evaluation.evaluatorKeyId,
    evaluation.humanReplayUnit,
    evaluation.nativeReplayUnit,
  ];
}

function makeResource(
  kind: AdmissionResourceReservationInput['kind'],
  resourceId: string,
  expiresAt: string,
  context: readonly string[],
): AdmissionResourceReservationInput {
  return {
    kind,
    resource_id: resourceId,
    reservation_id: `fido-ap2-reservation:${bridgeDigest(
      'reservation',
      kind,
      resourceId,
      expiresAt,
      ...context,
    )}`,
    digest: bridgeDigest('resource', kind, resourceId, ...context),
    expires_at: expiresAt,
  };
}

function deriveResources(
  bindings: Obj,
  artifact: ValidatedHumanArtifact,
  evaluation: ValidatedEvaluation,
  provider: ValidatedProvider,
  expiresAt: string,
  webauthnCounterHead: number,
  signCountPolicy: FidoAp2SignCountPolicy,
): AdmissionResourceReservationInput[] {
  const context = resourceDigestParts(bindings, artifact, provider, evaluation);
  const webauthnId = `webauthn-assertion:${bridgeDigest(
    'replay/webauthn-assertion',
    artifact.credentialId,
    String(artifact.signCount),
    artifact.artifactDigest,
    evaluation.humanReplayUnit,
  )}`;
  const checkoutId = `ap2-checkout-mandate-token:${bridgeDigest(
    'replay/ap2-checkout-mandate-token',
    artifact.checkoutMandateTokenDigest,
  )}`;
  const paymentId = `ap2-payment-mandate-token:${bridgeDigest(
    'replay/ap2-payment-mandate-token',
    artifact.paymentMandateTokenDigest,
  )}`;
  const counterId = `webauthn-sign-count:${bridgeDigest(
    'webauthn/sign-count-head',
    artifact.relyingPartyId,
    artifact.credentialId,
  )}`;
  const counter: AdmissionResourceReservationInput = {
    kind: 'monotonic_counter',
    resource_id: counterId,
    reservation_id: `fido-ap2-reservation:${bridgeDigest(
      'reservation/monotonic-counter',
      counterId,
      String(webauthnCounterHead),
      String(artifact.signCount),
      ...context,
    )}`,
    digest: bridgeDigest(
      'resource/monotonic-counter',
      counterId,
      String(webauthnCounterHead),
      String(artifact.signCount),
      ...context,
    ),
    expires_at: expiresAt,
    expected_value: webauthnCounterHead,
    next_value: artifact.signCount,
  };

  const resources: AdmissionResourceReservationInput[] = [
    makeResource('replay', checkoutId, expiresAt, context),
    makeResource('replay', paymentId, expiresAt, context),
    makeResource('replay', webauthnId, expiresAt, context),
  ];
  if (signCountPolicy === 'above-enrollment-and-one-time') resources.push(counter);
  resources.push(makeResource(
    'provider_operation',
    evaluation.operationId,
    expiresAt,
    context,
  ));
  return resources;
}

function aebInput(
  evaluation: ValidatedEvaluation,
  artifact: ValidatedHumanArtifact,
): AdmissionInput {
  const validUntil = [
    { iso: artifact.expiresAt, ms: artifact.expiresAtMs },
    { iso: artifact.sourceExpiresAt, ms: artifact.sourceExpiresAtMs },
    { iso: evaluation.legExpiresAt, ms: evaluation.legExpiresAtMs },
  ].sort((left, right) => left.ms - right.ms)[0].iso;
  return {
    role: 'aeb',
    artifact_type: AEB_ARTIFACT_TYPE,
    subject: evaluation.humanId,
    payload_digest: evaluation.recordDigest,
    profile_digest: evaluation.requirementDigest,
    verifier_id: evaluation.relyingPartyId,
    trust_configuration_digest: evaluation.pinnedConfigDigest,
    valid_until: validUntil,
  };
}

function insertAebInput(raw: unknown, aeb: AdmissionInput): AdmissionInput[] {
  if (!Array.isArray(raw)) fail('bindings.inputs must be an array');
  const inputs = raw.map((value, index) => {
    const entry = object(value, `bindings.inputs[${index}]`);
    closed(entry, ADMISSION_INPUT_KEYS, `bindings.inputs[${index}]`);
    if (entry.role === 'aeb') {
      fail('bindings.inputs must not contain a presenter-supplied AEB input');
    }
    return structuredClone(entry) as unknown as AdmissionInput;
  });
  const insertion = inputs.findIndex((entry) => [
    'aec',
    'local_policy',
    'authorization',
  ].includes(entry.role));
  inputs.splice(insertion === -1 ? inputs.length : insertion, 0, aeb);
  return inputs;
}

/**
 * Build the complete immutable input to one Gate admission. All replay and
 * provider-operation identities are derived here; none are presenter-selected.
 */
export function createFidoAp2AdmissionInput(
  raw: unknown,
  controls: FidoAp2TrustedAdmissionControls,
): AdmissionSnapshotInput {
  // Refuse accessors, symbols, sparse arrays, cycles, and non-JSON values
  // before any field is read. This keeps the pure builder from executing
  // presenter-controlled getters during validation.
  const admitted = trustedNow(controls);
  const cloned = cloneStrictJsonInput(raw, 'input');
  aebDigest(cloned, 'input');
  const input = object(cloned, 'input');
  closed(input, INPUT_KEYS, 'input');
  const bindings = object(input.bindings, 'bindings');
  closed(bindings, BINDING_KEYS, 'bindings');
  const artifact = validateHumanArtifact(input.humanArtifact);
  const evaluation = validateEvaluation(input.evaluation, admitted.ms);
  const expires = instant(bindings.expires_at, 'bindings.expires_at');
  if (expires.ms <= admitted.ms) fail('admission expiration is invalid');
  if (artifact.expiresAtMs <= admitted.ms
      || artifact.sourceExpiresAtMs <= admitted.ms
      || expires.ms > artifact.expiresAtMs
      || expires.ms > artifact.sourceExpiresAtMs) {
    fail('closed source freshness does not cover admission');
  }
  const trusted = validateTrustedControls(controls);
  let projectedAction: Obj;
  try {
    projectedAction = projectFidoAp2PaymentAction({
      checkout_mandate: controls.ap2_source.checkout_mandate_payload,
      payment_mandate: controls.ap2_source.payment_mandate_payload,
      source_binding: trusted.source,
    });
  } catch {
    return fail('trusted AP2 source cannot be projected into the closed action');
  }
  const projectedActionDigest = aebDigest(projectedAction, 'trusted AP2 projected action');
  const nativeAttestation = validateNativeAttestation(
    input.nativeAttestation,
    artifact,
    trusted.source.native_artifact_digest as AdmissionDigest,
  );
  const statuses = resolveTrustedStatuses(controls, evaluation, admitted);
  const pinnedConfig = verifyEvaluationAtAdmission(
    input.evaluation,
    controls.pinned_config,
    statuses.current,
    input.humanArtifact,
    input.nativeAttestation,
    projectedAction,
    admitted.iso,
    evaluation,
  );
  if (expires.ms > evaluation.legExpiresAtMs) {
    fail('AEB freshness does not cover admission expiration');
  }
  if (nativeAttestation.expiresAtMs <= admitted.ms
      || nativeAttestation.verifiedAtMs > admitted.ms
      || expires.ms > nativeAttestation.expiresAtMs) {
    fail('native AP2 attestation does not cover admission expiration');
  }
  for (const lease of statuses.leases) {
    if (Date.parse(lease.expires_at) < expires.ms) {
      fail('authenticated current status does not cover admission expiration');
    }
  }

  const tenantId = string(bindings.tenant_id, 'bindings.tenant_id');
  const relyingPartyId = string(
    bindings.relying_party_id,
    'bindings.relying_party_id',
  );
  const audience = string(bindings.audience, 'bindings.audience');
  const operationId = string(bindings.operation_id, 'bindings.operation_id');
  const caid = string(bindings.caid, 'bindings.caid');
  const actionDigest = digest(bindings.action_digest, 'bindings.action_digest');
  const effectRequestDigest = digest(
    bindings.effect_request_digest,
    'bindings.effect_request_digest',
  );
  const provider = validateProvider(bindings.provider, 'bindings.provider');
  const signCountPolicy = pinnedSignCountPolicy(pinnedConfig, evaluation);

  exact(tenantId, trusted.tenantId, 'server-owned tenant binding');
  exact(relyingPartyId, trusted.relyingPartyId, 'server-owned relying-party binding');
  exact(audience, trusted.audience, 'server-owned audience binding');
  exact(operationId, trusted.operationId, 'server-owned operation binding');
  sameProvider(provider, trusted.provider, 'server-owned provider binding');
  exact(
    effectRequestDigest,
    trusted.effectRequestDigest,
    'server-owned provider-request digest binding',
  );
  exact(
    bindings.executor_adapter_digest,
    trusted.executorAdapterDigest,
    'server-owned executor-adapter binding',
  );
  exact(
    bindings.trust_configuration_digest,
    trusted.gateTrustConfigurationDigest,
    'server-owned Gate trust-configuration binding',
  );

  exact(
    artifact.checkoutMandateTokenDigest,
    trusted.source.checkout_mandate_token_digest,
    'trusted checkout token binding',
  );
  exact(
    artifact.paymentMandateTokenDigest,
    trusted.source.payment_mandate_token_digest,
    'trusted payment token binding',
  );
  exact(
    actionDigest,
    projectedActionDigest,
    'trusted AP2 projected-action binding',
  );
  if (signCountPolicy === 'above-enrollment-and-one-time'
      && artifact.signCount <= trusted.webauthnCounterHead) {
    fail('WebAuthn counter is not above the server-owned current head');
  }

  exact(artifact.tenantId, tenantId, 'artifact tenant binding');
  exact(artifact.relyingPartyId, relyingPartyId, 'artifact relying-party binding');
  exact(artifact.audience, audience, 'artifact audience binding');
  exact(artifact.operationId, operationId, 'artifact operation binding');
  exact(artifact.caid, caid, 'artifact CAID binding');
  exact(artifact.actionDigest, actionDigest, 'artifact normalized-action binding');
  exact(
    artifact.effectRequestDigest,
    effectRequestDigest,
    'artifact effect-request binding',
  );
  sameProvider(artifact.provider, provider, 'artifact provider binding');

  exact(evaluation.operationId, operationId, 'AEB operation binding');
  exact(evaluation.initiatorId, trusted.initiatorId, 'server-owned initiator binding');
  exact(evaluation.executorId, trusted.executorId, 'server-owned executor binding');
  exact(evaluation.relyingPartyId, relyingPartyId, 'AEB relying-party binding');
  exact(
    pinnedConfig.relying_party_id,
    relyingPartyId,
    'Gate/pinned-config relying-party binding',
  );
  exact(evaluation.caid, caid, 'AEB CAID binding');
  exact(evaluation.actionDigest, actionDigest, 'AEB action binding');
  exact(evaluation.humanId, artifact.approverId, 'AEB human approver binding');
  exact(
    evaluation.humanEvidenceDigest,
    artifact.artifactDigest,
    'AEB human artifact digest binding',
  );
  exact(
    evaluation.nativeEvidenceDigest,
    nativeAttestation.attestationDigest,
    'AEB native AP2 attestation binding',
  );
  exact(
    evaluation.nativeSubjectId,
    nativeAttestation.subjectId,
    'AEB native verifier subject binding',
  );
  exact(
    evaluation.nativeSubjectKind,
    nativeAttestation.subjectKind,
    'AEB native verifier kind binding',
  );

  const base = structuredClone(bindings) as Obj;
  delete base.relying_party_id;
  delete base.audience;
  base.admitted_at = admitted.iso;
  base.inputs = insertAebInput(bindings.inputs, aebInput(evaluation, artifact));
  base.resource_reservations = [
    ...deriveResources(
      bindings,
      artifact,
      evaluation,
      provider,
      expires.iso,
      trusted.webauthnCounterHead,
      signCountPolicy,
    ),
    ...statuses.leases,
  ];

  const admissionInput = base as unknown as AdmissionSnapshotInput;
  // Validate the complete Gate contract without retaining or reserving it.
  createAdmissionSnapshot(admissionInput);
  return freezeStrictJson(admissionInput);
}

function rolePayload(
  snapshot: Readonly<AdmissionSnapshot>,
  role: AdmissionInput['role'],
): AdmissionDigest {
  const values = snapshot.body.inputs
    .filter((entry) => entry.role === role)
    .map((entry) => entry.payload_digest);
  if (values.length !== 1) fail(`admission ${role} input is not singular`);
  return values[0];
}

function validateQualificationBinding(
  raw: unknown,
  snapshot: Readonly<AdmissionSnapshot>,
): GateQualificationBundleV2['qualification'] {
  const qualification = object(raw, 'qualification');
  const payloads = object(
    qualification.payload_digests,
    'qualification.payload_digests',
  );
  exact(
    payloads.candidate_manifest,
    snapshot.body.candidate_manifest_digest,
    'qualification candidate manifest binding',
  );
  exact(
    payloads.runtime_measurement,
    snapshot.body.runtime_measurement_digest,
    'qualification runtime binding',
  );
  exact(
    payloads.protected_request_digest,
    snapshot.body.effect_request_digest,
    'qualification protected request binding',
  );
  exact(
    payloads.qualification_statement,
    snapshot.body.qualification_statement_payload_digest,
    'qualification statement binding',
  );
  exact(
    payloads.qualification_status_head,
    snapshot.body.qualification_status.head_payload_digest,
    'qualification status binding',
  );
  digest(payloads.campaign_head, 'qualification campaign head');
  digest(payloads.qualification_graph, 'qualification graph');
  return structuredClone(raw) as GateQualificationBundleV2['qualification'];
}

function validateRequirementBinding(
  raw: unknown,
  snapshot: Readonly<AdmissionSnapshot>,
  role: 'aec',
): GateQualificationBundleV2['aec'] {
  const leg = object(raw, role);
  if (leg.decision !== 'allow' && leg.decision !== 'deny') {
    fail(`${role}.decision is invalid`);
  }
  string(leg.requirementId, `${role}.requirementId`);
  exact(leg.caid, snapshot.body.caid, `${role} CAID binding`);
  exact(leg.actionDigest, snapshot.body.action_digest, `${role} action binding`);
  exact(leg.evidenceDigest, rolePayload(snapshot, role), `${role} evidence binding`);
  return structuredClone(raw) as GateQualificationBundleV2['aec'];
}

function validateLocalPolicyBinding(
  raw: unknown,
  snapshot: Readonly<AdmissionSnapshot>,
): GateQualificationBundleV2['localPolicy'] {
  const leg = object(raw, 'localPolicy');
  if (leg.decision !== 'allow' && leg.decision !== 'deny') {
    fail('localPolicy.decision is invalid');
  }
  string(leg.policyId, 'localPolicy.policyId');
  exact(
    leg.policyDigest,
    snapshot.body.authorization_policy_digest,
    'local-policy program binding',
  );
  exact(leg.caid, snapshot.body.caid, 'local-policy CAID binding');
  exact(leg.actionDigest, snapshot.body.action_digest, 'local-policy action binding');
  exact(
    leg.evidenceDigest,
    rolePayload(snapshot, 'local_policy'),
    'local-policy evidence binding',
  );
  return structuredClone(raw) as GateQualificationBundleV2['localPolicy'];
}

function validateAdmissionAebBinding(
  snapshot: Readonly<AdmissionSnapshot>,
  evaluation: ValidatedEvaluation,
): void {
  exact(evaluation.operationId, snapshot.body.operation_id, 'AEB operation binding');
  exact(evaluation.caid, snapshot.body.caid, 'AEB CAID binding');
  exact(evaluation.actionDigest, snapshot.body.action_digest, 'AEB action binding');
  const input = snapshot.body.inputs.find((entry) => entry.role === 'aeb');
  if (!input) fail('admission AEB input is missing');
  exact(input.artifact_type, AEB_ARTIFACT_TYPE, 'admission AEB artifact type');
  exact(input.subject, evaluation.humanId, 'admission AEB subject binding');
  exact(input.payload_digest, evaluation.recordDigest, 'admission AEB record binding');
  exact(input.profile_digest, evaluation.requirementDigest, 'admission AEB profile binding');
  exact(input.verifier_id, evaluation.relyingPartyId, 'admission AEB verifier binding');
  exact(
    input.trust_configuration_digest,
    evaluation.pinnedConfigDigest,
    'admission AEB trust binding',
  );
  if (Date.parse(input.valid_until) > evaluation.legExpiresAtMs) {
    fail('admission AEB input outlives the verified AEB leg');
  }

  const replay = snapshot.body.resource_reservations.filter(
    (resource) => resource.kind === 'replay',
  );
  if (replay.length !== 3
      || !replay.some((resource) => resource.resource_id.startsWith('webauthn-assertion:sha256:'))
      || !replay.some((resource) => resource.resource_id.startsWith('ap2-checkout-mandate-token:sha256:'))
      || !replay.some((resource) => resource.resource_id.startsWith('ap2-payment-mandate-token:sha256:'))) {
    fail('admission replay resources are incomplete');
  }
  const leases = snapshot.body.resource_reservations.filter(
    (resource) => resource.kind === 'external_lease'
      && resource.resource_id.startsWith('aeb-status-head:sha256:'),
  );
  if (leases.length !== 2) {
    fail('admission authenticated-status leases are incomplete');
  }
  const providerOperations = snapshot.body.resource_reservations.filter(
    (resource) => resource.kind === 'provider_operation'
      && resource.resource_id === snapshot.body.operation_id,
  );
  if (providerOperations.length !== 1) {
    fail('admission provider-operation resource is not exact');
  }
}

/**
 * Derive the AEB requirement leg and pass through only qualification, AEC, and
 * local-policy decisions that bind to the same canonical admission input.
 */
export function createFidoAp2QualificationBundle(
  raw: unknown,
  controls: FidoAp2TrustedAdmissionControls,
): GateQualificationBundleV2 {
  const cloned = cloneStrictJsonInput(raw, 'qualification bundle input');
  aebDigest(cloned, 'qualification bundle input');
  const input = object(cloned, 'qualification bundle input');
  closed(
    input,
    QUALIFICATION_BUNDLE_INPUT_KEYS,
    'qualification bundle input',
  );
  const snapshot = createAdmissionSnapshot(
    createFidoAp2AdmissionInput(input.bridgeInput, controls),
  );
  const bridgeInput = object(input.bridgeInput, 'qualification bridge input');
  const evaluation = validateEvaluation(
    bridgeInput.evaluation,
    Date.parse(snapshot.body.admitted_at),
  );
  validateAdmissionAebBinding(snapshot, evaluation);

  return {
    qualification: validateQualificationBinding(
      input.qualification,
      snapshot,
    ),
    aeb: {
      decision: 'allow',
      requirementId: evaluation.requirementRef,
      caid: evaluation.caid,
      actionDigest: evaluation.actionDigest,
      evidenceDigest: evaluation.recordDigest,
    },
    aec: validateRequirementBinding(input.aec, snapshot, 'aec'),
    localPolicy: validateLocalPolicyBinding(input.localPolicy, snapshot),
  };
}
