// SPDX-License-Identifier: Apache-2.0
/**
 * AEB-ADAPTER-v1 — relying-party-pinned evidence adapter contract.
 *
 * This module is intentionally a composition boundary, not another receipt
 * format. An adapter verifies a native artifact and projects it into a named
 * CAID mapping profile. The relying party, not the presenter, pins the
 * adapter version, trust roots, mapping profile, and evidence requirement.
 *
 * The evaluator keeps four decisions separate:
 *   VERIFIED    native artifact verification succeeded
 *   ACCEPTED    the relying party accepts that native result under its pins
 *   SATISFIED   the complete pinned requirement is met for one CAID
 *   AUTHORIZED  a local execution policy has allowed the effect
 *
 * A signed evaluation record is useful for evidence transport, but it is not
 * blindly trusted: verifyAebEvaluation re-derives the result from the pinned
 * configuration, adapter registry, and artifacts supplied by the relying party.
 */
import crypto, { type KeyObject } from 'node:crypto';
import { AEC_VERSION, actionDigest as aecActionDigest, verifyAuthorizationChain } from './evidence-chain.js';

export const AEB_ADAPTER_VERSION = 'AEB-ADAPTER-v1';
export const AEB_EVALUATION_VERSION = 'AEB-EVALUATION-v1';
export const AEB_EVALUATION_DOMAIN = `${AEB_EVALUATION_VERSION}\0`;
export const AEB_REQUIREMENT_VERSION = 'AEB-REQUIREMENT-v1';
export const AEB_REGISTRY_VERSION = 'EP-EVIDENCE-REGISTRY-v1';
export const AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION = 'EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v1';
export const AEB_NATIVE_VERIFICATION_ATTESTATION_DOMAIN = `${AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION}\0`;

export type NativeVerification = 'VERIFIED' | 'FAILED';
export type Acceptance = 'ACCEPTED' | 'REJECTED' | 'INDETERMINATE';
export type MappingVerdict = 'MATCH' | 'MISMATCH' | 'INDETERMINATE';
export type AebVerdict = 'SATISFIED' | 'UNSATISFIED' | 'INDETERMINATE';
export type AebLegVerdict = AebVerdict;
export type AebVerificationMode = 'execution' | 'historical';

export type AebJson = null | boolean | string | number | AebJson[] | { [key: string]: AebJson };
export type AebDigest = `sha256:${string}`;

export interface AebStatusInput {
  checked_at: string;
  expires_at: string;
  revocation_checked: boolean;
  revoked: boolean;
  consumed: boolean;
  /** A status source that could not be authenticated or reached. */
  unavailable?: boolean;
}

export interface AebNativeResult {
  native_verification: NativeVerification;
  acceptance: Acceptance;
  evidence_digest: AebDigest;
  /** Binds the adapter result to the status input it evaluated. */
  status_digest: AebDigest;
  evidence_role: string;
  subject: AebEvidenceSubject;
  /** Stable native authorization identity, independent of an AEB operation wrapper. */
  replay_unit: AebDigest;
  reasons: string[];
}

export interface AebEvidenceSubject {
  id: string;
  kind: 'human' | 'workload' | 'organization' | 'system';
}

export interface AebMappingResult {
  mapping: MappingVerdict;
  /** CAID derived by the adapter under the selected profile. */
  caid: string | null;
  action_digest: AebDigest | null;
  reasons: string[];
}

export interface AebAdapterInput {
  artifact: unknown;
  artifact_ref: string;
  status: AebStatusInput;
  trust_roots: readonly unknown[];
  /** Immutable relying-party configuration pinned by adapterConfigDigest. */
  adapter_config: unknown;
  profile: AebPinnedProfile;
  /** Exact action the relying party is deciding whether to execute. */
  expected_action: unknown;
  now: string;
}

export interface AebAdapter {
  readonly id: string;
  readonly version: string;
  /** Pure, deterministic native verification. No network or ambient trust. */
  verifyNative(input: Omit<AebAdapterInput, 'profile'>): AebNativeResult;
  /** Pure, deterministic projection and CAID derivation under a pinned profile. */
  mapAction(input: AebAdapterInput & { native: AebNativeResult }): AebMappingResult;
}

export interface AebNativeVerificationAttestationBody {
  '@version': typeof AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION;
  protocol_id: string;
  audience: string;
  native_artifact_ref: string;
  native_artifact_digest: AebDigest;
  evidence_role: string;
  subject: AebEvidenceSubject;
  verified_at: string;
  expires_at: string;
  mapping: {
    profile_digest: AebDigest;
    mapper_id: string;
    resolver_digest: AebDigest;
    caid: string;
    normalized_action_digest: AebDigest;
  };
}

export interface AebNativeVerificationAttestation extends AebNativeVerificationAttestationBody {
  signature: { alg: 'Ed25519'; key_id: string; value: string };
}

export interface AebNativeVerificationAttestationSigner {
  key_id: string;
  private_key: KeyObject;
}

export interface AebPinnedAdapter {
  version: string;
  trust_roots: readonly unknown[];
  /** Adapter-specific immutable parameters, if any. */
  config?: unknown;
  /** Must equal adapterConfigDigest(id, this). */
  config_digest: AebDigest;
  /** Maximum age of the authenticated status input. */
  max_status_age_sec: number;
}

export interface AebPinnedProfile {
  version: string;
  definition?: unknown;
  registry_entry_ref: string;
  mapper_id: string;
  resolver: {
    id: string;
    version: string;
    implementation_digest: AebDigest;
  };
  semantic_equivalence: {
    assertion: 'EQUIVALENT_UNDER_PROFILE';
    loss_policy: 'NO_MATERIAL_FIELD_LOSS';
    omitted_material_fields: readonly string[];
    omitted_nonmaterial_fields: readonly string[];
  };
  /** Must equal profileDigest(id, this). */
  profile_digest: AebDigest;
}

export interface AebDistinctHumanQuorumTerm {
  type: 'distinct-human-quorum';
  role: string;
  threshold: number;
}

export interface AebInitiatorExclusionTerm {
  type: 'initiator-exclusion';
  roles: readonly string[];
}

export interface AebExecutorExclusionTerm {
  type: 'executor-exclusion';
  roles: readonly string[];
}

export interface AebOneTimeConsumptionTerm {
  type: 'one-time-consumption';
}

export type AebRequirementTerm =
  | AebDistinctHumanQuorumTerm
  | AebInitiatorExclusionTerm
  | AebExecutorExclusionTerm
  | AebOneTimeConsumptionTerm;

export interface AebRequirement {
  '@version': typeof AEB_REQUIREMENT_VERSION;
  /** Every listed role must have a satisfied leg. */
  all_of: readonly string[];
  /** Each group requires at least one satisfied role. */
  any_of?: readonly (readonly string[])[];
  /** Authority and execution predicates evaluated in addition to the AEC role expression. */
  terms: readonly AebRequirementTerm[];
}

export type AebRegistryEntryKind = 'mapping-profile' | 'evidence-role' | 'receipt-extension';

export interface AebRegistryEntry {
  kind: AebRegistryEntryKind;
  version: string;
  status: 'active' | 'deprecated';
  definition: unknown;
  definition_digest: AebDigest;
}

export interface AebUnifiedRegistry {
  '@version': typeof AEB_REGISTRY_VERSION;
  registry_id: string;
  epoch: number;
  entries: Record<string, AebRegistryEntry>;
  registry_digest: AebDigest;
}

export interface AebEvaluatorKey {
  public_key: string;
}

export interface AebPinnedConfig {
  '@version': typeof AEB_ADAPTER_VERSION;
  relying_party_id: string;
  evaluator_keys: Record<string, AebEvaluatorKey>;
  registry: AebUnifiedRegistry;
  accepted_mappers: readonly string[];
  adapters: Record<string, AebPinnedAdapter>;
  profiles: Record<string, AebPinnedProfile>;
  requirements: Record<string, AebRequirement>;
}

export interface AebEvidenceLegInput {
  adapter_id: string;
  profile_id: string;
  artifact_ref: string;
  artifact: unknown;
  status: AebStatusInput;
}

export interface AebEvaluationSigner {
  key_id: string;
  private_key: KeyObject;
}

export interface AebEvaluationLeg {
  adapter_id: string;
  adapter_version: string;
  profile_id: string;
  profile_version: string;
  profile_digest: AebDigest;
  artifact_ref: string;
  evidence_digest: AebDigest;
  status_digest: AebDigest;
  replay_unit: AebDigest;
  evidence_role: string;
  subject: AebEvidenceSubject | null;
  mapper_id: string;
  resolver_digest: AebDigest;
  native_verification: NativeVerification;
  acceptance: Acceptance;
  mapping: MappingVerdict;
  action_digest: AebDigest | null;
  caid: string | null;
  freshness: AebFreshness;
  verdict: AebLegVerdict;
  reasons: string[];
}

export interface AebFreshness {
  checked_at: string;
  expires_at: string;
  revocation_checked: boolean;
  revoked: boolean;
  consumed: boolean;
  unavailable: boolean;
  age_seconds: number | null;
  fresh: boolean;
}

export interface AebEvaluationRecord {
  '@type': typeof AEB_EVALUATION_VERSION;
  operation_id: string;
  consumption_nonce: string;
  initiator_id: string;
  executor_id?: string;
  evaluator: {
    id: string;
    key_id: string;
    pinned_config_digest: AebDigest;
  };
  requirement_ref: string;
  requirement_digest: AebDigest;
  registry_digest: AebDigest;
  caid: string;
  legs: AebEvaluationLeg[];
  composition: {
    engine: typeof AEC_VERSION;
    requirement_expression: string;
    action_digest: AebDigest;
    satisfied: boolean;
  };
  authority_constraints: {
    distinct_human_quorum: boolean;
    initiator_exclusion: boolean;
    executor_exclusion: boolean;
    one_time_consumption: boolean;
  };
  verdict: AebVerdict;
  evaluated_at: string;
  evidence_digest: AebDigest;
  reasons: string[];
  signature?: {
    alg: 'Ed25519';
    key_id: string;
    value: string;
  };
}

export interface AebEvaluationResult {
  record: AebEvaluationRecord;
  valid: boolean;
  reasons: string[];
}

export interface AebEvaluationOptions {
  config: AebPinnedConfig;
  adapters: Record<string, AebAdapter>;
  operation_id: string;
  consumption_nonce: string;
  initiator_id: string;
  executor_id?: string;
  requirement_ref: string;
  caid: string;
  expected_action?: unknown;
  legs: readonly AebEvidenceLegInput[];
  evaluated_at: string;
  signer?: AebEvaluationSigner;
  /** Internal re-derivation input; callers should use signer instead. */
  evaluator_key_id?: string;
}

export interface AebVerificationOptions {
  config: AebPinnedConfig;
  adapters: Record<string, AebAdapter>;
  artifacts: Record<string, unknown>;
  /**
   * Historical verification can re-derive evidence but can never authorize
   * execution. Omission retains the PTE-compatible split: execution inputs
   * select execution mode; otherwise verification is historical.
   */
  mode?: AebVerificationMode;
  expected_action?: unknown;
  /** Fresh status results authenticated by the relying party at execution time. */
  current_statuses?: Record<string, AebStatusInput>;
  now?: string;
}

export interface AebEvaluationVerification {
  valid: boolean;
  /** True only for a complete, fresh execution-mode verification. */
  execution_authorizing: boolean;
  checks: {
    schema: boolean;
    signature: boolean;
    pinned_config: boolean;
    rederived: boolean;
    current_status: boolean;
    verdict: boolean;
  };
  reasons: string[];
}

export interface AebExecutionDecision {
  allowed: boolean;
  invoke_allowed: boolean;
  state: 'AUTHORIZED' | 'REFUSED' | 'RECONCILIATION_REQUIRED';
  reason: string;
  reservation_key?: string;
}

export interface AebConsumptionStore {
  reserve(key: string, replayKeys: readonly string[]): boolean;
  commit(key: string): boolean;
  release(key: string): boolean;
  state(key: string): 'AVAILABLE' | 'RESERVED' | 'CONSUMED';
}

/** Fleet-safe store contract implemented by @emilia-protocol/gate durable stores. */
export interface AebDurableConsumptionStore {
  durable: true;
  ownershipFenced: true;
  permanentConsumption: true;
  atomicReplayFenced: true;
  reserve(key: string, replayKeys: readonly string[]): Promise<boolean | AebReservationResult>;
  commit(key: string): Promise<boolean>;
  release(key: string): Promise<boolean>;
}

export type AebReservationResult = 'RESERVED' | 'CONSUMPTION_CONFLICT' | 'NATIVE_REPLAY_CONFLICT';

/** Small synchronous reference store. Production stores must provide an atomic equivalent. */
export class InMemoryAebConsumptionStore implements AebConsumptionStore {
  private readonly entries = new Map<string, 'RESERVED' | 'CONSUMED'>();
  private readonly replayOwners = new Map<string, string>();

  reserve(key: string, replayKeys: readonly string[] = []): boolean {
    if (this.entries.has(key)) return false;
    if (replayKeys.some((replayKey) => this.replayOwners.has(replayKey))) return false;
    this.entries.set(key, 'RESERVED');
    for (const replayKey of replayKeys) this.replayOwners.set(replayKey, key);
    return true;
  }

  commit(key: string): boolean {
    if (this.entries.get(key) !== 'RESERVED') return false;
    this.entries.set(key, 'CONSUMED');
    return true;
  }

  release(key: string): boolean {
    if (this.entries.get(key) !== 'RESERVED') return false;
    this.entries.delete(key);
    for (const [replayKey, owner] of this.replayOwners) {
      if (owner === key) this.replayOwners.delete(replayKey);
    }
    return true;
  }

  state(key: string): 'AVAILABLE' | 'RESERVED' | 'CONSUMED' {
    return this.entries.get(key) ?? 'AVAILABLE';
  }
}

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CAID_RE = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const IDENT_RE = /^[A-Za-z0-9_.:-]{1,256}$/;
const ROLE_RE = /^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/;
const RFC3339_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function canonicalize(value: unknown, seen = new WeakSet<object>()): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('non-integer number is not canonicalizable');
    return JSON.stringify(value);
  }
  if (typeof value !== 'object' || value === undefined) throw new Error('value is not canonicalizable');
  if (seen.has(value)) throw new Error('cyclic value is not canonicalizable');
  seen.add(value);
  let output: string;
  if (Array.isArray(value)) {
    output = `[${value.map((item) => canonicalize(item, seen)).join(',')}]`;
  } else {
    output = `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize((value as Record<string, unknown>)[key], seen)}`).join(',')}}`;
  }
  seen.delete(value);
  return output;
}

function sha256(value: string | Buffer): AebDigest {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}` as AebDigest;
}

function digest(value: unknown): AebDigest {
  return sha256(Buffer.from(canonicalize(value), 'utf8'));
}

function validDigest(value: unknown): value is AebDigest {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function parseInstant(value: unknown): number {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_RE);
  if (!match) return NaN;
  const [, y, mo, d, h, mi, s] = match;
  const date = new Date(0);
  date.setUTCFullYear(Number(y), Number(mo) - 1, Number(d));
  date.setUTCHours(Number(h), Number(mi), Number(s), 0);
  if (date.toISOString().slice(0, 19) !== `${y}-${mo}-${d}T${h}:${mi}:${s}`) return NaN;
  return date.getTime();
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function exactString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && IDENT_RE.test(value);
}

function ed25519PublicKey(value: unknown): KeyObject | null {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.length === 0 || bytes.toString('base64url') !== value) return null;
    const key = crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
    const canonical = key.export({ type: 'spki', format: 'der' });
    return key.type === 'public' && key.asymmetricKeyType === 'ed25519'
      && Buffer.isBuffer(canonical) && canonical.equals(bytes) ? key : null;
  } catch {
    return null;
  }
}

function isEd25519PrivateKey(value: unknown): value is KeyObject {
  return value instanceof crypto.KeyObject && value.type === 'private' && value.asymmetricKeyType === 'ed25519';
}

function privateKeyMatchesPublicKey(privateKey: KeyObject, publicKey: KeyObject): boolean {
  try {
    const signerJwk = privateKey.export({ format: 'jwk' });
    const pinnedJwk = publicKey.export({ format: 'jwk' });
    return signerJwk.kty === 'OKP' && signerJwk.crv === 'Ed25519'
      && typeof signerJwk.x === 'string' && signerJwk.x === pinnedJwk.x;
  } catch {
    return false;
  }
}

function validEd25519Signature(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(value)) return false;
  try {
    const bytes = Buffer.from(value, 'base64url');
    return bytes.length === 64 && bytes.toString('base64url') === value;
  } catch {
    return false;
  }
}

function safeClone<T>(value: T): T {
  return JSON.parse(canonicalize(value)) as T;
}

function unsignedRecord(record: AebEvaluationRecord): Omit<AebEvaluationRecord, 'signature'> {
  const { signature: _signature, ...body } = record;
  return body;
}

function signingBytes(record: AebEvaluationRecord | Omit<AebEvaluationRecord, 'signature'>): Buffer {
  return Buffer.from(`${AEB_EVALUATION_DOMAIN}${canonicalize(unsignedRecord(record as AebEvaluationRecord))}`, 'utf8');
}

function nativeAttestationBody(attestation: AebNativeVerificationAttestation): AebNativeVerificationAttestationBody {
  const { signature: _signature, ...body } = attestation;
  return body;
}

function nativeAttestationSigningBytes(body: AebNativeVerificationAttestationBody): Buffer {
  return Buffer.from(`${AEB_NATIVE_VERIFICATION_ATTESTATION_DOMAIN}${canonicalize(body)}`, 'utf8');
}

/** Sign the exact result emitted by a native verifier or protocol gateway. */
export function signAebNativeVerificationAttestation(
  body: AebNativeVerificationAttestationBody,
  signer: AebNativeVerificationAttestationSigner,
): AebNativeVerificationAttestation {
  if (!exactString(signer?.key_id) || !isEd25519PrivateKey(signer?.private_key)) {
    throw new TypeError('Ed25519 native attestation signer required');
  }
  const detached = safeClone(body);
  const value = crypto.sign(null, nativeAttestationSigningBytes(detached), signer.private_key).toString('base64url');
  return { ...detached, signature: { alg: 'Ed25519', key_id: signer.key_id, value } };
}

const NATIVE_ATTESTATION_KEYS = new Set([
  '@version', 'protocol_id', 'audience', 'native_artifact_ref', 'native_artifact_digest',
  'evidence_role', 'subject', 'verified_at', 'expires_at', 'mapping', 'signature',
]);
const NATIVE_MAPPING_KEYS = new Set([
  'profile_digest', 'mapper_id', 'resolver_digest', 'caid', 'normalized_action_digest',
]);
const NATIVE_SUBJECT_KEYS = new Set(['id', 'kind']);
const NATIVE_SIGNATURE_KEYS = new Set(['alg', 'key_id', 'value']);
const NATIVE_ADAPTER_CONFIG_KEYS = new Set(['audience', 'accepted_protocols']);

function exactKeys(value: Record<string, unknown>, keys: ReadonlySet<string>): boolean {
  return Object.keys(value).length === keys.size && Object.keys(value).every((key) => keys.has(key));
}

function onlyKeys(value: Record<string, unknown>, keys: ReadonlySet<string>): boolean {
  return Object.keys(value).every((key) => keys.has(key));
}

function nativeAttestationShape(value: unknown): value is AebNativeVerificationAttestation {
  if (!isObject(value) || !exactKeys(value, NATIVE_ATTESTATION_KEYS)
      || value['@version'] !== AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION
      || !exactString(value.protocol_id) || !exactString(value.audience)
      || !exactString(value.native_artifact_ref) || !validDigest(value.native_artifact_digest)
      || !validRole(value.evidence_role) || !isObject(value.subject)
      || !exactKeys(value.subject, NATIVE_SUBJECT_KEYS) || !exactString(value.subject.id)
      || !['human', 'workload', 'organization', 'system'].includes(String(value.subject.kind))
      || !Number.isFinite(parseInstant(value.verified_at)) || !Number.isFinite(parseInstant(value.expires_at))
      || parseInstant(value.verified_at) >= parseInstant(value.expires_at)
      || !isObject(value.mapping) || !exactKeys(value.mapping, NATIVE_MAPPING_KEYS)
      || !validDigest(value.mapping.profile_digest) || !exactString(value.mapping.mapper_id)
      || !validDigest(value.mapping.resolver_digest) || typeof value.mapping.caid !== 'string'
      || !CAID_RE.test(value.mapping.caid) || !validDigest(value.mapping.normalized_action_digest)
      || !isObject(value.signature) || !exactKeys(value.signature, NATIVE_SIGNATURE_KEYS)
      || value.signature.alg !== 'Ed25519' || !exactString(value.signature.key_id)
      || !validEd25519Signature(value.signature.value)) return false;
  return true;
}

function nativeAttestationConfig(value: unknown): { audience: string; accepted_protocols: string[] } | null {
  if (!isObject(value) || !exactKeys(value, NATIVE_ADAPTER_CONFIG_KEYS)
      || !exactString(value.audience) || !Array.isArray(value.accepted_protocols)
      || value.accepted_protocols.length === 0
      || value.accepted_protocols.some((item) => !exactString(item))
      || new Set(value.accepted_protocols).size !== value.accepted_protocols.length) return null;
  return { audience: value.audience, accepted_protocols: value.accepted_protocols as string[] };
}

function verifyNativeAttestationSignature(
  attestation: AebNativeVerificationAttestation,
  trustRoots: readonly unknown[],
): boolean {
  const root = trustRoots.find((candidate) => isObject(candidate)
    && candidate.key_id === attestation.signature.key_id && typeof candidate.public_key === 'string');
  if (!isObject(root) || typeof root.public_key !== 'string') return false;
  try {
    const key = ed25519PublicKey(root.public_key);
    return key !== null && crypto.verify(null, nativeAttestationSigningBytes(nativeAttestationBody(attestation)), key,
      Buffer.from(attestation.signature.value, 'base64url'));
  } catch { return false; }
}

/**
 * Concrete bridge for WIMSE, RATS, permit, receipt, and other native verifiers.
 * The bridge verifies a pinned verifier's signed result; presenter assertions
 * and unsigned gateway headers never become evidence.
 */
export function createAebNativeVerificationAttestationAdapter(
  options: { id: string; version: string },
): AebAdapter {
  if (!exactString(options?.id) || !exactString(options?.version)) throw new TypeError('valid adapter id and version required');
  return Object.freeze({
    id: options.id,
    version: options.version,
    verifyNative(input: Omit<AebAdapterInput, 'profile'>): AebNativeResult {
      const evidenceDigest = digest(input.artifact);
      const inputStatusDigest = statusDigest(input.status);
      const fallback: AebNativeResult = {
        native_verification: 'FAILED', acceptance: 'REJECTED', evidence_digest: evidenceDigest,
        status_digest: inputStatusDigest, evidence_role: 'invalid-evidence',
        subject: { id: 'invalid-evidence', kind: 'system' }, replay_unit: evidenceDigest, reasons: [],
      };
      if (!nativeAttestationShape(input.artifact)) {
        fallback.reasons = ['native_attestation_malformed'];
        return fallback;
      }
      fallback.evidence_role = input.artifact.evidence_role;
      fallback.subject = safeClone(input.artifact.subject);
      fallback.replay_unit = digest({
        adapter_id: options.id,
        protocol_id: input.artifact.protocol_id,
        audience: input.artifact.audience,
        native_artifact_ref: input.artifact.native_artifact_ref,
        native_artifact_digest: input.artifact.native_artifact_digest,
        verifier_key_id: input.artifact.signature.key_id,
      });
      const config = nativeAttestationConfig(input.adapter_config);
      if (!config || input.artifact.audience !== config.audience
          || !config.accepted_protocols.includes(input.artifact.protocol_id)) {
        fallback.reasons = ['native_attestation_scope_refused'];
        return fallback;
      }
      if (!verifyNativeAttestationSignature(input.artifact, input.trust_roots)) {
        fallback.reasons = ['native_attestation_signature_invalid'];
        return fallback;
      }
      const now = parseInstant(input.now);
      if (!Number.isFinite(now) || now < parseInstant(input.artifact.verified_at)
          || now > parseInstant(input.artifact.expires_at)) {
        fallback.acceptance = 'INDETERMINATE';
        fallback.reasons = ['native_attestation_outside_validity'];
        return fallback;
      }
      return { ...fallback, native_verification: 'VERIFIED', acceptance: 'ACCEPTED', reasons: [] };
    },
    mapAction(input: AebAdapterInput & { native: AebNativeResult }): AebMappingResult {
      if (input.native.native_verification !== 'VERIFIED' || !nativeAttestationShape(input.artifact)) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_verification_required'] };
      }
      const mapping = input.artifact.mapping;
      const reasons: string[] = [];
      if (mapping.profile_digest !== input.profile.profile_digest) reasons.push('native_mapping_profile_mismatch');
      if (mapping.mapper_id !== input.profile.mapper_id) reasons.push('native_mapper_mismatch');
      if (mapping.resolver_digest !== input.profile.resolver.implementation_digest) reasons.push('native_resolver_mismatch');
      if (reasons.length) return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons };
      return { mapping: 'MATCH', caid: mapping.caid, action_digest: mapping.normalized_action_digest, reasons: [] };
    },
  });
}

function adapterConfigDigest(id: string, pin: AebPinnedAdapter): AebDigest {
  return digest({ adapter_id: id, version: pin.version, trust_roots: pin.trust_roots, config: pin.config ?? null, max_status_age_sec: pin.max_status_age_sec });
}

function profileDigest(id: string, pin: AebPinnedProfile): AebDigest {
  return digest({
    profile_id: id,
    version: pin.version,
    definition: pin.definition ?? null,
    registry_entry_ref: pin.registry_entry_ref,
    mapper_id: pin.mapper_id,
    resolver: pin.resolver,
    semantic_equivalence: pin.semantic_equivalence,
  });
}

function registryEntryDigestInternal(id: string, entry: AebRegistryEntry): AebDigest {
  return digest({
    entry_id: id,
    kind: entry.kind,
    version: entry.version,
    status: entry.status,
    definition: entry.definition,
  });
}

function registryDigestInternal(registry: AebUnifiedRegistry): AebDigest {
  return digest({
    '@version': registry['@version'],
    registry_id: registry.registry_id,
    epoch: registry.epoch,
    entries: registry.entries,
  });
}

export function pinnedConfigDigest(config: AebPinnedConfig): AebDigest {
  return digest(config);
}

export function adapterPinDigest(id: string, pin: AebPinnedAdapter): AebDigest {
  return adapterConfigDigest(id, pin);
}

export function mappingProfileDigest(id: string, pin: AebPinnedProfile): AebDigest {
  return profileDigest(id, pin);
}

export function registryEntryDigest(id: string, entry: AebRegistryEntry): AebDigest {
  return registryEntryDigestInternal(id, entry);
}

export function unifiedRegistryDigest(registry: AebUnifiedRegistry): AebDigest {
  return registryDigestInternal(registry);
}

function statusDigest(status: AebStatusInput): AebDigest {
  return digest({
    checked_at: status.checked_at,
    expires_at: status.expires_at,
    revocation_checked: status.revocation_checked,
    revoked: status.revoked,
    consumed: status.consumed,
    unavailable: status.unavailable === true,
  });
}

function emptyFreshness(status: AebStatusInput, now: string, maxAgeSec: number): AebFreshness {
  const nowMs = parseInstant(now);
  const checkedMs = parseInstant(status.checked_at);
  const expiresMs = parseInstant(status.expires_at);
  const ageSeconds = Number.isFinite(nowMs) && Number.isFinite(checkedMs) ? Math.floor((nowMs - checkedMs) / 1000) : null;
  const fresh = status.unavailable !== true
    && status.revocation_checked === true
    && status.revoked === false
    && status.consumed === false
    && Number.isFinite(nowMs) && Number.isFinite(checkedMs) && Number.isFinite(expiresMs)
    && checkedMs <= nowMs && nowMs < expiresMs
    && ageSeconds !== null && ageSeconds >= 0 && ageSeconds <= maxAgeSec;
  return {
    checked_at: status.checked_at,
    expires_at: status.expires_at,
    revocation_checked: status.revocation_checked === true,
    revoked: status.revoked === true,
    consumed: status.consumed === true,
    unavailable: status.unavailable === true,
    age_seconds: ageSeconds,
    fresh,
  };
}

function freshnessReasons(freshness: AebFreshness, status: AebStatusInput, maxAgeSec: number, now: string): string[] {
  const reasons: string[] = [];
  const nowMs = parseInstant(now);
  const checkedMs = parseInstant(status.checked_at);
  const expiresMs = parseInstant(status.expires_at);
  if (status.unavailable === true) reasons.push('status_unavailable');
  if (status.revoked === true) reasons.push('evidence_revoked');
  if (status.consumed === true) reasons.push('evidence_consumed');
  if (status.revocation_checked !== true) reasons.push('revocation_not_checked');
  if (!Number.isFinite(nowMs) || !Number.isFinite(checkedMs) || !Number.isFinite(expiresMs)) reasons.push('invalid_status_time');
  else {
    if (checkedMs > nowMs) reasons.push('status_checked_in_future');
    if (nowMs >= expiresMs) reasons.push('evidence_expired');
    if (freshness.age_seconds !== null && freshness.age_seconds > maxAgeSec) reasons.push('status_stale');
  }
  return reasons;
}

function validRole(value: unknown): value is string {
  return typeof value === 'string' && ROLE_RE.test(value);
}

function validTextList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string' && item.length > 0 && item.length <= 512)
    && new Set(value).size === value.length;
}

function activeRegistryEntry(config: AebPinnedConfig, id: string, kind: AebRegistryEntryKind): AebRegistryEntry | null {
  const entry = config?.registry?.entries?.[id];
  return entry && entry.kind === kind && entry.status === 'active' ? entry : null;
}

function roleRegistryEntry(config: AebPinnedConfig, role: string): AebRegistryEntry | null {
  const entry = activeRegistryEntry(config, `role:${role}`, 'evidence-role');
  if (!entry || !isObject(entry.definition) || entry.definition.role !== role
      || !Array.isArray(entry.definition.subject_kinds)
      || entry.definition.subject_kinds.length === 0
      || new Set(entry.definition.subject_kinds).size !== entry.definition.subject_kinds.length
      || !entry.definition.subject_kinds.every((kind) => ['human', 'workload', 'organization', 'system'].includes(String(kind)))) return null;
  return entry;
}

const CONFIG_KEYS = new Set(['@version', 'relying_party_id', 'evaluator_keys', 'registry', 'accepted_mappers', 'adapters', 'profiles', 'requirements']);
const REGISTRY_KEYS = new Set(['@version', 'registry_id', 'epoch', 'entries', 'registry_digest']);
const REGISTRY_ENTRY_KEYS = new Set(['kind', 'version', 'status', 'definition', 'definition_digest']);
const ADAPTER_PIN_KEYS = new Set(['version', 'trust_roots', 'config', 'config_digest', 'max_status_age_sec']);
const PROFILE_KEYS = new Set(['version', 'definition', 'registry_entry_ref', 'mapper_id', 'resolver', 'semantic_equivalence', 'profile_digest']);
const RESOLVER_KEYS = new Set(['id', 'version', 'implementation_digest']);
const EQUIVALENCE_KEYS = new Set(['assertion', 'loss_policy', 'omitted_material_fields', 'omitted_nonmaterial_fields']);
const REQUIREMENT_KEYS = new Set(['@version', 'all_of', 'any_of', 'terms']);
const QUORUM_TERM_KEYS = new Set(['type', 'role', 'threshold']);
const EXCLUSION_TERM_KEYS = new Set(['type', 'roles']);
const ONE_TIME_TERM_KEYS = new Set(['type']);
const EVALUATOR_KEY_KEYS = new Set(['public_key']);

function validConfig(config: AebPinnedConfig): string[] {
  const reasons: string[] = [];
  if (!isObject(config) || !exactKeys(config, CONFIG_KEYS) || config['@version'] !== AEB_ADAPTER_VERSION) reasons.push('invalid_config_version');
  if (!exactString(config?.relying_party_id)) reasons.push('invalid_relying_party_id');
  if (!isObject(config?.adapters) || !isObject(config?.profiles) || !isObject(config?.requirements)
      || !isObject(config?.evaluator_keys) || !isObject(config?.registry)) reasons.push('invalid_config_maps');

  const registry = config?.registry;
  if (!isObject(registry) || !exactKeys(registry, REGISTRY_KEYS)
      || registry['@version'] !== AEB_REGISTRY_VERSION || !exactString(registry.registry_id)
      || !Number.isSafeInteger(registry.epoch) || registry.epoch < 1 || !isObject(registry.entries)
      || !validDigest(registry.registry_digest)) {
    reasons.push('invalid_registry');
  } else {
    let expectedRegistryDigest: AebDigest | null = null;
    try { expectedRegistryDigest = registryDigestInternal(registry as unknown as AebUnifiedRegistry); } catch { expectedRegistryDigest = null; }
    if (expectedRegistryDigest !== registry.registry_digest) reasons.push('registry_digest_mismatch');
    for (const [id, rawEntry] of Object.entries(registry.entries)) {
      const entry = rawEntry as unknown as AebRegistryEntry;
      let expectedEntryDigest: AebDigest | null = null;
      try { expectedEntryDigest = isObject(rawEntry) ? registryEntryDigestInternal(id, entry) : null; } catch { expectedEntryDigest = null; }
      if (!exactString(id) || !isObject(rawEntry) || !exactKeys(rawEntry, REGISTRY_ENTRY_KEYS)
          || !['mapping-profile', 'evidence-role', 'receipt-extension'].includes(String(entry.kind))
          || !exactString(entry.version) || !['active', 'deprecated'].includes(String(entry.status))
          || !validDigest(entry.definition_digest) || expectedEntryDigest !== entry.definition_digest) {
        reasons.push(`invalid_registry_entry:${id}`);
      }
    }
  }

  if (!Array.isArray(config?.accepted_mappers) || config.accepted_mappers.length === 0
      || !config.accepted_mappers.every(exactString)
      || new Set(config.accepted_mappers).size !== config.accepted_mappers.length) reasons.push('invalid_accepted_mappers');

  for (const [id, pin] of Object.entries(config?.adapters ?? {})) {
    let pinDigest: AebDigest | null = null;
    try { pinDigest = isObject(pin) ? adapterConfigDigest(id, pin as AebPinnedAdapter) : null; } catch { pinDigest = null; }
    if (!exactString(id) || !isObject(pin) || !onlyKeys(pin, ADAPTER_PIN_KEYS)
        || !exactString(pin.version) || !Array.isArray(pin.trust_roots)
        || !Number.isInteger(pin.max_status_age_sec) || pin.max_status_age_sec < 0
        || !validDigest(pin.config_digest) || pinDigest !== pin.config_digest) reasons.push(`invalid_adapter_pin:${id}`);
  }

  for (const [id, rawPin] of Object.entries(config?.profiles ?? {})) {
    const pin = rawPin as unknown as AebPinnedProfile;
    let pinDigest: AebDigest | null = null;
    try { pinDigest = isObject(rawPin) ? profileDigest(id, pin) : null; } catch { pinDigest = null; }
    if (!exactString(id) || !isObject(rawPin) || !onlyKeys(rawPin, PROFILE_KEYS)
        || !exactString(pin.version) || !validDigest(pin.profile_digest)
        || pinDigest !== pin.profile_digest || !exactString(pin.registry_entry_ref) || !exactString(pin.mapper_id)
        || !isObject(pin.resolver) || !exactKeys(pin.resolver, RESOLVER_KEYS)
        || !exactString(pin.resolver.id) || !exactString(pin.resolver.version)
        || !validDigest(pin.resolver.implementation_digest) || !isObject(pin.semantic_equivalence)
        || !exactKeys(pin.semantic_equivalence, EQUIVALENCE_KEYS)
        || pin.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
        || pin.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
        || !validTextList(pin.semantic_equivalence.omitted_material_fields)
        || !validTextList(pin.semantic_equivalence.omitted_nonmaterial_fields)) reasons.push(`invalid_profile_pin:${id}`);
    if (!config.accepted_mappers?.includes(pin.mapper_id)) reasons.push(`mapper_not_accepted:${id}`);
    if (Array.isArray(pin.semantic_equivalence?.omitted_material_fields)
        && pin.semantic_equivalence.omitted_material_fields.length > 0) reasons.push(`material_information_loss:${id}`);
    const profileEntry = activeRegistryEntry(config, pin.registry_entry_ref, 'mapping-profile');
    if (!profileEntry || !isObject(profileEntry.definition) || profileEntry.definition.profile_digest !== pin.profile_digest) {
      reasons.push(`mapping_profile_not_registered:${id}`);
    }
  }

  for (const [id, rawRequirement] of Object.entries(config?.requirements ?? {})) {
    const requirement = rawRequirement as unknown as AebRequirement;
    const allOfValid = Array.isArray(requirement.all_of) && requirement.all_of.every(validRole)
      && new Set(requirement.all_of).size === requirement.all_of.length;
    const anyOfValid = requirement.any_of === undefined || (Array.isArray(requirement.any_of)
      && requirement.any_of.every((group) => Array.isArray(group) && group.length > 0 && group.every(validRole)
        && new Set(group).size === group.length));
    const rawTerms = Array.isArray(requirement.terms) ? requirement.terms : [];
    const quorumRules = rawTerms.filter((term) => isObject(term) && term.type === 'distinct-human-quorum');
    const exclusionRules = rawTerms.filter((term) => isObject(term) && term.type === 'initiator-exclusion');
    const executorExclusionRules = rawTerms.filter((term) => isObject(term) && term.type === 'executor-exclusion');
    const oneTimeRules = rawTerms.filter((term) => isObject(term) && term.type === 'one-time-consumption');
    const termsValid = Array.isArray(requirement.terms) && requirement.terms.length > 0
      && requirement.terms.every((term) => {
        if (!isObject(term) || !exactString(term.type)) return false;
        if (term.type === 'distinct-human-quorum') {
          return exactKeys(term, QUORUM_TERM_KEYS) && validRole(term.role)
            && typeof term.threshold === 'number' && Number.isSafeInteger(term.threshold) && term.threshold >= 2;
        }
        if (term.type === 'initiator-exclusion' || term.type === 'executor-exclusion') {
          return exactKeys(term, EXCLUSION_TERM_KEYS) && Array.isArray(term.roles) && term.roles.length > 0
            && term.roles.every(validRole) && new Set(term.roles).size === term.roles.length;
        }
        return term.type === 'one-time-consumption' && exactKeys(term, ONE_TIME_TERM_KEYS);
      })
      && new Set(quorumRules.map((term) => term.role)).size === quorumRules.length
      && exclusionRules.length <= 1
      && executorExclusionRules.length <= 1
      && oneTimeRules.length === 1;
    const hasRequirement = (allOfValid && requirement.all_of.length > 0)
      || (Array.isArray(requirement.any_of) && requirement.any_of.length > 0)
      || quorumRules.length > 0;
    if (!exactString(id) || !isObject(rawRequirement) || !onlyKeys(rawRequirement, REQUIREMENT_KEYS)
        || requirement['@version'] !== AEB_REQUIREMENT_VERSION
        || !allOfValid || !anyOfValid || !termsValid || !hasRequirement) reasons.push(`invalid_requirement:${id}`);
    const roles = new Set<string>([
      ...(Array.isArray(requirement.all_of) ? requirement.all_of : []),
      ...(Array.isArray(requirement.any_of) ? requirement.any_of.flat() : []),
      ...quorumRules.map((rule) => String(rule.role)),
      ...exclusionRules.flatMap((rule) => Array.isArray(rule.roles) ? rule.roles.map(String) : []),
      ...executorExclusionRules.flatMap((rule) => Array.isArray(rule.roles) ? rule.roles.map(String) : []),
    ]);
    for (const role of roles) if (!roleRegistryEntry(config, role)) reasons.push(`role_not_registered:${role}`);
  }
  for (const [id, key] of Object.entries(config?.evaluator_keys ?? {})) {
    if (!exactString(id) || !isObject(key) || !exactKeys(key, EVALUATOR_KEY_KEYS)
        || ed25519PublicKey(key.public_key) === null) reasons.push(`invalid_evaluator_key:${id}`);
  }
  return sortedUnique(reasons);
}

function distinctHumanQuorumTerms(requirement: AebRequirement): AebDistinctHumanQuorumTerm[] {
  return requirement.terms.filter((term): term is AebDistinctHumanQuorumTerm => term.type === 'distinct-human-quorum');
}

function initiatorExclusionTerm(requirement: AebRequirement): AebInitiatorExclusionTerm | undefined {
  return requirement.terms.find((term): term is AebInitiatorExclusionTerm => term.type === 'initiator-exclusion');
}

function executorExclusionTerm(requirement: AebRequirement): AebExecutorExclusionTerm | undefined {
  return requirement.terms.find((term): term is AebExecutorExclusionTerm => term.type === 'executor-exclusion');
}

function requiresOneTimeConsumption(requirement: AebRequirement): boolean {
  return requirement.terms.some((term) => term.type === 'one-time-consumption');
}

function requiredRoles(requirement: AebRequirement): Set<string> {
  return new Set([
    ...requirement.all_of,
    ...(requirement.any_of ?? []).flat(),
    ...distinctHumanQuorumTerms(requirement).map((rule) => rule.role),
  ]);
}

function aecRequirementExpression(requirement: AebRequirement): string {
  const terms = [
    ...sortedUnique(requirement.all_of),
    ...(requirement.any_of ?? []).map((group) => `(${sortedUnique(group).join(' OR ')})`),
    ...sortedUnique(distinctHumanQuorumTerms(requirement).map((rule) => rule.role)),
  ];
  return sortedUnique(terms).join(' AND ');
}

function composeWithAec(requirement: AebRequirement, legs: readonly AebEvaluationLeg[], caid: string): {
  engine: typeof AEC_VERSION;
  requirement_expression: string;
  action_digest: AebDigest;
  satisfied: boolean;
  indeterminate: boolean;
  reasons: string[];
} {
  const expression = aecRequirementExpression(requirement);
  const roles = requiredRoles(requirement);
  const relevant = legs.filter((leg) => roles.has(leg.evidence_role));
  const normalizedDigests = new Set(relevant.filter((leg) => leg.verdict === 'SATISFIED' && leg.action_digest !== null)
    .map((leg) => leg.action_digest));
  const normalizedActionDigest = normalizedDigests.size === 1 ? [...normalizedDigests][0] : null;
  const action = { caid, normalized_action_digest: normalizedActionDigest };
  const rawActionDigest = aecActionDigest(action);
  const actionDigest = (rawActionDigest.startsWith('sha256:') ? rawActionDigest : `sha256:${rawActionDigest}`) as AebDigest;
  if (normalizedDigests.size > 1) {
    return {
      engine: AEC_VERSION,
      requirement_expression: expression,
      action_digest: actionDigest,
      satisfied: false,
      indeterminate: false,
      reasons: ['normalized_action_digest_mismatch'],
    };
  }
  if (relevant.some((leg) => leg.verdict === 'SATISFIED' && leg.action_digest === null)) {
    return {
      engine: AEC_VERSION,
      requirement_expression: expression,
      action_digest: actionDigest,
      satisfied: false,
      indeterminate: true,
      reasons: ['normalized_action_digest_missing'],
    };
  }
  const verifiers: Record<string, (evidence: unknown) => { valid: boolean; action_digest: string | null }> = {};
  for (const role of roles) {
    verifiers[role] = (evidence: unknown) => {
      const index = isObject(evidence) && Number.isSafeInteger(evidence.leg_index) ? Number(evidence.leg_index) : -1;
      const leg = relevant[index];
      return { valid: Boolean(leg && leg.evidence_role === role && leg.verdict === 'SATISFIED'), action_digest: leg ? actionDigest : null };
    };
  }
  const result = verifyAuthorizationChain({
    '@version': AEC_VERSION,
    action,
    action_digest: actionDigest,
    components: relevant.map((leg, index) => ({ type: leg.evidence_role, evidence: { leg_index: index } })),
    requirement: expression,
  }, {
    verifiers,
    requirement: expression,
    expectedAction: action,
  });
  return {
    engine: AEC_VERSION,
    requirement_expression: expression,
    action_digest: actionDigest,
    satisfied: result.satisfied === true,
    indeterminate: result.satisfied !== true && relevant.some((leg) => leg.verdict === 'INDETERMINATE'),
    reasons: Array.isArray(result.reasons) ? result.reasons.map(String) : ['aec_composition_failed'],
  };
}

function evaluateAuthorityConstraints(
  requirement: AebRequirement,
  legs: readonly AebEvaluationLeg[],
  initiatorId: string,
  executorId?: string,
): {
  verdict: AebVerdict;
  distinct_human_quorum: boolean;
  initiator_exclusion: boolean;
  executor_exclusion: boolean;
  one_time_consumption: boolean;
  reasons: string[];
} {
  const reasons: string[] = [];
  let indeterminate = false;
  let quorumSatisfied = true;
  for (const rule of distinctHumanQuorumTerms(requirement)) {
    const candidates = legs.filter((leg) => leg.evidence_role === rule.role);
    const satisfiedHumans = candidates.filter((leg) => leg.verdict === 'SATISFIED' && leg.subject?.kind === 'human');
    const distinct = new Set(satisfiedHumans.map((leg) => leg.subject!.id));
    if (distinct.size < rule.threshold) {
      quorumSatisfied = false;
      reasons.push(`quorum_not_met:${rule.role}`);
      if (candidates.some((leg) => leg.verdict === 'INDETERMINATE')) indeterminate = true;
    }
  }
  const excludedRoles = new Set(initiatorExclusionTerm(requirement)?.roles ?? []);
  const selfApprovedRoles = new Set(legs
    .filter((leg) => leg.verdict === 'SATISFIED'
      && excludedRoles.has(leg.evidence_role) && leg.subject?.id === initiatorId)
    .map((leg) => leg.evidence_role));
  const selfApproval = selfApprovedRoles.size > 0;
  if (selfApproval) reasons.push(...[...selfApprovedRoles].map((role) => `initiator_excluded:${role}`));
  const executorRule = executorExclusionTerm(requirement);
  let executorExcluded = true;
  if (executorRule) {
    if (!exactString(executorId)) {
      executorExcluded = false;
      reasons.push('executor_binding_required');
    } else {
      const excludedRoles = new Set(executorRule.roles);
      const executorApprovedRoles = new Set(legs
        .filter((leg) => leg.verdict === 'SATISFIED'
          && excludedRoles.has(leg.evidence_role) && leg.subject?.id === executorId)
        .map((leg) => leg.evidence_role));
      executorExcluded = executorApprovedRoles.size === 0;
      if (!executorExcluded) reasons.push(...[...executorApprovedRoles].map((role) => `executor_excluded:${role}`));
    }
  }
  const oneTime = requiresOneTimeConsumption(requirement);
  if (!oneTime) reasons.push('one_time_consumption_not_required');
  const verdict: AebVerdict = indeterminate ? 'INDETERMINATE'
    : quorumSatisfied && !selfApproval && executorExcluded && oneTime ? 'SATISFIED' : 'UNSATISFIED';
  return {
    verdict,
    distinct_human_quorum: quorumSatisfied,
    initiator_exclusion: !selfApproval,
    executor_exclusion: executorExcluded,
    one_time_consumption: oneTime,
    reasons: sortedUnique(reasons),
  };
}

function deriveEvaluation(options: AebEvaluationOptions): { body: Omit<AebEvaluationRecord, 'signature'>; reasons: string[] } {
  const reasons: string[] = [];
  let configReasons: string[] = [];
  try { configReasons = validConfig(options.config); reasons.push(...configReasons); } catch { configReasons = ['invalid_config']; reasons.push('invalid_config'); }
  if (!exactString(options.operation_id) || !exactString(options.consumption_nonce)) reasons.push('invalid_operation_binding');
  if (!exactString(options.initiator_id)) reasons.push('invalid_initiator_binding');
  if (options.executor_id !== undefined && !exactString(options.executor_id)) reasons.push('invalid_executor_binding');
  if (!exactString(options.requirement_ref) || !exactString(options.caid) || !CAID_RE.test(options.caid)) reasons.push('invalid_action_binding');
  if (!Number.isFinite(parseInstant(options.evaluated_at))) reasons.push('invalid_evaluated_at');
  const requirement = options.config?.requirements?.[options.requirement_ref];
  if (!requirement) reasons.push('requirement_not_pinned');
  let requirementDigest: AebDigest = 'sha256:' + '0'.repeat(64) as AebDigest;
  try { requirementDigest = digest(requirement); } catch { reasons.push('requirement_not_canonicalizable'); }

  const legs: AebEvaluationLeg[] = [];
  for (const input of options.legs ?? []) {
    const adapterPin = options.config?.adapters?.[input.adapter_id];
    const profile = options.config?.profiles?.[input.profile_id];
    const adapter = options.adapters?.[input.adapter_id];
    const base: AebEvaluationLeg = {
      adapter_id: input.adapter_id,
      adapter_version: adapterPin?.version ?? '',
      profile_id: input.profile_id,
      profile_version: profile?.version ?? '',
      profile_digest: profile?.profile_digest ?? ('sha256:' + '0'.repeat(64)) as AebDigest,
      artifact_ref: input.artifact_ref,
      evidence_digest: ('sha256:' + '0'.repeat(64)) as AebDigest,
      status_digest: ('sha256:' + '0'.repeat(64)) as AebDigest,
      replay_unit: ('sha256:' + '0'.repeat(64)) as AebDigest,
      evidence_role: '',
      subject: null,
      mapper_id: profile?.mapper_id ?? '',
      resolver_digest: profile?.resolver?.implementation_digest ?? ('sha256:' + '0'.repeat(64)) as AebDigest,
      native_verification: 'FAILED',
      acceptance: 'INDETERMINATE',
      mapping: 'INDETERMINATE',
      action_digest: null,
      caid: null,
      freshness: emptyFreshness(input.status, options.evaluated_at, adapterPin?.max_status_age_sec ?? 0),
      verdict: 'INDETERMINATE',
      reasons: [],
    };
    if (!adapterPin || !profile || !adapter) {
      base.reasons = ['adapter_or_profile_not_pinned'];
      legs.push(base);
      continue;
    }
    if (adapter.id !== input.adapter_id || adapter.version !== adapterPin.version) {
      base.reasons = ['adapter_version_not_registered'];
      legs.push(base);
      continue;
    }
    if (profile.profile_digest !== profileDigest(input.profile_id, profile)) {
      base.reasons = ['mapping_profile_digest_mismatch'];
      legs.push(base);
      continue;
    }
    try {
      // Adapters receive only a detached copy of relying-party-pinned data.
      // A presenter cannot supply it and adapter code cannot mutate the config
      // object used to re-derive the evaluation.
      const artifact = deepFreeze(safeClone(input.artifact));
      const status = deepFreeze(safeClone(input.status));
      const trustRoots = deepFreeze(safeClone(adapterPin.trust_roots));
      const profileInput = deepFreeze(safeClone(profile));
      const expectedAction = deepFreeze(JSON.parse(canonicalize(options.expected_action ?? null)) as unknown);
      const adapterConfig = deepFreeze(JSON.parse(canonicalize(adapterPin.config ?? null)) as unknown);
      base.evidence_digest = digest(artifact);
      base.status_digest = statusDigest(status);
      const native = adapter.verifyNative({
        artifact,
        artifact_ref: input.artifact_ref,
        status,
        trust_roots: trustRoots,
        adapter_config: adapterConfig,
        expected_action: expectedAction,
        now: options.evaluated_at,
      });
      if (!isObject(native) || !validDigest(native.evidence_digest) || native.evidence_digest !== base.evidence_digest
          || !validDigest(native.status_digest) || native.status_digest !== base.status_digest
          || !validDigest(native.replay_unit)
          || (native.native_verification !== 'VERIFIED' && native.native_verification !== 'FAILED')
          || !['ACCEPTED', 'REJECTED', 'INDETERMINATE'].includes(native.acceptance)
          || !validRole(native.evidence_role) || !isObject(native.subject) || !exactString(native.subject.id)
          || !['human', 'workload', 'organization', 'system'].includes(String(native.subject.kind))
          || !Array.isArray(native.reasons)) {
        base.reasons = ['malformed_native_result'];
        legs.push(base);
        continue;
      }
      base.native_verification = native.native_verification;
      base.acceptance = native.acceptance;
      base.evidence_role = native.evidence_role;
      base.subject = { id: native.subject.id, kind: native.subject.kind };
      base.replay_unit = native.replay_unit;
      base.reasons.push(...native.reasons);
      const roleEntry = roleRegistryEntry(options.config, native.evidence_role);
      const allowedSubjectKinds = roleEntry && isObject(roleEntry.definition) && Array.isArray(roleEntry.definition.subject_kinds)
        ? roleEntry.definition.subject_kinds.map(String) : [];
      const roleAccepted = Boolean(roleEntry && allowedSubjectKinds.includes(native.subject.kind));
      if (!roleAccepted) base.reasons.push('evidence_role_not_registered_or_subject_kind_refused');
      const freshnessIssues = freshnessReasons(base.freshness, status, adapterPin.max_status_age_sec, options.evaluated_at);
      base.reasons.push(...freshnessIssues);
      const mapping = adapter.mapAction({
        artifact,
        artifact_ref: input.artifact_ref,
        status,
        trust_roots: trustRoots,
        adapter_config: adapterConfig,
        profile: profileInput,
        expected_action: expectedAction,
        now: options.evaluated_at,
        native,
      });
      if (!isObject(mapping) || !['MATCH', 'MISMATCH', 'INDETERMINATE'].includes(mapping.mapping)
          || (mapping.caid !== null && typeof mapping.caid !== 'string')
          || (mapping.action_digest !== null && !validDigest(mapping.action_digest))
          || !Array.isArray(mapping.reasons)) {
        base.reasons.push('malformed_mapping_result');
      } else {
        base.mapping = mapping.mapping;
        base.caid = mapping.caid;
        base.action_digest = mapping.action_digest;
        base.reasons.push(...mapping.reasons);
        if (mapping.mapping === 'MATCH' && mapping.action_digest === null) base.reasons.push('normalized_action_digest_missing');
        if (options.expected_action !== undefined && mapping.action_digest !== digest(expectedAction)) {
          base.mapping = 'MISMATCH';
          base.reasons.push('expected_action_digest_mismatch', 'normalized_action_digest_mismatch');
        }
      }
      const hardFailure = base.native_verification === 'FAILED' || base.acceptance === 'REJECTED'
        || base.mapping === 'MISMATCH' || base.freshness.revoked || base.freshness.consumed
        || !roleAccepted
        || (Number.isFinite(parseInstant(options.evaluated_at)) && Number.isFinite(parseInstant(base.freshness.expires_at))
          && parseInstant(options.evaluated_at) >= parseInstant(base.freshness.expires_at));
      const unknown = base.acceptance === 'INDETERMINATE' || base.mapping === 'INDETERMINATE'
        || (base.mapping === 'MATCH' && base.action_digest === null)
        || !base.freshness.fresh || freshnessIssues.some((reason) => !['evidence_revoked', 'evidence_consumed', 'evidence_expired'].includes(reason));
      if (hardFailure) base.verdict = 'UNSATISFIED';
      else if (unknown || base.native_verification !== 'VERIFIED' || base.mapping !== 'MATCH' || base.caid !== options.caid) base.verdict = 'INDETERMINATE';
      else base.verdict = 'SATISFIED';
      if (base.caid !== null && base.caid !== options.caid && base.mapping === 'MATCH') {
        base.verdict = 'UNSATISFIED';
        base.reasons.push('caid_mismatch');
      }
    } catch {
      base.reasons.push('adapter_evaluation_error');
    }
    base.reasons = sortedUnique(base.reasons);
    legs.push(base);
  }
  const zero = ('sha256:' + '0'.repeat(64)) as AebDigest;
  let composition: AebEvaluationRecord['composition'] = {
    engine: AEC_VERSION,
    requirement_expression: requirement ? aecRequirementExpression(requirement) : '',
    action_digest: zero,
    satisfied: false,
  };
  let authorityConstraints = {
    distinct_human_quorum: false,
    initiator_exclusion: false,
    executor_exclusion: false,
    one_time_consumption: false,
  };
  let aggregate: { verdict: AebVerdict; reasons: string[] } = {
    verdict: 'INDETERMINATE', reasons: ['cannot_evaluate_unpinned_requirement'],
  };
  if (requirement && configReasons.length === 0) {
    const composed = composeWithAec(requirement, legs, options.caid);
    const constrained = evaluateAuthorityConstraints(requirement, legs, options.initiator_id, options.executor_id);
    composition = {
      engine: composed.engine,
      requirement_expression: composed.requirement_expression,
      action_digest: composed.action_digest,
      satisfied: composed.satisfied,
    };
    authorityConstraints = {
      distinct_human_quorum: constrained.distinct_human_quorum,
      initiator_exclusion: constrained.initiator_exclusion,
      executor_exclusion: constrained.executor_exclusion,
      one_time_consumption: constrained.one_time_consumption,
    };
    const verdict: AebVerdict = composed.satisfied && constrained.verdict === 'SATISFIED' ? 'SATISFIED'
      : composed.indeterminate || constrained.verdict === 'INDETERMINATE' ? 'INDETERMINATE' : 'UNSATISFIED';
    aggregate = {
      verdict,
      reasons: sortedUnique([
        ...(!composed.satisfied && !composed.indeterminate ? composed.reasons : []),
        ...constrained.reasons,
      ]),
    };
  }
  let configDigest: AebDigest = ('sha256:' + '0'.repeat(64)) as AebDigest;
  try { configDigest = pinnedConfigDigest(options.config); } catch { reasons.push('config_not_canonicalizable'); }
  let evidenceDigest: AebDigest = ('sha256:' + '0'.repeat(64)) as AebDigest;
  try { evidenceDigest = digest(legs); } catch { reasons.push('evaluation_not_canonicalizable'); }
  const body: Omit<AebEvaluationRecord, 'signature'> = {
    '@type': AEB_EVALUATION_VERSION,
    operation_id: options.operation_id,
    consumption_nonce: options.consumption_nonce,
    initiator_id: options.initiator_id,
    ...(options.executor_id !== undefined ? { executor_id: options.executor_id } : {}),
    evaluator: { id: options.config?.relying_party_id ?? '', key_id: options.signer?.key_id ?? options.evaluator_key_id ?? '', pinned_config_digest: configDigest },
    requirement_ref: options.requirement_ref,
    requirement_digest: requirementDigest,
    registry_digest: validDigest(options.config?.registry?.registry_digest) ? options.config.registry.registry_digest : zero,
    caid: options.caid,
    legs,
    composition,
    authority_constraints: authorityConstraints,
    verdict: aggregate.verdict,
    evaluated_at: options.evaluated_at,
    evidence_digest: evidenceDigest,
    reasons: sortedUnique([...reasons, ...aggregate.reasons, ...legs.flatMap((leg) => leg.reasons)]),
  };
  return { body, reasons: body.reasons };
}

export function evaluateAebEvidence(options: AebEvaluationOptions): AebEvaluationResult {
  try {
    const { body } = deriveEvaluation(options);
    const record: AebEvaluationRecord = safeClone(body) as AebEvaluationRecord;
    if (options.signer) {
      const pinnedKey = options.config.evaluator_keys?.[options.signer.key_id]?.public_key;
      if (pinnedKey === undefined) {
        record.reasons = sortedUnique([...record.reasons, 'evaluator_key_not_pinned']);
      } else if (!isEd25519PrivateKey(options.signer.private_key)) {
        record.reasons = sortedUnique([...record.reasons, 'evaluator_signer_not_ed25519']);
      } else {
        const publicKey = ed25519PublicKey(pinnedKey);
        if (!publicKey || !privateKeyMatchesPublicKey(options.signer.private_key, publicKey)) {
          record.reasons = sortedUnique([...record.reasons, 'evaluator_signer_key_mismatch']);
        } else {
          const signature = crypto.sign(null, signingBytes(body), options.signer.private_key).toString('base64url');
          record.signature = { alg: 'Ed25519', key_id: options.signer.key_id, value: signature };
        }
      }
    } else {
      record.reasons = sortedUnique([...record.reasons, 'evaluation_signature_required']);
    }
    return { record, valid: record.verdict === 'SATISFIED' && Boolean(record.signature) && record.reasons.length === 0, reasons: record.reasons };
  } catch {
    const zero = ('sha256:' + '0'.repeat(64)) as AebDigest;
    const record: AebEvaluationRecord = {
      '@type': AEB_EVALUATION_VERSION,
      operation_id: typeof options?.operation_id === 'string' ? options.operation_id : '',
      consumption_nonce: typeof options?.consumption_nonce === 'string' ? options.consumption_nonce : '',
      initiator_id: typeof options?.initiator_id === 'string' ? options.initiator_id : '',
      ...(typeof options?.executor_id === 'string' ? { executor_id: options.executor_id } : {}),
      evaluator: { id: '', key_id: '', pinned_config_digest: zero },
      requirement_ref: typeof options?.requirement_ref === 'string' ? options.requirement_ref : '',
      requirement_digest: zero,
      registry_digest: zero,
      caid: typeof options?.caid === 'string' ? options.caid : '',
      legs: [],
      composition: { engine: AEC_VERSION, requirement_expression: '', action_digest: zero, satisfied: false },
      authority_constraints: {
        distinct_human_quorum: false,
        initiator_exclusion: false,
        executor_exclusion: false,
        one_time_consumption: false,
      },
      verdict: 'INDETERMINATE', evaluated_at: typeof options?.evaluated_at === 'string' ? options.evaluated_at : '',
      evidence_digest: zero, reasons: ['evaluation_error'],
    };
    return { record, valid: false, reasons: record.reasons };
  }
}

function shapeValid(record: unknown): record is AebEvaluationRecord {
  if (!isObject(record) || record['@type'] !== AEB_EVALUATION_VERSION || !exactString(record.operation_id)
      || !exactString(record.consumption_nonce) || !exactString(record.initiator_id)
      || (record.executor_id !== undefined && !exactString(record.executor_id)) || !isObject(record.evaluator)
      || !exactString(record.evaluator.id) || !exactString(record.evaluator.key_id) || !validDigest(record.evaluator.pinned_config_digest)
      || !exactString(record.requirement_ref) || !validDigest(record.requirement_digest) || !validDigest(record.registry_digest) || !exactString(record.caid)
      || typeof record.caid !== 'string' || !CAID_RE.test(record.caid) || !Array.isArray(record.legs) || typeof record.verdict !== 'string' || !['SATISFIED', 'UNSATISFIED', 'INDETERMINATE'].includes(record.verdict)
      || !isObject(record.composition) || record.composition.engine !== AEC_VERSION || typeof record.composition.requirement_expression !== 'string'
      || !validDigest(record.composition.action_digest) || typeof record.composition.satisfied !== 'boolean'
      || !isObject(record.authority_constraints) || typeof record.authority_constraints.distinct_human_quorum !== 'boolean'
      || typeof record.authority_constraints.initiator_exclusion !== 'boolean'
      || typeof record.authority_constraints.executor_exclusion !== 'boolean'
      || typeof record.authority_constraints.one_time_consumption !== 'boolean'
      || !Number.isFinite(parseInstant(record.evaluated_at)) || !validDigest(record.evidence_digest) || !Array.isArray(record.reasons)
      || !isObject(record.signature) || record.signature.alg !== 'Ed25519' || record.signature.key_id !== record.evaluator.key_id
      || !validEd25519Signature(record.signature.value)) return false;
  return true;
}

function verifyAebEvaluationInner(record: unknown, options: AebVerificationOptions): AebEvaluationVerification {
  const mode = options.mode
    ?? (options.now !== undefined || options.current_statuses !== undefined ? 'execution' : 'historical');
  const checks = {
    schema: shapeValid(record),
    signature: false,
    pinned_config: false,
    rederived: false,
    current_status: mode === 'historical',
    verdict: false,
  };
  const reasons: string[] = [];
  if (!checks.schema) {
    return { valid: false, execution_authorizing: false, checks, reasons: ['malformed_evaluation_record'] };
  }
  if (mode !== 'execution' && mode !== 'historical') {
    return { valid: false, execution_authorizing: false, checks, reasons: ['verification_mode_invalid'] };
  }
  const typed = record as AebEvaluationRecord;
  if (mode === 'execution') {
    if (options.expected_action === undefined) reasons.push('expected_action_required');
    if (options.now === undefined) {
      reasons.push('execution_now_required');
    } else {
      const nowMs = parseInstant(options.now);
      const evaluatedMs = parseInstant(typed.evaluated_at);
      if (!Number.isFinite(nowMs)) {
        reasons.push('execution_now_invalid');
      } else if (!Number.isFinite(evaluatedMs) || evaluatedMs > nowMs) {
        reasons.push('evaluation_time_in_future');
      }
      checks.current_status = Number.isFinite(nowMs);
      for (const leg of typed.legs) {
        const status = options.current_statuses?.[leg.artifact_ref];
        const pin = options.config.adapters?.[leg.adapter_id];
        if (!status || !pin) {
          checks.current_status = false;
          reasons.push(`current_status_unavailable:${leg.artifact_ref}`);
          continue;
        }
        const current = emptyFreshness(status, options.now, pin.max_status_age_sec);
        if (!current.fresh) {
          checks.current_status = false;
          if (status.revoked === true) reasons.push(`current_status_revoked:${leg.artifact_ref}`);
          else if (status.consumed === true) reasons.push(`current_status_consumed:${leg.artifact_ref}`);
          else reasons.push(`current_status_not_fresh:${leg.artifact_ref}`);
        }
      }
    }
  }
  const configErrors = validConfig(options.config);
  checks.pinned_config = configErrors.length === 0
    && typed.evaluator.pinned_config_digest === pinnedConfigDigest(options.config)
    && typed.registry_digest === options.config.registry.registry_digest;
  if (!checks.pinned_config) reasons.push('pinned_config_mismatch');
  const key = options.config.evaluator_keys?.[typed.signature!.key_id]?.public_key;
  const keyObject = ed25519PublicKey(key);
  if (keyObject) {
    try {
      checks.signature = crypto.verify(null, signingBytes(typed), keyObject, Buffer.from(typed.signature!.value, 'base64url'));
    } catch { checks.signature = false; }
  }
  if (!checks.signature) reasons.push('evaluation_signature_invalid');
  const legs: AebEvidenceLegInput[] = [];
  for (const leg of typed.legs) {
    const artifact = options.artifacts?.[leg.artifact_ref];
    if (artifact === undefined) { reasons.push(`artifact_missing:${leg.artifact_ref}`); continue; }
    const pin = options.config.adapters?.[leg.adapter_id];
    const profile = options.config.profiles?.[leg.profile_id];
    const status: AebStatusInput = {
      checked_at: leg.freshness.checked_at,
      expires_at: leg.freshness.expires_at,
      revocation_checked: leg.freshness.revocation_checked,
      revoked: leg.freshness.revoked,
      consumed: leg.freshness.consumed,
      ...(leg.freshness.unavailable ? { unavailable: true } : {}),
    };
    if (!pin || !profile || !validDigest(leg.profile_digest) || leg.profile_digest !== profile.profile_digest) {
      reasons.push(`leg_pin_mismatch:${leg.artifact_ref}`);
      continue;
    }
    legs.push({ adapter_id: leg.adapter_id, profile_id: leg.profile_id, artifact_ref: leg.artifact_ref, artifact, status });
  }
  const derived = deriveEvaluation({
    config: options.config,
    adapters: options.adapters,
    operation_id: typed.operation_id,
    consumption_nonce: typed.consumption_nonce,
    initiator_id: typed.initiator_id,
    ...(typed.executor_id !== undefined ? { executor_id: typed.executor_id } : {}),
    requirement_ref: typed.requirement_ref,
    caid: typed.caid,
    ...(options.expected_action !== undefined ? { expected_action: options.expected_action } : {}),
    legs,
    evaluated_at: typed.evaluated_at,
    evaluator_key_id: typed.evaluator.key_id,
  });
  const derivedRecord = derived.body;
  checks.rederived = reasons.every((reason) => !reason.startsWith('artifact_missing:') && !reason.startsWith('leg_pin_mismatch:'))
    && canonicalize(unsignedRecord(typed)) === canonicalize(derivedRecord);
  checks.verdict = typed.verdict === derivedRecord.verdict;
  if (!checks.rederived) reasons.push('evaluation_not_rederivable');
  if (!checks.verdict) reasons.push('verdict_mismatch');
  const valid = Object.values(checks).every(Boolean)
    && !reasons.includes('expected_action_required')
    && !reasons.includes('execution_now_required')
    && !reasons.includes('execution_now_invalid')
    && !reasons.includes('evaluation_time_in_future');
  return {
    valid,
    execution_authorizing: valid && mode === 'execution',
    checks,
    reasons: sortedUnique(reasons),
  };
}

export function verifyAebEvaluation(record: unknown, options: AebVerificationOptions): AebEvaluationVerification {
  try {
    return verifyAebEvaluationInner(record, options);
  } catch {
    return {
      valid: false,
      execution_authorizing: false,
      checks: { schema: false, signature: false, pinned_config: false, rederived: false, current_status: false, verdict: false },
      reasons: ['evaluation_verification_error'],
    };
  }
}

export function authorizeAebExecution(
  record: AebEvaluationRecord,
  options: {
    verification: Pick<AebEvaluationVerification, 'valid' | 'execution_authorizing'>;
    local_authorization: boolean;
    store: AebConsumptionStore;
  },
): AebExecutionDecision {
  const reservationKey = aebReservationKey(record);
  if (options.verification?.valid !== true) return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'evaluation_not_verified' };
  if (options.verification.execution_authorizing !== true) return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'execution_verification_required' };
  if (record.verdict === 'INDETERMINATE') return { allowed: false, invoke_allowed: false, state: 'RECONCILIATION_REQUIRED', reason: 'evidence_indeterminate' };
  if (record.verdict !== 'SATISFIED') return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'evidence_requirement_not_satisfied' };
  if (record.authority_constraints?.one_time_consumption !== true) return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'one_time_consumption_not_required' };
  if (!options.local_authorization) return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'local_authorization_denied' };
  if (!options.store.reserve(reservationKey, aebNativeReplayKeys(record))) {
    return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'consumption_conflict' };
  }
  return { allowed: true, invoke_allowed: true, state: 'AUTHORIZED', reason: 'reserved_for_execution', reservation_key: reservationKey };
}

/** Stable native approval identities that must be fenced with the operation reservation. */
export function aebNativeReplayKeys(record: Pick<AebEvaluationRecord, 'evaluator' | 'legs'>): string[] {
  return sortedUnique(record.legs.map((leg) => `aeb-native:${digest({
    relying_party_id: record.evaluator.id,
    replay_unit: leg.replay_unit,
  })}`));
}

/** Collision-resistant, tenant-scoped key used by both reference and durable stores. */
export function aebReservationKey(record: Pick<AebEvaluationRecord,
  'evaluator' | 'composition' | 'caid' | 'operation_id' | 'consumption_nonce'>): string {
  return `aeb:${digest({
    relying_party_id: record.evaluator.id,
    config_digest: record.evaluator.pinned_config_digest,
    caid: record.caid,
    normalized_action_digest: record.composition.action_digest,
    operation_id: record.operation_id,
    consumption_nonce: record.consumption_nonce,
  })}`;
}

export function reconcileAebExecution(
  store: AebConsumptionStore,
  reservationKey: string,
  outcome: 'COMMITTED' | 'NOT_COMMITTED' | 'INDETERMINATE',
): { state: 'CONSUMED' | 'AVAILABLE' | 'RECONCILIATION_REQUIRED'; retry_allowed: boolean; reason: string } {
  if (outcome === 'COMMITTED') {
    return store.commit(reservationKey)
      ? { state: 'CONSUMED', retry_allowed: false, reason: 'execution_committed' }
      : { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'reservation_not_open' };
  }
  if (outcome === 'NOT_COMMITTED') {
    return store.release(reservationKey)
      ? { state: 'AVAILABLE', retry_allowed: true, reason: 'execution_not_committed' }
      : { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'reservation_not_open' };
  }
  return { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'execution_outcome_indeterminate' };
}

function secureDurableStore(store: unknown): store is AebDurableConsumptionStore {
  return isObject(store) && store.durable === true && store.ownershipFenced === true
    && store.permanentConsumption === true && store.atomicReplayFenced === true && typeof store.reserve === 'function'
    && typeof store.commit === 'function' && typeof store.release === 'function';
}

/** Production authorization path for shared Postgres/Redis/DynamoDB-backed custody. */
export async function authorizeAebExecutionDurable(
  record: AebEvaluationRecord,
  options: {
    verification: Pick<AebEvaluationVerification, 'valid' | 'execution_authorizing'>;
    local_authorization: boolean;
    store: unknown;
  },
): Promise<AebExecutionDecision> {
  const reservationKey = aebReservationKey(record);
  if (options.verification?.valid !== true) return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'evaluation_not_verified' };
  if (options.verification.execution_authorizing !== true) return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'execution_verification_required' };
  if (record.verdict === 'INDETERMINATE') return { allowed: false, invoke_allowed: false, state: 'RECONCILIATION_REQUIRED', reason: 'evidence_indeterminate' };
  if (record.verdict !== 'SATISFIED') return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'evidence_requirement_not_satisfied' };
  if (record.authority_constraints?.one_time_consumption !== true) return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'one_time_consumption_not_required' };
  if (!options.local_authorization) return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'local_authorization_denied' };
  if (!secureDurableStore(options.store)) return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'secure_consumption_store_required' };
  try {
    const reservation = await options.store.reserve(reservationKey, aebNativeReplayKeys(record));
    if (reservation !== true && reservation !== 'RESERVED') {
      return {
        allowed: false,
        invoke_allowed: false,
        state: 'REFUSED',
        reason: reservation === 'NATIVE_REPLAY_CONFLICT' ? 'native_replay_conflict' : 'consumption_conflict',
      };
    }
  } catch {
    return { allowed: false, invoke_allowed: false, state: 'REFUSED', reason: 'consumption_store_unavailable' };
  }
  return { allowed: true, invoke_allowed: true, state: 'AUTHORIZED', reason: 'reserved_for_execution', reservation_key: reservationKey };
}

export async function reconcileAebExecutionDurable(
  store: unknown,
  reservationKey: string,
  outcome: 'COMMITTED' | 'NOT_COMMITTED' | 'INDETERMINATE',
): Promise<{ state: 'CONSUMED' | 'AVAILABLE' | 'RECONCILIATION_REQUIRED'; retry_allowed: boolean; reason: string }> {
  if (!secureDurableStore(store)) return { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'secure_consumption_store_required' };
  if (outcome === 'INDETERMINATE') return { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'execution_outcome_indeterminate' };
  try {
    if (outcome === 'COMMITTED') {
      return await store.commit(reservationKey) === true
        ? { state: 'CONSUMED', retry_allowed: false, reason: 'execution_committed' }
        : { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'reservation_not_open' };
    }
    return await store.release(reservationKey) === true
      ? { state: 'AVAILABLE', retry_allowed: true, reason: 'execution_not_committed' }
      : { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'reservation_not_open' };
  } catch {
    return { state: 'RECONCILIATION_REQUIRED', retry_allowed: false, reason: 'consumption_store_unavailable' };
  }
}

export { canonicalize as canonicalizeAeb, digest as digestAeb };
