// SPDX-License-Identifier: Apache-2.0
/**
 * EP-PORTABLE-STATE-HANDOFF-v0.1.
 *
 * Carrier-neutral, recipient-bound transfer of a declared state set. The
 * protocol authenticates a source assertion, verifies source-side EP release
 * evidence, and requires one recipient-local atomic transition that consumes
 * exact import authority and commits state together. Payload bytes never carry
 * reusable authority.
 */
import crypto from 'node:crypto';

// The package build does not emit a declaration for the governed JS module;
// every returned field is checked below before it enters the typed boundary.
// @ts-ignore -- package-local tsc has no declaration; root checkJs infers one.
import { computeCaid } from '../vendor/caid.mjs';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  type AgileAlgorithm,
  type AgileSignature,
  type AgileSigningKey,
  type AgileVerificationKey,
  type AgilityOptions,
} from './pq-signature-agility.js';
import { canonicalizeStrictJson } from './strict-json.js';

export const PORTABLE_STATE_PROFILE = 'EP-PORTABLE-STATE-HANDOFF-v0.1';
export const PORTABLE_STATE_MANIFEST_VERSION = 'EP-STATE-HANDOFF-MANIFEST-v0.1';
export const PORTABLE_STATE_IMPORT_RECEIPT_VERSION = 'EP-STATE-HANDOFF-IMPORT-RECEIPT-v0.1';
export const PORTABLE_STATE_AUTHORITY_PROFILE = 'EP-STATE-HANDOFF-AUTHORITY-v0.1';
export const PORTABLE_STATE_SIGNATURE_PROFILE = 'EP-SIG-AGILITY-v1';
export const PORTABLE_STATE_LIMITS = Object.freeze({
  max_objects: 4096,
  max_reasons: 256,
  max_depth: 64,
  max_nodes: 100_000,
  max_string_bytes: 16 * 1024 * 1024,
});

export const PORTABLE_STATE_ACTIONS = Object.freeze({
  EXPORT: 'agent.state.export.1',
  IMPORT: 'agent.state.import.1',
  KEY_RELEASE: 'agent.state.key-release.1',
  RETIRE_SOURCE: 'agent.state.retire-source.1',
} as const);

const MANIFEST_DOMAIN = `${PORTABLE_STATE_MANIFEST_VERSION}\0`;
const RECEIPT_DOMAIN = `${PORTABLE_STATE_IMPORT_RECEIPT_VERSION}\0`;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RFC3339_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/;
const ALLOWED_SIGNATURE_POLICIES = [
  ['Ed25519'],
  ['Ed25519', 'ML-DSA-65'],
] as const;

type Obj = Record<string, unknown>;
export type StateDigest = `sha256:${string}`;
export type StateSensitivity = 'OPEN' | 'PROTECTED' | 'VAULT';
export type StateDisposition = 'ACTIVE' | 'TOMBSTONE';
export type StateImportResult = 'ACCEPTED' | 'PARTIAL' | 'REFUSED' | 'INDETERMINATE';
export type StateActionType = (typeof PORTABLE_STATE_ACTIONS)[keyof typeof PORTABLE_STATE_ACTIONS];

export interface StateSignaturePolicy {
  profile: typeof PORTABLE_STATE_SIGNATURE_PROFILE;
  required_algorithms: AgileAlgorithm[];
}

export interface StateObjectDescriptor {
  position: number;
  object_id: string;
  object_digest: StateDigest;
  media_type: string;
  schema_uri: string;
  required: boolean;
  snapshot_at: string;
  sensitivity: StateSensitivity;
  disposition: StateDisposition;
  generation: number;
  predecessor_digest: StateDigest | null;
}

export interface PortableStateManifest {
  '@version': typeof PORTABLE_STATE_MANIFEST_VERSION;
  handoff_id: string;
  transfer_mode: 'COPY';
  payload_profile: string;
  source_agent: string;
  source_boundary_id: string;
  recipient_agent: string;
  recipient_boundary_id: string;
  relying_party_id: string;
  created_at: string;
  snapshot_at: string;
  expires_at: string;
  nonce: string;
  index: {
    ordered_object_ids: string[];
    index_digest: StateDigest;
  };
  objects: StateObjectDescriptor[];
  scope_digest: StateDigest;
  authority: {
    profile: typeof PORTABLE_STATE_AUTHORITY_PROFILE;
    source_actions: StateActionType[];
    recipient_action: typeof PORTABLE_STATE_ACTIONS.IMPORT;
  };
  nonclaims: {
    source_truth: 'NOT_ESTABLISHED';
    authority_transfer: 'PROHIBITED';
    source_population_completeness: 'NOT_ESTABLISHED';
    physical_erasure: 'NOT_ESTABLISHED';
    trusted_time: 'NOT_ESTABLISHED';
  };
  signature_policy: StateSignaturePolicy;
  signatures: AgileSignature[];
}

export interface PortableStateBundle {
  manifest: PortableStateManifest;
  objects: unknown[];
  source_authority_evidence: Partial<Record<StateActionType, unknown>>;
}

export interface StateActionObject {
  action_type: StateActionType;
  handoff_id: string;
  manifest_digest: StateDigest;
  payload_profile: string;
  transfer_mode: 'COPY';
  source_agent: string;
  source_boundary_id: string;
  recipient_agent: string;
  recipient_boundary_id: string;
  relying_party_id: string;
  scope_digest: StateDigest;
  expires_at: string;
  nonce: string;
  vault_set_digest?: StateDigest;
  import_receipt_digest?: StateDigest;
  retirement_set_digest?: StateDigest;
}

export interface StateActionExpectation {
  profile: typeof PORTABLE_STATE_AUTHORITY_PROFILE;
  action_object: StateActionObject;
  caid: string;
  action_digest: StateDigest;
}

export interface StateAuthorityEvidenceRecord {
  stage: 'SOURCE_RELEASE' | 'RECIPIENT_COMMIT';
  action: StateActionType;
  caid: string;
  receipt_digest: StateDigest;
}

export interface PortableStateImportReceipt {
  '@version': typeof PORTABLE_STATE_IMPORT_RECEIPT_VERSION;
  receipt_kind: 'INITIAL' | 'RECONCILIATION';
  handoff_id: string;
  manifest_digest: StateDigest;
  payload_profile: string;
  importer_boundary_id: string;
  result: StateImportResult;
  accepted_object_ids: string[];
  unavailable_objects: Array<{ object_id: string; reason: string }>;
  reasons: string[];
  authority_evidence: StateAuthorityEvidenceRecord[];
  admission_record_digest: StateDigest | null;
  completed_at: string;
  issued_at: string;
  nonclaims: PortableStateManifest['nonclaims'];
  signature_policy: StateSignaturePolicy;
  signatures: AgileSignature[];
}

export interface ArtifactSigner {
  principal_id: string;
  policy: StateSignaturePolicy;
  keys: AgileSigningKey[];
  agility?: AgilityOptions;
}

export interface ArtifactSignerPin extends AgileVerificationKey {
  key_id: string;
  status: 'active' | 'revoked';
  principals: string[];
  valid_from: string;
  valid_until: string;
}

export interface StatePayloadAdapter {
  profile: string;
  validateObject(
    value: unknown,
    descriptor: Readonly<StateObjectDescriptor>,
  ):
    | { status: 'VALID' }
    | { status: 'REFUSED' | 'INDETERMINATE'; reasons: string[] };
}

export interface SourceAuthorityVerifier {
  verify(
    expected: Readonly<StateActionExpectation>,
    evidence: unknown,
  ): Promise<
    | { status: 'VERIFIED'; receipt_digest: StateDigest; consumption: 'CONSUMED' }
    | { status: 'REFUSED' | 'INDETERMINATE'; reasons: string[] }
  >;
}

export interface StateHead {
  generation: number;
  object_digest: StateDigest;
}

export interface StateCommitWrite {
  object_id: string;
  object_digest: StateDigest;
  generation: number;
  predecessor_digest: StateDigest | null;
  object: unknown;
}

export interface StateAdmissionRecord {
  handoff_id: string;
  manifest_digest: StateDigest;
  payload_profile: string;
  recipient_boundary_id: string;
  result: 'ACCEPTED' | 'PARTIAL';
  accepted_object_ids: string[];
  unavailable_objects: Array<{ object_id: string; reason: string }>;
  source_authority_evidence: StateAuthorityEvidenceRecord[];
  recipient_authority_evidence: StateAuthorityEvidenceRecord;
  committed_at: string;
}

export interface RecipientCommitRequest {
  handoff_id: string;
  manifest_digest: StateDigest;
  payload_profile: string;
  recipient_boundary_id: string;
  expected_heads: Array<{ object_id: string; head: StateHead | null }>;
  writes: StateCommitWrite[];
  unavailable_objects: Array<{ object_id: string; reason: string }>;
  source_authority_evidence: StateAuthorityEvidenceRecord[];
  import_authority: {
    expected: StateActionExpectation;
    evidence: unknown;
  };
  committed_at: string;
}

export interface RecipientStateBoundary {
  readHead(objectId: string): StateHead | null;
  lookupAdmission(handoffId: string): StateAdmissionRecord | null;
  commitImport(request: RecipientCommitRequest): Promise<
    | { status: 'COMMITTED'; record: StateAdmissionRecord }
    | { status: 'REFUSED' | 'INDETERMINATE'; reasons: string[] }
  >;
}

export interface ImportPortableStateOptions {
  now: string;
  expected_recipient_agent: string;
  expected_recipient_boundary_id: string;
  expected_relying_party_id: string;
  source_signer_pins: ArtifactSignerPin[];
  payload_adapters: StatePayloadAdapter[];
  source_authority_verifier: SourceAuthorityVerifier;
  recipient_boundary: RecipientStateBoundary;
  import_authority_evidence: unknown;
  importer_signer: ArtifactSigner;
  signature_agility?: AgilityOptions;
  verify_vault_availability?: (
    objects: ReadonlyArray<{ descriptor: StateObjectDescriptor; object: unknown }>,
  ) => Promise<
    | { status: 'AVAILABLE' }
    | { status: 'REFUSED' | 'INDETERMINATE'; reasons: string[] }
  >;
}

export interface ReferenceRecipientBoundaryOptions {
  authorizeImport(
    expected: Readonly<StateActionExpectation>,
    evidence: unknown,
  ):
    | { status: 'AUTHORIZED'; receipt_digest: StateDigest }
    | { status: 'REFUSED' | 'INDETERMINATE'; reasons: string[] };
  loseAcknowledgementAfterCommit?: boolean;
}

const MANIFEST_KEYS = new Set([
  '@version', 'handoff_id', 'transfer_mode', 'payload_profile', 'source_agent',
  'source_boundary_id', 'recipient_agent', 'recipient_boundary_id', 'relying_party_id',
  'created_at', 'snapshot_at', 'expires_at',
  'nonce', 'index', 'objects', 'scope_digest', 'authority', 'nonclaims',
  'signature_policy', 'signatures',
]);
const INDEX_KEYS = new Set(['ordered_object_ids', 'index_digest']);
const DESCRIPTOR_KEYS = new Set([
  'position', 'object_id', 'object_digest', 'media_type', 'schema_uri', 'required',
  'snapshot_at', 'sensitivity', 'disposition', 'generation', 'predecessor_digest',
]);
const AUTHORITY_KEYS = new Set(['profile', 'source_actions', 'recipient_action']);
const NONCLAIM_KEYS = new Set([
  'source_truth', 'authority_transfer', 'source_population_completeness', 'physical_erasure',
  'trusted_time',
]);
const SIGNATURE_POLICY_KEYS = new Set(['profile', 'required_algorithms']);
const SIGNATURE_KEYS = new Set(['alg', 'sig', 'key_id']);
const RECEIPT_KEYS = new Set([
  '@version', 'receipt_kind', 'handoff_id', 'manifest_digest', 'payload_profile',
  'importer_boundary_id', 'result', 'accepted_object_ids', 'unavailable_objects', 'reasons',
  'authority_evidence', 'admission_record_digest', 'completed_at', 'issued_at', 'nonclaims',
  'signature_policy', 'signatures',
]);
const UNAVAILABLE_KEYS = new Set(['object_id', 'reason']);
const EVIDENCE_KEYS = new Set(['stage', 'action', 'caid', 'receipt_digest']);
const BUNDLE_KEYS = new Set(['manifest', 'objects', 'source_authority_evidence']);

function isObject(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function exact(value: unknown, keys: Set<string>): value is Obj {
  if (!isObject(value)) return false;
  const actual = Object.keys(value);
  return actual.length === keys.size && actual.every((key) => keys.has(key));
}

function text(value: unknown, max = 2048): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function time(value: unknown): value is string {
  if (!text(value, 64)) return false;
  const match = RFC3339_UTC.exec(value);
  if (!match) return false;
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day >= 1 && day <= days[month - 1];
}

function digest(value: unknown): value is StateDigest {
  return typeof value === 'string' && SHA256.test(value);
}

function uniqueText(
  value: unknown,
  maxItems: number = PORTABLE_STATE_LIMITS.max_objects,
): value is string[] {
  return Array.isArray(value) && value.length <= maxItems && value.every((entry) => text(entry))
    && new Set(value).size === value.length;
}

function same(value: unknown, expected: unknown): boolean {
  const limits = {
    maxDepth: PORTABLE_STATE_LIMITS.max_depth,
    maxNodes: PORTABLE_STATE_LIMITS.max_nodes,
    maxStringBytes: PORTABLE_STATE_LIMITS.max_string_bytes,
  };
  try {
    return canonicalizeStrictJson(value, limits) === canonicalizeStrictJson(expected, limits);
  } catch {
    return false;
  }
}

function reason(reasons: string[], value: string): void {
  if (!reasons.includes(value)) reasons.push(value);
}

export function stateHandoffDigest(value: unknown): StateDigest {
  const bytes = Buffer.from(canonicalizeStrictJson(value, {
    maxDepth: PORTABLE_STATE_LIMITS.max_depth,
    maxNodes: PORTABLE_STATE_LIMITS.max_nodes,
    maxStringBytes: PORTABLE_STATE_LIMITS.max_string_bytes,
  }), 'utf8');
  // SHA-256 is the registered content-addressing suite, not password storage.
  const hex = crypto.createHash('sha256').update(bytes).digest('hex');
  return `sha256:${hex}`;
}

function policyIsValid(value: unknown): value is StateSignaturePolicy {
  if (!exact(value, SIGNATURE_POLICY_KEYS)
      || value.profile !== PORTABLE_STATE_SIGNATURE_PROFILE
      || !Array.isArray(value.required_algorithms)) return false;
  return ALLOWED_SIGNATURE_POLICIES.some((candidate) => same(value.required_algorithms, candidate));
}

function signaturesAreShaped(value: unknown): value is AgileSignature[] {
  return Array.isArray(value) && value.length > 0 && value.length <= 2 && value.every((entry) => (
    exact(entry, SIGNATURE_KEYS)
      && ['Ed25519', 'ML-DSA-65'].includes(entry.alg as string)
      && text(entry.sig, 8192)
      && text(entry.key_id)
  ));
}

function artifactBytes(domain: string, unsigned: unknown): Buffer {
  return Buffer.concat([
    Buffer.from(domain, 'utf8'),
    Buffer.from(canonicalizeStrictJson(unsigned, {
      maxDepth: PORTABLE_STATE_LIMITS.max_depth,
      maxNodes: PORTABLE_STATE_LIMITS.max_nodes,
      maxStringBytes: PORTABLE_STATE_LIMITS.max_string_bytes,
    }), 'utf8'),
  ]);
}

function withoutSignatures<T extends { signatures: AgileSignature[] }>(value: T): Omit<T, 'signatures'> {
  const { signatures: _signatures, ...unsigned } = value;
  return unsigned;
}

async function signArtifact<T extends { signature_policy: StateSignaturePolicy; signatures: AgileSignature[] }>(
  domain: string,
  unsigned: Omit<T, 'signatures'>,
  signer: ArtifactSigner,
): Promise<AgileSignature[]> {
  if (!policyIsValid(signer.policy) || !same(signer.policy, unsigned.signature_policy)) {
    throw new TypeError('artifact signer policy mismatch');
  }
  const keyAlgorithms = signer.keys.map((key) => key.alg);
  if (!same(keyAlgorithms, signer.policy.required_algorithms)
      || signer.keys.some((key) => !text(key.key_id))) {
    throw new TypeError('artifact signer keys do not match the signed algorithm set');
  }
  return signAgileSet(artifactBytes(domain, unsigned), signer.keys, signer.agility);
}

async function verifyArtifact(
  domain: string,
  value: { signature_policy: StateSignaturePolicy; signatures: AgileSignature[] },
  principal: string,
  issuedAt: string,
  pins: ArtifactSignerPin[],
  agility: AgilityOptions | undefined,
): Promise<string[]> {
  const reasons: string[] = [];
  const required = value.signature_policy.required_algorithms;
  const activePins: ArtifactSignerPin[] = [];
  for (const alg of required) {
    const matches = pins.filter((pin) => pin.alg === alg);
    if (matches.length !== 1) {
      reason(reasons, 'signer_pin_ambiguous_or_missing');
      continue;
    }
    const pin = matches[0];
    if (pin.status !== 'active') reason(reasons, 'signer_pin_inactive');
    if (!pin.principals.includes(principal)) reason(reasons, 'signer_principal_mismatch');
    if (!time(pin.valid_from) || !time(pin.valid_until)
        || Date.parse(issuedAt) < Date.parse(pin.valid_from)
        || Date.parse(issuedAt) > Date.parse(pin.valid_until)) {
      reason(reasons, 'signer_time_invalid');
    }
    const signature = value.signatures.find((entry) => entry.alg === alg);
    if (!signature || signature.key_id !== pin.key_id) reason(reasons, 'signer_key_id_mismatch');
    activePins.push(pin);
  }
  if (reasons.length > 0) return reasons;
  const result = await verifyAgileSignatureSet(
    artifactBytes(domain, withoutSignatures(value)),
    value.signatures,
    activePins,
    { ...agility, policy: 'hybrid_all', requiredAlgorithms: required },
  );
  if (result.verified !== true) reason(reasons, `artifact_signature_invalid:${result.reason ?? 'unknown'}`);
  return reasons;
}

function validateNonclaims(value: unknown): value is PortableStateManifest['nonclaims'] {
  return exact(value, NONCLAIM_KEYS)
    && value.source_truth === 'NOT_ESTABLISHED'
    && value.authority_transfer === 'PROHIBITED'
    && value.source_population_completeness === 'NOT_ESTABLISHED'
    && value.physical_erasure === 'NOT_ESTABLISHED'
    && value.trusted_time === 'NOT_ESTABLISHED';
}

function validateDescriptor(value: unknown, position: number): value is StateObjectDescriptor {
  return exact(value, DESCRIPTOR_KEYS)
    && value.position === position
    && text(value.object_id)
    && digest(value.object_digest)
    && text(value.media_type)
    && text(value.schema_uri)
    && typeof value.required === 'boolean'
    && time(value.snapshot_at)
    && ['OPEN', 'PROTECTED', 'VAULT'].includes(value.sensitivity as string)
    && ['ACTIVE', 'TOMBSTONE'].includes(value.disposition as string)
    && Number.isSafeInteger(value.generation)
    && (value.generation as number) >= 0
    && (value.predecessor_digest === null || digest(value.predecessor_digest));
}

function expectedSourceActions(manifest: PortableStateManifest): StateActionType[] {
  const actions: StateActionType[] = [PORTABLE_STATE_ACTIONS.EXPORT];
  if (manifest.objects.some((entry) => entry.sensitivity === 'VAULT')) {
    actions.push(PORTABLE_STATE_ACTIONS.KEY_RELEASE);
  }
  return actions;
}

function validateManifestShape(value: unknown, reasons: string[]): value is PortableStateManifest {
  if (!exact(value, MANIFEST_KEYS)) {
    reason(reasons, 'manifest_schema_invalid');
    return false;
  }
  let valid = value['@version'] === PORTABLE_STATE_MANIFEST_VERSION
    && text(value.handoff_id)
    && value.transfer_mode === 'COPY'
    && text(value.payload_profile)
    && text(value.source_agent)
    && text(value.source_boundary_id)
    && text(value.recipient_agent)
    && text(value.recipient_boundary_id)
    && text(value.relying_party_id)
    && time(value.created_at)
    && time(value.snapshot_at)
    && time(value.expires_at)
    && text(value.nonce, 256)
    && Array.isArray(value.objects)
    && value.objects.length > 0
    && value.objects.length <= PORTABLE_STATE_LIMITS.max_objects
    && digest(value.scope_digest)
    && validateNonclaims(value.nonclaims)
    && policyIsValid(value.signature_policy)
    && signaturesAreShaped(value.signatures);
  if (!exact(value.index, INDEX_KEYS)
      || !uniqueText(value.index.ordered_object_ids)
      || !digest(value.index.index_digest)) valid = false;
  if (!exact(value.authority, AUTHORITY_KEYS)
      || value.authority.profile !== PORTABLE_STATE_AUTHORITY_PROFILE
      || !Array.isArray(value.authority.source_actions)
      || value.authority.recipient_action !== PORTABLE_STATE_ACTIONS.IMPORT) valid = false;
  if (Array.isArray(value.objects)) {
    value.objects.forEach((entry, position) => {
      if (!validateDescriptor(entry, position)) valid = false;
    });
  }
  if (!valid) reason(reasons, 'manifest_schema_invalid');
  return valid;
}

function vaultSetDigest(manifest: PortableStateManifest): StateDigest {
  return stateHandoffDigest(manifest.objects
    .filter((entry) => entry.sensitivity === 'VAULT')
    .map((entry) => ({ object_id: entry.object_id, object_digest: entry.object_digest })));
}

export const STATE_HANDOFF_CAID_DEFINITIONS = Object.freeze([
  ...[PORTABLE_STATE_ACTIONS.EXPORT, PORTABLE_STATE_ACTIONS.IMPORT].map((action_type) => ({
    action_type,
    status: 'active',
    required_fields: [
      { name: 'handoff_id', type: 'string' },
      { name: 'manifest_digest', type: 'digest' },
      { name: 'payload_profile', type: 'string' },
      { name: 'transfer_mode', type: 'enum', values_ref: 'inline: COPY' },
      { name: 'source_agent', type: 'string' },
      { name: 'source_boundary_id', type: 'string' },
      { name: 'recipient_agent', type: 'string' },
      { name: 'recipient_boundary_id', type: 'string' },
      { name: 'relying_party_id', type: 'string' },
      { name: 'scope_digest', type: 'digest' },
      { name: 'expires_at', type: 'timestamp' },
      { name: 'nonce', type: 'string' },
    ],
    optional_fields: [],
  })),
  {
    action_type: PORTABLE_STATE_ACTIONS.KEY_RELEASE,
    status: 'active',
    required_fields: [
      { name: 'handoff_id', type: 'string' }, { name: 'manifest_digest', type: 'digest' },
      { name: 'payload_profile', type: 'string' }, { name: 'transfer_mode', type: 'enum', values_ref: 'inline: COPY' },
      { name: 'source_agent', type: 'string' }, { name: 'source_boundary_id', type: 'string' },
      { name: 'recipient_agent', type: 'string' }, { name: 'recipient_boundary_id', type: 'string' },
      { name: 'relying_party_id', type: 'string' }, { name: 'scope_digest', type: 'digest' },
      { name: 'expires_at', type: 'timestamp' }, { name: 'nonce', type: 'string' },
      { name: 'vault_set_digest', type: 'digest' },
    ],
    optional_fields: [],
  },
  {
    action_type: PORTABLE_STATE_ACTIONS.RETIRE_SOURCE,
    status: 'active',
    required_fields: [
      { name: 'handoff_id', type: 'string' }, { name: 'manifest_digest', type: 'digest' },
      { name: 'payload_profile', type: 'string' }, { name: 'transfer_mode', type: 'enum', values_ref: 'inline: COPY' },
      { name: 'source_agent', type: 'string' }, { name: 'source_boundary_id', type: 'string' },
      { name: 'recipient_agent', type: 'string' }, { name: 'recipient_boundary_id', type: 'string' },
      { name: 'relying_party_id', type: 'string' }, { name: 'scope_digest', type: 'digest' },
      { name: 'expires_at', type: 'timestamp' }, { name: 'nonce', type: 'string' },
      { name: 'import_receipt_digest', type: 'digest' },
      { name: 'retirement_set_digest', type: 'digest' },
    ],
    optional_fields: [],
  },
]);

export function stateActionExpectation(
  manifest: PortableStateManifest,
  actionType: StateActionType,
  importReceiptDigest?: StateDigest,
  retirementSetDigest?: StateDigest,
): StateActionExpectation {
  const manifestDigest = stateHandoffDigest(manifest);
  const action: StateActionObject = {
    action_type: actionType,
    handoff_id: manifest.handoff_id,
    manifest_digest: manifestDigest,
    payload_profile: manifest.payload_profile,
    transfer_mode: 'COPY',
    source_agent: manifest.source_agent,
    source_boundary_id: manifest.source_boundary_id,
    recipient_agent: manifest.recipient_agent,
    recipient_boundary_id: manifest.recipient_boundary_id,
    relying_party_id: manifest.relying_party_id,
    scope_digest: manifest.scope_digest,
    expires_at: manifest.expires_at,
    nonce: manifest.nonce,
  };
  if (actionType === PORTABLE_STATE_ACTIONS.KEY_RELEASE) action.vault_set_digest = vaultSetDigest(manifest);
  if (actionType === PORTABLE_STATE_ACTIONS.RETIRE_SOURCE) {
    if (!importReceiptDigest || !digest(importReceiptDigest)
        || !retirementSetDigest || !digest(retirementSetDigest)) {
      throw new TypeError('source retirement requires receipt and accepted-object-set digests');
    }
    action.import_receipt_digest = importReceiptDigest;
    action.retirement_set_digest = retirementSetDigest;
  }
  const computed = computeCaid(action, {
    suite: 'jcs-sha256',
    definitions: STATE_HANDOFF_CAID_DEFINITIONS,
  });
  if (!isObject(computed) || !text(computed.caid) || !digest(computed.digest)) {
    throw new Error('state handoff action could not be mapped to CAID');
  }
  return {
    profile: PORTABLE_STATE_AUTHORITY_PROFILE,
    action_object: action,
    caid: computed.caid,
    action_digest: computed.digest,
  };
}

function safeManifestDigest(value: unknown): StateDigest {
  try { return stateHandoffDigest(value); } catch { return `sha256:${'0'.repeat(64)}`; }
}

function receiptShapeValid(value: unknown): value is PortableStateImportReceipt {
  const valid = exact(value, RECEIPT_KEYS)
    && value['@version'] === PORTABLE_STATE_IMPORT_RECEIPT_VERSION
    && ['INITIAL', 'RECONCILIATION'].includes(value.receipt_kind as string)
    && text(value.handoff_id)
    && digest(value.manifest_digest)
    && text(value.payload_profile)
    && text(value.importer_boundary_id)
    && ['ACCEPTED', 'PARTIAL', 'REFUSED', 'INDETERMINATE'].includes(value.result as string)
    && uniqueText(value.accepted_object_ids)
    && Array.isArray(value.unavailable_objects)
    && value.unavailable_objects.length <= PORTABLE_STATE_LIMITS.max_objects
    && value.unavailable_objects.every((entry) => exact(entry, UNAVAILABLE_KEYS)
      && text(entry.object_id) && text(entry.reason))
    && uniqueText(value.reasons, PORTABLE_STATE_LIMITS.max_reasons)
    && Array.isArray(value.authority_evidence)
    && value.authority_evidence.length <= 3
    && value.authority_evidence.every((entry) => exact(entry, EVIDENCE_KEYS)
      && ['SOURCE_RELEASE', 'RECIPIENT_COMMIT'].includes(entry.stage as string)
      && Object.values(PORTABLE_STATE_ACTIONS).includes(entry.action as StateActionType)
      && (entry.stage !== 'SOURCE_RELEASE'
        || entry.action === PORTABLE_STATE_ACTIONS.EXPORT
        || entry.action === PORTABLE_STATE_ACTIONS.KEY_RELEASE)
      && (entry.stage !== 'RECIPIENT_COMMIT' || entry.action === PORTABLE_STATE_ACTIONS.IMPORT)
      && text(entry.caid) && digest(entry.receipt_digest))
    && (value.admission_record_digest === null || digest(value.admission_record_digest))
    && time(value.completed_at)
    && time(value.issued_at)
    && validateNonclaims(value.nonclaims)
    && policyIsValid(value.signature_policy)
    && signaturesAreShaped(value.signatures);
  if (!valid) return false;
  const evidence = value.authority_evidence as StateAuthorityEvidenceRecord[];
  const unavailable = value.unavailable_objects as Array<{ object_id: string; reason: string }>;
  return new Set(evidence.map((entry) => `${entry.stage}:${entry.action}`)).size === evidence.length
    && new Set(unavailable.map((entry) => entry.object_id)).size === unavailable.length;
}

function indeterminate(reasons: string[]): boolean {
  const markers = new Set([
    'required_payload_profile_unsupported', 'lineage_unanchored', 'lineage_gap',
    'source_authority_indeterminate', 'recipient_boundary_indeterminate',
    'vault_availability_indeterminate', 'commit_acknowledgement_lost',
    'head_changed_during_commit', 'handoff_already_committed_use_reconciliation',
    'payload_validation_indeterminate', 'recipient_head_read_indeterminate',
    'manifest_validation_indeterminate',
  ]);
  return reasons.some((entry) => markers.has(entry));
}

async function issueReceipt(
  partial: Omit<PortableStateImportReceipt, 'signatures'>,
  signer: ArtifactSigner,
): Promise<PortableStateImportReceipt> {
  if (partial.importer_boundary_id !== signer.principal_id) {
    throw new TypeError('import receipt signer does not match importer_boundary_id');
  }
  const signatures = await signArtifact<PortableStateImportReceipt>(RECEIPT_DOMAIN, partial, signer);
  return { ...partial, signatures };
}

async function failureReceipt(
  bundle: PortableStateBundle,
  options: ImportPortableStateOptions,
  manifestDigest: StateDigest,
  reasons: string[],
  sourceEvidence: StateAuthorityEvidenceRecord[] = [],
  unavailable: Array<{ object_id: string; reason: string }> = [],
): Promise<PortableStateImportReceipt> {
  const manifest = isObject(bundle?.manifest) ? bundle.manifest as unknown as PortableStateManifest : null;
  return issueReceipt({
    '@version': PORTABLE_STATE_IMPORT_RECEIPT_VERSION,
    receipt_kind: 'INITIAL',
    handoff_id: manifest && text(manifest.handoff_id) ? manifest.handoff_id : 'urn:ep:state-handoff:invalid',
    manifest_digest: manifestDigest,
    payload_profile: manifest && text(manifest.payload_profile) ? manifest.payload_profile : 'invalid',
    importer_boundary_id: options.importer_signer.principal_id,
    result: indeterminate(reasons) ? 'INDETERMINATE' : 'REFUSED',
    accepted_object_ids: [],
    unavailable_objects: unavailable,
    reasons,
    authority_evidence: sourceEvidence,
    admission_record_digest: null,
    completed_at: options.now,
    issued_at: options.now,
    nonclaims: {
      source_truth: 'NOT_ESTABLISHED',
      authority_transfer: 'PROHIBITED',
      source_population_completeness: 'NOT_ESTABLISHED',
      physical_erasure: 'NOT_ESTABLISHED',
      trusted_time: 'NOT_ESTABLISHED',
    },
    signature_policy: options.importer_signer.policy,
  }, options.importer_signer);
}

async function successReceipt(
  record: StateAdmissionRecord,
  options: ImportPortableStateOptions,
  kind: 'INITIAL' | 'RECONCILIATION',
): Promise<PortableStateImportReceipt> {
  if (record.recipient_boundary_id !== options.importer_signer.principal_id) {
    throw new TypeError('stored admission boundary does not match import receipt signer');
  }
  const evidence = [...record.source_authority_evidence, record.recipient_authority_evidence];
  const admissionRecordDigest = stateHandoffDigest(record);
  return issueReceipt({
    '@version': PORTABLE_STATE_IMPORT_RECEIPT_VERSION,
    receipt_kind: kind,
    handoff_id: record.handoff_id,
    manifest_digest: record.manifest_digest,
    payload_profile: record.payload_profile,
    importer_boundary_id: record.recipient_boundary_id,
    result: record.result,
    accepted_object_ids: record.accepted_object_ids,
    unavailable_objects: record.unavailable_objects,
    reasons: [],
    authority_evidence: evidence,
    admission_record_digest: admissionRecordDigest,
    completed_at: record.committed_at,
    issued_at: options.now,
    nonclaims: {
      source_truth: 'NOT_ESTABLISHED',
      authority_transfer: 'PROHIBITED',
      source_population_completeness: 'NOT_ESTABLISHED',
      physical_erasure: 'NOT_ESTABLISHED',
      trusted_time: 'NOT_ESTABLISHED',
    },
    signature_policy: options.importer_signer.policy,
  }, options.importer_signer);
}

function validateManifestIntrinsic(
  manifest: PortableStateManifest,
  reasons: string[],
): void {
  if (Date.parse(manifest.snapshot_at) > Date.parse(manifest.created_at)
      || Date.parse(manifest.created_at) >= Date.parse(manifest.expires_at)) {
    reason(reasons, 'manifest_time_order_invalid');
  }
  if (manifest.objects.some((entry) => Date.parse(entry.snapshot_at) > Date.parse(manifest.snapshot_at))) {
    reason(reasons, 'object_snapshot_after_manifest_cut');
  }
  if (!same(manifest.authority.source_actions, expectedSourceActions(manifest))) {
    reason(reasons, 'source_authority_set_mismatch');
  }
  const orderedIds = manifest.objects.map((entry) => entry.object_id);
  if (new Set(orderedIds).size !== orderedIds.length) reason(reasons, 'duplicate_manifest_object');
  if (!same(orderedIds, manifest.index.ordered_object_ids)) reason(reasons, 'index_order_mismatch');
  if (stateHandoffDigest(manifest.objects) !== manifest.index.index_digest) reason(reasons, 'index_digest_mismatch');
  const expectedScope = stateHandoffDigest({
    transfer_mode: manifest.transfer_mode,
    payload_profile: manifest.payload_profile,
    source_agent: manifest.source_agent,
    source_boundary_id: manifest.source_boundary_id,
    recipient_agent: manifest.recipient_agent,
    recipient_boundary_id: manifest.recipient_boundary_id,
    relying_party_id: manifest.relying_party_id,
    index_digest: manifest.index.index_digest,
  });
  if (manifest.scope_digest !== expectedScope) reason(reasons, 'scope_digest_mismatch');
}

async function evaluateManifest(
  value: unknown,
  options: ImportPortableStateOptions,
  reasons: string[],
): Promise<boolean> {
  if (!validateManifestShape(value, reasons)) return false;
  const manifest = value;
  if (manifest.recipient_agent !== options.expected_recipient_agent) reason(reasons, 'recipient_mismatch');
  if (manifest.recipient_boundary_id !== options.expected_recipient_boundary_id) {
    reason(reasons, 'recipient_boundary_mismatch');
  }
  if (options.importer_signer.principal_id !== options.expected_recipient_boundary_id) {
    reason(reasons, 'importer_signer_boundary_mismatch');
  }
  if (manifest.relying_party_id !== options.expected_relying_party_id) reason(reasons, 'relying_party_mismatch');
  if (!time(options.now)) reason(reasons, 'verifier_time_invalid');
  if (time(options.now) && Date.parse(options.now) < Date.parse(manifest.created_at)) {
    reason(reasons, 'manifest_not_yet_valid');
  }
  if (time(options.now) && Date.parse(options.now) > Date.parse(manifest.expires_at)) reason(reasons, 'manifest_expired');
  validateManifestIntrinsic(manifest, reasons);
  const signatureReasons = await verifyArtifact(
    MANIFEST_DOMAIN,
    manifest,
    manifest.source_agent,
    manifest.created_at,
    options.source_signer_pins,
    options.signature_agility,
  );
  signatureReasons.forEach((entry) => reason(reasons, entry));
  return true;
}

/**
 * Verify, admit, and commit one portable-state handoff.
 *
 * Caller input never authorizes through a boolean. Source evidence must verify
 * as already consumed at the source boundary. Recipient authority is consumed
 * only inside RecipientStateBoundary.commitImport, in the same atomic state
 * domain that rechecks current heads and stores the objects.
 */
export async function importPortableState(
  bundle: PortableStateBundle,
  options: ImportPortableStateOptions,
): Promise<PortableStateImportReceipt> {
  const manifestDigest = safeManifestDigest(bundle?.manifest);
  const reasons: string[] = [];
  const unavailable: Array<{ object_id: string; reason: string }> = [];
  if (!exact(bundle, BUNDLE_KEYS) || !Array.isArray(bundle.objects)
      || bundle.objects.length > PORTABLE_STATE_LIMITS.max_objects
      || !isObject(bundle.source_authority_evidence)) {
    return failureReceipt(bundle, options, manifestDigest, ['bundle_schema_invalid']);
  }
  let manifestEvaluated: boolean;
  try {
    manifestEvaluated = await evaluateManifest(bundle.manifest, options, reasons);
  } catch {
    return failureReceipt(bundle, options, manifestDigest, ['manifest_validation_indeterminate']);
  }
  if (!manifestEvaluated) {
    return failureReceipt(bundle, options, manifestDigest, reasons);
  }
  const manifest = bundle.manifest as PortableStateManifest;
  let prior: StateAdmissionRecord | null;
  try {
    prior = options.recipient_boundary.lookupAdmission(manifest.handoff_id);
  } catch {
    return failureReceipt(bundle, options, manifestDigest, [
      'recipient_admission_lookup_failed',
      'recipient_boundary_indeterminate',
    ]);
  }
  if (prior) {
    if (prior.manifest_digest !== manifestDigest) {
      return failureReceipt(bundle, options, manifestDigest, ['handoff_id_manifest_conflict']);
    }
    return failureReceipt(bundle, options, manifestDigest, ['handoff_already_committed_use_reconciliation']);
  }

  const adapter = options.payload_adapters.find((candidate) => candidate.profile === manifest.payload_profile);
  if (!adapter || options.payload_adapters.filter((candidate) => candidate.profile === manifest.payload_profile).length !== 1) {
    return failureReceipt(bundle, options, manifestDigest, ['required_payload_profile_unsupported']);
  }
  const expectedSource = expectedSourceActions(manifest);
  const evidenceKeys = Object.keys(bundle.source_authority_evidence);
  if (!same(evidenceKeys.sort(), [...expectedSource].sort())) {
    return failureReceipt(bundle, options, manifestDigest, ['source_authority_evidence_set_mismatch']);
  }
  const sourceEvidence: StateAuthorityEvidenceRecord[] = [];
  for (const action of expectedSource) {
    const expected = stateActionExpectation(manifest, action);
    let verified: Awaited<ReturnType<SourceAuthorityVerifier['verify']>>;
    try {
      verified = await options.source_authority_verifier.verify(
        expected,
        bundle.source_authority_evidence[action],
      );
    } catch {
      reason(reasons, 'source_authority_verifier_failed');
      reason(reasons, 'source_authority_indeterminate');
      continue;
    }
    if (verified.status !== 'VERIFIED') {
      verified.reasons.forEach((entry) => reason(reasons, entry));
      if (verified.status === 'INDETERMINATE') reason(reasons, 'source_authority_indeterminate');
      continue;
    }
    if (verified.consumption !== 'CONSUMED' || !digest(verified.receipt_digest)) {
      reason(reasons, 'source_authority_not_consumed');
      continue;
    }
    sourceEvidence.push({
      stage: 'SOURCE_RELEASE',
      action,
      caid: expected.caid,
      receipt_digest: verified.receipt_digest,
    });
  }
  if (reasons.length > 0) return failureReceipt(bundle, options, manifestDigest, reasons, sourceEvidence);

  const byId = new Map<string, unknown>();
  for (const object of bundle.objects) {
    let objectId: string | null = null;
    if (isObject(object)) {
      const candidate = object.object_id ?? object.shard_id;
      if (text(candidate)) objectId = candidate;
    }
    if (!objectId) {
      reason(reasons, 'payload_object_id_missing');
      continue;
    }
    if (byId.has(objectId)) reason(reasons, 'duplicate_bundle_object');
    byId.set(objectId, object);
  }
  const listed = new Set(manifest.objects.map((entry) => entry.object_id));
  for (const objectId of byId.keys()) {
    if (!listed.has(objectId)) reason(reasons, 'unlisted_object_present');
  }

  const writes: StateCommitWrite[] = [];
  const expectedHeads: Array<{ object_id: string; head: StateHead | null }> = [];
  const vaultObjects: Array<{ descriptor: StateObjectDescriptor; object: unknown }> = [];
  for (const descriptor of manifest.objects) {
    const object = byId.get(descriptor.object_id);
    if (object === undefined) {
      if (descriptor.required) reason(reasons, 'required_object_missing');
      else unavailable.push({ object_id: descriptor.object_id, reason: 'optional_object_missing' });
      continue;
    }
    let objectDigest: StateDigest;
    try {
      objectDigest = stateHandoffDigest(object);
    } catch {
      reason(reasons, 'payload_not_strict_bounded_json');
      continue;
    }
    if (objectDigest !== descriptor.object_digest) {
      reason(reasons, 'object_digest_mismatch');
      continue;
    }
    let profileResult: ReturnType<StatePayloadAdapter['validateObject']>;
    try {
      profileResult = adapter.validateObject(object, descriptor);
    } catch {
      profileResult = { status: 'INDETERMINATE', reasons: ['payload_adapter_failed'] };
    }
    if (profileResult.status !== 'VALID') {
      if (!descriptor.required && profileResult.status === 'INDETERMINATE') {
        unavailable.push({ object_id: descriptor.object_id, reason: profileResult.reasons.join(',') });
        continue;
      }
      profileResult.reasons.forEach((entry) => reason(reasons, entry));
      if (profileResult.status === 'INDETERMINATE') reason(reasons, 'payload_validation_indeterminate');
      continue;
    }
    let head: StateHead | null;
    try {
      head = options.recipient_boundary.readHead(descriptor.object_id);
    } catch {
      reason(reasons, 'recipient_head_read_indeterminate');
      reason(reasons, 'recipient_boundary_indeterminate');
      continue;
    }
    expectedHeads.push({ object_id: descriptor.object_id, head });
    if (head) {
      if (descriptor.generation <= head.generation) reason(reasons, 'lineage_rollback');
      else if (descriptor.generation > head.generation + 1) reason(reasons, 'lineage_gap');
      else if (descriptor.predecessor_digest !== head.object_digest) reason(reasons, 'lineage_fork');
    } else if (descriptor.generation !== 0 || descriptor.predecessor_digest !== null) {
      reason(reasons, 'lineage_unanchored');
    }
    writes.push({
      object_id: descriptor.object_id,
      object_digest: descriptor.object_digest,
      generation: descriptor.generation,
      predecessor_digest: descriptor.predecessor_digest,
      object,
    });
    if (descriptor.sensitivity === 'VAULT') vaultObjects.push({ descriptor, object });
  }
  if (reasons.length > 0) return failureReceipt(bundle, options, manifestDigest, reasons, sourceEvidence, unavailable);
  if (vaultObjects.length > 0) {
    let availability:
      | { status: 'AVAILABLE' }
      | { status: 'REFUSED' | 'INDETERMINATE'; reasons: string[] };
    try {
      availability = await (options.verify_vault_availability?.(vaultObjects)
        ?? Promise.resolve({ status: 'INDETERMINATE' as const, reasons: ['vault_key_unavailable'] }));
    } catch {
      availability = { status: 'INDETERMINATE', reasons: ['vault_availability_check_failed'] };
    }
    if (availability.status !== 'AVAILABLE') {
      availability.reasons.forEach((entry) => reason(reasons, entry));
      if (availability.status === 'INDETERMINATE') reason(reasons, 'vault_availability_indeterminate');
      return failureReceipt(bundle, options, manifestDigest, reasons, sourceEvidence, unavailable);
    }
  }

  const importExpectation = stateActionExpectation(manifest, PORTABLE_STATE_ACTIONS.IMPORT);
  let committed: Awaited<ReturnType<RecipientStateBoundary['commitImport']>>;
  try {
    committed = await options.recipient_boundary.commitImport({
      handoff_id: manifest.handoff_id,
      manifest_digest: manifestDigest,
      payload_profile: manifest.payload_profile,
      recipient_boundary_id: manifest.recipient_boundary_id,
      expected_heads: expectedHeads,
      writes,
      unavailable_objects: unavailable,
      source_authority_evidence: sourceEvidence,
      import_authority: { expected: importExpectation, evidence: options.import_authority_evidence },
      committed_at: options.now,
    });
  } catch {
    return failureReceipt(bundle, options, manifestDigest, [
      'recipient_commit_response_unknown',
      'recipient_boundary_indeterminate',
    ], sourceEvidence, unavailable);
  }
  if (committed.status !== 'COMMITTED') {
    committed.reasons.forEach((entry) => reason(reasons, entry));
    if (committed.status === 'INDETERMINATE') reason(reasons, 'recipient_boundary_indeterminate');
    return failureReceipt(bundle, options, manifestDigest, reasons, sourceEvidence, unavailable);
  }
  return successReceipt(committed.record, options, 'INITIAL');
}

export async function reconcilePortableStateImport(
  handoffId: string,
  manifestDigest: StateDigest,
  options: ImportPortableStateOptions,
): Promise<PortableStateImportReceipt | null> {
  const record = options.recipient_boundary.lookupAdmission(handoffId);
  if (!record || record.manifest_digest !== manifestDigest) return null;
  return successReceipt(record, options, 'RECONCILIATION');
}

export async function verifyPortableStateImportReceipt(
  value: unknown,
  pins: ArtifactSignerPin[],
  agility?: AgilityOptions,
): Promise<{ valid: boolean; reasons: string[] }> {
  if (!receiptShapeValid(value)) return { valid: false, reasons: ['receipt_schema_invalid'] };
  let reasons: string[];
  try {
    reasons = await verifyArtifact(
      RECEIPT_DOMAIN,
      value,
      value.importer_boundary_id,
      value.issued_at,
      pins,
      agility,
    );
  } catch {
    return { valid: false, reasons: ['receipt_not_strict_bounded_json'] };
  }
  if (['ACCEPTED', 'PARTIAL'].includes(value.result)
      && (!value.admission_record_digest
        || value.authority_evidence.filter((entry) => entry.stage === 'RECIPIENT_COMMIT').length !== 1
        || value.authority_evidence.filter((entry) => entry.action === PORTABLE_STATE_ACTIONS.EXPORT).length !== 1)) {
    reason(reasons, 'accepted_receipt_without_atomic_admission');
  }
  if (['ACCEPTED', 'PARTIAL'].includes(value.result) && value.reasons.length !== 0) {
    reason(reasons, 'accepted_receipt_carries_failure_reasons');
  }
  if (value.result === 'ACCEPTED' && value.unavailable_objects.length !== 0) {
    reason(reasons, 'accepted_receipt_claims_unavailable_state');
  }
  if (value.result === 'PARTIAL' && value.unavailable_objects.length === 0) {
    reason(reasons, 'partial_receipt_without_unavailable_state');
  }
  if (['REFUSED', 'INDETERMINATE'].includes(value.result)
      && (value.accepted_object_ids.length > 0 || value.admission_record_digest !== null)) {
    reason(reasons, 'failed_receipt_claims_committed_state');
  }
  if (['REFUSED', 'INDETERMINATE'].includes(value.result) && value.reasons.length === 0) {
    reason(reasons, 'failed_receipt_without_reason');
  }
  if (['REFUSED', 'INDETERMINATE'].includes(value.result)
      && value.authority_evidence.some((entry) => entry.stage === 'RECIPIENT_COMMIT')) {
    reason(reasons, 'failed_receipt_claims_recipient_commit');
  }
  if (Date.parse(value.issued_at) < Date.parse(value.completed_at)) {
    reason(reasons, 'receipt_issued_before_completion');
  }
  if (value.receipt_kind === 'RECONCILIATION'
      && !['ACCEPTED', 'PARTIAL'].includes(value.result)) {
    reason(reasons, 'reconciliation_receipt_not_committed');
  }
  return { valid: reasons.length === 0, reasons };
}

/**
 * Verify an import receipt and its exact relationship to an already obtained
 * manifest. This function does not replace source-manifest signature
 * verification; it closes the cross-artifact set, boundary, CAID, and time
 * bindings after that verification has succeeded.
 */
export async function verifyPortableStateImportReceiptForManifest(
  value: unknown,
  manifestValue: unknown,
  pins: ArtifactSignerPin[],
  agility?: AgilityOptions,
): Promise<{ valid: boolean; reasons: string[] }> {
  const checked = await verifyPortableStateImportReceipt(value, pins, agility);
  const reasons = [...checked.reasons];
  const manifestReasons: string[] = [];
  if (!validateManifestShape(manifestValue, manifestReasons)) {
    manifestReasons.forEach((entry) => reason(reasons, entry));
    return { valid: false, reasons };
  }
  if (!receiptShapeValid(value)) return { valid: false, reasons };
  const manifest = manifestValue;
  let manifestDigest: StateDigest;
  try {
    manifestDigest = stateHandoffDigest(manifest);
  } catch {
    reason(reasons, 'manifest_not_strict_bounded_json');
    return { valid: false, reasons };
  }
  if (value.handoff_id !== manifest.handoff_id) reason(reasons, 'receipt_handoff_mismatch');
  if (value.manifest_digest !== manifestDigest) reason(reasons, 'receipt_manifest_digest_mismatch');
  if (value.payload_profile !== manifest.payload_profile) reason(reasons, 'receipt_payload_profile_mismatch');
  if (value.importer_boundary_id !== manifest.recipient_boundary_id) {
    reason(reasons, 'receipt_recipient_boundary_mismatch');
  }

  const descriptorById = new Map(manifest.objects.map((entry) => [entry.object_id, entry]));
  const unavailableIds = value.unavailable_objects.map((entry) => entry.object_id);
  for (const objectId of [...value.accepted_object_ids, ...unavailableIds]) {
    if (!descriptorById.has(objectId)) reason(reasons, 'receipt_object_not_in_manifest');
  }
  if (value.accepted_object_ids.some((objectId) => unavailableIds.includes(objectId))) {
    reason(reasons, 'receipt_object_both_accepted_and_unavailable');
  }
  if (value.unavailable_objects.some((entry) => descriptorById.get(entry.object_id)?.required === true)) {
    reason(reasons, 'receipt_required_object_marked_unavailable');
  }
  if (['ACCEPTED', 'PARTIAL'].includes(value.result)) {
    const unavailableSet = new Set(unavailableIds);
    const expectedAccepted = manifest.objects
      .map((entry) => entry.object_id)
      .filter((objectId) => !unavailableSet.has(objectId));
    if (!same(value.accepted_object_ids, expectedAccepted)
        || value.accepted_object_ids.length + unavailableIds.length !== manifest.objects.length) {
      reason(reasons, 'receipt_state_set_mismatch');
    }
    if (Date.parse(value.completed_at) < Date.parse(manifest.created_at)
        || Date.parse(value.completed_at) > Date.parse(manifest.expires_at)) {
      reason(reasons, 'accepted_receipt_time_outside_manifest');
    }
  }

  const sourceEvidence = value.authority_evidence.filter((entry) => entry.stage === 'SOURCE_RELEASE');
  const recipientEvidence = value.authority_evidence.filter((entry) => entry.stage === 'RECIPIENT_COMMIT');
  if (sourceEvidence.some((entry) => !manifest.authority.source_actions.includes(entry.action))) {
    reason(reasons, 'receipt_unexpected_source_authority');
  }
  for (const entry of value.authority_evidence) {
    try {
      const expected = stateActionExpectation(manifest, entry.action);
      if (entry.caid !== expected.caid) reason(reasons, 'receipt_authority_caid_mismatch');
    } catch {
      reason(reasons, 'receipt_authority_relationship_invalid');
    }
  }
  if (['ACCEPTED', 'PARTIAL'].includes(value.result)) {
    if (!same(sourceEvidence.map((entry) => entry.action), manifest.authority.source_actions)) {
      reason(reasons, 'receipt_source_authority_set_mismatch');
    }
    if (recipientEvidence.length !== 1 || recipientEvidence[0]?.action !== PORTABLE_STATE_ACTIONS.IMPORT) {
      reason(reasons, 'receipt_recipient_authority_mismatch');
    }
  }
  return { valid: reasons.length === 0, reasons };
}

/** Process-local conformance boundary. Not a durable production store. */
export class InMemoryRecipientStateBoundary implements RecipientStateBoundary {
  readonly #heads = new Map<string, StateHead>();
  readonly #objects = new Map<string, unknown>();
  readonly #admissions = new Map<string, StateAdmissionRecord>();
  readonly #options: ReferenceRecipientBoundaryOptions;
  #loseAcknowledgement: boolean;
  #consumptions = 0;

  constructor(options: ReferenceRecipientBoundaryOptions) {
    this.#options = options;
    this.#loseAcknowledgement = options.loseAcknowledgementAfterCommit === true;
  }

  readHead(objectId: string): StateHead | null {
    const value = this.#heads.get(objectId);
    return value ? { ...value } : null;
  }

  readObject(objectId: string): unknown {
    const value = this.#objects.get(objectId);
    return value === undefined ? null : structuredClone(value);
  }

  lookupAdmission(handoffId: string): StateAdmissionRecord | null {
    const value = this.#admissions.get(handoffId);
    return value ? structuredClone(value) : null;
  }

  seedHead(objectId: string, head: StateHead, object: unknown = null): void {
    if (!text(objectId) || !Number.isSafeInteger(head.generation) || head.generation < 0
        || !digest(head.object_digest)) throw new TypeError('invalid state head');
    this.#heads.set(objectId, { ...head });
    this.#objects.set(objectId, structuredClone(object));
  }

  consumptionCount(): number { return this.#consumptions; }

  loseNextAcknowledgement(): void { this.#loseAcknowledgement = true; }

  async commitImport(request: RecipientCommitRequest): Promise<
    | { status: 'COMMITTED'; record: StateAdmissionRecord }
    | { status: 'REFUSED' | 'INDETERMINATE'; reasons: string[] }
  > {
    if (this.#admissions.has(request.handoff_id)) return { status: 'REFUSED', reasons: ['handoff_replay'] };
    const action = request.import_authority.expected.action_object;
    if (action.action_type !== PORTABLE_STATE_ACTIONS.IMPORT
        || action.handoff_id !== request.handoff_id
        || action.manifest_digest !== request.manifest_digest
        || action.payload_profile !== request.payload_profile
        || action.recipient_boundary_id !== request.recipient_boundary_id) {
      return { status: 'REFUSED', reasons: ['recipient_commit_action_mismatch'] };
    }
    for (const expected of request.expected_heads) {
      if (!same(this.readHead(expected.object_id), expected.head)) {
        return { status: 'INDETERMINATE', reasons: ['head_changed_during_commit'] };
      }
    }
    const decision = this.#options.authorizeImport(
      request.import_authority.expected,
      request.import_authority.evidence,
    );
    if (decision.status !== 'AUTHORIZED') return decision;
    if (!digest(decision.receipt_digest)) return { status: 'REFUSED', reasons: ['authority_receipt_digest_invalid'] };

    const recipientEvidence: StateAuthorityEvidenceRecord = {
      stage: 'RECIPIENT_COMMIT',
      action: PORTABLE_STATE_ACTIONS.IMPORT,
      caid: request.import_authority.expected.caid,
      receipt_digest: decision.receipt_digest,
    };
    const record: StateAdmissionRecord = {
      handoff_id: request.handoff_id,
      manifest_digest: request.manifest_digest,
      payload_profile: request.payload_profile,
      recipient_boundary_id: request.recipient_boundary_id,
      result: request.unavailable_objects.length > 0 ? 'PARTIAL' : 'ACCEPTED',
      accepted_object_ids: request.writes.map((entry) => entry.object_id),
      unavailable_objects: request.unavailable_objects,
      source_authority_evidence: request.source_authority_evidence,
      recipient_authority_evidence: recipientEvidence,
      committed_at: request.committed_at,
    };

    // This block is the reference transaction: replay fence, authority
    // consumption counter, object bytes, lineage heads, and admission record
    // change together after the final head comparison.
    for (const write of request.writes) {
      this.#objects.set(write.object_id, structuredClone(write.object));
      this.#heads.set(write.object_id, {
        generation: write.generation,
        object_digest: write.object_digest,
      });
    }
    this.#admissions.set(request.handoff_id, structuredClone(record));
    this.#consumptions += 1;

    if (this.#loseAcknowledgement) {
      this.#loseAcknowledgement = false;
      return { status: 'INDETERMINATE', reasons: ['commit_acknowledgement_lost'] };
    }
    return { status: 'COMMITTED', record: structuredClone(record) };
  }
}

export async function signPortableStateManifest(
  unsigned: Omit<PortableStateManifest, 'signatures'>,
  signer: ArtifactSigner,
): Promise<PortableStateManifest> {
  if (unsigned.source_agent !== signer.principal_id) {
    throw new TypeError('manifest signer does not match source_agent');
  }
  const reasons: string[] = [];
  const validationCandidate: PortableStateManifest = {
    ...unsigned,
    signatures: unsigned.signature_policy.required_algorithms.map((alg) => ({
      alg,
      sig: 'A',
      key_id: 'pre-sign-validation',
    })),
  };
  if (validateManifestShape(validationCandidate, reasons)) {
    validateManifestIntrinsic(validationCandidate, reasons);
  }
  if (reasons.length > 0) {
    throw new TypeError(`refusing to sign invalid portable-state manifest: ${reasons.join(',')}`);
  }
  const signatures = await signArtifact<PortableStateManifest>(MANIFEST_DOMAIN, unsigned, signer);
  const signed = { ...unsigned, signatures };
  return signed;
}

export function buildSourceRetirementExpectation(
  manifest: PortableStateManifest,
  acceptedImportReceipt: PortableStateImportReceipt,
): StateActionExpectation {
  // This builder checks cross-artifact binding only. The source AEB must first
  // authenticate it with verifyPortableStateImportReceiptForManifest under
  // pinned recipient keys, then authorize and consume the returned action.
  if (!['ACCEPTED', 'PARTIAL'].includes(acceptedImportReceipt.result)
      || acceptedImportReceipt.handoff_id !== manifest.handoff_id
      || acceptedImportReceipt.manifest_digest !== stateHandoffDigest(manifest)
      || acceptedImportReceipt.importer_boundary_id !== manifest.recipient_boundary_id
      || !acceptedImportReceipt.admission_record_digest) {
    throw new TypeError('source retirement requires a matching accepted import receipt');
  }
  const acceptedSet = new Set(acceptedImportReceipt.accepted_object_ids);
  const unavailableSet = new Set(acceptedImportReceipt.unavailable_objects.map((entry) => entry.object_id));
  const manifestIds = manifest.objects.map((entry) => entry.object_id);
  if (acceptedSet.size !== acceptedImportReceipt.accepted_object_ids.length
      || unavailableSet.size !== acceptedImportReceipt.unavailable_objects.length
      || acceptedImportReceipt.accepted_object_ids.some((objectId) => !manifestIds.includes(objectId))
      || acceptedImportReceipt.unavailable_objects.some((entry) => {
        const descriptor = manifest.objects.find((candidate) => candidate.object_id === entry.object_id);
        return !descriptor || descriptor.required || acceptedSet.has(entry.object_id);
      })
      || acceptedSet.size + unavailableSet.size !== manifest.objects.length
      || manifestIds.some((objectId) => !acceptedSet.has(objectId) && !unavailableSet.has(objectId))) {
    throw new TypeError('source retirement receipt does not partition the manifest state set');
  }
  const retirementSetDigest = stateHandoffDigest(manifest.objects
    .filter((entry) => acceptedSet.has(entry.object_id))
    .map((entry) => ({ object_id: entry.object_id, object_digest: entry.object_digest })));
  return stateActionExpectation(
    manifest,
    PORTABLE_STATE_ACTIONS.RETIRE_SOURCE,
    stateHandoffDigest(acceptedImportReceipt),
    retirementSetDigest,
  );
}
