// SPDX-License-Identifier: Apache-2.0
/**
 * Revision-pinned APS policy-decision adapter for AEB-ADAPTER-v1.
 *
 * Source lock: draft-pidlisnyi-aps-03.
 *
 * The adapter verifies an APS action-intent -> policy-decision chain, including
 * exact action_ref and DecisionRefV1 recomputation. Delegation semantics are
 * supplied by a pure relying-party-pinned authority verifier; an enforcement
 * boundary's signature is never treated as proof of its own authority claim.
 * A verified APS permit remains evidence. AEB decides sufficiency and Gate
 * owns atomic consumption and execution authorization.
 */
import crypto, { type KeyObject } from 'node:crypto';

// @ts-expect-error -- governed JavaScript implementation, runtime checked.
import { computeCaid } from '../vendor/caid.mjs';
import {
  canonicalizeAeb,
  digestAeb,
  type Acceptance,
  type AebAdapter,
  type AebAdapterInput,
  type AebDigest,
  type AebMappingResult,
  type AebNativeResult,
  type AebPinnedProfile,
  type AebStatusInput,
} from './aeb-adapter-contract.js';

type Obj = Record<string, unknown>;

export const APS_DRAFT_REVISION = 'draft-pidlisnyi-aps-03';
export const APS_AEB_ADAPTER_ID = 'native:aps-policy-decision';
export const APS_AEB_ADAPTER_VERSION = '1';
export const APS_AEB_CONFIG_VERSION = 'AEB-APS-CONFIG-v1';
export const APS_TRUST_ROOT_VERSION = 'AEB-APS-ED25519-ROOT-v1';
export const APS_CAID_MAPPING_VERSION = 'AEB-APS-CAID-MAPPING-v1';
export const APS_CAID_MAPPER_ID = 'mapper:aps-exact-action-v1';

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const HEX_32_RE = /^[0-9a-f]{64}$/;
const HEX_64_RE = /^[0-9a-f]{128}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9_.:@/#-]{0,511}$/;
const UTC_MILLIS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const NONCE_RE = /^[0-9a-f]{32}$/;
const CONFIG_KEYS = new Set([
  '@version', 'evidence_role', 'subject', 'action_type', 'authority_verifier',
  'clock_skew_seconds', 'max_receipt_age_seconds', 'max_status_age_seconds',
]);
const SUBJECT_KEYS = new Set(['id', 'kind', 'native_id']);
const VERIFIER_DESCRIPTOR_KEYS = new Set(['id', 'version', 'implementation_digest']);
const ROOT_KEYS = new Set(['@version', 'signer', 'key_id', 'public_key']);
const STATUS_KEYS = new Set([
  'checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed', 'unavailable',
]);
const ARTIFACT_KEYS = new Set([
  'action_input', 'payload', 'action_intent', 'policy_decision', 'decision_material',
]);
const ACTION_INPUT_KEYS = new Set([
  'profile', 'agent_id', 'action_type', 'target', 'payload_ref', 'scope_required',
  'issued_at', 'nonce',
]);
const EXPECTED_ACTION_KEYS = new Set(['action_type', 'aps_action']);
const APS_ACTION_KEYS = new Set([
  'profile', 'agent_id', 'action_type', 'target', 'payload', 'scope_required', 'issued_at', 'nonce',
]);
const DECISION_MATERIAL_KEYS = new Set(['authority_state', 'policy_input', 'decision_context']);
const INTENT_KEYS = new Set([
  'profile', 'receipt_id', 'receipt_type', 'issuer', 'subject_agent', 'action_ref',
  'delegation_ref', 'issued_at', 'evidence_refs', 'result', 'signatures',
]);
const DECISION_KEYS = new Set([
  'profile', 'receipt_id', 'receipt_type', 'issuer', 'subject_agent', 'action_ref',
  'delegation_ref', 'decision_ref', 'issued_at', 'prev', 'evidence_refs', 'result', 'signatures',
]);
const INTENT_RESULT_KEYS = new Set(['profile', 'status']);
const DECISION_RESULT_KEYS = new Set([
  'profile', 'verdict', 'effective_authority_ref', 'constraints', 'valid_until',
]);
const SIGNATURE_KEYS = new Set(['signer', 'key_id', 'alg', 'value']);
const MAPPING_KEYS = new Set([
  '@version', 'native_protocol', 'projection', 'action_type', 'suite', 'definitions',
]);

export interface ApsAuthorityVerifierDescriptor {
  id: string;
  version: string;
  implementation_digest: AebDigest;
}

export interface ApsAuthorityVerificationInput {
  authority_state: unknown;
  delegation_ref: string;
  effective_authority_ref: string;
  subject_agent: string;
  issued_at: string;
  now: string;
}

export interface ApsAuthorityVerifier extends ApsAuthorityVerifierDescriptor {
  verify(input: ApsAuthorityVerificationInput): { verified: boolean; reason: string | null };
}

export interface ApsAdapterConfig {
  '@version': typeof APS_AEB_CONFIG_VERSION;
  evidence_role: string;
  subject: { id: string; kind: 'organization' | 'system'; native_id: string };
  action_type: string;
  authority_verifier: ApsAuthorityVerifierDescriptor;
  clock_skew_seconds: number;
  max_receipt_age_seconds: number;
  max_status_age_seconds: number;
}

export interface ApsTrustRoot {
  '@version': typeof APS_TRUST_ROOT_VERSION;
  signer: string;
  key_id: string;
  /** Canonical unpadded base64url DER SubjectPublicKeyInfo. */
  public_key: string;
}

export interface ApsConstructorPins {
  config: ApsAdapterConfig;
  trust_roots: readonly ApsTrustRoot[];
  authority_verifier: ApsAuthorityVerifier;
}

interface ParsedRoot extends ApsTrustRoot { key: KeyObject }
interface ParsedPins {
  config: ApsAdapterConfig;
  roots: ParsedRoot[];
  authorityVerifier: ApsAuthorityVerifier;
  configDigest: AebDigest;
  rootsDigest: AebDigest;
}

function isRecord(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Obj, keys: ReadonlySet<string>): boolean {
  return Object.keys(value).length === keys.size && Object.keys(value).every((key) => keys.has(key));
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && !/[\u0000-\u001f\u007f]/.test(value);
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function safeDigest(value: unknown): AebDigest {
  try { return digestAeb(value); } catch { return digestAeb({ invalid_native_value: true }); }
}

function domainHash(tag: string, value: unknown): string {
  return crypto.createHash('sha256')
    .update(Buffer.from(tag, 'ascii'))
    .update(Buffer.from([0]))
    .update(Buffer.from(canonicalizeAeb(value), 'utf8'))
    .digest('hex');
}

export function computeApsPayloadRef(payload: unknown): string {
  return domainHash('APS-ACTION-PAYLOAD-V1', payload);
}

export function computeApsActionRef(inputObject: unknown): string {
  return domainHash('APS-ACTION-REF-V2', inputObject);
}

export function computeApsReceiptId(receipt: unknown): string {
  if (!isRecord(receipt)) throw new TypeError('APS receipt must be an object');
  const body: Obj = {};
  for (const [key, value] of Object.entries(receipt)) {
    if (key !== 'receipt_id' && key !== 'signatures') body[key] = value;
  }
  return domainHash('APS-RECEIPT-ID-V1', body);
}

export function computeApsDecisionRef(input: {
  action_ref: string;
  authority_state: unknown;
  policy_input: unknown;
  decision_context: unknown;
  decision_output: unknown;
}): string {
  const decisionRefInput = {
    profile: 'aps-decision-ref-v1',
    action_ref: input.action_ref,
    authority_state_ref: domainHash('APS-DECISION-AUTHORITY-V1', input.authority_state),
    policy_ref: domainHash('APS-DECISION-POLICY-V1', input.policy_input),
    context_ref: domainHash('APS-DECISION-CONTEXT-V1', input.decision_context),
    decision_output_ref: domainHash('APS-DECISION-OUTPUT-V1', input.decision_output),
  };
  return domainHash('APS-DECISION-REF-V1', decisionRefInput);
}

function parseUtcMillis(value: unknown): number {
  if (typeof value !== 'string' || !UTC_MILLIS_RE.test(value)) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : NaN;
}

function parseInstant(value: unknown): number {
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)) return NaN;
  return Date.parse(value);
}

function canonicalB64url(value: unknown): value is string {
  if (typeof value !== 'string' || !B64URL_RE.test(value) || value.length % 4 === 1) return false;
  try {
    const bytes = Buffer.from(value, 'base64url');
    return bytes.length > 0 && bytes.toString('base64url') === value;
  } catch { return false; }
}

function utf8Compare(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function canonicalStrings(value: unknown, allowEmpty = true): value is string[] {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)
      || !value.every((entry) => nonEmptyString(entry) && entry.normalize('NFC') === entry)
      || new Set(value).size !== value.length) return false;
  return value.every((entry, index) => index === 0 || utf8Compare(value[index - 1], entry) < 0);
}

function parseConfig(value: unknown): ApsAdapterConfig | null {
  if (!isRecord(value) || !exactKeys(value, CONFIG_KEYS)
      || value['@version'] !== APS_AEB_CONFIG_VERSION
      || typeof value.evidence_role !== 'string' || !IDENTIFIER_RE.test(value.evidence_role)
      || !isRecord(value.subject) || !exactKeys(value.subject, SUBJECT_KEYS)
      || typeof value.subject.id !== 'string' || !IDENTIFIER_RE.test(value.subject.id)
      || !['organization', 'system'].includes(String(value.subject.kind))
      || !nonEmptyString(value.subject.native_id)
      || typeof value.action_type !== 'string' || !ACTION_TYPE_RE.test(value.action_type)
      || !isRecord(value.authority_verifier) || !exactKeys(value.authority_verifier, VERIFIER_DESCRIPTOR_KEYS)
      || !nonEmptyString(value.authority_verifier.id)
      || !nonEmptyString(value.authority_verifier.version)
      || typeof value.authority_verifier.implementation_digest !== 'string'
      || !DIGEST_RE.test(value.authority_verifier.implementation_digest)
      || !nonNegativeInteger(value.clock_skew_seconds)
      || !nonNegativeInteger(value.max_receipt_age_seconds)
      || value.max_receipt_age_seconds < 1
      || !nonNegativeInteger(value.max_status_age_seconds)) return null;
  return structuredClone(value) as unknown as ApsAdapterConfig;
}

function parseRoots(value: readonly unknown[]): ParsedRoot[] | null {
  if (!Array.isArray(value) || value.length < 2) return null;
  const roots: ParsedRoot[] = [];
  const identities = new Set<string>();
  for (const candidate of value) {
    if (!isRecord(candidate) || !exactKeys(candidate, ROOT_KEYS)
        || candidate['@version'] !== APS_TRUST_ROOT_VERSION
        || !nonEmptyString(candidate.signer) || !nonEmptyString(candidate.key_id)
        || !canonicalB64url(candidate.public_key)) return null;
    const identity = `${candidate.signer}\0${candidate.key_id}`;
    if (identities.has(identity)) return null;
    let key: KeyObject;
    try {
      const bytes = Buffer.from(candidate.public_key, 'base64url');
      key = crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
      if (key.asymmetricKeyType !== 'ed25519'
          || !key.export({ type: 'spki', format: 'der' }).equals(bytes)) return null;
    } catch { return null; }
    identities.add(identity);
    roots.push({ ...(structuredClone(candidate) as unknown as ApsTrustRoot), key });
  }
  return roots;
}

function parsePins(value: ApsConstructorPins): ParsedPins {
  const config = parseConfig(value?.config);
  const roots = parseRoots(value?.trust_roots);
  const verifier = value?.authority_verifier;
  if (!config || !roots || !verifier || typeof verifier.verify !== 'function'
      || verifier.id !== config.authority_verifier.id
      || verifier.version !== config.authority_verifier.version
      || verifier.implementation_digest !== config.authority_verifier.implementation_digest) {
    throw new TypeError('invalid APS constructor pins');
  }
  return {
    config,
    roots,
    authorityVerifier: verifier,
    configDigest: safeDigest(config),
    rootsDigest: safeDigest(value.trust_roots),
  };
}

function statusDigest(status: AebStatusInput): AebDigest {
  return safeDigest({
    checked_at: status?.checked_at,
    expires_at: status?.expires_at,
    revocation_checked: status?.revocation_checked,
    revoked: status?.revoked,
    consumed: status?.consumed,
    unavailable: status?.unavailable === true,
  });
}

function statusDisposition(
  status: AebStatusInput,
  now: string,
  maxAgeSeconds: number,
): { acceptance: Acceptance; reasons: string[] } {
  if (!isRecord(status)
      || !(Object.keys(status).every((key) => STATUS_KEYS.has(key)))
      || !['checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed']
        .every((key) => Object.hasOwn(status, key))) {
    return { acceptance: 'INDETERMINATE', reasons: ['status_malformed'] };
  }
  const reasons: string[] = [];
  if (status.unavailable === true) reasons.push('status_unavailable');
  if (status.revoked === true) reasons.push('evidence_revoked');
  if (status.consumed === true) reasons.push('evidence_consumed');
  if (status.revocation_checked !== true) reasons.push('revocation_not_checked');
  const nowMs = parseInstant(now);
  const checked = parseInstant(status.checked_at);
  const expires = parseInstant(status.expires_at);
  if (!Number.isFinite(nowMs) || !Number.isFinite(checked) || !Number.isFinite(expires)) {
    reasons.push('status_time_indeterminate');
  } else {
    const age = Math.floor((nowMs - checked) / 1000);
    if (checked > nowMs) reasons.push('status_checked_in_future');
    if (checked >= expires || nowMs >= expires) reasons.push('status_expired');
    if (age < 0 || age > maxAgeSeconds) reasons.push('status_too_old');
  }
  const unique = [...new Set(reasons)].sort();
  if (status.revoked === true || status.consumed === true) {
    return { acceptance: 'REJECTED', reasons: unique };
  }
  return unique.length === 0
    ? { acceptance: 'ACCEPTED', reasons: [] }
    : { acceptance: 'INDETERMINATE', reasons: unique };
}

function validActionInput(value: unknown): value is Obj {
  return isRecord(value) && exactKeys(value, ACTION_INPUT_KEYS)
    && value.profile === 'aps-action-ref-v2'
    && nonEmptyString(value.agent_id)
    && nonEmptyString(value.action_type)
    && nonEmptyString(value.target)
    && typeof value.payload_ref === 'string' && HEX_32_RE.test(value.payload_ref)
    && canonicalStrings(value.scope_required)
    && Number.isFinite(parseUtcMillis(value.issued_at))
    && typeof value.nonce === 'string' && NONCE_RE.test(value.nonce);
}

function materialFromExpected(value: unknown, config: ApsAdapterConfig): { input: Obj; payload: unknown } | null {
  if (!isRecord(value) || !exactKeys(value, EXPECTED_ACTION_KEYS)
      || value.action_type !== config.action_type
      || !isRecord(value.aps_action) || !exactKeys(value.aps_action, APS_ACTION_KEYS)
      || value.aps_action.profile !== 'aps-action-ref-v2'
      || !nonEmptyString(value.aps_action.agent_id)
      || !nonEmptyString(value.aps_action.action_type)
      || !nonEmptyString(value.aps_action.target)
      || !canonicalStrings(value.aps_action.scope_required)
      || !Number.isFinite(parseUtcMillis(value.aps_action.issued_at))
      || typeof value.aps_action.nonce !== 'string' || !NONCE_RE.test(value.aps_action.nonce)) return null;
  try {
    canonicalizeAeb(value.aps_action.payload);
    return {
      input: {
        profile: value.aps_action.profile,
        agent_id: value.aps_action.agent_id,
        action_type: value.aps_action.action_type,
        target: value.aps_action.target,
        payload_ref: computeApsPayloadRef(value.aps_action.payload),
        scope_required: value.aps_action.scope_required,
        issued_at: value.aps_action.issued_at,
        nonce: value.aps_action.nonce,
      },
      payload: value.aps_action.payload,
    };
  } catch { return null; }
}

function validSignatures(receipt: Obj, roots: ParsedRoot[]): boolean {
  if (!Array.isArray(receipt.signatures) || receipt.signatures.length < 1) return false;
  let prior: string | null = null;
  let issuerSigned = false;
  const unsigned = structuredClone(receipt) as Obj;
  delete unsigned.signatures;
  for (const signature of receipt.signatures) {
    if (!isRecord(signature) || !exactKeys(signature, SIGNATURE_KEYS)
        || !nonEmptyString(signature.signer) || !nonEmptyString(signature.key_id)
        || signature.alg !== 'Ed25519'
        || typeof signature.value !== 'string' || !HEX_64_RE.test(signature.value)) return false;
    const identity = `${signature.signer}\0${signature.key_id}`;
    if (prior !== null && utf8Compare(prior, identity) >= 0) return false;
    prior = identity;
    const root = roots.find((candidate) => candidate.signer === signature.signer
      && candidate.key_id === signature.key_id);
    if (!root) return false;
    const descriptor = { signer: signature.signer, key_id: signature.key_id, alg: 'Ed25519' };
    const bytes = Buffer.concat([
      Buffer.from('APS-RECEIPT-SIG-V1\0', 'utf8'),
      Buffer.from(canonicalizeAeb({ receipt: unsigned, signer: descriptor }), 'utf8'),
    ]);
    if (!crypto.verify(null, bytes, root.key, Buffer.from(signature.value, 'hex'))) return false;
    if (signature.signer === receipt.issuer) issuerSigned = true;
  }
  return issuerSigned;
}

function validReceiptCommon(receipt: Obj, roots: ParsedRoot[]): string | null {
  if (typeof receipt.receipt_id !== 'string' || !HEX_32_RE.test(receipt.receipt_id)
      || receipt.profile !== 'aps-receipt-v1'
      || !nonEmptyString(receipt.issuer)
      || !nonEmptyString(receipt.subject_agent)
      || typeof receipt.action_ref !== 'string' || !HEX_32_RE.test(receipt.action_ref)
      || typeof receipt.delegation_ref !== 'string' || !DIGEST_RE.test(receipt.delegation_ref)
      || !Number.isFinite(parseUtcMillis(receipt.issued_at))
      || !Array.isArray(receipt.evidence_refs) || receipt.evidence_refs.length !== 0) {
    return 'aps:receipt_schema_invalid';
  }
  if (computeApsReceiptId(receipt) !== receipt.receipt_id) return 'aps:receipt_id_mismatch';
  if (!validSignatures(receipt, roots)) return 'aps:receipt_signature_invalid';
  return null;
}

function fallbackNative(input: Omit<AebAdapterInput, 'profile'>, pins: ParsedPins): AebNativeResult {
  const evidenceDigest = safeDigest(input?.artifact);
  return {
    native_verification: 'FAILED',
    acceptance: 'INDETERMINATE',
    evidence_digest: evidenceDigest,
    status_digest: statusDigest(input?.status),
    evidence_role: pins.config.evidence_role,
    subject: { id: pins.config.subject.id, kind: pins.config.subject.kind },
    replay_unit: evidenceDigest,
    reasons: [],
  };
}

function reject(result: AebNativeResult, reason: string): AebNativeResult {
  result.acceptance = 'REJECTED';
  result.reasons = [reason];
  return result;
}

function verifyNative(input: Omit<AebAdapterInput, 'profile'>, pins: ParsedPins): AebNativeResult {
  const result = fallbackNative(input, pins);
  if (safeDigest(input.adapter_config) !== pins.configDigest
      || safeDigest(input.trust_roots) !== pins.rootsDigest) {
    return reject(result, 'aps:constructor_pin_mismatch');
  }
  const expected = materialFromExpected(input.expected_action, pins.config);
  if (!expected) {
    result.reasons = ['aps:missing_or_ambiguous_exact_action'];
    return result;
  }
  if (!isRecord(input.artifact) || !exactKeys(input.artifact, ARTIFACT_KEYS)
      || !validActionInput(input.artifact.action_input)
      || !isRecord(input.artifact.action_intent)
      || !isRecord(input.artifact.policy_decision)
      || !isRecord(input.artifact.decision_material)
      || !exactKeys(input.artifact.decision_material, DECISION_MATERIAL_KEYS)) {
    return reject(result, 'aps:artifact_schema_invalid');
  }
  const artifact = input.artifact as Obj;
  const actionInput = artifact.action_input as Obj;
  const intent = artifact.action_intent as Obj;
  const decision = artifact.policy_decision as Obj;
  const decisionMaterial = artifact.decision_material as Obj;
  if (computeApsPayloadRef(artifact.payload) !== actionInput.payload_ref) {
    return reject(result, 'aps:payload_ref_mismatch');
  }
  if (safeDigest(expected.input) !== safeDigest(artifact.action_input)
      || safeDigest(expected.payload) !== safeDigest(artifact.payload)) {
    return reject(result, 'aps:exact_action_mismatch');
  }
  const actionRef = computeApsActionRef(actionInput);
  if (!exactKeys(intent, INTENT_KEYS)
      || intent.receipt_type !== 'aps:action-intent:v1'
      || !isRecord(intent.result) || !exactKeys(intent.result, INTENT_RESULT_KEYS)
      || intent.result.profile !== 'aps-action-intent-result-v1'
      || intent.result.status !== 'declared') return reject(result, 'aps:intent_schema_invalid');
  const intentFailure = validReceiptCommon(intent, pins.roots);
  if (intentFailure) return reject(result, intentFailure);
  if (intent.issuer !== actionInput.agent_id
      || intent.subject_agent !== actionInput.agent_id
      || intent.action_ref !== actionRef
      || intent.issued_at !== actionInput.issued_at) {
    return reject(result, 'aps:intent_binding_mismatch');
  }
  if (!exactKeys(decision, DECISION_KEYS)
      || decision.receipt_type !== 'aps:policy-decision:v1'
      || !isRecord(decision.result) || !exactKeys(decision.result, DECISION_RESULT_KEYS)) {
    return reject(result, 'aps:decision_schema_invalid');
  }
  const decisionFailure = validReceiptCommon(decision, pins.roots);
  if (decisionFailure) return reject(result, decisionFailure);
  if (decision.issuer !== pins.config.subject.native_id
      || decision.subject_agent !== actionInput.agent_id
      || decision.action_ref !== actionRef
      || decision.delegation_ref !== intent.delegation_ref
      || decision.prev !== intent.receipt_id) {
    return reject(result, 'aps:decision_chain_mismatch');
  }
  const output = decision.result as Obj;
  if (output.profile !== 'aps-core-decision-output-v1'
      || !['permit', 'narrow'].includes(String(output.verdict))
      || typeof output.effective_authority_ref !== 'string'
      || !HEX_32_RE.test(output.effective_authority_ref)
      || !canonicalStrings(output.constraints)
      || !Number.isFinite(parseUtcMillis(output.valid_until))) {
    return reject(result, output.verdict === 'deny' ? 'aps:native_decision_denied' : 'aps:decision_output_invalid');
  }
  const nowMs = parseInstant(input.now);
  const actionIssued = parseUtcMillis(actionInput.issued_at);
  const intentIssued = parseUtcMillis(intent.issued_at);
  const decisionIssued = parseUtcMillis(decision.issued_at);
  const validUntil = parseUtcMillis(output.valid_until);
  if (!Number.isFinite(nowMs)) {
    result.reasons = ['aps:verification_time_invalid'];
    return result;
  }
  if (intentIssued !== actionIssued || decisionIssued < intentIssued
      || decisionIssued > nowMs + pins.config.clock_skew_seconds * 1000
      || validUntil <= decisionIssued || nowMs >= validUntil
      || nowMs - decisionIssued > pins.config.max_receipt_age_seconds * 1000) {
    return reject(result, 'aps:receipt_time_invalid');
  }
  const computedDecisionRef = computeApsDecisionRef({
    action_ref: actionRef,
    authority_state: decisionMaterial.authority_state,
    policy_input: decisionMaterial.policy_input,
    decision_context: decisionMaterial.decision_context,
    decision_output: output,
  });
  if (decision.decision_ref !== computedDecisionRef) {
    return reject(result, 'aps:decision_ref_mismatch');
  }
  let authority: { verified: boolean; reason: string | null };
  try {
    authority = pins.authorityVerifier.verify({
      authority_state: decisionMaterial.authority_state,
      delegation_ref: String(decision.delegation_ref),
      effective_authority_ref: String(output.effective_authority_ref),
      subject_agent: String(decision.subject_agent),
      issued_at: String(decision.issued_at),
      now: input.now,
    });
  } catch {
    result.reasons = ['aps:authority_verifier_error'];
    return result;
  }
  if (!authority || authority.verified !== true) {
    return reject(result, `aps:${nonEmptyString(authority?.reason) ? authority.reason : 'authority_not_verified'}`);
  }
  result.replay_unit = safeDigest({
    protocol: APS_DRAFT_REVISION,
    policy_decision_receipt_id: decision.receipt_id,
  });
  result.native_verification = 'VERIFIED';
  const status = statusDisposition(input.status, input.now, pins.config.max_status_age_seconds);
  result.acceptance = status.acceptance;
  result.reasons = status.reasons;
  return result;
}

export function createApsActionDefinition(actionType: string): Obj {
  if (!ACTION_TYPE_RE.test(actionType)) throw new TypeError('invalid APS action type');
  return {
    '@version': APS_CAID_MAPPING_VERSION,
    native_protocol: APS_DRAFT_REVISION,
    projection: 'aps-exact-action-v1',
    action_type: actionType,
    suite: 'jcs-sha256',
    definitions: [{
      action_type: actionType,
      required_fields: [
        { name: 'action_type', type: 'string' },
        { name: 'aps_action', type: 'object' },
      ],
      optional_fields: [],
    }],
  };
}

function validMappingProfile(profile: AebPinnedProfile, config: ApsAdapterConfig): boolean {
  return isRecord(profile)
    && profile.version === APS_CAID_MAPPING_VERSION
    && profile.mapper_id === APS_CAID_MAPPER_ID
    && isRecord(profile.resolver)
    && profile.resolver.id === APS_CAID_MAPPER_ID
    && profile.resolver.version === '1'
    && typeof profile.resolver.implementation_digest === 'string'
    && DIGEST_RE.test(profile.resolver.implementation_digest)
    && isRecord(profile.semantic_equivalence)
    && profile.semantic_equivalence.assertion === 'EQUIVALENT_UNDER_PROFILE'
    && profile.semantic_equivalence.loss_policy === 'NO_MATERIAL_FIELD_LOSS'
    && Array.isArray(profile.semantic_equivalence.omitted_material_fields)
    && profile.semantic_equivalence.omitted_material_fields.length === 0
    && Array.isArray(profile.semantic_equivalence.omitted_nonmaterial_fields)
    && isRecord(profile.definition)
    && exactKeys(profile.definition, MAPPING_KEYS)
    && safeDigest(profile.definition) === safeDigest(createApsActionDefinition(config.action_type));
}

function mapAction(input: AebAdapterInput & { native: AebNativeResult }, pins: ParsedPins): AebMappingResult {
  if (input.native.native_verification !== 'VERIFIED' || input.native.acceptance !== 'ACCEPTED') {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
  }
  if (safeDigest(input.adapter_config) !== pins.configDigest
      || safeDigest(input.trust_roots) !== pins.rootsDigest) {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_constructor_pin_mismatch'] };
  }
  if (!validMappingProfile(input.profile, pins.config)) {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_invalid'] };
  }
  if (!materialFromExpected(input.expected_action, pins.config)) {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['missing_or_ambiguous_exact_action'] };
  }
  const actionDigest = safeDigest(input.expected_action);
  let computed: unknown;
  try {
    computed = computeCaid(input.expected_action, {
      suite: 'jcs-sha256',
      definitions: (input.profile.definition as Obj).definitions,
    });
  } catch { computed = null; }
  if (!isRecord(computed) || typeof computed.caid !== 'string'
      || typeof computed.digest !== 'string' || !DIGEST_RE.test(computed.digest)) {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_mapping_failed'] };
  }
  if (computed.digest !== actionDigest) {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_digest_disagreement'] };
  }
  return { mapping: 'MATCH', caid: computed.caid, action_digest: actionDigest, reasons: [] };
}

export function createApsAebAdapter(constructorPins: ApsConstructorPins): AebAdapter {
  const pins = parsePins(constructorPins);
  return Object.freeze({
    id: APS_AEB_ADAPTER_ID,
    version: APS_AEB_ADAPTER_VERSION,
    verifyNative(input: Omit<AebAdapterInput, 'profile'>): AebNativeResult {
      try { return verifyNative(input, pins); } catch {
        const result = fallbackNative(input, pins);
        result.reasons = ['aps:unexpected_adapter_error'];
        return result;
      }
    },
    mapAction(input: AebAdapterInput & { native: AebNativeResult }): AebMappingResult {
      try { return mapAction(input, pins); } catch {
        return {
          mapping: 'INDETERMINATE', caid: null, action_digest: null,
          reasons: ['aps:unexpected_mapping_error'],
        };
      }
    },
  });
}
