// SPDX-License-Identifier: Apache-2.0
/**
 * EP-ACTION-REMEDY-RECEIPT-v1
 *
 * A portable, offline-verifiable operator receipt over one exact Remedy
 * Program state snapshot. The receipt preserves the original effect as an
 * immutable fact and describes a later remedy only as a compensating action.
 * It never claims that the original effect was rolled back or erased.
 */
import crypto from 'node:crypto';

import { canonicalize } from '../execution-binding.js';
// Opt-in FIPS operation-policy consult at the receipt signer call site (see
// issueRemedyProgramReceipt below). A genuine declared dependency of
// @emilia-protocol/gate, same as @emilia-protocol/verify/pq-signature-agility
// elsewhere in this package.
import { checkOperationPolicy, type FipsPosture } from '@emilia-protocol/verify/fips-mode';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  type AgileSigningKey,
  type AgileSignature,
  type AgilityOptions,
} from '@emilia-protocol/verify/pq-signature-agility';

export const ACTION_REMEDY_RECEIPT_VERSION = 'EP-ACTION-REMEDY-RECEIPT-v1';
export const REMEDY_PROGRAM_RECEIPT_VERSION = ACTION_REMEDY_RECEIPT_VERSION;
export const ACTION_REMEDY_RECEIPT_DOMAIN = `${ACTION_REMEDY_RECEIPT_VERSION}\0`;

const REMEDY_PROGRAM_VERSION = 'EP-GATE-REMEDY-PROGRAM-PROFILE-v1';
/** See the EP-ACTION-REMEDY-RECEIPT-v2 header for why v2 accepts both. */
export const REMEDY_PROGRAM_PROFILE_V2_VERSION = 'EP-GATE-REMEDY-PROGRAM-PROFILE-v2';
const REMEDY_PROGRAM_PROFILE_V1_ONLY: ReadonlySet<string> = new Set([REMEDY_PROGRAM_VERSION]);
const REMEDY_PROGRAM_PROFILE_V1_OR_V2: ReadonlySet<string> = new Set([
  REMEDY_PROGRAM_VERSION, REMEDY_PROGRAM_PROFILE_V2_VERSION,
]);
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CAID = /^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,255}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const FORBIDDEN_FIELD_NAMES = new Set(['__proto__', 'prototype', 'constructor']);
const MAX_CONTEXT_BYTES = 512;
const MAX_REMEDIES = 1024;

const TOP_KEYS = new Set(['version', 'issuer', 'payload', 'content_digest', 'signature']);
const ISSUER_KEYS = new Set(['issuer', 'tenant', 'environment', 'audience', 'key_id']);
const PAYLOAD_KEYS = new Set([
  'case', 'original_effect', 'original_reconciliation', 'remedy', 'semantics',
]);
const CASE_KEYS = new Set([
  'instance_id', 'revision', 'status', 'state_snapshot_digest', 'updated_at',
]);
const ORIGINAL_KEYS = new Set([
  'caid', 'action_digest', 'operation_id', 'consequence_mode',
  'consequence_digest', 'terminal_evidence_digest', 'outcome', 'occurred_at',
  'evidence_digest',
]);
const REMEDY_KEYS = new Set([
  'operation_id', 'caid', 'action_digest', 'destination_binding_digest',
  'units', 'unit', 'owner_mode', 'owner_digest', 'status', 'outcome',
]);
const SEMANTICS_KEYS = new Set(['original_effect', 'remedy_effect', 'rollback']);
const SIGNATURE_KEYS = new Set(['algorithm', 'value']);
const EXPECTED_KEYS = new Set([
  'original_operation_id', 'original_action_digest',
  'original_terminal_evidence_digest', 'case_instance_id', 'case_revision',
  'case_status', 'remedy_operation_id', 'remedy_action_digest', 'remedy_caid',
  'destination_binding_digest', 'units', 'unit', 'owner_mode', 'owner_digest',
]);
const STATE_KEYS = new Set([
  'version', 'instance_id', 'tenant_id', 'environment', 'audience', 'status',
  'revision', 'created_at', 'updated_at', 'original', 'remedy_profile_digest',
  'destination_binding_digest', 'max_remedy_units', 'unit', 'remedied_units',
  'remaining_units', 'used_evidence_ids', 'used_evidence_digests',
  'original_reconciliation', 'revocation', 'dispute', 'active_remedy',
  'remedies', 'resolution',
  'create_request_digest',
]);
const ATTEMPT_KEYS = new Set([
  'evidence_id', 'evidence_digest', 'dispute_id', 'original_operation_id',
  'remedy_operation_id', 'remedy_caid', 'remedy_action_digest',
  'consequence_mode', 'capability_template_digest', 'escrow_profile_digest',
  'destination_binding_digest', 'units', 'unit', 'authorized_at',
  'request_digest', 'status', 'claim_token_digest', 'claimed_at',
  'claim_request_digest', 'outcome', 'outcome_evidence',
  'finalize_request_digest', 'reconciliation', 'reconcile_request_digest',
]);
const OUTCOME_EVIDENCE_KEYS = new Set([
  'evidence_id', 'evidence_digest', 'remedy_operation_id',
  'remedy_action_digest', 'destination_binding_digest', 'units', 'unit',
  'outcome', 'observed_at',
]);
const DISPUTE_KEYS = new Set([
  'dispute_id', 'evidence_id', 'evidence_digest', 'challenger_id',
  'requested_units', 'opened_at', 'original_operation_id',
  'original_action_digest', 'request_digest',
]);
const REVOCATION_KEYS = new Set([
  'evidence_id', 'evidence_digest', 'target_operation_id', 'action_digest',
  'authority_id', 'revoked_at', 'effect', 'request_digest',
]);
const RESOLUTION_KEYS = new Set([
  'evidence_id', 'evidence_digest', 'outcome', 'resolved_at', 'dispute_id',
  'request_digest',
]);

const CASE_STATUSES = new Set([
  'effect_executed', 'effect_indeterminate', 'disputed', 'remedy_authorized',
  'remedy_claimed', 'remedy_indeterminate', 'partially_remedied', 'remedied',
  'resolved_no_remedy',
  'original_proved_no_effect',
]);
const REMEDY_STATUSES = new Set([
  'authorized', 'claimed', 'indeterminate', 'executed', 'proved_no_effect',
]);
const REMEDY_OUTCOMES = new Set(['executed', 'proved_no_effect', 'indeterminate']);

type DataRecord = Record<string, any>;

export interface RemedyReceiptExpectedBindings extends Record<string, unknown> {
  original_operation_id: string;
  original_action_digest: string;
  original_terminal_evidence_digest: string;
  case_instance_id: string;
  case_revision: number;
  case_status: string;
  remedy_operation_id: string;
  remedy_action_digest: string;
  remedy_caid: string;
  destination_binding_digest: string;
  units: number;
  unit: string;
  owner_mode: string;
  owner_digest: string;
}

function isRecord(value: unknown): value is DataRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isDataRecord(value: unknown): value is DataRecord {
  return isRecord(value) && Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function exactKeys(value: unknown, keys: Set<string>): value is DataRecord {
  return isDataRecord(value)
    && Reflect.ownKeys(value).length === keys.size
    && Object.keys(value).every((key) => keys.has(key));
}

function assertNoPrototypeNamedFields(value: unknown): void {
  if (value === null || typeof value !== 'object') return;
  const stack: object[] = [value as object];
  const seen = new WeakSet<object>();
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (seen.has(current)) continue;
    seen.add(current);
    for (const key of Reflect.ownKeys(current)) {
      if (typeof key === 'string' && FORBIDDEN_FIELD_NAMES.has(key)) {
        throw new TypeError(`prototype-named field ${key} is forbidden`);
      }
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) continue;
      const child = descriptor.value;
      if (typeof child === 'number' && Object.is(child, -0)) {
        throw new TypeError('negative zero is not canonical JSON');
      }
      if (child !== null && typeof child === 'object') stack.push(child);
    }
  }
}

function canonicalCopy<T>(value: T, label: string): T {
  try {
    assertNoPrototypeNamedFields(value);
    return JSON.parse(canonicalize(value)) as T;
  } catch (error) {
    if (error instanceof TypeError && /prototype-named field/.test(error.message)) throw error;
    throw new TypeError(`${label} must be bounded canonical JSON`);
  }
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (value === null || typeof value !== 'object') return value;
  const stack: object[] = [value as object];
  const seen = new WeakSet<object>();
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (seen.has(current)) continue;
    seen.add(current);
    for (const child of Object.values(current)) {
      if (child !== null && typeof child === 'object') stack.push(child);
    }
    Object.freeze(current);
  }
  return value;
}

function validId(value: unknown): value is string {
  return typeof value === 'string' && ID.test(value)
    && !FORBIDDEN_FIELD_NAMES.has(value);
}

function validContext(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
    && Buffer.byteLength(value, 'utf8') <= MAX_CONTEXT_BYTES
    && !/[\u0000-\u001f\u007f]/.test(value)
    && !FORBIDDEN_FIELD_NAMES.has(value);
}

function strictInstant(value: unknown): number {
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : NaN;
}

function canonicalDigest(value: unknown): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}

function strictBase64url(value: unknown, length?: number): Buffer | null {
  if (typeof value !== 'string' || !BASE64URL.test(value) || value.length % 4 === 1) return null;
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value
      || (length !== undefined && bytes.length !== length)) return null;
  return bytes;
}

function publicKey(value: unknown): crypto.KeyObject | null {
  try {
    if (value instanceof crypto.KeyObject) {
      return value.type === 'public' && value.asymmetricKeyType === 'ed25519' ? value : null;
    }
    const bytes = strictBase64url(value);
    if (!bytes) return null;
    const key = crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function privateKey(value: unknown): crypto.KeyObject {
  try {
    const key = value instanceof crypto.KeyObject ? value : crypto.createPrivateKey(value as any);
    if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') throw new Error('wrong key');
    return key;
  } catch {
    throw new TypeError('remedy receipt private key must be Ed25519');
  }
}

function publicKeyB64u(value: crypto.KeyObject): string {
  return crypto.createPublicKey(value as any)
    .export({ type: 'spki', format: 'der' }).toString('base64url');
}

function canonicalSignature(value: unknown): { bytes: Buffer; encoded: string } {
  const bytes = Buffer.isBuffer(value)
    ? Buffer.from(value)
    : value instanceof Uint8Array ? Buffer.from(value)
      : strictBase64url(value, 64);
  if (!bytes || bytes.length !== 64) {
    throw new TypeError('remedy receipt signer returned a malformed Ed25519 signature');
  }
  const encoded = bytes.toString('base64url');
  if (typeof value === 'string' && value !== encoded) {
    throw new TypeError('remedy receipt signer returned a noncanonical signature');
  }
  return { bytes, encoded };
}

function validOriginal(value: unknown): value is DataRecord {
  return exactKeys(value, ORIGINAL_KEYS)
    && typeof value.caid === 'string' && CAID.test(value.caid)
    && typeof value.action_digest === 'string' && DIGEST.test(value.action_digest)
    && validId(value.operation_id)
    && validContext(value.consequence_mode)
    && typeof value.consequence_digest === 'string' && DIGEST.test(value.consequence_digest)
    && typeof value.terminal_evidence_digest === 'string'
    && DIGEST.test(value.terminal_evidence_digest)
    && ['executed', 'indeterminate'].includes(value.outcome)
    && Number.isFinite(strictInstant(value.occurred_at))
    && typeof value.evidence_digest === 'string' && DIGEST.test(value.evidence_digest);
}

function validOutcomeEvidence(value: unknown): value is DataRecord {
  return exactKeys(value, OUTCOME_EVIDENCE_KEYS)
    && validId(value.evidence_id)
    && typeof value.evidence_digest === 'string' && DIGEST.test(value.evidence_digest)
    && validId(value.remedy_operation_id)
    && typeof value.remedy_action_digest === 'string' && DIGEST.test(value.remedy_action_digest)
    && typeof value.destination_binding_digest === 'string'
    && DIGEST.test(value.destination_binding_digest)
    && Number.isSafeInteger(value.units) && value.units > 0
    && validContext(value.unit)
    && REMEDY_OUTCOMES.has(value.outcome)
    && Number.isFinite(strictInstant(value.observed_at));
}

function ownerDigest(value: DataRecord): string | null {
  if (value.consequence_mode === 'receipt-program'
      && typeof value.capability_template_digest === 'string'
      && DIGEST.test(value.capability_template_digest)
      && value.escrow_profile_digest === null) return value.capability_template_digest;
  if (value.consequence_mode === 'action-escrow'
      && value.capability_template_digest === null
      && typeof value.escrow_profile_digest === 'string'
      && DIGEST.test(value.escrow_profile_digest)) return value.escrow_profile_digest;
  return null;
}

function validNullableDigest(value: unknown): boolean {
  return value === null || (typeof value === 'string' && DIGEST.test(value));
}

function validAttempt(value: unknown): value is DataRecord {
  return exactKeys(value, ATTEMPT_KEYS)
    && validId(value.evidence_id)
    && typeof value.evidence_digest === 'string' && DIGEST.test(value.evidence_digest)
    && validId(value.dispute_id) && validId(value.original_operation_id)
    && validId(value.remedy_operation_id)
    && typeof value.remedy_caid === 'string' && CAID.test(value.remedy_caid)
    && typeof value.remedy_action_digest === 'string' && DIGEST.test(value.remedy_action_digest)
    && ownerDigest(value) !== null
    && typeof value.destination_binding_digest === 'string'
    && DIGEST.test(value.destination_binding_digest)
    && Number.isSafeInteger(value.units) && value.units > 0
    && validContext(value.unit)
    && Number.isFinite(strictInstant(value.authorized_at))
    && typeof value.request_digest === 'string' && DIGEST.test(value.request_digest)
    && REMEDY_STATUSES.has(value.status)
    && validNullableDigest(value.claim_token_digest)
    && (value.claimed_at === null || Number.isFinite(strictInstant(value.claimed_at)))
    && validNullableDigest(value.claim_request_digest)
    && (value.outcome === null || REMEDY_OUTCOMES.has(value.outcome))
    && (value.outcome_evidence === null || validOutcomeEvidence(value.outcome_evidence))
    && validNullableDigest(value.finalize_request_digest)
    && (value.reconciliation === null || validOutcomeEvidence(value.reconciliation))
    && validNullableDigest(value.reconcile_request_digest);
}

function validDispute(value: unknown): boolean {
  return exactKeys(value, DISPUTE_KEYS)
    && validId(value.dispute_id) && validId(value.evidence_id)
    && typeof value.evidence_digest === 'string' && DIGEST.test(value.evidence_digest)
    && validContext(value.challenger_id)
    && Number.isSafeInteger(value.requested_units) && value.requested_units > 0
    && Number.isFinite(strictInstant(value.opened_at))
    && validId(value.original_operation_id)
    && typeof value.original_action_digest === 'string' && DIGEST.test(value.original_action_digest)
    && typeof value.request_digest === 'string' && DIGEST.test(value.request_digest);
}

function validRevocation(value: unknown): boolean {
  return exactKeys(value, REVOCATION_KEYS)
    && validId(value.evidence_id)
    && typeof value.evidence_digest === 'string' && DIGEST.test(value.evidence_digest)
    && validId(value.target_operation_id)
    && typeof value.action_digest === 'string' && DIGEST.test(value.action_digest)
    && validContext(value.authority_id)
    && Number.isFinite(strictInstant(value.revoked_at))
    && value.effect === 'future_authority_only'
    && typeof value.request_digest === 'string' && DIGEST.test(value.request_digest);
}

function validResolution(value: unknown): boolean {
  return exactKeys(value, RESOLUTION_KEYS)
    && validId(value.evidence_id)
    && typeof value.evidence_digest === 'string' && DIGEST.test(value.evidence_digest)
    && value.outcome === 'no_remedy'
    && Number.isFinite(strictInstant(value.resolved_at))
    && validId(value.dispute_id)
    && typeof value.request_digest === 'string' && DIGEST.test(value.request_digest);
}

function validOriginalReconciliation(value: unknown): boolean {
  return exactKeys(value, new Set([
    'evidence_id', 'evidence_digest', 'original_operation_id',
    'original_action_digest', 'terminal_evidence_digest', 'outcome',
    'observed_at', 'request_digest',
  ]))
    && validId(value.evidence_id)
    && typeof value.evidence_digest === 'string' && DIGEST.test(value.evidence_digest)
    && validId(value.original_operation_id)
    && typeof value.original_action_digest === 'string' && DIGEST.test(value.original_action_digest)
    && typeof value.terminal_evidence_digest === 'string' && DIGEST.test(value.terminal_evidence_digest)
    && ['executed', 'proved_no_effect'].includes(value.outcome)
    && Number.isFinite(strictInstant(value.observed_at))
    && typeof value.request_digest === 'string' && DIGEST.test(value.request_digest);
}

function validState(state: unknown): state is DataRecord {
  return validStateUnder(state, REMEDY_PROGRAM_PROFILE_V1_ONLY);
}

/**
 * ONE state-snapshot validation body for both receipt versions. The v1 and v2
 * receipts differ ONLY in which Remedy Program profile markers they will
 * describe, so every structural, arithmetic, and cross-field rule about a
 * remedy case cannot drift between them.
 */
function validStateUnder(state: unknown, allowedProfileVersions: ReadonlySet<string>): state is DataRecord {
  if (!exactKeys(state, STATE_KEYS)
      || typeof state.version !== 'string'
      || !allowedProfileVersions.has(state.version)
      || !validId(state.instance_id)
      || !validContext(state.tenant_id)
      || !validContext(state.environment)
      || !validContext(state.audience)
      || !CASE_STATUSES.has(state.status)
      || !Number.isSafeInteger(state.revision) || state.revision < 0
      || !Number.isFinite(strictInstant(state.created_at))
      || !Number.isFinite(strictInstant(state.updated_at))
      || strictInstant(state.updated_at) < strictInstant(state.created_at)
      || !validOriginal(state.original)
      || typeof state.remedy_profile_digest !== 'string' || !DIGEST.test(state.remedy_profile_digest)
      || typeof state.destination_binding_digest !== 'string'
      || !DIGEST.test(state.destination_binding_digest)
      || !Number.isSafeInteger(state.max_remedy_units) || state.max_remedy_units < 1
      || !validContext(state.unit)
      || !Number.isSafeInteger(state.remedied_units) || state.remedied_units < 0
      || !Number.isSafeInteger(state.remaining_units) || state.remaining_units < 0
      || state.remedied_units + state.remaining_units !== state.max_remedy_units
      || !Array.isArray(state.used_evidence_ids)
      || !state.used_evidence_ids.every(validId)
      || new Set(state.used_evidence_ids).size !== state.used_evidence_ids.length
      || !Array.isArray(state.used_evidence_digests)
      || !state.used_evidence_digests.every((entry: unknown) => (
        typeof entry === 'string' && DIGEST.test(entry)
      ))
      || new Set(state.used_evidence_digests).size !== state.used_evidence_digests.length
      || !Array.isArray(state.remedies) || state.remedies.length > MAX_REMEDIES
      || !state.remedies.every(validAttempt)
      || (state.active_remedy !== null && !validAttempt(state.active_remedy))
      || (state.dispute !== null && !validDispute(state.dispute))
      || (state.revocation !== null && !validRevocation(state.revocation))
      || (state.original_reconciliation !== null
        && !validOriginalReconciliation(state.original_reconciliation))
      || (state.resolution !== null && !validResolution(state.resolution))
      || typeof state.create_request_digest !== 'string'
      || !DIGEST.test(state.create_request_digest)) return false;

  if (state.original_reconciliation !== null
      && (state.original.outcome !== 'indeterminate'
        || state.original_reconciliation.original_operation_id !== state.original.operation_id
        || state.original_reconciliation.original_action_digest !== state.original.action_digest
        || state.original_reconciliation.terminal_evidence_digest !== state.original.terminal_evidence_digest
        || strictInstant(state.original_reconciliation.observed_at) < strictInstant(state.original.occurred_at))) {
    return false;
  }

  const attempts = [
    ...(state.active_remedy === null ? [] : [state.active_remedy]),
    ...state.remedies,
  ];
  return attempts.every((attempt: DataRecord) => (
    attempt.original_operation_id === state.original.operation_id
    && attempt.destination_binding_digest === state.destination_binding_digest
    && attempt.unit === state.unit
  ));
}

function selectAttempt(state: DataRecord, remedyOperationId: string): DataRecord {
  const attempts = [
    ...(state.active_remedy === null ? [] : [state.active_remedy]),
    ...state.remedies,
  ].filter((attempt: DataRecord) => attempt.remedy_operation_id === remedyOperationId);
  if (attempts.length === 0) throw new TypeError('remedy operation is absent from the state snapshot');
  if (attempts.length !== 1) throw new TypeError('remedy operation is not unique in the state snapshot');
  const attempt = attempts[0];
  if (attempt.remedy_operation_id === state.original.operation_id
      || attempt.remedy_action_digest === state.original.action_digest) {
    throw new TypeError('a remedy receipt must describe a compensating action, never rollback');
  }
  return attempt;
}

function expectedBindings(state: DataRecord, attempt: DataRecord): RemedyReceiptExpectedBindings {
  return {
    original_operation_id: state.original.operation_id,
    original_action_digest: state.original.action_digest,
    original_terminal_evidence_digest: state.original.terminal_evidence_digest,
    case_instance_id: state.instance_id,
    case_revision: state.revision,
    case_status: state.status,
    remedy_operation_id: attempt.remedy_operation_id,
    remedy_action_digest: attempt.remedy_action_digest,
    remedy_caid: attempt.remedy_caid,
    destination_binding_digest: attempt.destination_binding_digest,
    units: attempt.units,
    unit: attempt.unit,
    owner_mode: attempt.consequence_mode,
    owner_digest: ownerDigest(attempt)!,
  };
}

function snapshotAndAttempt(
  value: unknown,
  remedyOperationId: unknown,
  allowedProfileVersions: ReadonlySet<string> = REMEDY_PROGRAM_PROFILE_V1_ONLY,
): { state: DataRecord; attempt: DataRecord } {
  const state = canonicalCopy(value, 'remedy state snapshot') as unknown;
  if (!validStateUnder(state, allowedProfileVersions)) throw new TypeError('remedy state snapshot is invalid');
  if (!validId(remedyOperationId)) throw new TypeError('remedyOperationId is invalid');
  return { state, attempt: selectAttempt(state, remedyOperationId) };
}

/** Derive every relying-party binding that must be independently expected. */
export function expectedRemedyProgramReceiptBindings(
  state: unknown,
  remedyOperationId: string,
): Readonly<RemedyReceiptExpectedBindings> {
  const selected = snapshotAndAttempt(state, remedyOperationId);
  return deepFreeze(expectedBindings(selected.state, selected.attempt));
}

function payloadFor(state: DataRecord, attempt: DataRecord): DataRecord {
  return {
    case: {
      instance_id: state.instance_id,
      revision: state.revision,
      status: state.status,
      state_snapshot_digest: canonicalDigest(state),
      updated_at: state.updated_at,
    },
    original_effect: canonicalCopy(state.original, 'original effect'),
    original_reconciliation: state.original_reconciliation === null
      ? null : canonicalCopy(state.original_reconciliation, 'original reconciliation'),
    remedy: {
      operation_id: attempt.remedy_operation_id,
      caid: attempt.remedy_caid,
      action_digest: attempt.remedy_action_digest,
      destination_binding_digest: attempt.destination_binding_digest,
      units: attempt.units,
      unit: attempt.unit,
      owner_mode: attempt.consequence_mode,
      owner_digest: ownerDigest(attempt),
      status: attempt.status,
      outcome: attempt.outcome,
    },
    semantics: {
      original_effect: 'immutable_fact',
      remedy_effect: 'compensating_action',
      rollback: false,
    },
  };
}

function contentBody(receipt: DataRecord): DataRecord {
  return {
    version: receipt.version,
    issuer: receipt.issuer,
    payload: receipt.payload,
  };
}

function signingBody(receipt: DataRecord): DataRecord {
  return {
    ...contentBody(receipt),
    content_digest: receipt.content_digest,
  };
}

/** Return the exact domain-separated canonical bytes signed by Ed25519. */
export function remedyProgramReceiptSigningBytes(receipt: unknown): Buffer {
  if (!isDataRecord(receipt)) throw new TypeError('remedy receipt signing body is invalid');
  return Buffer.from(
    ACTION_REMEDY_RECEIPT_DOMAIN + canonicalize(signingBody(receipt)),
    'utf8',
  );
}

function validIssuer(value: unknown): value is DataRecord {
  return exactKeys(value, ISSUER_KEYS) && Object.values(value).every(validContext);
}

function validExpected(value: unknown): value is RemedyReceiptExpectedBindings {
  return exactKeys(value, EXPECTED_KEYS)
    && validId(value.original_operation_id)
    && typeof value.original_action_digest === 'string' && DIGEST.test(value.original_action_digest)
    && typeof value.original_terminal_evidence_digest === 'string'
    && DIGEST.test(value.original_terminal_evidence_digest)
    && validId(value.case_instance_id)
    && Number.isSafeInteger(value.case_revision) && value.case_revision >= 0
    && CASE_STATUSES.has(value.case_status)
    && validId(value.remedy_operation_id)
    && typeof value.remedy_action_digest === 'string' && DIGEST.test(value.remedy_action_digest)
    && typeof value.remedy_caid === 'string' && CAID.test(value.remedy_caid)
    && typeof value.destination_binding_digest === 'string'
    && DIGEST.test(value.destination_binding_digest)
    && Number.isSafeInteger(value.units) && value.units > 0
    && validContext(value.unit)
    && ['receipt-program', 'action-escrow'].includes(value.owner_mode)
    && typeof value.owner_digest === 'string' && DIGEST.test(value.owner_digest);
}

function validPayload(value: unknown): value is DataRecord {
  return exactKeys(value, PAYLOAD_KEYS)
    && exactKeys(value.case, CASE_KEYS)
    && validId(value.case.instance_id)
    && Number.isSafeInteger(value.case.revision) && value.case.revision >= 0
    && CASE_STATUSES.has(value.case.status)
    && typeof value.case.state_snapshot_digest === 'string'
    && DIGEST.test(value.case.state_snapshot_digest)
    && Number.isFinite(strictInstant(value.case.updated_at))
    && validOriginal(value.original_effect)
    && (value.original_reconciliation === null
      || validOriginalReconciliation(value.original_reconciliation))
    && exactKeys(value.remedy, REMEDY_KEYS)
    && validId(value.remedy.operation_id)
    && typeof value.remedy.caid === 'string' && CAID.test(value.remedy.caid)
    && typeof value.remedy.action_digest === 'string' && DIGEST.test(value.remedy.action_digest)
    && typeof value.remedy.destination_binding_digest === 'string'
    && DIGEST.test(value.remedy.destination_binding_digest)
    && Number.isSafeInteger(value.remedy.units) && value.remedy.units > 0
    && validContext(value.remedy.unit)
    && ['receipt-program', 'action-escrow'].includes(value.remedy.owner_mode)
    && typeof value.remedy.owner_digest === 'string' && DIGEST.test(value.remedy.owner_digest)
    && REMEDY_STATUSES.has(value.remedy.status)
    && (value.remedy.outcome === null || REMEDY_OUTCOMES.has(value.remedy.outcome))
    && exactKeys(value.semantics, SEMANTICS_KEYS)
    && value.semantics.original_effect === 'immutable_fact'
    && value.semantics.remedy_effect === 'compensating_action'
    && value.semantics.rollback === false
    && value.remedy.operation_id !== value.original_effect.operation_id
    && value.remedy.action_digest !== value.original_effect.action_digest;
}

function validReceipt(value: unknown): value is DataRecord {
  return exactKeys(value, TOP_KEYS)
    && value.version === ACTION_REMEDY_RECEIPT_VERSION
    && validIssuer(value.issuer)
    && validPayload(value.payload)
    && typeof value.content_digest === 'string' && DIGEST.test(value.content_digest)
    && exactKeys(value.signature, SIGNATURE_KEYS)
    && value.signature.algorithm === 'Ed25519'
    && strictBase64url(value.signature.value, 64) !== null;
}

function sameCanonical(left: unknown, right: unknown): boolean {
  try {
    return canonicalize(left) === canonicalize(right);
  } catch {
    return false;
  }
}

function receiptExpected(receipt: DataRecord): RemedyReceiptExpectedBindings {
  return {
    original_operation_id: receipt.payload.original_effect.operation_id,
    original_action_digest: receipt.payload.original_effect.action_digest,
    original_terminal_evidence_digest: receipt.payload.original_effect.terminal_evidence_digest,
    case_instance_id: receipt.payload.case.instance_id,
    case_revision: receipt.payload.case.revision,
    case_status: receipt.payload.case.status,
    remedy_operation_id: receipt.payload.remedy.operation_id,
    remedy_action_digest: receipt.payload.remedy.action_digest,
    remedy_caid: receipt.payload.remedy.caid,
    destination_binding_digest: receipt.payload.remedy.destination_binding_digest,
    units: receipt.payload.remedy.units,
    unit: receipt.payload.remedy.unit,
    owner_mode: receipt.payload.remedy.owner_mode,
    owner_digest: receipt.payload.remedy.owner_digest,
  };
}

function configureSigner(options: DataRecord, context: DataRecord) {
  const hasPrivateKey = options.privateKey !== undefined;
  const hasSigner = options.signer !== undefined;
  if (hasPrivateKey === hasSigner) throw new TypeError('configure exactly one remedy receipt signer');
  const allowEphemeralState = options.allowEphemeralState === true;

  if (hasPrivateKey) {
    if (!allowEphemeralState) {
      throw new TypeError('production remedy receipt issuance requires an external KMS/HSM signer');
    }
    const key = privateKey(options.privateKey);
    return Object.freeze({
      keyId: context.key_id,
      publicKey: publicKeyB64u(key),
      sign: async (bytes: Buffer) => crypto.sign(null, bytes, key),
    });
  }

  const signer = options.signer;
  if (!isDataRecord(signer)) throw new TypeError('remedy receipt signer must be a data object');
  if (!validContext(signer.keyId)
      || typeof signer.publicKey !== 'string'
      || typeof signer.sign !== 'function') {
    throw new TypeError('remedy receipt signer requires keyId, publicKey, and sign(bytes)');
  }
  if (!allowEphemeralState && !['kms', 'hsm'].includes(signer.custody)) {
    throw new TypeError('production remedy receipt signer custody must be kms or hsm');
  }
  if (!publicKey(signer.publicKey)) {
    throw new TypeError('remedy receipt signer public key must be Ed25519 SPKI base64url');
  }
  return Object.freeze({
    keyId: signer.keyId,
    publicKey: signer.publicKey,
    sign: signer.sign,
  });
}

/**
 * Issue one receipt. Local private keys require an explicit ephemeral/test
 * opt-in; production issuance requires an external signer declaring KMS/HSM
 * custody. Every returned signature is verified against the configured public
 * key before the receipt leaves this function.
 */
export async function issueRemedyProgramReceipt(
  input: {
    state?: unknown;
    remedyOperationId?: string;
  } = {},
  options: {
    context?: unknown;
    privateKey?: unknown;
    signer?: unknown;
    allowEphemeralState?: boolean;
    // OPT-IN. When provided, issuance consults checkOperationPolicy()
    // (packages/verify/src/fips-mode.ts) for the receipt signature algorithm
    // ('Ed25519') before the signer is called. A denied policy THROWS --
    // matching this function's existing throw-on-misuse contract -- and the
    // signer is never invoked. Left undefined (the default), issuance is
    // BYTE-IDENTICAL to before this option existed: the consult does not run.
    fipsPosture?: FipsPosture;
  } = {},
) {
  if (!exactKeys(input, new Set(['state', 'remedyOperationId']))) {
    throw new TypeError('remedy receipt input must contain exactly state and remedyOperationId');
  }
  const selected = snapshotAndAttempt(input.state, input.remedyOperationId);
  const context = canonicalCopy(options.context, 'remedy receipt context') as unknown;
  if (!validIssuer(context)) {
    throw new TypeError('remedy receipt context must contain exact pinned issuer fields');
  }
  if (context.tenant !== selected.state.tenant_id
      || context.environment !== selected.state.environment
      || context.audience !== selected.state.audience) {
    throw new TypeError('remedy receipt context does not match state tenant/environment/audience');
  }
  const signer = configureSigner(options as DataRecord, context);
  if (signer.keyId !== context.key_id) {
    throw new TypeError('remedy receipt context key_id does not match signer keyId');
  }

  const unsigned = {
    version: ACTION_REMEDY_RECEIPT_VERSION,
    issuer: context,
    payload: payloadFor(selected.state, selected.attempt),
  };
  const signedBody = {
    ...unsigned,
    content_digest: canonicalDigest(unsigned),
  };
  const signingBytes = remedyProgramReceiptSigningBytes(signedBody);
  if (options.fipsPosture !== undefined) {
    const policy = checkOperationPolicy('Ed25519', options.fipsPosture);
    if (policy.permitted !== true) {
      throw new Error(`remedy receipt issuance refused: fips_policy_denied:${policy.reason}`);
    }
  }
  const signature = canonicalSignature(await signer.sign(Buffer.from(signingBytes)));
  const verificationKey = publicKey(signer.publicKey)!;
  if (!crypto.verify(null, signingBytes, verificationKey, signature.bytes)) {
    throw new TypeError('remedy receipt signer self-verification failed');
  }
  const receipt = canonicalCopy({
    ...signedBody,
    signature: { algorithm: 'Ed25519', value: signature.encoded },
  }, 'remedy receipt');
  const expected = expectedBindings(selected.state, selected.attempt);
  const selfCheck = verifyRemedyProgramReceipt(receipt, {
    trustedKeys: { [context.key_id]: signer.publicKey },
    expectedIssuer: context,
    state: selected.state,
    expected,
  });
  if (!selfCheck.valid) {
    throw new TypeError(`remedy receipt self-verification failed: ${selfCheck.reason}`);
  }
  return deepFreeze(receipt);
}

export const signRemedyProgramReceipt = issueRemedyProgramReceipt;
export const createRemedyProgramReceipt = issueRemedyProgramReceipt;

function refusal(reason: string, checks: Record<string, boolean>) {
  return Object.freeze({
    valid: false,
    reason,
    checks: Object.freeze({ ...checks }),
    content_digest: null,
    payload: null,
  });
}

/**
 * Verify a receipt without network access. Trust keys, all issuer fields, the
 * exact current state snapshot, and every material original/remedy binding are
 * relying-party inputs; none are accepted from the receipt itself.
 */
export function verifyRemedyProgramReceipt(receipt: unknown, {
  trustedKeys,
  expectedIssuer,
  state,
  expected,
}: {
  trustedKeys?: unknown;
  expectedIssuer?: unknown;
  state?: unknown;
  expected?: unknown;
} = {}) {
  const checks = {
    structure: false,
    payload: false,
    content_digest: false,
    issuer_pin: false,
    key: false,
    signature: false,
    state_snapshot: false,
    expected_bindings: false,
  };
  try {
    const snapshot = canonicalCopy(receipt, 'remedy receipt') as unknown;
    if (!exactKeys(snapshot, TOP_KEYS)
        || snapshot.version !== ACTION_REMEDY_RECEIPT_VERSION
        || !validIssuer(snapshot.issuer)
        || !exactKeys(snapshot.signature, SIGNATURE_KEYS)) {
      return refusal('receipt_structure_invalid', checks);
    }
    checks.structure = true;
    if (!validPayload(snapshot.payload)) {
      return refusal('receipt_structure_invalid', checks);
    }
    checks.payload = true;
    if (typeof snapshot.content_digest !== 'string'
        || !DIGEST.test(snapshot.content_digest)
        || canonicalDigest(contentBody(snapshot)) !== snapshot.content_digest) {
      return refusal('receipt_content_digest_mismatch', checks);
    }
    checks.content_digest = true;

    let issuerPin: unknown;
    try {
      issuerPin = canonicalCopy(expectedIssuer, 'expected remedy receipt issuer');
    } catch {
      return refusal('receipt_expected_issuer_mismatch', checks);
    }
    checks.issuer_pin = validIssuer(issuerPin) && sameCanonical(snapshot.issuer, issuerPin);
    if (!checks.issuer_pin) return refusal('receipt_expected_issuer_mismatch', checks);

    const trusted = isDataRecord(trustedKeys)
      && Object.hasOwn(trustedKeys, snapshot.issuer.key_id)
      ? trustedKeys[snapshot.issuer.key_id] : null;
    const key = publicKey(trusted);
    checks.key = key !== null;
    if (!checks.key) return refusal('receipt_key_untrusted', checks);

    const signatureBytes = snapshot.signature.algorithm === 'Ed25519'
      ? strictBase64url(snapshot.signature.value, 64) : null;
    checks.signature = signatureBytes !== null
      && crypto.verify(null, remedyProgramReceiptSigningBytes(snapshot), key!, signatureBytes);
    if (!checks.signature) return refusal('receipt_signature_invalid', checks);

    let stateCopy: unknown;
    try {
      stateCopy = canonicalCopy(state, 'expected remedy state snapshot');
    } catch {
      return refusal('receipt_state_snapshot_mismatch', checks);
    }
    checks.state_snapshot = validState(stateCopy)
      && canonicalDigest(stateCopy) === snapshot.payload.case.state_snapshot_digest
      && stateCopy.instance_id === snapshot.payload.case.instance_id
      && stateCopy.revision === snapshot.payload.case.revision
      && stateCopy.status === snapshot.payload.case.status
      && stateCopy.updated_at === snapshot.payload.case.updated_at;
    if (!checks.state_snapshot) return refusal('receipt_state_snapshot_mismatch', checks);

    let expectedCopy: unknown;
    try {
      expectedCopy = canonicalCopy(expected, 'expected remedy bindings');
    } catch {
      return refusal('receipt_expected_binding_mismatch', checks);
    }
    let derivedAttempt: DataRecord;
    try {
      if (!validExpected(expectedCopy)) {
        return refusal('receipt_expected_binding_mismatch', checks);
      }
      derivedAttempt = selectAttempt(stateCopy as DataRecord, expectedCopy.remedy_operation_id);
    } catch {
      return refusal('receipt_expected_binding_mismatch', checks);
    }
    checks.expected_bindings = sameCanonical(receiptExpected(snapshot), expectedCopy)
      && sameCanonical(expectedBindings(stateCopy as DataRecord, derivedAttempt), expectedCopy)
      && sameCanonical(payloadFor(stateCopy as DataRecord, derivedAttempt), snapshot.payload);
    if (!checks.expected_bindings) {
      return refusal('receipt_expected_binding_mismatch', checks);
    }

    return deepFreeze({
      valid: true,
      reason: 'verified',
      checks,
      content_digest: snapshot.content_digest,
      payload: canonicalCopy(snapshot.payload, 'verified remedy receipt payload'),
    });
  } catch {
    return refusal('receipt_structure_invalid', checks);
  }
}

// ===========================================================================
// EP-ACTION-REMEDY-RECEIPT-v2 -- the hybrid (Ed25519 + ML-DSA-65) remedy
// receipt, and EP-GATE-REMEDY-PROGRAM-PROFILE-v2 as a describable state
// ===========================================================================
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the operator remedy receipt.
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. `signature: {algorithm, value}` becomes
 *    `signature: {profile, required_algorithms, public_key, key_id,
 *    pq_public_key, pq_key_id, signatures}`, a wire-format change, so the
 *    receipt takes a new `version` (-v1 -> -v2). verifyRemedyProgramReceipt
 *    above is UNCHANGED and refuses a v2 receipt at
 *    `receipt_structure_invalid` -- its exact-key check on the closed
 *    `{algorithm, value}` signature object fails before any signature is
 *    inspected, and it does not crash.
 * 2. SET SHAPE. `signature.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
 *    array ({ alg, sig, key_id? }), one entry per registered algorithm, in the
 *    registered order, reused verbatim. Ed25519 keeps its base64url SPKI DER
 *    public key; ML-DSA-65 carries raw base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is INSIDE the signed bytes
 *    (remedyProgramReceiptV2SigningBytes). Drop the ML-DSA leg and narrow the
 *    set to ["Ed25519"] and the surviving Ed25519 signature no longer
 *    verifies. Leave the set intact and the missing leg is a structural
 *    refusal. The verifier rebuilds the bytes from the REGISTERED set and from
 *    the body it independently recomputed.
 * 4. V1 COMPATIBILITY. verifyRemedyProgramReceipt stays SYNCHRONOUS and
 *    untouched. verifyRemedyProgramReceiptV2 is a SEPARATE async entry point
 *    (ML-DSA verification is inherently async); verifyRemedyProgramReceiptStatement
 *    routes on the version marker for callers holding a mixed bag.
 * 5. NAMED REFUSALS. Verification never throws on caller input; every failure
 *    returns `{valid:false, reason}` with the same reason vocabulary as v1 plus
 *    the hybrid-specific ones. An absent ML-DSA backend surfaces as
 *    `pq_backend_unavailable`, never a skipped check and never a pass on the
 *    classical leg. Issuance keeps v1's throw-on-misuse contract.
 *
 * THE PROFILE MARKER, STATED PRECISELY. A v2 receipt may describe a case whose
 * state snapshot carries EITHER EP-GATE-REMEDY-PROGRAM-PROFILE-v1 or -v2. That
 * is not a loose pin: the state snapshot's own `version` string is inside
 * `canonicalDigest(state)`, which is `payload.case.state_snapshot_digest`,
 * which is inside `content_digest`, which is inside the signed bytes. Swapping
 * the profile marker on a presented state therefore breaks BOTH the recomputed
 * state-snapshot digest and both signature legs. Accepting both is what keeps
 * the v2 receipt issuable over the Remedy Program kernel as it ships today,
 * without weakening what the signature commits to. The v1 receipt is
 * unchanged and still describes v1-profile states ONLY.
 *
 * THE FIPS CONSULT. The `fipsPosture` opt-in that v1 issuance already carries
 * is threaded through the v2 path and consults checkOperationPolicy() for BOTH
 * registered algorithms before the signer is called. Under a posture that is
 * not verifiably FIPS-inactive, ML-DSA-65's policy is a REFUSAL unless the
 * deployment explicitly acknowledges the unvalidated implementation
 * (`allowUnvalidatedMldsa: true`), because EP's ML-DSA backend is pure
 * JavaScript and inside no validated module boundary. Under a plainly
 * non-FIPS posture (`fips_status: 'inactive'`, the normal case) no
 * acknowledgment is required and the consult changes nothing. Left undefined
 * (the default), the consult does not run at all, exactly as in v1.
 *
 * HONEST BOUNDARY, UNCHANGED FROM V1: the receipt preserves the original
 * effect as an immutable fact and describes a later remedy only as a
 * compensating action. It never claims the original effect was rolled back or
 * erased. The ML-DSA-65 backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, not independently audited and not a FIPS validated module,
 * and its secret key is software-held: this profile does NOT satisfy a
 * kms/hsm-only custody requirement, and issuing under it is not a
 * certification claim.
 */

export const ACTION_REMEDY_RECEIPT_V2_VERSION = 'EP-ACTION-REMEDY-RECEIPT-v2';
export const REMEDY_PROGRAM_RECEIPT_V2_VERSION = ACTION_REMEDY_RECEIPT_V2_VERSION;
export const ACTION_REMEDY_RECEIPT_V2_DOMAIN = `${ACTION_REMEDY_RECEIPT_V2_VERSION}\0`;

/** The registered required algorithm set, in canonical order. */
export const ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

const SIGNATURE_V2_KEYS = new Set([
  'profile', 'required_algorithms', 'public_key', 'key_id',
  'pq_public_key', 'pq_key_id', 'signatures',
]);

/** A v2 issuer pin: BOTH public halves, pinned out of band by key id. */
export interface RemedyReceiptV2KeyPin {
  /** Ed25519 base64url SPKI DER. */
  public_key: string;
  /** ML-DSA-65 base64url raw public key bytes. */
  pq_public_key: string;
}

/**
 * An injected hybrid signer. Structurally the `signSet()` contract of
 * lib/key-custody.ts's HybridCustodySigner: sign the SAME bytes under every
 * required algorithm, in canonical order. Accepted structurally rather than
 * imported because @emilia-protocol/gate does not depend on the app-tier lib/
 * tree; a HybridCustodySigner satisfies this shape as-is.
 */
export interface RemedyReceiptV2SignSetSigner {
  keyId: string;
  custody?: string;
  publicKeys: RemedyReceiptV2KeyPin;
  signSet(bytes: Uint8Array | Buffer, context?: Record<string, unknown>): Promise<
    Array<{ alg: string; sig: string; key_id?: string }>
  >;
}

export interface RemedyReceiptV2SigningKeys {
  ed: { privateKey: unknown; publicKey?: string };
  pq: { secretKey: Uint8Array | string; publicKey: string };
}

/**
 * Derive every relying-party binding for a v2 receipt. Identical to
 * expectedRemedyProgramReceiptBindings except that it accepts a state snapshot
 * under EITHER Remedy Program profile marker, which is exactly the set a v2
 * receipt may describe.
 */
export function expectedRemedyProgramReceiptV2Bindings(
  state: unknown,
  remedyOperationId: string,
): Readonly<RemedyReceiptExpectedBindings> {
  const selected = snapshotAndAttempt(state, remedyOperationId, REMEDY_PROGRAM_PROFILE_V1_OR_V2);
  return deepFreeze(expectedBindings(selected.state, selected.attempt));
}

function remedyV2AlgorithmSetRegistered(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS[i]);
}

/** ML-DSA-65 public-key identifier: the SHA-256 of the raw public key bytes. */
function remedyPqKeyId(publicKeyRawB64u: unknown): string {
  try {
    if (typeof publicKeyRawB64u !== 'string' || publicKeyRawB64u.length === 0) return '';
    const raw = Buffer.from(publicKeyRawB64u, 'base64url');
    if (raw.length !== ML_DSA_65_PUBLIC_KEY_BYTES || raw.toString('base64url') !== publicKeyRawB64u) return '';
    return `ep:remedy-receipt-key:ml-dsa-65:sha256:${crypto.createHash('sha256').update(raw).digest('hex')}`;
  } catch {
    return '';
  }
}

function remedyAgilityPassthrough(opts: AgilityOptions | undefined): AgilityOptions {
  const out: AgilityOptions = {};
  if (opts?.mldsaBackend !== undefined) out.mldsaBackend = opts.mldsaBackend;
  if (opts?.mldsaBackendLoader !== undefined) out.mldsaBackendLoader = opts.mldsaBackendLoader;
  return out;
}

/**
 * The bytes BOTH legs sign: the same body v1 signs (version, issuer, payload,
 * content_digest) under the v2 domain tag, plus the committed
 * `required_algorithms` set. Recomputed independently by the verifier from the
 * PRESENTED body and the REGISTERED set. See move 3 above.
 */
export function remedyProgramReceiptV2SigningBytes(
  receipt: unknown,
  requiredAlgorithms: readonly string[] = ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!isDataRecord(receipt)) throw new TypeError('remedy receipt v2 signing body is invalid');
  if (!remedyV2AlgorithmSetRegistered(requiredAlgorithms)) {
    throw new TypeError('remedyProgramReceiptV2SigningBytes: algorithm set is not the registered EP-ACTION-REMEDY-RECEIPT-v2 set');
  }
  return Buffer.from(
    ACTION_REMEDY_RECEIPT_V2_DOMAIN + canonicalize({
      ...signingBody(receipt),
      required_algorithms: [...requiredAlgorithms],
    }),
    'utf8',
  );
}

function configureHybridSigner(options: DataRecord, context: DataRecord): {
  keyId: string;
  publicKeys: RemedyReceiptV2KeyPin;
  signSet: (bytes: Buffer) => Promise<Array<{ alg: string; sig: string }>>;
} {
  const hasKeys = options.keys !== undefined;
  const hasSigner = options.signer !== undefined;
  if (hasKeys === hasSigner) throw new TypeError('configure exactly one remedy receipt v2 signer');
  const allowEphemeralState = options.allowEphemeralState === true;

  if (hasKeys) {
    if (!allowEphemeralState) {
      throw new TypeError('production remedy receipt v2 issuance requires an external signSet signer');
    }
    const keys = options.keys as RemedyReceiptV2SigningKeys;
    if (!keys?.ed?.privateKey || !keys?.pq?.secretKey || typeof keys?.pq?.publicKey !== 'string') {
      throw new TypeError('remedy receipt v2 keys require ed.privateKey, pq.secretKey, and pq.publicKey');
    }
    const edKey = privateKey(keys.ed.privateKey);
    if (!remedyPqKeyId(keys.pq.publicKey)) {
      throw new TypeError('remedy receipt v2 ML-DSA-65 public key must be raw base64url bytes');
    }
    const signingKeys: AgileSigningKey[] = [
      { alg: 'Ed25519', private_key: edKey },
      { alg: 'ML-DSA-65', private_key: keys.pq.secretKey },
    ];
    return {
      keyId: context.key_id,
      publicKeys: {
        public_key: keys.ed.publicKey ?? publicKeyB64u(edKey),
        pq_public_key: keys.pq.publicKey,
      },
      signSet: async (bytes: Buffer) => signAgileSet(new Uint8Array(bytes), signingKeys),
    };
  }

  const signer = options.signer as RemedyReceiptV2SignSetSigner;
  if (!isDataRecord(signer)) throw new TypeError('remedy receipt v2 signer must be a data object');
  if (!validContext(signer.keyId) || typeof signer.signSet !== 'function'
      || !isDataRecord(signer.publicKeys)
      || typeof signer.publicKeys.public_key !== 'string'
      || typeof signer.publicKeys.pq_public_key !== 'string') {
    throw new TypeError('remedy receipt v2 signer requires keyId, publicKeys { public_key, pq_public_key }, and signSet(bytes)');
  }
  // The classical leg's custody gate is unchanged from v1. The ML-DSA leg is
  // software-held either way (there is no KMS/HSM ML-DSA path today), which is
  // why this profile does not satisfy a kms/hsm-only custody requirement.
  if (!allowEphemeralState && !['kms', 'hsm'].includes(signer.custody as string)) {
    throw new TypeError('production remedy receipt v2 classical signer custody must be kms or hsm');
  }
  if (!publicKey(signer.publicKeys.public_key)) {
    throw new TypeError('remedy receipt v2 signer Ed25519 public key must be Ed25519 SPKI base64url');
  }
  if (!remedyPqKeyId(signer.publicKeys.pq_public_key)) {
    throw new TypeError('remedy receipt v2 signer ML-DSA-65 public key must be raw base64url bytes');
  }
  const publicKeys: RemedyReceiptV2KeyPin = {
    public_key: signer.publicKeys.public_key,
    pq_public_key: signer.publicKeys.pq_public_key,
  };
  return {
    keyId: signer.keyId,
    publicKeys,
    signSet: async (bytes: Buffer) => {
      const set = await signer.signSet(bytes, { profile: ACTION_REMEDY_RECEIPT_V2_VERSION });
      if (!Array.isArray(set)
          || !ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS.every((alg, index) => (
            set[index]?.alg === alg && typeof set[index]?.sig === 'string'))) {
        throw new TypeError('remedy receipt v2 signer returned a malformed signature set');
      }
      return set.map((entry) => ({ alg: entry.alg, sig: entry.sig }));
    },
  };
}

/**
 * Issue one hybrid receipt. Local private keys require an explicit
 * ephemeral/test opt-in; production issuance requires an external signSet
 * signer. Every returned signature set is verified against the configured
 * public halves before the receipt leaves this function.
 */
export async function issueRemedyProgramReceiptV2(
  input: {
    state?: unknown;
    remedyOperationId?: string;
  } = {},
  options: {
    context?: unknown;
    keys?: RemedyReceiptV2SigningKeys;
    signer?: RemedyReceiptV2SignSetSigner;
    allowEphemeralState?: boolean;
    fipsPosture?: FipsPosture;
    /**
     * ML-DSA-65 is implemented in JavaScript and is inside no validated
     * module. Under a configured `fipsPosture` its policy is a REFUSAL unless
     * the deployment acknowledges that explicitly here. The default is the
     * named refusal, never a silent pass.
     */
    allowUnvalidatedMldsa?: boolean;
  } = {},
) {
  if (!exactKeys(input, new Set(['state', 'remedyOperationId']))) {
    throw new TypeError('remedy receipt input must contain exactly state and remedyOperationId');
  }
  const selected = snapshotAndAttempt(
    input.state, input.remedyOperationId, REMEDY_PROGRAM_PROFILE_V1_OR_V2,
  );
  const context = canonicalCopy(options.context, 'remedy receipt context') as unknown;
  if (!validIssuer(context)) {
    throw new TypeError('remedy receipt context must contain exact pinned issuer fields');
  }
  if (context.tenant !== selected.state.tenant_id
      || context.environment !== selected.state.environment
      || context.audience !== selected.state.audience) {
    throw new TypeError('remedy receipt context does not match state tenant/environment/audience');
  }
  const signer = configureHybridSigner(options as DataRecord, context);
  if (signer.keyId !== context.key_id) {
    throw new TypeError('remedy receipt context key_id does not match signer keyId');
  }

  const requiredAlgorithms = [...ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS];
  const unsigned = {
    version: ACTION_REMEDY_RECEIPT_V2_VERSION,
    issuer: context,
    payload: payloadFor(selected.state, selected.attempt),
  };
  const signedBody = {
    ...unsigned,
    content_digest: canonicalDigest(unsigned),
  };
  const signingBytes = remedyProgramReceiptV2SigningBytes(signedBody, requiredAlgorithms);
  // OPT-IN FIPS consult, BOTH algorithms, BEFORE the signer is called.
  if (options.fipsPosture !== undefined) {
    for (const alg of requiredAlgorithms) {
      const policy = checkOperationPolicy(alg, options.fipsPosture, {
        allow_unvalidated_mldsa: options.allowUnvalidatedMldsa === true,
      });
      if (policy.permitted !== true) {
        throw new Error(`remedy receipt v2 issuance refused: fips_policy_denied:${alg}:${policy.reason}`);
      }
    }
  }
  const signatures = await signer.signSet(Buffer.from(signingBytes));
  const receipt = canonicalCopy({
    ...signedBody,
    signature: {
      profile: ACTION_REMEDY_RECEIPT_V2_VERSION,
      required_algorithms: requiredAlgorithms,
      public_key: signer.publicKeys.public_key,
      key_id: context.key_id,
      pq_public_key: signer.publicKeys.pq_public_key,
      pq_key_id: remedyPqKeyId(signer.publicKeys.pq_public_key),
      signatures,
    },
  }, 'remedy receipt');
  const expected = expectedBindings(selected.state, selected.attempt);
  const selfCheck = await verifyRemedyProgramReceiptV2(receipt, {
    trustedKeys: { [context.key_id]: signer.publicKeys },
    expectedIssuer: context,
    state: selected.state,
    expected,
  });
  if (!selfCheck.valid) {
    throw new TypeError(`remedy receipt v2 self-verification failed: ${selfCheck.reason}`);
  }
  return deepFreeze(receipt);
}

export const signRemedyProgramReceiptV2 = issueRemedyProgramReceiptV2;

/**
 * FAIL-CLOSED hybrid remedy-receipt verifier. Never throws on caller input; a
 * v2 receipt NEVER verifies on one leg alone. Trust keys, all issuer fields,
 * the exact current state snapshot, and every material original/remedy binding
 * are relying-party inputs; none is accepted from the receipt itself.
 */
export async function verifyRemedyProgramReceiptV2(receipt: unknown, {
  trustedKeys,
  expectedIssuer,
  state,
  expected,
  mldsaBackend,
  mldsaBackendLoader,
}: {
  trustedKeys?: unknown;
  expectedIssuer?: unknown;
  state?: unknown;
  expected?: unknown;
  mldsaBackend?: AgilityOptions['mldsaBackend'];
  mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
} = {}) {
  const checks = {
    structure: false,
    payload: false,
    content_digest: false,
    issuer_pin: false,
    algorithm_set: false,
    legs_present: false,
    key: false,
    signature: false,
    state_snapshot: false,
    expected_bindings: false,
  };
  try {
    const snapshot = canonicalCopy(receipt, 'remedy receipt') as unknown;
    // 1. Version marker + closed shape. A v1 receipt refuses here, the mirror
    //    image of the v1 verifier refusing a v2 receipt.
    if (!exactKeys(snapshot, TOP_KEYS)
        || snapshot.version !== ACTION_REMEDY_RECEIPT_V2_VERSION
        || !validIssuer(snapshot.issuer)
        || !exactKeys(snapshot.signature, SIGNATURE_V2_KEYS)
        || snapshot.signature.profile !== ACTION_REMEDY_RECEIPT_V2_VERSION) {
      return refusal('receipt_structure_invalid', checks);
    }
    checks.structure = true;
    if (!validPayload(snapshot.payload)) return refusal('receipt_structure_invalid', checks);
    checks.payload = true;
    if (typeof snapshot.content_digest !== 'string'
        || !DIGEST.test(snapshot.content_digest)
        || canonicalDigest(contentBody(snapshot)) !== snapshot.content_digest) {
      return refusal('receipt_content_digest_mismatch', checks);
    }
    checks.content_digest = true;

    let issuerPin: unknown;
    try {
      issuerPin = canonicalCopy(expectedIssuer, 'expected remedy receipt issuer');
    } catch {
      return refusal('receipt_expected_issuer_mismatch', checks);
    }
    checks.issuer_pin = validIssuer(issuerPin) && sameCanonical(snapshot.issuer, issuerPin);
    if (!checks.issuer_pin) return refusal('receipt_expected_issuer_mismatch', checks);

    // 2. Committed algorithm set: exact and order-sensitive. A narrowed set is
    //    the stripping attack's cover story, refused structurally here and
    //    (independently) by the signature check, which rebuilds the bytes from
    //    the REGISTERED set regardless of what the receipt claims.
    checks.algorithm_set = remedyV2AlgorithmSetRegistered(snapshot.signature.required_algorithms);
    if (!checks.algorithm_set) return refusal('receipt_algorithm_set_unsupported', checks);

    // 3. Exactly one signature per required algorithm.
    const signatures = Array.isArray(snapshot.signature.signatures)
      ? snapshot.signature.signatures as AgileSignature[] : null;
    if (!signatures) return refusal('receipt_signature_set_invalid', checks);
    const presented = new Set<string>();
    for (const entry of signatures) {
      if (!isDataRecord(entry) || typeof entry.alg !== 'string' || typeof entry.sig !== 'string') {
        return refusal('receipt_signature_set_invalid', checks);
      }
      if (presented.has(entry.alg)) return refusal('receipt_signature_set_invalid', checks);
      presented.add(entry.alg);
    }
    for (const alg of ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS) {
      if (!presented.has(alg)) return refusal('receipt_signature_leg_missing', checks);
    }
    for (const alg of presented) {
      if (!(ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) {
        return refusal('receipt_signature_set_invalid', checks);
      }
    }
    checks.legs_present = true;

    // 4. Issuer keys: BOTH halves pinned, and the presented halves must equal
    //    the pinned ones. Identified-but-not-trusted, per leg: a key id pinned
    //    for v1 only (Ed25519 half alone) does NOT satisfy a v2 pin.
    const pin = isDataRecord(trustedKeys) && Object.hasOwn(trustedKeys, snapshot.issuer.key_id)
      ? trustedKeys[snapshot.issuer.key_id] : null;
    checks.key = isDataRecord(pin)
      && typeof pin.public_key === 'string' && pin.public_key.length > 0
      && typeof pin.pq_public_key === 'string' && pin.pq_public_key.length > 0
      && pin.public_key === snapshot.signature.public_key
      && pin.pq_public_key === snapshot.signature.pq_public_key
      && snapshot.signature.key_id === snapshot.issuer.key_id
      // Curve-pinned: a non-Ed25519 SPKI presented as the classical half fails
      // here as well as in the signature check.
      && publicKey(pin.public_key) !== null
      && remedyPqKeyId(pin.pq_public_key) !== ''
      && snapshot.signature.pq_key_id === remedyPqKeyId(pin.pq_public_key);
    if (!checks.key) return refusal('receipt_key_untrusted', checks);

    // 5. Signature set over bytes rebuilt from the PRESENTED body and the
    //    REGISTERED algorithm set, under the PINNED keys. Never fall back to
    //    the receipt's own self-asserted key material.
    let setResult;
    try {
      setResult = await verifyAgileSignatureSet(
        new Uint8Array(remedyProgramReceiptV2SigningBytes(
          snapshot, ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS,
        )),
        signatures,
        [
          { alg: 'Ed25519', public_key: (pin as DataRecord).public_key },
          { alg: 'ML-DSA-65', public_key: (pin as DataRecord).pq_public_key },
        ],
        {
          ...remedyAgilityPassthrough({ mldsaBackend, mldsaBackendLoader }),
          policy: 'hybrid_all',
          requiredAlgorithms: [...ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS],
        },
      );
    } catch {
      // verifyAgileSignatureSet documents that it never throws; an injected
      // backend that does is still a refusal here, never a pass.
      setResult = null;
    }
    checks.signature = setResult?.verified === true;
    if (!checks.signature) {
      return refusal(
        `receipt_signature_invalid:${String(setResult?.reason ?? 'signature_set_unverified')}`,
        checks,
      );
    }

    // 6. State snapshot and expected bindings: identical to v1, except that a
    //    v2 receipt may describe either Remedy Program profile marker (see the
    //    header: the marker is still fully committed through
    //    state_snapshot_digest -> content_digest -> signed bytes).
    let stateCopy: unknown;
    try {
      stateCopy = canonicalCopy(state, 'expected remedy state snapshot');
    } catch {
      return refusal('receipt_state_snapshot_mismatch', checks);
    }
    checks.state_snapshot = validStateUnder(stateCopy, REMEDY_PROGRAM_PROFILE_V1_OR_V2)
      && canonicalDigest(stateCopy) === snapshot.payload.case.state_snapshot_digest
      && stateCopy.instance_id === snapshot.payload.case.instance_id
      && stateCopy.revision === snapshot.payload.case.revision
      && stateCopy.status === snapshot.payload.case.status
      && stateCopy.updated_at === snapshot.payload.case.updated_at;
    if (!checks.state_snapshot) return refusal('receipt_state_snapshot_mismatch', checks);

    let expectedCopy: unknown;
    try {
      expectedCopy = canonicalCopy(expected, 'expected remedy bindings');
    } catch {
      return refusal('receipt_expected_binding_mismatch', checks);
    }
    let derivedAttempt: DataRecord;
    try {
      if (!validExpected(expectedCopy)) {
        return refusal('receipt_expected_binding_mismatch', checks);
      }
      derivedAttempt = selectAttempt(stateCopy as DataRecord, expectedCopy.remedy_operation_id);
    } catch {
      return refusal('receipt_expected_binding_mismatch', checks);
    }
    checks.expected_bindings = sameCanonical(receiptExpected(snapshot), expectedCopy)
      && sameCanonical(expectedBindings(stateCopy as DataRecord, derivedAttempt), expectedCopy)
      && sameCanonical(payloadFor(stateCopy as DataRecord, derivedAttempt), snapshot.payload);
    if (!checks.expected_bindings) {
      return refusal('receipt_expected_binding_mismatch', checks);
    }

    return deepFreeze({
      valid: true,
      reason: 'verified',
      checks,
      content_digest: snapshot.content_digest,
      payload: canonicalCopy(snapshot.payload, 'verified remedy receipt payload'),
    });
  } catch {
    return refusal('receipt_structure_invalid', checks);
  }
}

/**
 * Route a receipt of EITHER version to its verifier. v1 receipts keep the exact
 * v1 verdict; v2 receipts get the hybrid check. A receipt whose `version` is
 * neither refuses through the v1 verifier, which is the fail-closed answer.
 */
export async function verifyRemedyProgramReceiptStatement(receipt: unknown, options: {
  trustedKeys?: unknown;
  expectedIssuer?: unknown;
  state?: unknown;
  expected?: unknown;
  mldsaBackend?: AgilityOptions['mldsaBackend'];
  mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
} = {}) {
  if (isRecord(receipt) && receipt.version === ACTION_REMEDY_RECEIPT_V2_VERSION) {
    return verifyRemedyProgramReceiptV2(receipt, options);
  }
  return verifyRemedyProgramReceipt(receipt, options);
}

export default {
  ACTION_REMEDY_RECEIPT_VERSION,
  REMEDY_PROGRAM_RECEIPT_VERSION,
  ACTION_REMEDY_RECEIPT_DOMAIN,
  ACTION_REMEDY_RECEIPT_V2_VERSION,
  REMEDY_PROGRAM_RECEIPT_V2_VERSION,
  ACTION_REMEDY_RECEIPT_V2_DOMAIN,
  ACTION_REMEDY_RECEIPT_V2_REQUIRED_ALGORITHMS,
  REMEDY_PROGRAM_PROFILE_V2_VERSION,
  expectedRemedyProgramReceiptBindings,
  expectedRemedyProgramReceiptV2Bindings,
  remedyProgramReceiptSigningBytes,
  remedyProgramReceiptV2SigningBytes,
  issueRemedyProgramReceipt,
  issueRemedyProgramReceiptV2,
  signRemedyProgramReceipt,
  signRemedyProgramReceiptV2,
  createRemedyProgramReceipt,
  verifyRemedyProgramReceipt,
  verifyRemedyProgramReceiptV2,
  verifyRemedyProgramReceiptStatement,
};
