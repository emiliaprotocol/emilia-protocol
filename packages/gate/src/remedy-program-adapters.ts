// SPDX-License-Identifier: Apache-2.0
/**
 * Constructor-pinned production adapters for the Remedy Program kernel.
 *
 * The kernel deliberately stores evidence references for every post-create
 * transition. These adapters resolve those references from a relying-party
 * evidence source and perform the concrete cryptographic verification here.
 * Presenters cannot supply verifier functions, tenants, or trust keys.
 */
import crypto from 'node:crypto';

import { verifyRevocation } from '@emilia-protocol/verify';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  type AgileSigningKey,
  type AgileSignature,
  type AgilityOptions,
} from '@emilia-protocol/verify/pq-signature-agility';

import { canonicalize } from '../execution-binding.js';
import {
  verifyActionEscrowStateStatement,
  verifyActionEscrowStateStatementAny,
} from './action-escrow-state.js';

export const REMEDY_PROGRAM_EVIDENCE_VERSION = 'EP-GATE-REMEDY-EVIDENCE-v1';
export const REMEDY_PROGRAM_EVIDENCE_DOMAIN = `${REMEDY_PROGRAM_EVIDENCE_VERSION}\0`;

type DataRecord = Record<string, any>;

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,255}$/;
const CAID = /^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const ORIGINAL_KEYS = new Set([
  'caid', 'action_digest', 'operation_id', 'consequence_mode',
  'consequence_digest', 'terminal_evidence_digest', 'outcome', 'occurred_at',
]);
const STORED_ORIGINAL_KEYS = new Set([...ORIGINAL_KEYS, 'evidence_digest']);
const SIGNED_EVIDENCE_KEYS = new Set([
  'version', 'kind', 'issuer', 'payload', 'content_digest', 'signature',
]);
const SIGNING_BODY_KEYS = new Set([
  'version', 'kind', 'issuer', 'payload', 'content_digest',
]);
const ISSUER_KEYS = new Set(['authority_id', 'key_id']);
const SIGNATURE_KEYS = new Set(['algorithm', 'value']);
const AUTHORITY_KEYS = new Set(['authorityId', 'trustedKeys']);
const ORIGINAL_BINDING_KEYS = new Set([
  'agreementId', 'caid', 'bindingDigest', 'profileDigest', 'amendmentDigests',
]);
const DISPUTE_PAYLOAD_KEYS = new Set([
  'evidence_id', 'tenant_id', 'instance_id', 'dispute_id', 'challenger_id',
  'requested_units', 'opened_at', 'original_operation_id', 'original_action_digest',
]);
const AUTHORIZATION_PAYLOAD_KEYS = new Set([
  'evidence_id', 'tenant_id', 'instance_id', 'dispute_id',
  'original_operation_id', 'original_action_digest', 'remedy_operation_id',
  'remedy_caid', 'remedy_action_digest', 'destination_binding_digest',
  'consequence_mode', 'capability_template_digest', 'escrow_profile_digest',
  'units', 'unit', 'authorized_at',
]);
const OUTCOME_PAYLOAD_KEYS = new Set([
  'evidence_id', 'tenant_id', 'instance_id', 'remedy_operation_id',
  'remedy_action_digest', 'destination_binding_digest', 'units', 'unit',
  'outcome', 'observed_at', 'reconciliation',
]);
const ORIGINAL_OUTCOME_PAYLOAD_KEYS = new Set([
  'evidence_id', 'tenant_id', 'instance_id', 'original_operation_id',
  'original_action_digest', 'terminal_evidence_digest', 'outcome',
  'observed_at',
]);

export interface RemedyProgramEvidenceSource {
  get(input: Readonly<{
    tenantId: string;
    evidenceId: string;
    evidenceDigest: string;
  }>): unknown | Promise<unknown>;
}

export interface RemedyProgramPinnedAuthority {
  authorityId: string;
  trustedKeys: Record<string, string>;
}

export interface RemedyProgramOriginalEffectBinding {
  agreementId: string;
  caid: string;
  bindingDigest: string;
  profileDigest: string;
  amendmentDigests: string[];
}

export interface RemedyProgramAdapterOptions {
  tenantId: string;
  environment: string;
  audience: string;
  evidenceSource: RemedyProgramEvidenceSource;
  actionEscrow: {
    trustedKeys: Record<string, { operator_id: string; public_key: string }>;
    originalEffects: Record<string, RemedyProgramOriginalEffectBinding>;
  };
  revokerKeys: Record<string, { public_key: string; key_id?: string }>;
  disputeAuthority: RemedyProgramPinnedAuthority;
  remedyAuthority: RemedyProgramPinnedAuthority;
  providerAuthority: RemedyProgramPinnedAuthority;
  now?: () => number | string | Date;
}

function isRecord(value: unknown): value is DataRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isDataRecord(value: unknown): value is DataRecord {
  if (!isRecord(value)) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function exactKeys(value: unknown, keys: Set<string>): value is DataRecord {
  return isDataRecord(value)
    && Object.keys(value).length === keys.size
    && Object.keys(value).every((key) => keys.has(key));
}

function validContext(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
    && Buffer.byteLength(value, 'utf8') <= 512
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function validId(value: unknown): value is string {
  return typeof value === 'string' && ID.test(value);
}

function instant(value: unknown): number {
  if (typeof value !== 'string') return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function canonicalCopy<T>(value: T): T {
  return JSON.parse(canonicalize(value));
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value as DataRecord)) deepFreeze(child);
  return value;
}

function canonicalDigest(value: unknown): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}

/** Digest an exact evidence artifact for use as the kernel's evidence reference. */
export function remedyProgramEvidenceDigest(value: unknown): string {
  return canonicalDigest(value);
}

function signingBody(value: DataRecord): DataRecord {
  return {
    version: value.version,
    kind: value.kind,
    issuer: value.issuer,
    payload: value.payload,
    content_digest: value.content_digest,
  };
}

/** Domain-separated canonical bytes for the closed signed evidence envelope. */
export function remedyProgramEvidenceSigningBytes(value: unknown): Buffer {
  if (!isDataRecord(value)) throw new TypeError('remedy evidence signing body invalid');
  const body = signingBody(value);
  if (!exactKeys(body, SIGNING_BODY_KEYS)) {
    throw new TypeError('remedy evidence signing body invalid');
  }
  return Buffer.from(REMEDY_PROGRAM_EVIDENCE_DOMAIN + canonicalize(body), 'utf8');
}

function strictBase64url(value: unknown, length?: number): Buffer | null {
  if (typeof value !== 'string' || !BASE64URL.test(value) || value.length % 4 === 1) return null;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.toString('base64url') === value
    && (length === undefined || bytes.length === length) ? bytes : null;
}

function ed25519PublicKey(value: unknown): crypto.KeyObject | null {
  try {
    const bytes = strictBase64url(value);
    if (!bytes) return null;
    const key = crypto.createPublicKey({ key: bytes, format: 'der', type: 'spki' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function validTrustedKeys(value: unknown): value is Record<string, string> {
  return isDataRecord(value) && Object.keys(value).length > 0
    && Object.entries(value).every(([keyId, key]) => validId(keyId) && ed25519PublicKey(key) !== null);
}

function validAuthority(value: unknown): value is RemedyProgramPinnedAuthority {
  return exactKeys(value, AUTHORITY_KEYS)
    && validContext(value.authorityId)
    && validTrustedKeys(value.trustedKeys);
}

function validOriginal(value: unknown, stored = false): value is DataRecord {
  return exactKeys(value, stored ? STORED_ORIGINAL_KEYS : ORIGINAL_KEYS)
    && typeof value.caid === 'string' && CAID.test(value.caid)
    && typeof value.action_digest === 'string' && DIGEST.test(value.action_digest)
    && validId(value.operation_id)
    && value.consequence_mode === 'action-escrow'
    && typeof value.consequence_digest === 'string' && DIGEST.test(value.consequence_digest)
    && typeof value.terminal_evidence_digest === 'string' && DIGEST.test(value.terminal_evidence_digest)
    && ['executed', 'indeterminate'].includes(value.outcome)
    && Number.isFinite(instant(value.occurred_at))
    && (!stored || (typeof value.evidence_digest === 'string' && DIGEST.test(value.evidence_digest)));
}

function snapshotData<T>(value: T): Readonly<T> {
  return deepFreeze(canonicalCopy(value));
}

function failure(): Readonly<{ ok: false }> {
  return Object.freeze({ ok: false });
}

function contextMatches(expected: unknown, options: Readonly<RemedyProgramAdapterOptions>): expected is DataRecord {
  return isDataRecord(expected)
    && expected.tenant_id === options.tenantId
    && expected.environment === options.environment
    && expected.audience === options.audience
    && validId(expected.instance_id);
}

function payloadMatches(value: DataRecord, expected: DataRecord, fields: string[]): boolean {
  return fields.every((field) => value[field] === expected[field]);
}

function verifiedSignedEvidence(
  value: unknown,
  kind: string,
  authority: Readonly<RemedyProgramPinnedAuthority>,
): DataRecord | null {
  try {
    const evidence = canonicalCopy(value) as unknown;
    if (!exactKeys(evidence, SIGNED_EVIDENCE_KEYS)
        || evidence.version !== REMEDY_PROGRAM_EVIDENCE_VERSION
        || evidence.kind !== kind
        || !exactKeys(evidence.issuer, ISSUER_KEYS)
        || evidence.issuer.authority_id !== authority.authorityId
        || !validId(evidence.issuer.key_id)
        || !isDataRecord(evidence.payload)
        || typeof evidence.content_digest !== 'string'
        || !DIGEST.test(evidence.content_digest)
        || !exactKeys(evidence.signature, SIGNATURE_KEYS)
        || evidence.signature.algorithm !== 'Ed25519') return null;
    const unsigned = {
      version: evidence.version,
      kind: evidence.kind,
      issuer: evidence.issuer,
      payload: evidence.payload,
    };
    if (canonicalDigest(unsigned) !== evidence.content_digest) return null;
    const keyValue = authority.trustedKeys[evidence.issuer.key_id];
    const key = ed25519PublicKey(keyValue);
    const signature = strictBase64url(evidence.signature.value, 64);
    if (!key || !signature
        || !crypto.verify(null, remedyProgramEvidenceSigningBytes(evidence), key, signature)) return null;
    return evidence;
  } catch {
    return null;
  }
}

/**
 * The seam that lets ONE adapter body serve both evidence profiles. Every
 * member is a pinned repository verifier; there are still no caller-supplied
 * verifier override hooks. See createRemedyProgramAdaptersV2 for the v2 seam
 * and for why the Action Escrow leg is a ROUTER rather than a v2-only verifier.
 */
interface RemedyAdapterProfile {
  validAuthority(value: unknown): boolean;
  validEscrowKeyPin(pin: unknown): boolean;
  verifySignedEvidence(
    value: unknown,
    kind: string,
    authority: Readonly<RemedyProgramPinnedAuthority>,
  ): Promise<DataRecord | null>;
  verifyRevocationEvidence(target: unknown, statement: unknown, opts: unknown): Promise<{ valid?: unknown }>;
  verifyEscrowStatement(statement: unknown, opts: unknown): Promise<{
    valid?: unknown; statement_digest?: unknown;
  }>;
}

const REMEDY_ADAPTER_PROFILE_V1: RemedyAdapterProfile = Object.freeze({
  validAuthority,
  validEscrowKeyPin: (pin: unknown) => exactKeys(pin, new Set(['operator_id', 'public_key']))
    && validContext(pin.operator_id) && ed25519PublicKey(pin.public_key) !== null,
  async verifySignedEvidence(value, kind, authority) {
    return verifiedSignedEvidence(value, kind, authority);
  },
  async verifyRevocationEvidence(target, statement, opts) {
    return verifyRevocation(target as any, statement as any, opts as any);
  },
  async verifyEscrowStatement(statement, opts) {
    return verifyActionEscrowStateStatement(statement as any, opts as any);
  },
});

/**
 * Build all required Remedy Program callbacks using only pinned configuration
 * and concrete repository verifiers. There are intentionally no verifier
 * override hooks.
 */
export function createRemedyProgramAdapters(options: RemedyProgramAdapterOptions) {
  return buildRemedyProgramAdapters(options, REMEDY_ADAPTER_PROFILE_V1);
}

function buildRemedyProgramAdapters(
  options: RemedyProgramAdapterOptions,
  profile: RemedyAdapterProfile,
) {
  if (!isDataRecord(options)
      || !validContext(options.tenantId)
      || !validContext(options.environment)
      || !validContext(options.audience)
      || !options.evidenceSource
      || typeof options.evidenceSource.get !== 'function'
      || !isDataRecord(options.actionEscrow)
      || !isDataRecord(options.actionEscrow.trustedKeys)
      || Object.keys(options.actionEscrow.trustedKeys).length === 0
      || !isDataRecord(options.actionEscrow.originalEffects)
      || Object.keys(options.actionEscrow.originalEffects).length === 0
      || !isDataRecord(options.revokerKeys)
      || !profile.validAuthority(options.disputeAuthority)
      || !profile.validAuthority(options.remedyAuthority)
      || !profile.validAuthority(options.providerAuthority)
      || (options.now !== undefined && typeof options.now !== 'function')) {
    throw new TypeError('remedy program adapter configuration invalid');
  }
  for (const [keyId, pin] of Object.entries(options.actionEscrow.trustedKeys)) {
    if (!validId(keyId) || !profile.validEscrowKeyPin(pin)) {
      throw new TypeError('Action Escrow state key configuration invalid');
    }
  }
  for (const [operationId, binding] of Object.entries(options.actionEscrow.originalEffects)) {
    if (!validId(operationId) || !exactKeys(binding, ORIGINAL_BINDING_KEYS)
        || !validContext(binding.agreementId)
        || typeof binding.caid !== 'string' || !CAID.test(binding.caid)
        || typeof binding.bindingDigest !== 'string' || !DIGEST.test(binding.bindingDigest)
        || typeof binding.profileDigest !== 'string' || !DIGEST.test(binding.profileDigest)
        || !Array.isArray(binding.amendmentDigests)
        || binding.amendmentDigests.some((entry: unknown) => typeof entry !== 'string' || !DIGEST.test(entry))
        || new Set(binding.amendmentDigests).size !== binding.amendmentDigests.length) {
      throw new TypeError('Action Escrow original-effect binding invalid');
    }
  }

  const pinned = snapshotData({
    tenantId: options.tenantId,
    environment: options.environment,
    audience: options.audience,
    actionEscrow: options.actionEscrow,
    revokerKeys: options.revokerKeys,
    disputeAuthority: options.disputeAuthority,
    remedyAuthority: options.remedyAuthority,
    providerAuthority: options.providerAuthority,
  }) as Readonly<RemedyProgramAdapterOptions>;
  const getEvidence = options.evidenceSource.get.bind(options.evidenceSource);
  const now = options.now ?? Date.now;

  const resolvedNow = (): number | string | Date | null => {
    try {
      const value = now();
      if (value instanceof Date) return Number.isFinite(value.getTime()) ? new Date(value) : null;
      if (typeof value === 'number') return Number.isFinite(value) ? value : null;
      return Number.isFinite(instant(value)) ? value : null;
    } catch {
      return null;
    }
  };

  const resolveEvidence = async (
    evidenceId: string,
    evidenceDigest: string,
  ): Promise<unknown | null> => {
    try {
      const value = await getEvidence(Object.freeze({
        tenantId: pinned.tenantId,
        evidenceId,
        evidenceDigest,
      }));
      const copy = canonicalCopy(value);
      return canonicalDigest(copy) === evidenceDigest ? deepFreeze(copy) : null;
    } catch {
      return null;
    }
  };

  const resolveSigned = async (
    evidenceId: string,
    evidenceDigest: string,
    kind: string,
    authority: Readonly<RemedyProgramPinnedAuthority>,
  ): Promise<DataRecord | null> => {
    const value = await resolveEvidence(evidenceId, evidenceDigest);
    return profile.verifySignedEvidence(value, kind, authority);
  };

  async function verifyOriginalEffect(input: Readonly<DataRecord>) {
    try {
      if (!exactKeys(input, new Set(['original', 'evidence', 'expected']))
          || !validOriginal(input.original)
          || !contextMatches(input.expected, pinned)
          || !exactKeys(input.evidence, new Set(['snapshot', 'statement']))) return failure();
      const original = input.original;
      const expected = input.expected;
      const binding = pinned.actionEscrow.originalEffects[original.operation_id];
      if (!binding || original.caid !== binding.caid
          || original.consequence_digest !== binding.bindingDigest) return failure();
      const snapshot = input.evidence.snapshot;
      const statement = input.evidence.statement;
      const stage = original.outcome === 'executed' ? 'released' : 'release_indeterminate';
      if (!isDataRecord(snapshot) || !isDataRecord(statement)
          || snapshot['@version'] !== 'EP-ACTION-ESCROW-STATE-v1'
          || snapshot.state !== stage
          || !Number.isSafeInteger(snapshot.revision) || snapshot.revision < 0
          || snapshot.release_action_digest !== original.action_digest
          || snapshot.document_action_binding_digest !== binding.bindingDigest
          || snapshot.profile_digest !== binding.profileDigest
          || !isDataRecord(snapshot.release)
          || snapshot.release.operation_idempotency_key !== original.operation_id
          || statement.statement_digest !== original.terminal_evidence_digest
          || statement.payload?.occurred_at !== original.occurred_at) return failure();
      const evaluation = resolvedNow();
      if (evaluation === null) return failure();
      const verified = await profile.verifyEscrowStatement(statement, {
        trustedKeys: pinned.actionEscrow.trustedKeys,
        stateRecord: snapshot,
        expectedAgreementId: binding.agreementId,
        expectedBindingDigest: binding.bindingDigest,
        expectedActionDigest: original.action_digest,
        expectedProfileDigest: binding.profileDigest,
        expectedState: stage,
        expectedRevision: snapshot.revision,
        expectedAmendmentDigests: binding.amendmentDigests,
        expectedPreviousStatementDigest: statement.payload.previous_statement_digest,
        now: evaluation,
      });
      if (verified.valid !== true || verified.statement_digest !== original.terminal_evidence_digest) {
        return failure();
      }
      return Object.freeze({
        ok: true,
        ...canonicalCopy(original),
        evidence_digest: original.terminal_evidence_digest,
      });
    } catch {
      return failure();
    }
  }

  async function verifyRevocationEvidence(input: Readonly<DataRecord>) {
    try {
      if (!exactKeys(input, new Set(['evidence', 'expected']))
          || !contextMatches(input.expected, pinned)
          || !validOriginal(input.expected.original, true)
          || !exactKeys(input.evidence, new Set(['id', 'digest']))
          || !validId(input.evidence.id)
          || typeof input.evidence.digest !== 'string' || !DIGEST.test(input.evidence.digest)) {
        return failure();
      }
      const statement: any = await resolveEvidence(input.evidence.id, input.evidence.digest);
      const evaluation = resolvedNow();
      if (!isDataRecord(statement) || evaluation === null) return failure();
      const target = {
        target_type: 'commit' as const,
        target_id: input.expected.original.operation_id,
        action_hash: input.expected.original.action_digest,
      };
      const verified = await profile.verifyRevocationEvidence(target, statement, {
        revokerKeys: pinned.revokerKeys,
        now: evaluation,
      });
      if (verified.valid !== true) return failure();
      return Object.freeze({
        ok: true,
        evidence_id: input.evidence.id,
        evidence_digest: input.evidence.digest,
        target_operation_id: target.target_id,
        action_digest: target.action_hash,
        authority_id: statement.revoker_id,
        revoked_at: statement.revoked_at,
      });
    } catch {
      return failure();
    }
  }

  async function verifyDispute(input: Readonly<DataRecord>) {
    try {
      if (!exactKeys(input, new Set(['dispute', 'expected']))
          || !contextMatches(input.expected, pinned)
          || !validOriginal(input.expected.original, true)
          || !isDataRecord(input.dispute)
          || !validId(input.dispute.evidence_id)
          || typeof input.dispute.evidence_digest !== 'string'
          || !DIGEST.test(input.dispute.evidence_digest)) return failure();
      const artifact = await resolveSigned(
        input.dispute.evidence_id,
        input.dispute.evidence_digest,
        'dispute',
        pinned.disputeAuthority,
      );
      if (!artifact || !exactKeys(artifact.payload, DISPUTE_PAYLOAD_KEYS)) return failure();
      const payload = artifact.payload;
      if (payload.tenant_id !== pinned.tenantId
          || payload.instance_id !== input.expected.instance_id
          || payload.original_operation_id !== input.expected.original.operation_id
          || payload.original_action_digest !== input.expected.original.action_digest
          || !payloadMatches(payload, input.dispute, [
            'evidence_id', 'dispute_id', 'challenger_id', 'requested_units', 'opened_at',
          ])) return failure();
      return Object.freeze({
        ok: true,
        dispute_id: payload.dispute_id,
        evidence_id: payload.evidence_id,
        evidence_digest: input.dispute.evidence_digest,
        challenger_id: payload.challenger_id,
        requested_units: payload.requested_units,
        opened_at: payload.opened_at,
        original_operation_id: payload.original_operation_id,
        original_action_digest: payload.original_action_digest,
      });
    } catch {
      return failure();
    }
  }

  async function verifyRemedyAuthorization(input: Readonly<DataRecord>) {
    try {
      if (!exactKeys(input, new Set(['authorization', 'expected']))
          || !contextMatches(input.expected, pinned)
          || !validOriginal(input.expected.original, true)
          || !isDataRecord(input.expected.dispute)
          || !isDataRecord(input.authorization)
          || !validId(input.authorization.evidence_id)
          || typeof input.authorization.evidence_digest !== 'string'
          || !DIGEST.test(input.authorization.evidence_digest)) return failure();
      const artifact = await resolveSigned(
        input.authorization.evidence_id,
        input.authorization.evidence_digest,
        'remedy_authorization',
        pinned.remedyAuthority,
      );
      if (!artifact || !exactKeys(artifact.payload, AUTHORIZATION_PAYLOAD_KEYS)) return failure();
      const payload = artifact.payload;
      const authorizationFields = [
        'evidence_id', 'remedy_operation_id', 'remedy_caid', 'remedy_action_digest',
        'consequence_mode', 'capability_template_digest', 'escrow_profile_digest',
        'units', 'authorized_at',
      ];
      if (payload.tenant_id !== pinned.tenantId
          || payload.instance_id !== input.expected.instance_id
          || payload.dispute_id !== input.expected.dispute.dispute_id
          || payload.original_operation_id !== input.expected.original.operation_id
          || payload.original_action_digest !== input.expected.original.action_digest
          || payload.destination_binding_digest !== input.expected.destination_binding_digest
          || payload.unit !== input.expected.unit
          || !payloadMatches(payload, input.authorization, authorizationFields)) return failure();
      return Object.freeze({
        ok: true,
        evidence_id: payload.evidence_id,
        evidence_digest: input.authorization.evidence_digest,
        remedy_operation_id: payload.remedy_operation_id,
        remedy_caid: payload.remedy_caid,
        remedy_action_digest: payload.remedy_action_digest,
        consequence_mode: payload.consequence_mode,
        capability_template_digest: payload.capability_template_digest,
        escrow_profile_digest: payload.escrow_profile_digest,
        units: payload.units,
        authorized_at: payload.authorized_at,
        dispute_id: payload.dispute_id,
        original_operation_id: payload.original_operation_id,
        destination_binding_digest: payload.destination_binding_digest,
        unit: payload.unit,
      });
    } catch {
      return failure();
    }
  }

  async function verifyRemedyOutcome(input: Readonly<DataRecord>) {
    try {
      if (!exactKeys(input, new Set(['evidence', 'outcome', 'expected', 'reconciliation']))
          || !contextMatches(input.expected, pinned)
          || !validOriginal(input.expected.original, true)
          || typeof input.reconciliation !== 'boolean'
          || !isDataRecord(input.evidence)
          || !validId(input.evidence.evidence_id)
          || typeof input.evidence.evidence_digest !== 'string'
          || !DIGEST.test(input.evidence.evidence_digest)) return failure();
      const artifact = await resolveSigned(
        input.evidence.evidence_id,
        input.evidence.evidence_digest,
        'provider_outcome',
        pinned.providerAuthority,
      );
      if (!artifact || !exactKeys(artifact.payload, OUTCOME_PAYLOAD_KEYS)) return failure();
      const payload = artifact.payload;
      if (payload.tenant_id !== pinned.tenantId
          || payload.instance_id !== input.expected.instance_id
          || payload.reconciliation !== input.reconciliation
          || payload.outcome !== input.outcome
          || payload.evidence_id !== input.evidence.evidence_id
          || payload.observed_at !== input.evidence.observed_at
          || !payloadMatches(payload, input.expected, [
            'remedy_operation_id', 'remedy_action_digest', 'destination_binding_digest',
            'units', 'unit',
          ])) return failure();
      return Object.freeze({
        ok: true,
        evidence_id: payload.evidence_id,
        evidence_digest: input.evidence.evidence_digest,
        remedy_operation_id: payload.remedy_operation_id,
        remedy_action_digest: payload.remedy_action_digest,
        destination_binding_digest: payload.destination_binding_digest,
        units: payload.units,
        unit: payload.unit,
        outcome: payload.outcome,
        observed_at: payload.observed_at,
      });
    } catch {
      return failure();
    }
  }

  async function verifyOriginalReconciliation(input: Readonly<DataRecord>) {
    try {
      if (!exactKeys(input, new Set(['evidence', 'outcome', 'expected']))
          || !contextMatches(input.expected, pinned)
          || !validOriginal(input.expected.original, true)
          || !isDataRecord(input.evidence)
          || !validId(input.evidence.evidence_id)
          || typeof input.evidence.evidence_digest !== 'string'
          || !DIGEST.test(input.evidence.evidence_digest)) return failure();
      const artifact = await resolveSigned(
        input.evidence.evidence_id,
        input.evidence.evidence_digest,
        'original_outcome',
        pinned.providerAuthority,
      );
      if (!artifact || !exactKeys(artifact.payload, ORIGINAL_OUTCOME_PAYLOAD_KEYS)) return failure();
      const payload = artifact.payload;
      if (payload.tenant_id !== pinned.tenantId
          || payload.instance_id !== input.expected.instance_id
          || payload.evidence_id !== input.evidence.evidence_id
          || payload.observed_at !== input.evidence.observed_at
          || payload.outcome !== input.outcome
          || payload.original_operation_id !== input.expected.original.operation_id
          || payload.original_action_digest !== input.expected.original.action_digest
          || payload.terminal_evidence_digest !== input.expected.original.terminal_evidence_digest) {
        return failure();
      }
      return Object.freeze({
        ok: true,
        evidence_id: payload.evidence_id,
        evidence_digest: input.evidence.evidence_digest,
        original_operation_id: payload.original_operation_id,
        original_action_digest: payload.original_action_digest,
        terminal_evidence_digest: payload.terminal_evidence_digest,
        outcome: payload.outcome,
        observed_at: payload.observed_at,
      });
    } catch {
      return failure();
    }
  }

  return Object.freeze({
    verifyOriginalEffect,
    verifyRevocation: verifyRevocationEvidence,
    verifyDispute,
    verifyRemedyAuthorization,
    verifyRemedyOutcome,
    verifyOriginalReconciliation,
  });
}

// ===========================================================================
// EP-GATE-REMEDY-EVIDENCE-v2 -- the hybrid (Ed25519 + ML-DSA-65) signed
// evidence envelope the Remedy Program adapters consume
// ===========================================================================
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the pinned-authority evidence
 * envelope these adapters resolve for every post-create transition.
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. `signature: {algorithm, value}` becomes
 *    `signature: {profile, required_algorithms, public_key, key_id,
 *    pq_public_key, pq_key_id, signatures}`, a wire-format change, so the
 *    envelope takes a new `version` (-v1 -> -v2). verifiedSignedEvidence (the
 *    v1 path) is UNCHANGED and refuses a v2 envelope on the version marker
 *    (`evidence.version !== REMEDY_PROGRAM_EVIDENCE_VERSION`) before it
 *    inspects any signature, returning null rather than throwing.
 * 2. SET SHAPE. `signature.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
 *    array ({ alg, sig, key_id? }), one entry per registered algorithm, in the
 *    registered order, reused verbatim.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is INSIDE the signed bytes
 *    (remedyProgramEvidenceV2SigningBytes). Drop the ML-DSA leg and narrow the
 *    set and the surviving Ed25519 signature no longer verifies; leave the set
 *    intact and the missing leg is a structural refusal. The verifier rebuilds
 *    the bytes from the REGISTERED set and the body it recomputed itself.
 * 4. V1 COMPATIBILITY. createRemedyProgramAdapters is UNCHANGED in behavior:
 *    it is now one call into a shared body with the v1 seam injected, and the
 *    v1 seam is the same verifiedSignedEvidence / verifyRevocation /
 *    verifyActionEscrowStateStatement calls it always made.
 *    createRemedyProgramAdaptersV2 injects the hybrid seam instead.
 * 5. NAMED REFUSALS. Every verification path returns null / `{ok:false}`;
 *    nothing throws on presented evidence. An absent ML-DSA backend surfaces
 *    as a refusal through the agility result, never a skipped check and never
 *    a pass on the classical leg.
 *
 * THE TWO CONSUMED ARTIFACTS, STATED PRECISELY.
 *   - EP-ACTION-ESCROW-STATE-STATEMENT: the v2 adapters call the ALREADY
 *     SHIPPED router (verifyActionEscrowStateStatementAny), not a v2-only
 *     verifier, so a v1 escrow statement keeps verifying exactly as it does
 *     today and a v2 one is additionally accepted. The escrow STATE RECORD's
 *     own marker is still EP-ACTION-ESCROW-STATE-v1 in this repository, and
 *     the snapshot pin here is unchanged for that reason.
 *   - EP-REVOCATION: the v2 adapters call the EP-REVOCATION-v2 router
 *     (verifyRevocationStatement), which gives a v1 statement the exact v1
 *     verdict and a v2 statement the hybrid check.
 *
 * HONEST BOUNDARY. The ML-DSA-65 backend is @noble/post-quantum's pure-JS FIPS
 * 204 implementation, not independently audited and not a FIPS validated
 * module. This profile is opt-in and is not on in any deployment.
 */

export const REMEDY_PROGRAM_EVIDENCE_V2_VERSION = 'EP-GATE-REMEDY-EVIDENCE-v2';
export const REMEDY_PROGRAM_EVIDENCE_V2_DOMAIN = `${REMEDY_PROGRAM_EVIDENCE_V2_VERSION}\0`;

/** The registered required algorithm set, in canonical order. */
export const REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

const SIGNATURE_V2_KEYS = new Set([
  'profile', 'required_algorithms', 'public_key', 'key_id',
  'pq_public_key', 'pq_key_id', 'signatures',
]);

/** A v2 authority pin: BOTH public halves per key id, pinned out of band. */
export interface RemedyProgramEvidenceV2KeyPin {
  /** Ed25519 base64url SPKI DER. */
  public_key: string;
  /** ML-DSA-65 base64url raw public key bytes. */
  pq_public_key: string;
}

export interface RemedyProgramPinnedAuthorityV2 {
  authorityId: string;
  trustedKeys: Record<string, RemedyProgramEvidenceV2KeyPin>;
}

function evidenceV2AlgorithmSetRegistered(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS[i]);
}

/** ML-DSA-65 public-key identifier: the SHA-256 of the raw public key bytes. */
function evidencePqKeyId(publicKeyRawB64u: unknown): string {
  try {
    if (typeof publicKeyRawB64u !== 'string' || publicKeyRawB64u.length === 0) return '';
    const raw = Buffer.from(publicKeyRawB64u, 'base64url');
    if (raw.length !== ML_DSA_65_PUBLIC_KEY_BYTES || raw.toString('base64url') !== publicKeyRawB64u) return '';
    return `ep:remedy-evidence-key:ml-dsa-65:sha256:${crypto.createHash('sha256').update(raw).digest('hex')}`;
  } catch {
    return '';
  }
}

/**
 * Domain-separated canonical bytes for the closed hybrid evidence envelope:
 * the same signing body as v1 under the v2 domain tag, plus the committed
 * `required_algorithms` set. See move 3 above.
 */
export function remedyProgramEvidenceV2SigningBytes(
  value: unknown,
  requiredAlgorithms: readonly string[] = REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!isDataRecord(value)) throw new TypeError('remedy evidence v2 signing body invalid');
  if (!evidenceV2AlgorithmSetRegistered(requiredAlgorithms)) {
    throw new TypeError('remedyProgramEvidenceV2SigningBytes: algorithm set is not the registered EP-GATE-REMEDY-EVIDENCE-v2 set');
  }
  const body = signingBody(value);
  if (!exactKeys(body, SIGNING_BODY_KEYS)) {
    throw new TypeError('remedy evidence v2 signing body invalid');
  }
  return Buffer.from(
    REMEDY_PROGRAM_EVIDENCE_V2_DOMAIN
    + canonicalize({ ...body, required_algorithms: [...requiredAlgorithms] }),
    'utf8',
  );
}

/**
 * Issuer-side helper: mint one hybrid evidence envelope. Throws on invalid
 * input or an unavailable ML-DSA backend -- an envelope missing the ML-DSA leg
 * must never be emitted, only refused.
 */
export async function signRemedyProgramEvidenceV2(
  { kind, issuer, payload }: { kind: string; issuer: { authority_id: string; key_id: string }; payload: unknown },
  keys: {
    ed: { privateKey: crypto.KeyObject; publicKey?: string };
    pq: { secretKey: Uint8Array | string; publicKey: string };
  },
): Promise<DataRecord> {
  if (typeof kind !== 'string' || kind.length === 0
      || !isDataRecord(issuer) || !validContext(issuer.authority_id) || !validId(issuer.key_id)
      || !isDataRecord(payload)) {
    throw new TypeError('remedy evidence v2 requires kind, issuer { authority_id, key_id }, and a payload record');
  }
  if (!keys?.ed?.privateKey || !keys?.pq?.secretKey || typeof keys?.pq?.publicKey !== 'string') {
    throw new TypeError('remedy evidence v2 keys require ed.privateKey, pq.secretKey, and pq.publicKey');
  }
  const pqKeyId = evidencePqKeyId(keys.pq.publicKey);
  if (!pqKeyId) throw new TypeError('remedy evidence v2 ML-DSA-65 public key must be raw base64url bytes');
  const edPublicKey = keys.ed.publicKey ?? crypto.createPublicKey(keys.ed.privateKey)
    .export({ type: 'spki', format: 'der' }).toString('base64url');
  if (ed25519PublicKey(edPublicKey) === null) {
    throw new TypeError('remedy evidence v2 Ed25519 public key must be base64url SPKI DER');
  }
  const unsigned = {
    version: REMEDY_PROGRAM_EVIDENCE_V2_VERSION,
    kind,
    issuer: { authority_id: issuer.authority_id, key_id: issuer.key_id },
    payload: canonicalCopy(payload),
  };
  const requiredAlgorithms = [...REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS];
  const signedBody = { ...unsigned, content_digest: canonicalDigest(unsigned) };
  const bytes = remedyProgramEvidenceV2SigningBytes(signedBody, requiredAlgorithms);
  const signingKeys: AgileSigningKey[] = [
    { alg: 'Ed25519', private_key: keys.ed.privateKey },
    { alg: 'ML-DSA-65', private_key: keys.pq.secretKey },
  ];
  const signatures = await signAgileSet(new Uint8Array(bytes), signingKeys);
  return deepFreeze(canonicalCopy({
    ...signedBody,
    signature: {
      profile: REMEDY_PROGRAM_EVIDENCE_V2_VERSION,
      required_algorithms: requiredAlgorithms,
      public_key: edPublicKey,
      key_id: issuer.key_id,
      pq_public_key: keys.pq.publicKey,
      pq_key_id: pqKeyId,
      signatures,
    },
  })) as DataRecord;
}

function validTrustedKeysV2(value: unknown): value is Record<string, RemedyProgramEvidenceV2KeyPin> {
  return isDataRecord(value) && Object.keys(value).length > 0
    && Object.entries(value).every(([keyId, pin]) => validId(keyId)
      && exactKeys(pin, new Set(['public_key', 'pq_public_key']))
      && ed25519PublicKey(pin.public_key) !== null
      && evidencePqKeyId(pin.pq_public_key) !== '');
}

function validAuthorityV2(value: unknown): value is RemedyProgramPinnedAuthorityV2 {
  return exactKeys(value, AUTHORITY_KEYS)
    && validContext(value.authorityId)
    && validTrustedKeysV2(value.trustedKeys);
}

/**
 * FAIL-CLOSED hybrid evidence check. Returns the verified envelope or null;
 * never throws on presented evidence, and never verifies on one leg alone.
 */
async function verifiedSignedEvidenceV2(
  value: unknown,
  kind: string,
  authority: Readonly<RemedyProgramPinnedAuthorityV2>,
  agility: AgilityOptions = {},
): Promise<DataRecord | null> {
  try {
    const evidence = canonicalCopy(value) as unknown;
    // 1. Version marker + closed shape. A v1 envelope refuses here, the mirror
    //    image of the v1 path refusing a v2 envelope.
    if (!exactKeys(evidence, SIGNED_EVIDENCE_KEYS)
        || evidence.version !== REMEDY_PROGRAM_EVIDENCE_V2_VERSION
        || evidence.kind !== kind
        || !exactKeys(evidence.issuer, ISSUER_KEYS)
        || evidence.issuer.authority_id !== authority.authorityId
        || !validId(evidence.issuer.key_id)
        || !isDataRecord(evidence.payload)
        || typeof evidence.content_digest !== 'string'
        || !DIGEST.test(evidence.content_digest)
        || !exactKeys(evidence.signature, SIGNATURE_V2_KEYS)
        || evidence.signature.profile !== REMEDY_PROGRAM_EVIDENCE_V2_VERSION) return null;

    // 2. Content digest, recomputed. The envelope does not get to assert it.
    const unsigned = {
      version: evidence.version,
      kind: evidence.kind,
      issuer: evidence.issuer,
      payload: evidence.payload,
    };
    if (canonicalDigest(unsigned) !== evidence.content_digest) return null;

    // 3. Committed algorithm set: exact and order-sensitive.
    if (!evidenceV2AlgorithmSetRegistered(evidence.signature.required_algorithms)) return null;

    // 4. Exactly one signature per required algorithm.
    const signatures = Array.isArray(evidence.signature.signatures)
      ? evidence.signature.signatures as AgileSignature[] : null;
    if (!signatures) return null;
    const presented = new Set<string>();
    for (const entry of signatures) {
      if (!isDataRecord(entry) || typeof entry.alg !== 'string' || typeof entry.sig !== 'string') return null;
      if (presented.has(entry.alg)) return null;
      presented.add(entry.alg);
    }
    for (const alg of REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS) {
      if (!presented.has(alg)) return null;
    }
    for (const alg of presented) {
      if (!(REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) return null;
    }

    // 5. Authority keys: BOTH halves pinned, and the presented halves must
    //    equal the pinned ones. Identified-but-not-trusted, per leg.
    const pin = authority.trustedKeys[evidence.issuer.key_id];
    if (!isDataRecord(pin)
        || pin.public_key !== evidence.signature.public_key
        || pin.pq_public_key !== evidence.signature.pq_public_key
        || evidence.signature.key_id !== evidence.issuer.key_id
        // Curve-pinned: a non-Ed25519 SPKI presented as the classical half
        // fails here as well as in the signature check.
        || ed25519PublicKey(pin.public_key) === null
        || evidencePqKeyId(pin.pq_public_key) === ''
        || evidence.signature.pq_key_id !== evidencePqKeyId(pin.pq_public_key)) return null;

    // 6. Signature set over bytes rebuilt from the PRESENTED body and the
    //    REGISTERED algorithm set, under the PINNED keys.
    let setResult;
    try {
      setResult = await verifyAgileSignatureSet(
        new Uint8Array(remedyProgramEvidenceV2SigningBytes(
          evidence, REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS,
        )),
        signatures,
        [
          { alg: 'Ed25519', public_key: pin.public_key },
          { alg: 'ML-DSA-65', public_key: pin.pq_public_key },
        ],
        {
          ...agility,
          policy: 'hybrid_all',
          requiredAlgorithms: [...REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS],
        },
      );
    } catch {
      setResult = null;
    }
    if (setResult?.verified !== true) return null;
    return evidence;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// EP-REVOCATION-v2 router resolution.
//
// @emilia-protocol/verify publishes the revocation router at the literal
// "./revocation.js" subpath. Keep the workspace-relative compatibility path
// as a literal too, so Webpack can include both candidates in its dependency
// graph. Only v2-marked statements use this async router; v1 statements keep
// the package-root v1 path. If neither router candidate resolves, the v2 leg
// remains a fail-closed refusal, never a downgrade to v1 and never a pass.
// ---------------------------------------------------------------------------
const REVOCATION_V2_VERSION = 'EP-REVOCATION-v2';

type RevocationStatementVerifier = (
  target: unknown, statement: unknown, opts: unknown,
) => Promise<{ valid: boolean; checks: Record<string, boolean>; errors: string[] }>;

let _remedyRevocationStatementVerifier: RevocationStatementVerifier | null = null;

async function resolveRevocationStatementVerifier(): Promise<RevocationStatementVerifier> {
  if (_remedyRevocationStatementVerifier) return _remedyRevocationStatementVerifier;
  let mod: any;
  try {
    mod = await import('@emilia-protocol/verify/revocation.js');
  } catch {
    // Resolution-failure shapes are not uniform across runtimes, so any
    // primary-resolution failure falls back to the workspace-relative path;
    // only a failure of that path is surfaced.
    mod = await import('../../verify/revocation.js');
  }
  if (typeof mod?.verifyRevocationStatement !== 'function') {
    throw new Error('EP-REVOCATION-v2 router (verifyRevocationStatement) unavailable');
  }
  _remedyRevocationStatementVerifier = mod.verifyRevocationStatement as RevocationStatementVerifier;
  return _remedyRevocationStatementVerifier;
}

/** Test-only hook: force re-resolution (e.g. after swapping module mocks). */
export function _resetRemedyRevocationRouterCacheForTests(): void {
  _remedyRevocationStatementVerifier = null;
}

/**
 * Build the Remedy Program callbacks against the HYBRID evidence profile.
 * Identical adapter body to createRemedyProgramAdapters (see
 * buildRemedyProgramAdapters); only the pinned verifier seam differs, so the
 * transition rules, tenant/context pins, and binding checks cannot drift
 * between the two profiles.
 *
 * `disputeAuthority`, `remedyAuthority`, and `providerAuthority` take
 * RemedyProgramPinnedAuthorityV2 pins (both public halves per key id).
 * `actionEscrow.trustedKeys` accepts EITHER the v1 pin
 * ({operator_id, public_key}) or the v2 pin
 * ({operator_id, public_key, pq_public_key}), because the escrow leg is a
 * ROUTER: a relying party mid-migration holds a mixed bag of escrow
 * statements and must be able to pin for both.
 */
export function createRemedyProgramAdaptersV2(options: Omit<
  RemedyProgramAdapterOptions,
  'disputeAuthority' | 'remedyAuthority' | 'providerAuthority'
> & {
  disputeAuthority: RemedyProgramPinnedAuthorityV2;
  remedyAuthority: RemedyProgramPinnedAuthorityV2;
  providerAuthority: RemedyProgramPinnedAuthorityV2;
  mldsaBackend?: AgilityOptions['mldsaBackend'];
  mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}) {
  const agility: AgilityOptions = {};
  if (options?.mldsaBackend !== undefined) agility.mldsaBackend = options.mldsaBackend;
  if (options?.mldsaBackendLoader !== undefined) agility.mldsaBackendLoader = options.mldsaBackendLoader;
  const profile: RemedyAdapterProfile = {
    validAuthority: validAuthorityV2,
    validEscrowKeyPin: (pin: unknown) => (
      (exactKeys(pin, new Set(['operator_id', 'public_key']))
        || (exactKeys(pin, new Set(['operator_id', 'public_key', 'pq_public_key']))
          && evidencePqKeyId(pin.pq_public_key) !== ''))
      && validContext((pin as DataRecord).operator_id)
      && ed25519PublicKey((pin as DataRecord).public_key) !== null
    ),
    verifySignedEvidence: (value, kind, authority) => verifiedSignedEvidenceV2(
      value, kind, authority as unknown as RemedyProgramPinnedAuthorityV2, agility,
    ),
    async verifyRevocationEvidence(target, statement, opts) {
      // Route on the statement's own version marker, exactly as the published
      // verifyRevocationStatement router does. A v1 statement goes to the
      // package-root verifier (exported, always resolvable), so the v1
      // consumption stays additive and unchanged. Only a v2-marked statement
      // needs the dynamically resolved router; see the note above for why, and
      // for why its unavailability is a refusal rather than a downgrade.
      if (!isDataRecord(statement)
          || (statement as DataRecord)['@version'] !== REVOCATION_V2_VERSION) {
        return verifyRevocation(target as any, statement as any, opts as any);
      }
      try {
        const route = await resolveRevocationStatementVerifier();
        return await route(target, statement, { ...(opts as object), ...agility });
      } catch {
        return { valid: false };
      }
    },
    verifyEscrowStatement: (statement, opts) => verifyActionEscrowStateStatementAny(
      statement as any, { ...(opts as object), ...agility } as any,
    ),
  };
  return buildRemedyProgramAdapters(
    options as unknown as RemedyProgramAdapterOptions,
    Object.freeze(profile),
  );
}

export default Object.freeze({
  REMEDY_PROGRAM_EVIDENCE_VERSION,
  REMEDY_PROGRAM_EVIDENCE_DOMAIN,
  REMEDY_PROGRAM_EVIDENCE_V2_VERSION,
  REMEDY_PROGRAM_EVIDENCE_V2_DOMAIN,
  REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS,
  remedyProgramEvidenceDigest,
  remedyProgramEvidenceSigningBytes,
  remedyProgramEvidenceV2SigningBytes,
  signRemedyProgramEvidenceV2,
  createRemedyProgramAdapters,
  createRemedyProgramAdaptersV2,
});
