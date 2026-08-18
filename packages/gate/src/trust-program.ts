// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate Trust Program Profile v1.
 *
 * A relying-party-controlled, fail-closed authorization DAG for consequential
 * actions. This module composes evidence verifiers; it does not redefine the
 * Handshake, Quorum, AEC, capability, or Action Escrow wire formats.
 */
import crypto from 'node:crypto';
import { canonicalize, hashCanonical } from './execution-binding.js';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  type AgileSigningKey,
  type AgileSignature,
  type AgilityOptions,
} from '@emilia-protocol/verify/pq-signature-agility';

export const TRUST_PROGRAM_VERSION = 'EP-GATE-TRUST-PROGRAM-PROFILE-v1';
export const TRUST_STAGE_RECEIPT_VERSION = 'EP-GATE-TRUST-STAGE-RECEIPT-v1';
const STAGE_RECEIPT_DOMAIN = `${TRUST_STAGE_RECEIPT_VERSION}\0`;

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CAID = /^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const MAX_STAGES = 64;
const MAX_REQUIREMENTS_PER_STAGE = 64;
const MAX_TOTAL_REQUIREMENTS = 1024;
const PROGRAM_KEYS = new Set([
  '@version', 'program_id', 'version', 'root_caid', 'action_digest',
  'valid_from', 'expires_at', 'stages', 'execution',
]);
const STAGE_KEYS = new Set(['stage_id', 'depends_on', 'rule', 'requirements']);
const REQUIREMENT_KEYS = new Set([
  'requirement_id', 'evidence_type', 'verifier_profile', 'policy_digest',
  'max_age_sec', 'revocation_required',
]);
const EXECUTION_KEYS = new Set([
  'depends_on', 'consequence_mode', 'capability_template_digest', 'escrow_profile_digest',
]);
const STAGE_RECEIPT_KEYS = new Set([
  'version', 'issuer', 'payload', 'receipt_digest', 'signature',
]);
const STAGE_RECEIPT_ISSUER_KEYS = new Set([
  'issuer', 'tenant', 'environment', 'audience', 'key_id',
]);
const STAGE_RECEIPT_PAYLOAD_KEYS = new Set([
  'instance_id', 'program_id', 'program_version', 'program_digest', 'root_caid',
  'action_digest', 'stage_id', 'stage_policy_digest', 'predecessor_receipt_digests',
  'evidence_digests', 'subjects', 'key_fingerprints', 'satisfied_at',
]);
const STAGE_RECEIPT_SIGNATURE_KEYS = new Set(['algorithm', 'value']);
const STATE_KEYS = new Set([
  'version', 'tenant_id', 'instance_id', 'program_id', 'program_version', 'program_digest',
  'root_caid', 'action_digest', 'status', 'revision', 'created_at', 'updated_at',
  'stages', 'used_evidence_ids', 'execution', 'invalidation_reason',
]);
const STAGE_STATE_KEYS = new Set([
  'status', 'predecessor_receipt_digests', 'evidence', 'receipt',
]);
const EVIDENCE_STATE_KEYS = new Set([
  'evidence_id', 'evidence_digest', 'policy_digest', 'binding_digest', 'subjects',
  'key_fingerprints', 'issued_at', 'expires_at', 'revocation_checked_at',
]);
const EXECUTION_STATE_KEYS = new Set([
  'status', 'claim_token_digest', 'evidence_digest', 'outcome', 'operation_id',
  'claimed_at', 'authorization_binding', 'finalized_at', 'reconciled_at',
]);
const AUTHORIZATION_BINDING_KEYS = new Set([
  'instance_id', 'operation_id', 'program_digest', 'root_caid', 'action_digest',
  'receipt_context_digest', 'terminal_stage_receipt_digests', 'consequence_mode',
  'capability_template_digest', 'escrow_profile_digest',
]);

type RecordLike = Record<string, any>;
type Failure = { ok: false; reason: string };

export type TrustJson = null | boolean | number | string | TrustJson[] | { [key: string]: TrustJson };

export interface TrustProgramState extends Record<string, unknown> {
  tenant_id: string;
  instance_id: string;
  program_digest: string;
  root_caid: string;
  action_digest: string;
  status: string;
  revision: number;
  stages: Record<string, Record<string, unknown>>;
  execution: Record<string, unknown>;
}

export interface TrustProgramResult extends Record<string, unknown> {
  ok: boolean;
  reason?: string;
  state?: TrustProgramState;
}

export interface TrustProgramStore {
  readonly durable: boolean;
  create(input: {
    tenantId: string;
    state: TrustProgramState;
  }): Promise<TrustProgramResult>;
  get(input: { tenantId: string; instanceId: string }): Promise<TrustProgramResult>;
  compareAndSwap(input: {
    tenantId: string;
    instanceId: string;
    expectedRevision: number;
    state: TrustProgramState;
  }): Promise<TrustProgramResult>;
  invalidate(input: {
    tenantId: string;
    instanceId: string;
    expectedRevision: number;
    reason: string;
    at: number;
  }): Promise<TrustProgramResult>;
}

export interface TrustEvidenceProjection extends Record<string, unknown> {
  valid: boolean;
  reason?: string | null;
  binding_digest?: string;
  policy_digest?: string;
  subjects?: string[];
  key_fingerprints?: string[];
  issued_at?: string;
  expires_at?: string;
  revocation_checked_at?: string | null;
}

export type TrustEvidenceVerifier = (input: {
  artifact: unknown;
  requirement: Readonly<Record<string, unknown>>;
  program: Readonly<Record<string, unknown>>;
}) => Promise<TrustEvidenceProjection> | TrustEvidenceProjection;

export interface TrustProgramKernelConfig {
  program: unknown;
  store: TrustProgramStore;
  verifiers: Readonly<Record<string, TrustEvidenceVerifier>>;
  receiptPrivateKey?: crypto.KeyLike;
  receiptVerificationKey?: string | crypto.KeyObject;
  receiptSigner?: (input: {
    signingBytes: Buffer;
    body: Readonly<Record<string, unknown>>;
    receiptDigest: string;
  }) => Promise<string> | string;
  receiptContext: Readonly<{
    issuer: string;
    tenant: string;
    environment: string;
    audience: string;
    key_id: string;
  }>;
  allowEphemeralState?: boolean;
  actionBindingVerifier?: (input: Readonly<Record<string, unknown>>) => Promise<boolean> | boolean;
  executionBindingVerifier?: (input: Readonly<Record<string, unknown>>) => Promise<boolean> | boolean;
  executionEvidenceRevalidator?: (input: Readonly<Record<string, unknown>>) => Promise<boolean> | boolean;
  executionOutcomeVerifier?: (input: Readonly<Record<string, unknown>>) => Promise<boolean> | boolean;
  reconciliationVerifier?: (input: Readonly<Record<string, unknown>>) => Promise<boolean> | boolean;
  now?: () => number;
}

export interface TrustProgramKernel {
  readonly program_digest: string;
  start(input: { instanceId: string; action?: unknown }): Promise<TrustProgramResult>;
  status(instanceId: string): Promise<TrustProgramResult>;
  challenge(input: {
    instanceId: string;
    stageId: string;
    requirementId: string;
  }): Promise<TrustProgramResult>;
  admit(input: {
    instanceId: string;
    stageId: string;
    requirementId: string;
    artifact: unknown;
  }): Promise<TrustProgramResult>;
  claimExecution(input: {
    instanceId: string;
    operationId?: string;
    claimToken?: string;
  }): Promise<TrustProgramResult>;
  finalizeExecution(input: {
    instanceId: string;
    claimToken: string;
    outcome: 'executed' | 'refused' | 'indeterminate';
    evidenceDigest: string;
    evidence?: unknown;
  }): Promise<TrustProgramResult>;
  reconcileExecution(input: {
    instanceId: string;
    outcome: 'executed' | 'proved_no_effect';
    evidenceDigest: string;
    evidence?: unknown;
  }): Promise<TrustProgramResult>;
  invalidate(input: {
    instanceId: string;
    expectedRevision: number;
    reason: string;
  }): Promise<TrustProgramResult>;
}

function fail(reason: string): Failure {
  return { ok: false, reason };
}

function isRecord(value: unknown): value is RecordLike {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isDataRecord(value: unknown): value is RecordLike {
  return isRecord(value) && Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function exactKeys(value: unknown, allowed: Set<string>): value is RecordLike {
  return isDataRecord(value)
    && Reflect.ownKeys(value).length === allowed.size
    && Object.keys(value).every((key) => allowed.has(key));
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function digest(value: unknown): string {
  return `sha256:${hashCanonical(value)}`;
}

function strictInstant(value: unknown): number {
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function exactUniqueStrings(value: unknown, maximum: number): value is string[] {
  return Array.isArray(value)
    && value.length <= maximum
    && value.every((entry) => typeof entry === 'string' && ID.test(entry))
    && new Set(value).size === value.length;
}

function boundedProjection(value: unknown, required: boolean): value is string[] {
  return Array.isArray(value)
    && (!required || value.length > 0)
    && value.length <= 256
    && value.every((entry) => typeof entry === 'string'
      && entry.length > 0 && entry.length <= 512
      && !/[\u0000-\u001f\u007f]/.test(entry))
    && new Set(value).size === value.length;
}

function sortedUniqueDigests(value: unknown, maximum: number): value is string[] {
  return Array.isArray(value)
    && value.length <= maximum
    && value.every((entry) => typeof entry === 'string' && DIGEST.test(entry))
    && new Set(value).size === value.length
    && value.every((entry, index) => index === 0 || value[index - 1] < entry);
}

function boundedContextString(value: unknown) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function effectiveRequired(stage: RecordLike): number {
  if (stage.rule.mode === 'all') return stage.requirements.length;
  if (stage.rule.mode === 'any') return 1;
  return stage.rule.required;
}

function validationFailure(reason: string) {
  return { valid: false, reason, digest: null };
}

/** Validate the closed, bounded DAG before any state is created. */
export function validateTrustProgram(program: unknown) {
  return validateTrustProgramUnder(program, TRUST_PROGRAM_VERSION);
}

/**
 * ONE validation body for both profile versions. validateTrustProgram (v1) and
 * validateTrustProgramV2 differ ONLY in the `@version` marker they accept, so
 * the DAG rules, bounds, cycle check, and execution-relevance check cannot
 * drift between them.
 */
function validateTrustProgramUnder(program: unknown, expectedVersion: string) {
  try {
    canonicalize(program);
  } catch {
    return validationFailure('program_not_canonical');
  }
  if (!exactKeys(program, PROGRAM_KEYS) || program['@version'] !== expectedVersion) {
    return validationFailure('program_version_unsupported');
  }
  if (typeof program.program_id !== 'string' || !ID.test(program.program_id)
      || !Number.isSafeInteger(program.version) || program.version < 1
      || typeof program.root_caid !== 'string' || !CAID.test(program.root_caid)
      || typeof program.action_digest !== 'string' || !DIGEST.test(program.action_digest)) {
    return validationFailure('program_binding_invalid');
  }
  const validFrom = strictInstant(program.valid_from);
  const expiresAt = strictInstant(program.expires_at);
  if (!Number.isFinite(validFrom) || !Number.isFinite(expiresAt) || expiresAt <= validFrom) {
    return validationFailure('program_time_window_invalid');
  }
  if (!Array.isArray(program.stages) || program.stages.length === 0 || program.stages.length > MAX_STAGES) {
    return validationFailure('program_stage_count_invalid');
  }
  if (!exactKeys(program.execution, EXECUTION_KEYS)
      || !exactUniqueStrings(program.execution.depends_on, MAX_STAGES)
      || program.execution.depends_on.length === 0
      || !['receipt-program', 'action-escrow'].includes(program.execution.consequence_mode)
      || (program.execution.consequence_mode === 'receipt-program'
        && (!DIGEST.test(program.execution.capability_template_digest)
          || program.execution.escrow_profile_digest !== null))
      || (program.execution.consequence_mode === 'action-escrow'
        && (!DIGEST.test(program.execution.escrow_profile_digest)
          || program.execution.capability_template_digest !== null))) {
    return validationFailure('program_execution_invalid');
  }

  const stageIds = new Set<string>();
  let totalRequirements = 0;
  for (const stage of program.stages) {
    if (!exactKeys(stage, STAGE_KEYS) || typeof stage.stage_id !== 'string' || !ID.test(stage.stage_id)
        || stageIds.has(stage.stage_id)) return validationFailure('stage_id_invalid');
    stageIds.add(stage.stage_id);
    if (!exactUniqueStrings(stage.depends_on, MAX_STAGES) || stage.depends_on.includes(stage.stage_id)) {
      return validationFailure('stage_dependency_invalid');
    }
    if (!Array.isArray(stage.requirements) || stage.requirements.length === 0
        || stage.requirements.length > MAX_REQUIREMENTS_PER_STAGE) {
      return validationFailure('stage_requirement_count_invalid');
    }
    totalRequirements += stage.requirements.length;
    if (totalRequirements > MAX_TOTAL_REQUIREMENTS) return validationFailure('program_requirement_limit');
    const requirementIds = new Set<string>();
    for (const requirement of stage.requirements) {
      if (!exactKeys(requirement, REQUIREMENT_KEYS)
          || typeof requirement.requirement_id !== 'string' || !ID.test(requirement.requirement_id)
          || requirementIds.has(requirement.requirement_id)
          || typeof requirement.evidence_type !== 'string' || !ID.test(requirement.evidence_type)
          || typeof requirement.verifier_profile !== 'string' || !ID.test(requirement.verifier_profile)
          || typeof requirement.policy_digest !== 'string' || !DIGEST.test(requirement.policy_digest)
          || !Number.isSafeInteger(requirement.max_age_sec) || requirement.max_age_sec < 1
          || requirement.max_age_sec > 31_536_000
          || typeof requirement.revocation_required !== 'boolean') {
        return validationFailure('stage_requirement_invalid');
      }
      requirementIds.add(requirement.requirement_id);
    }
    const ruleKeys = stage.rule?.mode === 'threshold'
      ? new Set(['mode', 'required', 'distinct_subjects', 'distinct_keys'])
      : new Set(['mode', 'distinct_subjects', 'distinct_keys']);
    if (!exactKeys(stage.rule, ruleKeys)
        || !['all', 'any', 'threshold'].includes(stage.rule.mode)
        || typeof stage.rule.distinct_subjects !== 'boolean'
        || typeof stage.rule.distinct_keys !== 'boolean') {
      return validationFailure('stage_rule_invalid');
    }
    const required = effectiveRequired(stage);
    if (!Number.isSafeInteger(required) || required < 1 || required > stage.requirements.length) {
      return validationFailure('stage_threshold_invalid');
    }
  }

  for (const stage of program.stages) {
    if (stage.depends_on.some((dependency: string) => !stageIds.has(dependency))) {
      return validationFailure('stage_dependency_unknown');
    }
  }
  if (program.execution.depends_on.some((dependency: string) => !stageIds.has(dependency))) {
    return validationFailure('execution_dependency_unknown');
  }

  const byId = new Map(program.stages.map((stage: RecordLike) => [stage.stage_id, stage]));
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (stageId: string): boolean => {
    if (visiting.has(stageId)) return false;
    if (visited.has(stageId)) return true;
    visiting.add(stageId);
    for (const dependency of byId.get(stageId)!.depends_on) {
      if (!visit(dependency)) return false;
    }
    visiting.delete(stageId);
    visited.add(stageId);
    return true;
  };
  for (const stageId of stageIds) {
    if (!visit(stageId)) return validationFailure('program_cycle');
  }

  const executionRelevant = new Set<string>();
  const markRelevant = (stageId: string) => {
    if (executionRelevant.has(stageId)) return;
    executionRelevant.add(stageId);
    for (const dependency of byId.get(stageId)!.depends_on) markRelevant(dependency);
  };
  for (const stageId of program.execution.depends_on) markRelevant(stageId);
  if ([...stageIds].some((stageId) => !executionRelevant.has(stageId))) {
    return validationFailure('stage_not_execution_relevant');
  }
  return { valid: true, reason: null, digest: digest(program) };
}

export function trustProgramDigest(program: unknown): string {
  const result = validateTrustProgram(program);
  if (!result.valid) throw new TypeError(`invalid trust program: ${result.reason}`);
  return result.digest!;
}

function publicKey(value: unknown): crypto.KeyObject | null {
  try {
    if (value instanceof crypto.KeyObject) return value;
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.toString('base64url') !== value) return null;
    const key = crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function stageReceiptBody(receipt: RecordLike) {
  return { version: receipt.version, issuer: receipt.issuer, payload: receipt.payload };
}

/**
 * The stage-receipt PAYLOAD shape, shared verbatim by the v1 and v2 receipt
 * verifiers so the two cannot drift on what a stage receipt is allowed to say.
 * Only the envelope (version marker and signature shape) differs between them.
 */
function validStageReceiptPayloadShape(payload: unknown): payload is RecordLike {
  return exactKeys(payload, STAGE_RECEIPT_PAYLOAD_KEYS)
    && typeof payload.instance_id === 'string' && ID.test(payload.instance_id)
    && typeof payload.program_id === 'string' && ID.test(payload.program_id)
    && Number.isSafeInteger(payload.program_version) && payload.program_version >= 1
    && typeof payload.program_digest === 'string' && DIGEST.test(payload.program_digest)
    && typeof payload.root_caid === 'string' && CAID.test(payload.root_caid)
    && typeof payload.action_digest === 'string' && DIGEST.test(payload.action_digest)
    && typeof payload.stage_id === 'string' && ID.test(payload.stage_id)
    && typeof payload.stage_policy_digest === 'string' && DIGEST.test(payload.stage_policy_digest)
    && sortedUniqueDigests(payload.predecessor_receipt_digests, MAX_STAGES)
    && sortedUniqueDigests(payload.evidence_digests, MAX_REQUIREMENTS_PER_STAGE)
    && boundedProjection(payload.subjects, false)
    && boundedProjection(payload.key_fingerprints, false)
    && payload.subjects.every((entry: string, index: number) =>
      index === 0 || payload.subjects[index - 1] < entry)
    && payload.key_fingerprints.every((entry: string, index: number) =>
      index === 0 || payload.key_fingerprints[index - 1] < entry)
    && Number.isFinite(strictInstant(payload.satisfied_at));
}

function validStageReceiptShape(receipt: unknown): receipt is RecordLike {
  if (!exactKeys(receipt, STAGE_RECEIPT_KEYS)
      || receipt.version !== TRUST_STAGE_RECEIPT_VERSION
      || !exactKeys(receipt.issuer, STAGE_RECEIPT_ISSUER_KEYS)
      || !Object.values(receipt.issuer).every(boundedContextString)
      || !validStageReceiptPayloadShape(receipt.payload)
      || typeof receipt.receipt_digest !== 'string' || !DIGEST.test(receipt.receipt_digest)
      || !exactKeys(receipt.signature, STAGE_RECEIPT_SIGNATURE_KEYS)
      || receipt.signature.algorithm !== 'Ed25519'
      || typeof receipt.signature.value !== 'string'
      || !/^[A-Za-z0-9_-]+$/.test(receipt.signature.value)
      || Buffer.from(receipt.signature.value, 'base64url').length !== 64
      || Buffer.from(receipt.signature.value, 'base64url').toString('base64url') !== receipt.signature.value) {
    return false;
  }
  return true;
}

async function signStageReceipt(
  payload: RecordLike,
  context: RecordLike,
  privateKey: crypto.KeyLike | undefined,
  signer: ((input: {
    signingBytes: Buffer;
    body: Readonly<Record<string, unknown>>;
    receiptDigest: string;
  }) => Promise<string> | string) | undefined,
) {
  const body = {
    version: TRUST_STAGE_RECEIPT_VERSION,
    issuer: {
      issuer: context.issuer,
      tenant: context.tenant,
      environment: context.environment,
      audience: context.audience,
      key_id: context.key_id,
    },
    payload,
  };
  const receiptDigest = digest(body);
  const signingBytes = Buffer.from(STAGE_RECEIPT_DOMAIN + canonicalize(body), 'utf8');
  const signature = signer
    ? await signer({ signingBytes, body: clone(body), receiptDigest })
    : crypto.sign(null, signingBytes, privateKey!).toString('base64url');
  if (typeof signature !== 'string' || !/^[A-Za-z0-9_-]+$/.test(signature)
      || Buffer.from(signature, 'base64url').length !== 64
      || Buffer.from(signature, 'base64url').toString('base64url') !== signature) {
    throw new TypeError('stage receipt signer returned a malformed Ed25519 signature');
  }
  return {
    ...body,
    receipt_digest: receiptDigest,
    signature: { algorithm: 'Ed25519', value: signature },
  };
}

/** Independently verify one stage receipt and optional relying-party bindings. */
export function verifyTrustStageReceipt(receipt: unknown, options: {
  trustedKeys?: Readonly<Record<string, string | crypto.KeyObject>>;
  expected?: Readonly<Record<string, unknown>>;
  expectedIssuer?: Readonly<Record<string, unknown>>;
} = {}) {
  const checks = {
    structure: false, digest: false, key: false, signature: false, issuer: false, expected: false,
  };
  if (!validStageReceiptShape(receipt)) {
    return { valid: false, reason: 'receipt_structure_invalid', checks };
  }
  checks.structure = true;
  let bodyDigest: string;
  try {
    bodyDigest = digest(stageReceiptBody(receipt));
  } catch {
    return { valid: false, reason: 'receipt_not_canonical', checks };
  }
  checks.digest = bodyDigest === receipt.receipt_digest;
  if (!checks.digest) return { valid: false, reason: 'receipt_digest_mismatch', checks };
  const key = publicKey(options.trustedKeys?.[receipt.issuer.key_id]);
  checks.key = key !== null;
  if (!key) return { valid: false, reason: 'receipt_key_untrusted', checks };
  try {
    checks.signature = crypto.verify(
      null,
      Buffer.from(STAGE_RECEIPT_DOMAIN + canonicalize(stageReceiptBody(receipt)), 'utf8'),
      key,
      Buffer.from(receipt.signature.value, 'base64url'),
    );
  } catch {
    checks.signature = false;
  }
  if (!checks.signature) return { valid: false, reason: 'receipt_signature_invalid', checks };
  try {
    checks.issuer = options.expectedIssuer === undefined
      || canonicalize(receipt.issuer) === canonicalize(options.expectedIssuer);
  } catch {
    checks.issuer = false;
  }
  if (!checks.issuer) return { valid: false, reason: 'receipt_expected_issuer_mismatch', checks };
  const expected = options.expected ?? {};
  checks.expected = Object.entries(expected).every(([field, value]) => {
    try {
      return canonicalize(receipt.payload[field]) === canonicalize(value);
    } catch {
      return false;
    }
  });
  if (!checks.expected) return { valid: false, reason: 'receipt_expected_binding_mismatch', checks };
  return { valid: true, reason: null, checks, receipt_digest: receipt.receipt_digest, payload: clone(receipt.payload) };
}

function initialState(
  program: RecordLike,
  programDigest: string,
  tenantId: string,
  instanceId: string,
  now: number,
) {
  const stages: RecordLike = {};
  for (const stage of program.stages) {
    stages[stage.stage_id] = {
      status: stage.depends_on.length === 0 ? 'collecting' : 'locked',
      predecessor_receipt_digests: [],
      evidence: {},
      receipt: null,
    };
  }
  return {
    version: TRUST_PROGRAM_VERSION,
    tenant_id: tenantId,
    instance_id: instanceId,
    program_id: program.program_id,
    program_version: program.version,
    program_digest: programDigest,
    root_caid: program.root_caid,
    action_digest: program.action_digest,
    status: 'active',
    revision: 0,
    created_at: new Date(now).toISOString(),
    updated_at: new Date(now).toISOString(),
    stages,
    used_evidence_ids: [],
    execution: { status: 'locked', claim_token_digest: null, evidence_digest: null, outcome: null },
    invalidation_reason: null,
  };
}

function invalidateState(state: RecordLike, reason: string, at: number) {
  const next = clone(state);
  next.status = 'invalidated';
  next.invalidation_reason = reason;
  next.revision += 1;
  next.updated_at = new Date(at).toISOString();
  for (const stage of Object.values(next.stages) as RecordLike[]) stage.status = 'invalidated';
  if (['locked', 'ready'].includes(next.execution.status)) next.execution.status = 'invalidated';
  return next;
}

function storedStateValid(
  state: unknown,
  program: RecordLike,
  programDigest: string,
  tenantId: string,
  instanceId: string,
  receiptContext: RecordLike,
  receiptVerificationKey?: string | crypto.KeyObject,
) {
  if (!exactKeys(state, STATE_KEYS)
      || state.version !== TRUST_PROGRAM_VERSION
      || state.tenant_id !== tenantId
      || state.instance_id !== instanceId
      || state.program_id !== program.program_id
      || state.program_version !== program.version
      || state.program_digest !== programDigest
      || state.root_caid !== program.root_caid
      || state.action_digest !== program.action_digest
      || !['active', 'invalidated'].includes(state.status)
      || !Number.isSafeInteger(state.revision) || state.revision < 0
      || !Number.isFinite(strictInstant(state.created_at))
      || !Number.isFinite(strictInstant(state.updated_at))
      || strictInstant(state.updated_at) < strictInstant(state.created_at)
      || (state.status === 'active' && state.invalidation_reason !== null)
      || (state.status === 'invalidated'
        && (typeof state.invalidation_reason !== 'string'
          || state.invalidation_reason.length < 1 || state.invalidation_reason.length > 256))
      || !isRecord(state.stages)
      || Object.keys(state.stages).length !== program.stages.length
      || !Array.isArray(state.used_evidence_ids)
      || state.used_evidence_ids.length > MAX_TOTAL_REQUIREMENTS
      || !state.used_evidence_ids.every((entry: unknown) => typeof entry === 'string' && ID.test(entry))
      || new Set(state.used_evidence_ids).size !== state.used_evidence_ids.length
      || !state.used_evidence_ids.every((entry: string, index: number) =>
        index === 0 || state.used_evidence_ids[index - 1] < entry)
      || !isRecord(state.execution)
      || !['status', 'claim_token_digest', 'evidence_digest', 'outcome'].every(
        (key) => Object.hasOwn(state.execution, key),
      )
      || Object.keys(state.execution).some((key) => !EXECUTION_STATE_KEYS.has(key))) {
    return false;
  }

  const usedEvidenceIds: string[] = [];
  for (const definition of program.stages) {
    const stage = state.stages[definition.stage_id];
    if (!exactKeys(stage, STAGE_STATE_KEYS)
        || !['locked', 'collecting', 'satisfied', 'invalidated'].includes(stage.status)
        || !sortedUniqueDigests(stage.predecessor_receipt_digests, MAX_STAGES)
        || !isRecord(stage.evidence)
        || Object.keys(stage.evidence).length > definition.requirements.length) return false;

    const dependencyReceipts = definition.depends_on.map(
      (dependency: string) => state.stages[dependency]?.receipt,
    );
    const expectedPredecessors = dependencyReceipts.every((entry: unknown) => entry !== null)
      ? dependencyReceipts.map((entry: RecordLike) => entry.receipt_digest).sort()
      : [];
    if (canonicalize(stage.predecessor_receipt_digests) !== canonicalize(expectedPredecessors)) return false;

    for (const [requirementId, accepted] of Object.entries(stage.evidence)) {
      const requirement = definition.requirements.find(
        (candidate: RecordLike) => candidate.requirement_id === requirementId,
      );
      if (!requirement || !exactKeys(accepted, EVIDENCE_STATE_KEYS)
          || typeof accepted.evidence_id !== 'string' || !ID.test(accepted.evidence_id)
          || typeof accepted.evidence_digest !== 'string' || !DIGEST.test(accepted.evidence_digest)
          || accepted.policy_digest !== requirement.policy_digest
          || typeof accepted.binding_digest !== 'string' || !DIGEST.test(accepted.binding_digest)
          || !boundedProjection(accepted.subjects, definition.rule.distinct_subjects)
          || !boundedProjection(accepted.key_fingerprints, definition.rule.distinct_keys)
          || !Number.isFinite(strictInstant(accepted.issued_at))
          || !Number.isFinite(strictInstant(accepted.expires_at))
          || strictInstant(accepted.expires_at) <= strictInstant(accepted.issued_at)
          || (accepted.revocation_checked_at !== null
            && !Number.isFinite(strictInstant(accepted.revocation_checked_at)))
          || (requirement.revocation_required && accepted.revocation_checked_at === null)) return false;
      usedEvidenceIds.push(accepted.evidence_id);
    }

    const thresholdMet = stageIsSatisfied(definition, stage);
    if (state.status === 'active') {
      const dependenciesSatisfied = definition.depends_on.every(
        (dependency: string) => state.stages[dependency].status === 'satisfied',
      );
      if ((!dependenciesSatisfied && stage.status !== 'locked')
          || (dependenciesSatisfied && stage.status === 'locked')
          || (stage.status === 'satisfied' && !thresholdMet)
          || (stage.status === 'collecting' && thresholdMet)
          || stage.status === 'invalidated') return false;
    } else if (stage.status !== 'invalidated') return false;

    if (stage.receipt !== null) {
      if (!validStageReceiptShape(stage.receipt)
          || digest(stageReceiptBody(stage.receipt)) !== stage.receipt.receipt_digest) return false;
      const evidenceEntries = Object.values(stage.evidence) as RecordLike[];
      const expectedPayload = {
        instance_id: instanceId,
        program_id: program.program_id,
        program_version: program.version,
        program_digest: programDigest,
        root_caid: program.root_caid,
        action_digest: program.action_digest,
        stage_id: definition.stage_id,
        stage_policy_digest: digest(definition),
        predecessor_receipt_digests: [...stage.predecessor_receipt_digests],
        evidence_digests: evidenceEntries.map((entry) => entry.evidence_digest).sort(),
        subjects: [...new Set(evidenceEntries.flatMap((entry) => entry.subjects))].sort(),
        key_fingerprints: [...new Set(evidenceEntries.flatMap((entry) => entry.key_fingerprints))].sort(),
      };
      if (!Object.entries(expectedPayload).every(([key, value]) =>
        canonicalize(stage.receipt.payload[key]) === canonicalize(value))) return false;
      if (receiptVerificationKey) {
        const verified = verifyTrustStageReceipt(stage.receipt, {
          trustedKeys: { [receiptContext.key_id]: receiptVerificationKey },
          expectedIssuer: receiptContext,
          expected: expectedPayload,
        });
        if (!verified.valid) return false;
      }
    }
    if (stage.status === 'satisfied' && stage.receipt === null) return false;
    if (state.status === 'active' && stage.status !== 'satisfied' && stage.receipt !== null) return false;
  }
  if (canonicalize([...usedEvidenceIds].sort()) !== canonicalize(state.used_evidence_ids)) return false;

  const execution = state.execution;
  if (!['locked', 'ready', 'claimed', 'executed', 'refused', 'indeterminate',
    'proved_no_effect', 'invalidated'].includes(execution.status)) return false;
  const terminalReceipts = program.execution.depends_on.map(
    (stageId: string) => state.stages[stageId].receipt?.receipt_digest,
  );
  const terminalSatisfied = terminalReceipts.every((entry: unknown) => typeof entry === 'string');
  if (state.status === 'active'
      && ((terminalSatisfied && execution.status === 'locked')
        || (!terminalSatisfied && execution.status !== 'locked')
        || execution.status === 'invalidated')) return false;
  if (state.status === 'invalidated'
      && !['invalidated', 'claimed', 'executed', 'refused', 'indeterminate', 'proved_no_effect']
        .includes(execution.status)) return false;

  const claimedOrTerminal = ['claimed', 'executed', 'refused', 'indeterminate', 'proved_no_effect']
    .includes(execution.status);
  const createdAt = strictInstant(state.created_at);
  const updatedAt = strictInstant(state.updated_at);
  let claimedAt = NaN;
  if (claimedOrTerminal) {
    const binding = execution.authorization_binding;
    claimedAt = strictInstant(execution.claimed_at);
    if (!exactKeys(binding, AUTHORIZATION_BINDING_KEYS)
        || binding.instance_id !== instanceId
        || typeof binding.operation_id !== 'string' || !ID.test(binding.operation_id)
        || binding.program_digest !== programDigest
        || binding.root_caid !== program.root_caid
        || binding.action_digest !== program.action_digest
        || typeof binding.receipt_context_digest !== 'string'
        || !DIGEST.test(binding.receipt_context_digest)
        || binding.receipt_context_digest !== digest(receiptContext)
        || canonicalize(binding.terminal_stage_receipt_digests)
          !== canonicalize([...terminalReceipts].sort())
        || binding.consequence_mode !== program.execution.consequence_mode
        || binding.capability_template_digest !== program.execution.capability_template_digest
        || binding.escrow_profile_digest !== program.execution.escrow_profile_digest
        || !Number.isFinite(claimedAt) || claimedAt < createdAt || claimedAt > updatedAt) return false;
  } else if (Object.hasOwn(execution, 'authorization_binding')
      || Object.hasOwn(execution, 'operation_id') || Object.hasOwn(execution, 'claimed_at')) return false;

  if (execution.status === 'claimed') {
    if (typeof execution.claim_token_digest !== 'string' || !DIGEST.test(execution.claim_token_digest)
        || execution.evidence_digest !== null || execution.outcome !== null) return false;
  } else if (execution.claim_token_digest !== null) return false;

  const outcomeStatus = ['executed', 'refused', 'indeterminate', 'proved_no_effect']
    .includes(execution.status);
  if (outcomeStatus) {
    if (execution.outcome !== execution.status
        || typeof execution.evidence_digest !== 'string' || !DIGEST.test(execution.evidence_digest)) return false;
  } else if (execution.evidence_digest !== null || execution.outcome !== null) return false;
  const hasFinalizedAt = Object.hasOwn(execution, 'finalized_at');
  const hasReconciledAt = Object.hasOwn(execution, 'reconciled_at');
  const finalizedAt = hasFinalizedAt ? strictInstant(execution.finalized_at) : NaN;
  const reconciledAt = hasReconciledAt ? strictInstant(execution.reconciled_at) : NaN;
  if (outcomeStatus) {
    if (!hasFinalizedAt || !Number.isFinite(finalizedAt)
        || finalizedAt < claimedAt || finalizedAt > updatedAt) return false;
    if (execution.status === 'proved_no_effect') {
      if (!hasReconciledAt || !Number.isFinite(reconciledAt)
          || reconciledAt < finalizedAt || reconciledAt > updatedAt) return false;
    } else if (execution.status === 'executed' && hasReconciledAt) {
      if (!Number.isFinite(reconciledAt)
          || reconciledAt < finalizedAt || reconciledAt > updatedAt) return false;
    } else if (execution.status !== 'executed' && hasReconciledAt) return false;
  } else if (hasFinalizedAt || hasReconciledAt) return false;
  return true;
}

function assertStoreIdentity(tenantId: unknown, instanceId: unknown) {
  if (typeof tenantId !== 'string'
      || Buffer.byteLength(tenantId, 'utf8') < 1
      || Buffer.byteLength(tenantId, 'utf8') > 512
      || /[\u0000-\u001f\u007f]/.test(tenantId)) {
    throw new TypeError('trust-program tenantId is invalid');
  }
  if (typeof instanceId !== 'string' || !ID.test(instanceId)) {
    throw new TypeError('trust-program instanceId is invalid');
  }
}

/**
 * In-process compare-and-swap store. Deliberately rejected by the kernel unless
 * allowEphemeralState is explicit; production must use a durable atomic store.
 */
export function createMemoryTrustProgramStore(): TrustProgramStore {
  const records = new Map<string, RecordLike>();
  const storageKey = (tenantId: string, instanceId: string) => `${tenantId.length}:${tenantId}${instanceId}`;
  return {
    durable: false,
    async create({ tenantId, state }: RecordLike) {
      assertStoreIdentity(tenantId, state?.instance_id);
      if (state?.tenant_id !== tenantId) return fail('state_binding_invalid');
      const key = storageKey(state.tenant_id, state.instance_id);
      if (records.has(key)) return fail('instance_exists');
      records.set(key, clone(state));
      return { ok: true, state: clone(state) };
    },
    async get({ tenantId, instanceId }: { tenantId: string; instanceId: string }) {
      assertStoreIdentity(tenantId, instanceId);
      const state = records.get(storageKey(tenantId, instanceId));
      return state ? { ok: true, state: clone(state) } : fail('instance_not_found');
    },
    async compareAndSwap({ tenantId, instanceId, expectedRevision, state }: RecordLike) {
      assertStoreIdentity(tenantId, instanceId);
      const key = storageKey(tenantId, instanceId);
      const current = records.get(key);
      if (!current) return fail('instance_not_found');
      if (state?.tenant_id !== tenantId || state?.instance_id !== instanceId) {
        return fail('state_binding_invalid');
      }
      if (current.revision !== expectedRevision) return fail('revision_conflict');
      if (strictInstant(state?.updated_at) < strictInstant(current.updated_at)) {
        return fail('clock_regression');
      }
      records.set(key, clone(state));
      return { ok: true, state: clone(state) };
    },
    async invalidate({ tenantId, instanceId, expectedRevision, reason, at }: RecordLike) {
      assertStoreIdentity(tenantId, instanceId);
      const key = storageKey(tenantId, instanceId);
      const current = records.get(key);
      if (!current) return fail('instance_not_found');
      if (current.revision !== expectedRevision) return fail('revision_conflict');
      if (current.status === 'invalidated') return fail('program_instance_invalidated');
      if (!Number.isSafeInteger(at) || at < strictInstant(current.updated_at)) {
        return fail('clock_regression');
      }
      const next = invalidateState(current, reason, at);
      records.set(key, clone(next));
      return { ok: true, state: clone(next) };
    },
  } as unknown as TrustProgramStore;
}

function findStage(program: RecordLike, stageId: string) {
  return program.stages.find((stage: RecordLike) => stage.stage_id === stageId);
}

function findRequirement(stage: RecordLike, requirementId: string) {
  return stage.requirements.find((requirement: RecordLike) => requirement.requirement_id === requirementId);
}

function updateUnlocks(state: RecordLike, program: RecordLike) {
  for (const definition of program.stages) {
    const stage = state.stages[definition.stage_id];
    if (stage.status !== 'locked') continue;
    const predecessors = definition.depends_on.map((stageId: string) => state.stages[stageId]);
    if (predecessors.every((entry: RecordLike) => entry.status === 'satisfied')) {
      stage.status = 'collecting';
      stage.predecessor_receipt_digests = predecessors
        .map((entry: RecordLike) => entry.receipt.receipt_digest)
        .sort();
    }
  }
  if (program.execution.depends_on.every((stageId: string) => state.stages[stageId].status === 'satisfied')) {
    state.execution.status = 'ready';
  }
}

function stageIsSatisfied(definition: RecordLike, state: RecordLike) {
  return Object.keys(state.evidence).length >= effectiveRequired(definition);
}

function tokenDigest(value: string) {
  return digest({ token: value });
}

export function createTrustProgramKernel(options: TrustProgramKernelConfig): TrustProgramKernel {
  const checked = validateTrustProgram(options?.program);
  if (!checked.valid) throw new TypeError(`invalid trust program: ${checked.reason}`);
  if (!options.store || typeof options.store.create !== 'function'
      || typeof options.store.get !== 'function'
      || typeof options.store.compareAndSwap !== 'function'
      || typeof options.store.invalidate !== 'function') throw new TypeError('trust program store required');
  if (options.store.durable !== true && options.allowEphemeralState !== true) {
    throw new TypeError('durable trust program store required');
  }
  if (!isDataRecord(options.verifiers)
      || Object.values(options.verifiers).some((verifier) => typeof verifier !== 'function')) {
    throw new TypeError('trust program verifier registry required');
  }
  if ((!options.receiptPrivateKey && typeof options.receiptSigner !== 'function')
      || !isDataRecord(options.receiptContext)
      || !exactKeys(options.receiptContext, STAGE_RECEIPT_ISSUER_KEYS)
      || !Object.values(options.receiptContext).every(boundedContextString)
      || Buffer.byteLength(options.receiptContext.tenant, 'utf8') > 512) {
    throw new TypeError('stage receipt signer required');
  }
  if (options.allowEphemeralState !== true
      && (!options.receiptVerificationKey
        || typeof options.actionBindingVerifier !== 'function'
        || typeof options.executionBindingVerifier !== 'function'
        || typeof options.executionEvidenceRevalidator !== 'function'
        || typeof options.executionOutcomeVerifier !== 'function'
        || typeof options.reconciliationVerifier !== 'function')) {
    throw new TypeError('production trust verifiers required');
  }

  const program = clone(options.program) as RecordLike;
  const programDigest = checked.digest!;
  const receiptContext = Object.freeze(clone(options.receiptContext)) as RecordLike;
  const tenantId = receiptContext.tenant;
  const sourceStore = options.store;
  const store: TrustProgramStore = Object.freeze({
    durable: sourceStore.durable === true,
    create: sourceStore.create.bind(sourceStore),
    get: sourceStore.get.bind(sourceStore),
    compareAndSwap: sourceStore.compareAndSwap.bind(sourceStore),
    invalidate: sourceStore.invalidate.bind(sourceStore),
  });
  const verifiers = Object.freeze({ ...options.verifiers });
  const receiptPrivateKey = options.receiptPrivateKey;
  const receiptVerificationKey = options.receiptVerificationKey;
  const receiptSigner = options.receiptSigner;
  const allowEphemeralState = options.allowEphemeralState === true;
  const actionBindingVerifier = options.actionBindingVerifier;
  const executionBindingVerifier = options.executionBindingVerifier;
  const executionEvidenceRevalidator = options.executionEvidenceRevalidator;
  const executionOutcomeVerifier = options.executionOutcomeVerifier;
  const reconciliationVerifier = options.reconciliationVerifier;
  const now = typeof options.now === 'function' ? options.now : Date.now;
  const clockInstant = () => {
    const current = now();
    return Number.isSafeInteger(current) && current >= 0 && current <= 8_640_000_000_000_000
      ? current : NaN;
  };

  const checkedStoreResult = (result: unknown, instanceId: string): RecordLike => {
    if (!isRecord(result) || typeof result.ok !== 'boolean') return fail('store_response_invalid');
    if (result.ok !== true) return typeof result.reason === 'string'
      ? result : fail('store_response_invalid');
    if (!storedStateValid(
      result.state,
      program,
      programDigest,
      tenantId,
      instanceId,
      receiptContext,
      receiptVerificationKey,
    )) return fail('store_state_invalid');
    return result;
  };

  const load = async (instanceId: string): Promise<RecordLike> => {
    try {
      const result = await store.get({ tenantId, instanceId });
      return checkedStoreResult(result, instanceId);
    } catch {
      return fail('store_unavailable');
    }
  };
  const compareAndSwap = async (input: RecordLike): Promise<RecordLike> => {
    try {
      const result = await store.compareAndSwap({ ...input, tenantId } as {
        tenantId: string;
        instanceId: string;
        expectedRevision: number;
        state: TrustProgramState;
      });
      return checkedStoreResult(result, input.instanceId);
    } catch {
      return fail('store_unavailable');
    }
  };
  const active = (state: RecordLike) => state.status === 'invalidated'
    ? fail('program_instance_invalidated') : null;
  const inWindow = (current = clockInstant()) => {
    if (!Number.isFinite(current)) return fail('clock_invalid');
    if (current < strictInstant(program.valid_from)) return fail('program_not_yet_valid');
    if (current >= strictInstant(program.expires_at)) return fail('program_expired');
    return null;
  };
  const transitionInstant = (state: RecordLike) => {
    const current = clockInstant();
    if (!Number.isFinite(current)) return { ok: false as const, reason: 'clock_invalid' };
    if (current < strictInstant(state.updated_at)) {
      return { ok: false as const, reason: 'clock_regression' };
    }
    return { ok: true as const, at: current };
  };

  async function start({ instanceId, action }: RecordLike) {
    if (typeof instanceId !== 'string' || !ID.test(instanceId)) return fail('instance_id_invalid');
    const current = clockInstant();
    const windowFailure = inWindow(current);
    if (windowFailure) return windowFailure;
    if (typeof actionBindingVerifier === 'function') {
      let actionBound = false;
      try {
        actionBound = await actionBindingVerifier({
          action: clone(action),
          expectedCaid: program.root_caid,
          expectedActionDigest: program.action_digest,
          program: clone(program),
        }) === true;
      } catch {
        actionBound = false;
      }
      if (!actionBound) return fail('action_binding_invalid');
    } else if (!allowEphemeralState) {
      return fail('action_binding_verifier_unavailable');
    }
    try {
      const result = await store.create({
        tenantId,
        state: initialState(
          program, programDigest, tenantId, instanceId, current,
        ),
      });
      return checkedStoreResult(result, instanceId);
    } catch {
      return fail('store_unavailable');
    }
  }

  async function status(instanceId: string) {
    return load(instanceId);
  }

  async function challenge({ instanceId, stageId, requirementId }: RecordLike): Promise<RecordLike> {
    const loaded = await load(instanceId);
    if (!loaded.ok) return loaded;
    const stateFailure = active(loaded.state);
    if (stateFailure) return stateFailure;
    const windowFailure = inWindow();
    if (windowFailure) return windowFailure;
    const definition = findStage(program, stageId);
    if (!definition) return fail('stage_unknown');
    const requirement = findRequirement(definition, requirementId);
    if (!requirement) return fail('requirement_unknown');
    const stage = loaded.state.stages[stageId];
    if (stage.status === 'locked') return fail('stage_locked');
    if (stage.status !== 'collecting') return fail('stage_not_collecting');
    if (stage.evidence[requirementId]) return fail('requirement_already_satisfied');
    const binding = {
      instance_id: instanceId,
      program_digest: programDigest,
      program_version: program.version,
      root_caid: program.root_caid,
      action_digest: program.action_digest,
      stage_id: stageId,
      requirement_id: requirementId,
      policy_digest: requirement.policy_digest,
      predecessor_receipt_digests: [...stage.predecessor_receipt_digests],
    };
    return { ok: true, binding, binding_digest: digest(binding), verifier_profile: requirement.verifier_profile };
  }

  async function admit({ instanceId, stageId, requirementId, artifact }: RecordLike) {
    const loaded = await load(instanceId);
    if (!loaded.ok) return loaded;
    const stateFailure = active(loaded.state);
    if (stateFailure) return stateFailure;
    const transition = transitionInstant(loaded.state);
    if (!transition.ok) return fail(transition.reason);
    const current = transition.at;
    const windowFailure = inWindow(current);
    if (windowFailure) return windowFailure;
    const definition = findStage(program, stageId);
    if (!definition) return fail('stage_unknown');
    const requirement = findRequirement(definition, requirementId);
    if (!requirement) return fail('requirement_unknown');
    const stageState = loaded.state.stages[stageId];
    if (stageState.status === 'locked') return fail('stage_locked');
    if (stageState.status !== 'collecting') return fail('stage_not_collecting');
    if (!isRecord(artifact) || typeof artifact.evidence_id !== 'string' || !ID.test(artifact.evidence_id)) {
      return fail('evidence_id_invalid');
    }
    if (loaded.state.used_evidence_ids.includes(artifact.evidence_id)) return fail('evidence_replayed');
    if (stageState.evidence[requirementId]) return fail('requirement_already_satisfied');
    const verifier = verifiers[requirement.verifier_profile];
    if (typeof verifier !== 'function') return fail('verifier_unavailable');
    let verified: RecordLike;
    try {
      verified = await verifier({ artifact: clone(artifact), requirement: clone(requirement), program: clone(program) });
    } catch {
      return fail('evidence_verification_failed');
    }
    if (!isRecord(verified) || verified.valid !== true) return fail(verified?.reason ?? 'evidence_verification_failed');
    const expectedChallenge = await challenge({ instanceId, stageId, requirementId });
    if (!expectedChallenge.ok) return expectedChallenge;
    if (verified.binding_digest !== expectedChallenge.binding_digest) return fail('evidence_binding_mismatch');
    if (verified.policy_digest !== requirement.policy_digest) return fail('evidence_policy_mismatch');
    const issuedAt = strictInstant(verified.issued_at);
    const expiresAt = strictInstant(verified.expires_at);
    if (!Number.isFinite(issuedAt) || issuedAt > current || current - issuedAt > requirement.max_age_sec * 1000) {
      return fail('evidence_stale');
    }
    if (!Number.isFinite(expiresAt) || expiresAt <= current) return fail('evidence_expired');
    const revocationAt = strictInstant(verified.revocation_checked_at);
    if (requirement.revocation_required
        && (!Number.isFinite(revocationAt) || revocationAt > current
          || current - revocationAt > requirement.max_age_sec * 1000)) {
      return fail('revocation_check_required');
    }
    if (!boundedProjection(verified.subjects, definition.rule.distinct_subjects)
        || !boundedProjection(verified.key_fingerprints, definition.rule.distinct_keys)) {
      return fail('evidence_principal_set_invalid');
    }
    const prior = Object.values(stageState.evidence) as RecordLike[];
    const priorSubjects = new Set(prior.flatMap((entry) => entry.subjects));
    const priorKeys = new Set(prior.flatMap((entry) => entry.key_fingerprints));
    if (definition.rule.distinct_subjects && verified.subjects.some((entry: string) => priorSubjects.has(entry))) {
      return fail('stage_subject_not_distinct');
    }
    if (definition.rule.distinct_keys && verified.key_fingerprints.some((entry: string) => priorKeys.has(entry))) {
      return fail('stage_key_not_distinct');
    }

    const next = clone(loaded.state);
    const nextStage = next.stages[stageId];
    nextStage.evidence[requirementId] = {
      evidence_id: artifact.evidence_id,
      evidence_digest: digest(artifact),
      policy_digest: requirement.policy_digest,
      binding_digest: expectedChallenge.binding_digest,
      subjects: [...verified.subjects].sort(),
      key_fingerprints: [...verified.key_fingerprints].sort(),
      issued_at: verified.issued_at,
      expires_at: verified.expires_at,
      revocation_checked_at: verified.revocation_checked_at ?? null,
    };
    next.used_evidence_ids.push(artifact.evidence_id);
    next.used_evidence_ids.sort();
    next.revision += 1;
    next.updated_at = new Date(current).toISOString();
    let stageReceipt: RecordLike | null = null;
    if (stageIsSatisfied(definition, nextStage)) {
      nextStage.status = 'satisfied';
      const receiptPayload = {
        instance_id: instanceId,
        program_id: program.program_id,
        program_version: program.version,
        program_digest: programDigest,
        root_caid: program.root_caid,
        action_digest: program.action_digest,
        stage_id: stageId,
        stage_policy_digest: digest(definition),
        predecessor_receipt_digests: [...nextStage.predecessor_receipt_digests].sort(),
        evidence_digests: Object.values(nextStage.evidence)
          .map((entry: any) => entry.evidence_digest).sort(),
        subjects: [...new Set(Object.values(nextStage.evidence).flatMap((entry: any) => entry.subjects))].sort(),
        key_fingerprints: [...new Set(Object.values(nextStage.evidence).flatMap((entry: any) => entry.key_fingerprints))].sort(),
        satisfied_at: new Date(current).toISOString(),
      };
      try {
        stageReceipt = await signStageReceipt(
          receiptPayload,
          receiptContext,
          receiptPrivateKey,
          receiptSigner,
        );
      } catch {
        return fail('stage_receipt_signing_failed');
      }
      if (receiptVerificationKey) {
        const selfCheck = verifyTrustStageReceipt(stageReceipt, {
          trustedKeys: { [receiptContext.key_id]: receiptVerificationKey },
          expectedIssuer: receiptContext,
          expected: receiptPayload,
        });
        if (!selfCheck.valid) return fail('stage_receipt_self_verification_failed');
      }
      nextStage.receipt = stageReceipt;
      updateUnlocks(next, program);
    }
    const committed = await compareAndSwap({
      instanceId,
      expectedRevision: loaded.state.revision,
      state: next,
    });
    if (!committed.ok) return committed;
    return {
      ok: true,
      stage_completed: stageReceipt !== null,
      stage_receipt: stageReceipt,
      state: committed.state,
    };
  }

  async function claimExecution({ instanceId, operationId, claimToken: suppliedClaimToken }: RecordLike) {
    const loaded = await load(instanceId);
    if (!loaded.ok) return loaded;
    const stateFailure = active(loaded.state);
    if (stateFailure) return stateFailure;
    const transition = transitionInstant(loaded.state);
    if (!transition.ok) return fail(transition.reason);
    const current = transition.at;
    const windowFailure = inWindow(current);
    if (windowFailure) return windowFailure;
    const statusValue = loaded.state.execution.status;
    if (statusValue === 'locked') return fail('execution_locked');
    if (statusValue === 'claimed') {
      if (typeof operationId === 'string' && operationId === loaded.state.execution.operation_id
          && typeof suppliedClaimToken === 'string'
          && tokenDigest(suppliedClaimToken) === loaded.state.execution.claim_token_digest) {
        return {
          ok: true,
          idempotent: true,
          claim_token: suppliedClaimToken,
          authorization_binding: clone(loaded.state.execution.authorization_binding),
          state: loaded.state,
        };
      }
      return fail('execution_already_claimed');
    }
    if (statusValue === 'indeterminate') return fail('execution_indeterminate');
    if (['executed', 'proved_no_effect', 'refused'].includes(statusValue)) return fail('execution_already_terminal');
    if (statusValue !== 'ready') return fail('execution_unavailable');
    for (const definition of program.stages) {
      const accepted = Object.entries(
        loaded.state.stages[definition.stage_id].evidence,
      ) as [string, RecordLike][];
      for (const [requirementId, entry] of accepted) {
        const requirement = findRequirement(definition, requirementId);
        const issuedAt = strictInstant(entry.issued_at);
        const expiresAt = strictInstant(entry.expires_at);
        const revocationAt = strictInstant(entry.revocation_checked_at);
        if (!requirement || !Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)
            || issuedAt > current || current - issuedAt > requirement.max_age_sec * 1000
            || expiresAt <= current
            || (requirement.revocation_required
              && (!Number.isFinite(revocationAt)
                || revocationAt > current
                || current - revocationAt > requirement.max_age_sec * 1000))) {
          return fail('execution_evidence_stale');
        }
      }
    }
    if (typeof executionEvidenceRevalidator === 'function') {
      let evidenceStillValid = false;
      try {
        evidenceStillValid = await executionEvidenceRevalidator({
          state: clone(loaded.state),
          program: clone(program),
          checkedAt: new Date(current).toISOString(),
        }) === true;
      } catch {
        evidenceStillValid = false;
      }
      if (!evidenceStillValid) return fail('execution_evidence_revalidation_failed');
    } else if (!allowEphemeralState) {
      return fail('execution_evidence_revalidator_unavailable');
    }
    if (store.durable === true
        && (typeof operationId !== 'string' || !ID.test(operationId)
          || typeof suppliedClaimToken !== 'string' || suppliedClaimToken.length < 32)) {
      return fail('durable_execution_identity_required');
    }
    const claimToken = suppliedClaimToken ?? crypto.randomBytes(32).toString('base64url');
    if (typeof claimToken !== 'string' || claimToken.length < 32 || claimToken.length > 256) {
      return fail('execution_claim_token_invalid');
    }
    const stableOperationId = operationId ?? `tpo_${crypto.randomUUID()}`;
    const proposedBinding = {
      instance_id: instanceId,
      operation_id: stableOperationId,
      program_digest: programDigest,
      root_caid: program.root_caid,
      action_digest: program.action_digest,
      receipt_context_digest: digest(receiptContext),
      terminal_stage_receipt_digests: program.execution.depends_on
        .map((stageId: string) => loaded.state.stages[stageId].receipt.receipt_digest).sort(),
      consequence_mode: program.execution.consequence_mode,
      capability_template_digest: program.execution.capability_template_digest,
      escrow_profile_digest: program.execution.escrow_profile_digest,
    };
    if (typeof executionBindingVerifier === 'function') {
      let bindingValid = false;
      try {
        bindingValid = await executionBindingVerifier(clone(proposedBinding)) === true;
      } catch {
        bindingValid = false;
      }
      if (!bindingValid) return fail('execution_binding_invalid');
    } else if (!allowEphemeralState) {
      return fail('execution_binding_verifier_unavailable');
    }
    const next = clone(loaded.state);
    next.execution = {
      ...next.execution,
      status: 'claimed',
      operation_id: stableOperationId,
      claim_token_digest: tokenDigest(claimToken),
      claimed_at: new Date(current).toISOString(),
      authorization_binding: proposedBinding,
    };
    next.revision += 1;
    next.updated_at = new Date(current).toISOString();
    const committed = await compareAndSwap({
      instanceId, expectedRevision: loaded.state.revision, state: next,
    });
    if (!committed.ok) return committed;
    return {
      ok: true,
      claim_token: claimToken,
      authorization_binding: clone(next.execution.authorization_binding),
      state: committed.state,
    };
  }

  async function finalizeExecution({ instanceId, claimToken, outcome, evidenceDigest, evidence }: RecordLike) {
    const loaded = await load(instanceId);
    if (!loaded.ok) return loaded;
    const transition = transitionInstant(loaded.state);
    if (!transition.ok) return fail(transition.reason);
    const current = transition.at;
    if (loaded.state.execution.status !== 'claimed') {
      if (loaded.state.execution.status === 'indeterminate') return fail('execution_indeterminate');
      if (['executed', 'proved_no_effect', 'refused'].includes(loaded.state.execution.status)) {
        return fail('execution_already_terminal');
      }
      return fail('execution_not_claimed');
    }
    if (typeof claimToken !== 'string'
        || tokenDigest(claimToken) !== loaded.state.execution.claim_token_digest) {
      return fail('execution_claim_mismatch');
    }
    if (!['executed', 'refused', 'indeterminate'].includes(outcome) || !DIGEST.test(evidenceDigest)) {
      return fail('execution_outcome_invalid');
    }
    if (typeof executionOutcomeVerifier === 'function') {
      let verified = false;
      try {
        verified = await executionOutcomeVerifier({
          outcome,
          evidenceDigest,
          evidence: clone(evidence),
          authorizationBinding: clone(loaded.state.execution.authorization_binding),
          state: clone(loaded.state),
        }) === true;
      } catch {
        verified = false;
      }
      if (!verified) return fail('execution_evidence_invalid');
    } else if (!allowEphemeralState) {
      return fail('execution_outcome_verifier_unavailable');
    }
    const next = clone(loaded.state);
    next.execution.status = outcome;
    next.execution.outcome = outcome;
    next.execution.evidence_digest = evidenceDigest;
    next.execution.claim_token_digest = null;
    next.execution.finalized_at = new Date(current).toISOString();
    next.revision += 1;
    next.updated_at = new Date(current).toISOString();
    const committed = await compareAndSwap({
      instanceId, expectedRevision: loaded.state.revision, state: next,
    });
    return committed.ok ? { ok: true, state: committed.state } : committed;
  }

  async function reconcileExecution(input: RecordLike) {
    const loaded = await load(input.instanceId);
    if (!loaded.ok) return loaded;
    const transition = transitionInstant(loaded.state);
    if (!transition.ok) return fail(transition.reason);
    const current = transition.at;
    if (loaded.state.execution.status !== 'indeterminate') {
      if (['executed', 'proved_no_effect', 'refused'].includes(loaded.state.execution.status)) {
        return fail('execution_already_terminal');
      }
      return fail('execution_not_indeterminate');
    }
    if (!['executed', 'proved_no_effect'].includes(input.outcome) || !DIGEST.test(input.evidenceDigest)) {
      return fail('reconciliation_outcome_invalid');
    }
    if (typeof reconciliationVerifier === 'function') {
      let verified = false;
      try {
        verified = await reconciliationVerifier({
          ...clone(input),
          state: clone(loaded.state),
          authorizationBinding: clone(loaded.state.execution.authorization_binding),
        }) === true;
      } catch {
        verified = false;
      }
      if (!verified) return fail('reconciliation_evidence_invalid');
    } else if (!allowEphemeralState) {
      return fail('reconciliation_verifier_unavailable');
    }
    const next = clone(loaded.state);
    next.execution.status = input.outcome;
    next.execution.outcome = input.outcome;
    next.execution.evidence_digest = input.evidenceDigest;
    next.execution.reconciled_at = new Date(current).toISOString();
    next.revision += 1;
    next.updated_at = new Date(current).toISOString();
    const committed = await compareAndSwap({
      instanceId: input.instanceId, expectedRevision: loaded.state.revision, state: next,
    });
    return committed.ok ? { ok: true, state: committed.state } : committed;
  }

  async function invalidate({ instanceId, expectedRevision, reason }: RecordLike) {
    if (typeof reason !== 'string' || reason.length < 1 || reason.length > 256) return fail('invalidation_reason_invalid');
    const loaded = await load(instanceId);
    if (!loaded.ok) return loaded;
    if (!Number.isSafeInteger(expectedRevision) || loaded.state.revision !== expectedRevision) {
      return fail('revision_conflict');
    }
    if (loaded.state.status === 'invalidated') return fail('program_instance_invalidated');
    const transition = transitionInstant(loaded.state);
    if (!transition.ok) return fail(transition.reason);
    try {
      const result = await store.invalidate({
        tenantId, instanceId, expectedRevision, reason, at: transition.at,
      });
      return checkedStoreResult(result, instanceId);
    } catch {
      return fail('store_unavailable');
    }
  }

  return Object.freeze({
    program_digest: programDigest,
    start,
    status,
    challenge,
    admit,
    claimExecution,
    finalizeExecution,
    reconcileExecution,
    invalidate,
  }) as unknown as TrustProgramKernel;
}

// ===========================================================================
// EP-GATE-TRUST-PROGRAM-PROFILE-v2 / EP-GATE-TRUST-STAGE-RECEIPT-v2
// hybrid (Ed25519 + ML-DSA-65) trust-program profile and stage receipt
// ===========================================================================
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the two Trust Program artifacts.
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. The stage receipt's
 *    `signature: {algorithm, value}` becomes
 *    `signature: {profile, required_algorithms, public_key, key_id,
 *    pq_public_key, pq_key_id, signatures}`, which is a wire-format change, so
 *    the receipt takes a new `version` (-v1 -> -v2). The PROGRAM PROFILE moves
 *    with it: a v2 stage receipt is a receipt over a v2 program, and the
 *    program's `@version` is inside `program_digest`, which is inside the
 *    signed payload. verifyTrustStageReceipt and validateTrustProgram above
 *    are UNCHANGED and both refuse their v2 counterpart on the version marker
 *    (`receipt_structure_invalid` / `program_version_unsupported`) BEFORE any
 *    signature is inspected, and neither crashes on one.
 * 2. SET SHAPE. `signature.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
 *    array ({ alg, sig, key_id? }), one entry per registered algorithm, reused
 *    verbatim. Ed25519 keeps its base64url SPKI DER public key; ML-DSA-65
 *    carries raw base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is INSIDE the signed bytes
 *    (trustStageReceiptV2SigningBytes). Drop the ML-DSA leg and narrow the set
 *    to ["Ed25519"] and the surviving Ed25519 signature no longer verifies,
 *    because the bytes changed. Leave the set intact and the missing leg is a
 *    structural refusal. The verifier rebuilds the bytes from the REGISTERED
 *    set and from the body it recomputed itself; the presented receipt never
 *    chooses what it is checked against.
 * 4. V1 COMPATIBILITY. verifyTrustStageReceipt stays SYNCHRONOUS and untouched.
 *    verifyTrustStageReceiptV2 is a SEPARATE async entry point (ML-DSA
 *    verification is inherently async); verifyTrustStageReceiptStatement routes
 *    on the version marker for callers holding a mixed bag. The v1 kernel
 *    (createTrustProgramKernel) is untouched and still mints v1 receipts.
 * 5. NAMED REFUSALS. Every failure sets a named check false and returns a
 *    readable reason; nothing throws on caller input. An absent ML-DSA backend
 *    surfaces as `pq_backend_unavailable` through the agility result, never a
 *    skipped check and never a pass on the classical leg alone.
 *
 * HONEST BOUNDARY. The ML-DSA-65 backend is @noble/post-quantum's pure-JS FIPS
 * 204 implementation, which is not independently audited and is not a FIPS
 * validated module; issuing or verifying under this profile is not a
 * certification claim. This profile is opt-in and is not on in any deployment.
 * v2 does NOT retroactively protect receipts already issued under v1.
 */

export const TRUST_PROGRAM_V2_VERSION = 'EP-GATE-TRUST-PROGRAM-PROFILE-v2';
export const TRUST_STAGE_RECEIPT_V2_VERSION = 'EP-GATE-TRUST-STAGE-RECEIPT-v2';
const STAGE_RECEIPT_V2_DOMAIN = `${TRUST_STAGE_RECEIPT_V2_VERSION}\0`;

/** The registered required algorithm set, in canonical order. */
export const TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

const STAGE_RECEIPT_V2_SIGNATURE_KEYS = new Set([
  'profile', 'required_algorithms', 'public_key', 'key_id',
  'pq_public_key', 'pq_key_id', 'signatures',
]);

/** A v2 stage-receipt issuer pin: BOTH public halves, pinned out of band. */
export interface TrustStageReceiptV2KeyPin {
  /** Ed25519 base64url SPKI DER. */
  public_key: string;
  /** ML-DSA-65 base64url raw public key bytes. */
  pq_public_key: string;
}

/**
 * An injected hybrid signer. Structurally the `signSet()` contract of
 * lib/key-custody.ts's HybridCustodySigner: sign the SAME bytes under every
 * required algorithm, in canonical order. It is accepted structurally rather
 * than imported because @emilia-protocol/gate does not depend on the app-tier
 * lib/ tree; a HybridCustodySigner satisfies this shape as-is.
 */
export interface TrustStageReceiptV2SignSetSigner {
  signSet(bytes: Uint8Array | Buffer, context?: Record<string, unknown>): Promise<
    Array<{ alg: string; sig: string; key_id?: string }>
  >;
}

export interface TrustStageReceiptV2SigningKeys {
  ed: { privateKey: crypto.KeyObject; publicKey?: string };
  pq: { secretKey: Uint8Array | string; publicKey: string };
}

function trustV2AlgorithmSetRegistered(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS[i]);
}

/** Validate a v2 Trust Program profile. Same DAG body as v1, v2 marker only. */
export function validateTrustProgramV2(program: unknown) {
  return validateTrustProgramUnder(program, TRUST_PROGRAM_V2_VERSION);
}

/** Digest a v2 Trust Program profile. Throws on an invalid program, like v1. */
export function trustProgramV2Digest(program: unknown): string {
  const result = validateTrustProgramV2(program);
  if (!result.valid) throw new TypeError(`invalid trust program: ${result.reason}`);
  return result.digest!;
}

/**
 * Route a program of EITHER profile version to its validator. A program whose
 * `@version` is neither refuses through the v1 validator, which is the
 * fail-closed answer. Synchronous: program validation has no signature.
 */
export function validateTrustProgramStatement(program: unknown) {
  if (isRecord(program) && program['@version'] === TRUST_PROGRAM_V2_VERSION) {
    return validateTrustProgramV2(program);
  }
  return validateTrustProgram(program);
}

/** ML-DSA-65 public-key identifier: the SHA-256 of the raw public key bytes. */
function trustPqKeyId(publicKeyRawB64u: unknown): string {
  try {
    if (typeof publicKeyRawB64u !== 'string' || publicKeyRawB64u.length === 0) return '';
    const raw = Buffer.from(publicKeyRawB64u, 'base64url');
    if (raw.length !== ML_DSA_65_PUBLIC_KEY_BYTES || raw.toString('base64url') !== publicKeyRawB64u) return '';
    return `ep:trust-stage-key:ml-dsa-65:sha256:${crypto.createHash('sha256').update(raw).digest('hex')}`;
  } catch {
    return '';
  }
}

function trustAgilityPassthrough(opts: AgilityOptions | undefined): AgilityOptions {
  const out: AgilityOptions = {};
  if (opts?.mldsaBackend !== undefined) out.mldsaBackend = opts.mldsaBackend;
  if (opts?.mldsaBackendLoader !== undefined) out.mldsaBackendLoader = opts.mldsaBackendLoader;
  return out;
}

/**
 * The bytes BOTH legs sign: the same body v1 signs (version, issuer, payload)
 * under the v2 domain tag, plus the committed `required_algorithms` set.
 * Recomputed independently by the verifier from the PRESENTED body and the
 * REGISTERED set. See move 3 above.
 */
export function trustStageReceiptV2SigningBytes(
  body: { version?: unknown; issuer?: unknown; payload?: unknown },
  requiredAlgorithms: readonly string[] = TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!trustV2AlgorithmSetRegistered(requiredAlgorithms)) {
    throw new TypeError('trustStageReceiptV2SigningBytes: algorithm set is not the registered EP-GATE-TRUST-STAGE-RECEIPT-v2 set');
  }
  return Buffer.from(STAGE_RECEIPT_V2_DOMAIN + canonicalize({
    version: body.version,
    issuer: body.issuer,
    payload: body.payload,
    required_algorithms: [...requiredAlgorithms],
  }), 'utf8');
}

/**
 * Mint a hybrid stage receipt. Throws on invalid input, a signer that returns
 * a malformed set, or an unavailable ML-DSA backend: a receipt missing the
 * ML-DSA leg must never be emitted, only refused.
 */
export async function signTrustStageReceiptV2({
  payload,
  context,
  keys,
  signer,
}: {
  payload: Record<string, unknown>;
  context: Readonly<Record<string, unknown>>;
  keys?: TrustStageReceiptV2SigningKeys;
  signer?: TrustStageReceiptV2SignSetSigner;
}) {
  if (!exactKeys(context, STAGE_RECEIPT_ISSUER_KEYS)
      || !Object.values(context).every(boundedContextString)) {
    throw new TypeError('stage receipt v2 context must contain exact pinned issuer fields');
  }
  const hasKeys = keys !== undefined;
  const hasSigner = signer !== undefined;
  if (hasKeys === hasSigner) {
    throw new TypeError('configure exactly one stage receipt v2 signer (keys or signSet signer)');
  }
  if (hasKeys && (!keys!.ed?.privateKey || !keys!.pq?.secretKey || typeof keys!.pq?.publicKey !== 'string')) {
    throw new TypeError('stage receipt v2 keys require ed.privateKey, pq.secretKey, and pq.publicKey');
  }
  const requiredAlgorithms = [...TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS];
  const body = {
    version: TRUST_STAGE_RECEIPT_V2_VERSION,
    issuer: {
      issuer: context.issuer,
      tenant: context.tenant,
      environment: context.environment,
      audience: context.audience,
      key_id: context.key_id,
    },
    payload,
  };
  const receiptDigest = digest(body);
  const bytes = trustStageReceiptV2SigningBytes(body, requiredAlgorithms);

  let signatures: AgileSignature[];
  let edPublicKey: string;
  let pqPublicKey: string;
  if (hasKeys) {
    const signingKeys: AgileSigningKey[] = [
      { alg: 'Ed25519', private_key: keys!.ed.privateKey },
      { alg: 'ML-DSA-65', private_key: keys!.pq.secretKey },
    ];
    signatures = await signAgileSet(new Uint8Array(bytes), signingKeys);
    edPublicKey = keys!.ed.publicKey ?? crypto.createPublicKey(keys!.ed.privateKey)
      .export({ type: 'spki', format: 'der' }).toString('base64url');
    pqPublicKey = keys!.pq.publicKey;
  } else {
    if (typeof signer!.signSet !== 'function') {
      throw new TypeError('stage receipt v2 signer must expose signSet(bytes)');
    }
    const set = await signer!.signSet(bytes, { profile: TRUST_STAGE_RECEIPT_V2_VERSION });
    if (!Array.isArray(set)
        || !requiredAlgorithms.every((alg, index) => set[index]?.alg === alg
          && typeof set[index]?.sig === 'string')) {
      throw new TypeError('stage receipt v2 signer returned a malformed signature set');
    }
    signatures = set.map((entry) => ({ alg: entry.alg, sig: entry.sig }));
    const pins = (signer as unknown as { publicKeys?: TrustStageReceiptV2KeyPin }).publicKeys;
    if (!pins || typeof pins.public_key !== 'string' || typeof pins.pq_public_key !== 'string') {
      throw new TypeError('stage receipt v2 signSet signer must expose publicKeys { public_key, pq_public_key }');
    }
    edPublicKey = pins.public_key;
    pqPublicKey = pins.pq_public_key;
  }

  const pqKeyId = trustPqKeyId(pqPublicKey);
  if (!pqKeyId) throw new TypeError('stage receipt v2 ML-DSA-65 public key is malformed');
  if (publicKey(edPublicKey) === null) {
    throw new TypeError('stage receipt v2 Ed25519 public key must be base64url SPKI DER');
  }
  return {
    ...body,
    receipt_digest: receiptDigest,
    signature: {
      profile: TRUST_STAGE_RECEIPT_V2_VERSION,
      required_algorithms: requiredAlgorithms,
      public_key: edPublicKey,
      key_id: context.key_id,
      pq_public_key: pqPublicKey,
      pq_key_id: pqKeyId,
      signatures,
    },
  };
}

/**
 * FAIL-CLOSED hybrid stage-receipt verifier. Never throws on caller input; a
 * v2 receipt NEVER verifies on one leg alone. Trust keys, the expected issuer,
 * and every expected payload binding are relying-party inputs; none is
 * accepted from the receipt itself.
 */
export async function verifyTrustStageReceiptV2(receipt: unknown, options: {
  trustedKeys?: Readonly<Record<string, TrustStageReceiptV2KeyPin>>;
  expected?: Readonly<Record<string, unknown>>;
  expectedIssuer?: Readonly<Record<string, unknown>>;
  mldsaBackend?: AgilityOptions['mldsaBackend'];
  mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
} = {}) {
  const checks = {
    structure: false,
    digest: false,
    algorithm_set: false,
    legs_present: false,
    key: false,
    signature: false,
    issuer: false,
    expected: false,
  };
  const refuse = (reason: string) => ({ valid: false, reason, checks });
  try {
    // 1. Version marker + closed shape. A v1 receipt refuses here, the mirror
    //    image of the v1 verifier refusing a v2 receipt.
    if (!exactKeys(receipt, STAGE_RECEIPT_KEYS)
        || (receipt as RecordLike).version !== TRUST_STAGE_RECEIPT_V2_VERSION
        || !exactKeys((receipt as RecordLike).signature, STAGE_RECEIPT_V2_SIGNATURE_KEYS)
        || (receipt as RecordLike).signature.profile !== TRUST_STAGE_RECEIPT_V2_VERSION) {
      return refuse('receipt_structure_invalid');
    }
    const snapshot = receipt as RecordLike;
    if (!exactKeys(snapshot.issuer, STAGE_RECEIPT_ISSUER_KEYS)
        || !Object.values(snapshot.issuer).every(boundedContextString)
        || !validStageReceiptPayloadShape(snapshot.payload)
        || typeof snapshot.receipt_digest !== 'string' || !DIGEST.test(snapshot.receipt_digest)) {
      return refuse('receipt_structure_invalid');
    }
    checks.structure = true;

    // 2. Body digest, recomputed. The receipt does not get to assert it.
    let bodyDigest: string;
    try {
      bodyDigest = digest(stageReceiptBody(snapshot));
    } catch {
      return refuse('receipt_not_canonical');
    }
    checks.digest = bodyDigest === snapshot.receipt_digest;
    if (!checks.digest) return refuse('receipt_digest_mismatch');

    // 3. Committed algorithm set: exact and order-sensitive. A narrowed set is
    //    the stripping attack's cover story, refused structurally here and
    //    (independently) by the signature check, which rebuilds the bytes from
    //    the REGISTERED set regardless of what the receipt claims.
    checks.algorithm_set = trustV2AlgorithmSetRegistered(snapshot.signature.required_algorithms);
    if (!checks.algorithm_set) return refuse('receipt_algorithm_set_unsupported');

    // 4. Exactly one signature per required algorithm.
    const signatures = Array.isArray(snapshot.signature.signatures)
      ? snapshot.signature.signatures as AgileSignature[] : null;
    if (!signatures) return refuse('receipt_signature_set_invalid');
    const presented = new Set<string>();
    for (const entry of signatures) {
      if (!isRecord(entry) || typeof entry.alg !== 'string' || typeof entry.sig !== 'string') {
        return refuse('receipt_signature_set_invalid');
      }
      if (presented.has(entry.alg)) return refuse('receipt_signature_set_duplicate');
      presented.add(entry.alg);
    }
    for (const alg of TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS) {
      if (!presented.has(alg)) return refuse('receipt_signature_leg_missing');
    }
    for (const alg of presented) {
      if (!(TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) {
        return refuse('receipt_signature_set_invalid');
      }
    }
    checks.legs_present = true;

    // 5. Issuer keys: BOTH halves pinned, and the presented halves must equal
    //    the pinned ones. Identified-but-not-trusted, per leg: a key id pinned
    //    for v1 only (Ed25519 half alone) does NOT satisfy a v2 pin.
    const pin = isRecord(options.trustedKeys)
      && Object.hasOwn(options.trustedKeys as object, snapshot.issuer.key_id)
      ? (options.trustedKeys as Record<string, TrustStageReceiptV2KeyPin>)[snapshot.issuer.key_id]
      : null;
    const presentedEdKey = snapshot.signature.public_key;
    const presentedPqKey = snapshot.signature.pq_public_key;
    checks.key = isRecord(pin)
      && typeof pin!.public_key === 'string' && pin!.public_key.length > 0
      && typeof pin!.pq_public_key === 'string' && pin!.pq_public_key.length > 0
      && pin!.public_key === presentedEdKey
      && pin!.pq_public_key === presentedPqKey
      && snapshot.signature.key_id === snapshot.issuer.key_id
      // Curve-pinned: an Ed448 (or any non-Ed25519) SPKI presented as the
      // classical half fails here as well as in the signature check.
      && publicKey(presentedEdKey) !== null
      && trustPqKeyId(presentedPqKey) !== ''
      && snapshot.signature.pq_key_id === trustPqKeyId(presentedPqKey);
    if (!checks.key) return refuse('receipt_key_untrusted');

    // 6. Signature set over bytes rebuilt from the PRESENTED body and the
    //    REGISTERED algorithm set, under the PINNED keys. Never fall back to
    //    the receipt's own self-asserted key material.
    let bytes: Buffer;
    try {
      bytes = trustStageReceiptV2SigningBytes(snapshot, TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS);
    } catch {
      return refuse('receipt_not_canonical');
    }
    let setResult;
    try {
      setResult = await verifyAgileSignatureSet(
        new Uint8Array(bytes),
        signatures,
        [
          { alg: 'Ed25519', public_key: pin!.public_key },
          { alg: 'ML-DSA-65', public_key: pin!.pq_public_key },
        ],
        {
          ...trustAgilityPassthrough(options),
          policy: 'hybrid_all',
          requiredAlgorithms: [...TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS],
        },
      );
    } catch {
      // verifyAgileSignatureSet documents that it never throws; an injected
      // backend that does is still a refusal here, never a pass.
      setResult = null;
    }
    checks.signature = setResult?.verified === true;
    if (!checks.signature) {
      return refuse(`receipt_signature_invalid:${String(setResult?.reason ?? 'signature_set_unverified')}`);
    }

    // 7. Relying-party bindings: identical to v1.
    try {
      checks.issuer = options.expectedIssuer === undefined
        || canonicalize(snapshot.issuer) === canonicalize(options.expectedIssuer);
    } catch {
      checks.issuer = false;
    }
    if (!checks.issuer) return refuse('receipt_expected_issuer_mismatch');
    const expected = options.expected ?? {};
    checks.expected = Object.entries(expected).every(([field, value]) => {
      try {
        return canonicalize(snapshot.payload[field]) === canonicalize(value);
      } catch {
        return false;
      }
    });
    if (!checks.expected) return refuse('receipt_expected_binding_mismatch');
    return {
      valid: true,
      reason: null,
      checks,
      receipt_digest: snapshot.receipt_digest,
      payload: clone(snapshot.payload),
    };
  } catch {
    return refuse('receipt_structure_invalid');
  }
}

/**
 * Route a stage receipt of EITHER version to its verifier. v1 receipts keep
 * the exact v1 verdict; v2 receipts get the hybrid check. A receipt whose
 * `version` is neither refuses through the v1 verifier, which is the
 * fail-closed answer.
 */
export async function verifyTrustStageReceiptStatement(receipt: unknown, options: {
  trustedKeys?: Readonly<Record<string, string | crypto.KeyObject | TrustStageReceiptV2KeyPin>>;
  expected?: Readonly<Record<string, unknown>>;
  expectedIssuer?: Readonly<Record<string, unknown>>;
  mldsaBackend?: AgilityOptions['mldsaBackend'];
  mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
} = {}) {
  if (isRecord(receipt) && receipt.version === TRUST_STAGE_RECEIPT_V2_VERSION) {
    return verifyTrustStageReceiptV2(receipt, options as Parameters<typeof verifyTrustStageReceiptV2>[1]);
  }
  return verifyTrustStageReceipt(receipt, options as Parameters<typeof verifyTrustStageReceipt>[1]);
}

export default {
  TRUST_PROGRAM_VERSION,
  TRUST_STAGE_RECEIPT_VERSION,
  TRUST_PROGRAM_V2_VERSION,
  TRUST_STAGE_RECEIPT_V2_VERSION,
  TRUST_STAGE_RECEIPT_V2_REQUIRED_ALGORITHMS,
  validateTrustProgram,
  validateTrustProgramV2,
  validateTrustProgramStatement,
  trustProgramDigest,
  trustProgramV2Digest,
  verifyTrustStageReceipt,
  trustStageReceiptV2SigningBytes,
  signTrustStageReceiptV2,
  verifyTrustStageReceiptV2,
  verifyTrustStageReceiptStatement,
  createMemoryTrustProgramStore,
  createTrustProgramKernel,
};
