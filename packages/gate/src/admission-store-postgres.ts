// SPDX-License-Identifier: Apache-2.0
/**
 * Deployment-bound PostgreSQL Admission Store.
 *
 * Every mutation is one PostgreSQL function call.  The SQL functions use
 * explicit row locks and permanent unique fences; this adapter retries only
 * SQLSTATE 40001 (serialization failure) and 40P01 (deadlock), with the same
 * caller-generated capabilities.  It never retries an ambiguous provider
 * effect.  A lost beginInvocation acknowledgement is recovered only when an
 * authoritative read proves that this exact invocation-token digest committed.
 */

import crypto from 'node:crypto';
import { canonicalizeFiniteJson } from './strict-json.js';

import {
  ADMISSION_JOURNAL_VERSION,
  ADMISSION_LIMITS,
  ADMISSION_RECORD_VERSION,
  EXECUTION_PROGRAM_STATUS_VERSION,
  EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION,
  createAdmissionSnapshot,
  createExecutionProgramAdmissionBinding,
  EXECUTION_PROGRAM_RUNTIME_VERSION,
  executionProgramReportSnapshotMarker,
  verifyAdmissionJournal,
  type AdmissionBeginResult,
  type AdmissionCas,
  type AdmissionDigest,
  type AdmissionEffectRelationInput,
  type AdmissionExpiredRecoveryInput,
  type AdmissionInvariantCheck,
  type AdmissionJournalEntry,
  type AdmissionOperationReference,
  type AdmissionProviderOutcomeInput,
  type AdmissionRecord,
  type AdmissionRecoveryInput,
  type AdmissionRecoveryResult,
  type AdmissionReference,
  type AdmissionReserveResult,
  type AdmissionSnapshot,
  type AdmissionSnapshotInput,
  type ExecutionProgramAdmissionStore,
  type ExecutionProgramActionMatchExpected,
  type ExecutionProgramActionMatchVerifier,
  type ExecutionProgramOccurrence,
  type ExecutionProgramReportSnapshot,
  type ExecutionProgramReportSnapshotBody,
  type ExecutionProgramRefusalReason,
  type ExecutionProgramReference,
  type ExecutionProgramRegistrationContext,
  type ExecutionProgramRegistrationResult,
  type ExecutionProgramReserveInput,
  type ExecutionProgramReserveResult,
  type ExecutionProgramRuntimeState,
  type ExecutionProgramStatusObservation,
  type ExecutionProgramStatusOracle,
  type ExecutionProgramVerificationPolicy,
  type AdmissionSupersedeInput,
  type AdmissionSupersedeResult,
  type AdmissionTransitionResult,
} from './admission-store.js';
import {
  verifyBoundedExecutionProgram,
  type ExecutionProgramVerificationOptions,
  type VerifiedBoundedExecutionProgram,
} from './bounded-execution-program.js';

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export interface AdmissionPostgresQueryResult {
  rowCount: number;
  rows?: Array<Record<string, unknown>>;
}

export type AdmissionPostgresQuery = (
  text: string,
  params: readonly unknown[],
) => Promise<AdmissionPostgresQueryResult>;

export interface CreateAdmissionPostgresStoreOptions {
  /**
   * General Gate runtime credential. It must not have EXECUTE on assertion-bearing
   * execution-program RPCs.
   */
  query: AdmissionPostgresQuery;
  /**
   * Independently credentialed verifier-service connection. The service verifies
   * program signatures, action-profile matches, and status observations before
   * invoking the narrowly granted assertion-bearing RPCs.
   */
  executionProgramVerifierQuery?: AdmissionPostgresQuery;
  deploymentId: string;
  tenantId: string;
  now?: number | string | Date | (() => number | string | Date);
  executionProgramVerificationPolicy?: ExecutionProgramVerificationPolicy;
  executionProgramStatusOracle?: ExecutionProgramStatusOracle;
  maxExecutionProgramStatusAgeMs?: number;
  executionProgramActionMatchVerifier?: ExecutionProgramActionMatchVerifier;
  /** Test seam only. Production callers should use the cryptographic default. */
  ownerTokenFactory?: () => string;
  /** Test seam only. Production callers should use the cryptographic default. */
  invocationTokenFactory?: () => string;
  /** Number of retries after the first attempt for SQLSTATE 40001/40P01. */
  maxTransactionRetries?: number;
}

export interface AdmissionPostgresStore extends ExecutionProgramAdmissionStore {
  readonly guaranteeClass: 'local_atomic';
  readonly singleTenant: true;
  readonly deploymentBound: true;
  readonly managedTenantPrincipalMapping: false;
  readonly maxTransactionRetries: number;
}

export const ADMISSION_POSTGRES_SQL = Object.freeze({
  reserve: 'SELECT public.ep_gate_admission_reserve($1::text, $2::text, $3::jsonb, $4::text) AS result',
  release: 'SELECT public.ep_gate_admission_release($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::text) AS result',
  expire: 'SELECT public.ep_gate_admission_expire($1::text, $2::text, $3::text, $4::bigint, $5::text) AS result',
  reapExpiredReservation: 'SELECT public.ep_gate_admission_reap_expired($1::text, $2::text, $3::text, $4::bigint) AS result',
  supersede: 'SELECT public.ep_gate_admission_supersede($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::jsonb, $7::text) AS result',
  beginInvocation: 'SELECT public.ep_gate_admission_begin_invocation($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::text) AS result',
  recoverIndeterminate: 'SELECT public.ep_gate_admission_recover_indeterminate($1::text, $2::text, $3::text, $4::text, $5::text) AS result',
  recordProviderOutcome: 'SELECT public.ep_gate_admission_record_provider_outcome($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::text, $7::text, $8::text, $9::text) AS result',
  recordEffectRelation: 'SELECT public.ep_gate_admission_record_effect_relation($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::text, $7::text, $8::text, $9::text) AS result',
  read: 'SELECT public.ep_gate_admission_read($1::text, $2::text, $3::text) AS result',
  readByOperation: 'SELECT public.ep_gate_admission_read_by_operation($1::text, $2::text, $3::text) AS result',
  readSnapshot: 'SELECT public.ep_gate_admission_read_snapshot($1::text, $2::text, $3::text) AS result',
  journal: 'SELECT public.ep_gate_admission_journal($1::text, $2::text, $3::text) AS result',
  checkInvariants: 'SELECT public.ep_gate_admission_check_invariants($1::text, $2::text) AS result',
  registerExecutionProgram: 'SELECT public.ep_gate_execution_program_register($1::text, $2::text, $3::text, $4::jsonb, $5::jsonb, $6::text) AS result',
  reserveExecutionProgramAdmission: 'SELECT public.ep_gate_execution_program_reserve_admission($1::text, $2::text, $3::text, $4::text, $5::text, $6::jsonb, $7::jsonb, $8::text, $9::jsonb) AS result',
  beginExecutionProgramInvocation: 'SELECT public.ep_gate_execution_program_begin_invocation($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::text, $7::jsonb) AS result',
  releaseExecutionProgramAdmission: 'SELECT public.ep_gate_execution_program_release_admission($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::text) AS result',
  expireExecutionProgramAdmission: 'SELECT public.ep_gate_execution_program_expire_admission($1::text, $2::text, $3::text, $4::bigint, $5::text) AS result',
  supersedeExecutionProgram: 'SELECT public.ep_gate_execution_program_supersede($1::text, $2::text, $3::text, $4::jsonb, $5::jsonb, $6::text) AS result',
  readExecutionProgram: 'SELECT public.ep_gate_execution_program_read($1::text, $2::text, $3::text) AS result',
  readExecutionProgramReportSnapshot: 'SELECT public.ep_gate_execution_program_read_report_snapshot($1::text, $2::text, $3::text) AS result',
  readExecutionProgramByAdmission: 'SELECT public.ep_gate_execution_program_read_by_admission($1::text, $2::text, $3::text) AS result',
  readExecutionProgramOccurrence: 'SELECT public.ep_gate_execution_program_read_occurrence($1::text, $2::text, $3::text, $4::text) AS result',
});

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{0,511}$/;
const OWNER_TOKEN = /^admission-owner:v2:[A-Za-z0-9_-]{32,128}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const RETRYABLE_SQLSTATES = new Set(['40001', '40P01']);

export class AdmissionPostgresProtocolError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AdmissionPostgresProtocolError';
  }
}

export class AdmissionPostgresAmbiguousBeginError extends Error {
  readonly admissionId: string;
  constructor(admissionId: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AdmissionPostgresAmbiguousBeginError';
    this.admissionId = admissionId;
  }
}

function plain(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonical(value: Json): string {
  try { return canonicalizeFiniteJson(value); }
  catch (cause) { throw new AdmissionPostgresProtocolError('value is outside canonical JSON', { cause }); }
}

function hash(domain: string, value: unknown): AdmissionDigest {
  return `sha256:${crypto.createHash('sha256')
    .update(domain)
    .update('\0')
    .update(canonical(value as Json))
    .digest('hex')}`;
}

function tokenDigest(token: string): AdmissionDigest {
  return hash(`${ADMISSION_RECORD_VERSION}:TOKEN`, token);
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function detached<T>(value: T): Readonly<T> {
  return deepFreeze(structuredClone(value));
}

function identifier(value: unknown, field: string): string {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    throw new TypeError(`${field} is invalid`);
  }
  return value;
}

function digest(value: unknown, field: string): AdmissionDigest {
  if (typeof value !== 'string' || !SHA256.test(value)) {
    throw new TypeError(`${field} is invalid`);
  }
  return value as AdmissionDigest;
}

function revision(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError('expected_revision is invalid');
  }
  return value as number;
}

function ownerToken(value: unknown): string {
  if (typeof value !== 'string' || !OWNER_TOKEN.test(value)) {
    throw new TypeError('owner_token is invalid');
  }
  return value;
}

function invocationToken(value: unknown): string {
  if (typeof value !== 'string' || value.length < 48) {
    throw new TypeError('invocation_token is invalid');
  }
  return value;
}

function instant(value: unknown, field: string): string {
  if (typeof value !== 'string' || !RFC3339.test(value)) throw new TypeError(`${field} is invalid`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw new TypeError(`${field} is invalid`);
  return new Date(milliseconds).toISOString();
}

function currentMs(source: CreateAdmissionPostgresStoreOptions['now']): number {
  const raw = typeof source === 'function' ? source() : source;
  if (raw === undefined) return Date.now();
  if (raw instanceof Date) return raw.getTime();
  if (typeof raw === 'string') return Date.parse(instant(raw, 'now'));
  if (!Number.isFinite(raw)) throw new TypeError('now is invalid');
  return raw as number;
}

const EXECUTION_PROGRAM_CONTEXT_KEYS = Object.freeze([
  'expected_program_id',
  'expected_tenant_id',
  'expected_authorization_digest',
  'expected_audience',
] as const);

function registrationContext(raw: unknown): ExecutionProgramRegistrationContext | null {
  if (!plain(raw)
      || Reflect.ownKeys(raw).length !== EXECUTION_PROGRAM_CONTEXT_KEYS.length
      || !EXECUTION_PROGRAM_CONTEXT_KEYS.every((key) => Object.hasOwn(raw, key))) return null;
  try {
    return {
      expected_program_id: identifier(raw.expected_program_id, 'expected_program_id'),
      expected_tenant_id: identifier(raw.expected_tenant_id, 'expected_tenant_id'),
      expected_authorization_digest: digest(
        raw.expected_authorization_digest,
        'expected_authorization_digest',
      ),
      expected_audience: identifier(raw.expected_audience, 'expected_audience'),
    };
  } catch {
    return null;
  }
}

function executionProgramTrustPolicy(raw: ExecutionProgramVerificationPolicy | undefined): {
  trustedKeys: NonNullable<ExecutionProgramVerificationOptions['trusted_keys']>;
  activeAuthorizers: ReadonlyMap<string, string>;
} {
  const trustedKeys = Object.create(null) as NonNullable<
    ExecutionProgramVerificationOptions['trusted_keys']
  >;
  const activeAuthorizers = new Map<string, string>();
  if (raw === undefined) return { trustedKeys, activeAuthorizers };
  if (!plain(raw) || Reflect.ownKeys(raw).length !== 1
      || !Object.hasOwn(raw, 'trusted_keys') || !plain(raw.trusted_keys)) {
    throw new TypeError('execution program verification policy is invalid');
  }
  for (const [keyId, value] of Object.entries(raw.trusted_keys)) {
    if (!IDENTIFIER.test(keyId)
        || !plain(value)
        || Reflect.ownKeys(value).length !== 4
        || !['issuer_id', 'public_key', 'role', 'status'].every((key) => Object.hasOwn(value, key))
        || !IDENTIFIER.test(String(value.issuer_id ?? ''))
        || typeof value.public_key !== 'string'
        || !/^[A-Za-z0-9_-]+$/.test(value.public_key)
        || value.role !== 'program_authorizer'
        || !['ACTIVE', 'SUSPENDED', 'REVOKED'].includes(String(value.status ?? ''))) {
      throw new TypeError('execution program authorizer pin is invalid');
    }
    if (value.status !== 'ACTIVE') continue;
    trustedKeys[keyId] = {
      issuer_id: value.issuer_id as string,
      public_key: value.public_key,
    };
    activeAuthorizers.set(keyId, value.issuer_id as string);
  }
  return { trustedKeys, activeAuthorizers };
}

function defaultOwnerToken(): string {
  return `admission-owner:v2:${crypto.randomBytes(32).toString('base64url')}`;
}

function defaultInvocationToken(): string {
  return `admission-invocation:v2:${crypto.randomBytes(32).toString('base64url')}`;
}

function parseJson(value: unknown, operation: string): unknown {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new AdmissionPostgresProtocolError(`${operation}: malformed JSON result`, { cause: error });
  }
}

function validateSnapshot(value: unknown, operation: string): Readonly<AdmissionSnapshot> {
  if (!plain(value) || !plain(value.body)) {
    throw new AdmissionPostgresProtocolError(`${operation}: malformed snapshot`);
  }
  const recreated = createAdmissionSnapshot(value.body as unknown as AdmissionSnapshotInput);
  if (value.snapshot_digest !== recreated.snapshot_digest) {
    throw new AdmissionPostgresProtocolError(`${operation}: snapshot digest mismatch`);
  }
  return recreated;
}

function validateRecord(value: unknown, operation: string, tenantId: string): Readonly<AdmissionRecord> {
  if (!plain(value)
      || value['@version'] !== ADMISSION_RECORD_VERSION
      || value.tenant_id !== tenantId
      || !IDENTIFIER.test(String(value.admission_id ?? ''))
      || !IDENTIFIER.test(String(value.operation_id ?? ''))
      || !Number.isSafeInteger(value.revision)
      || (value.revision as number) < 0
      || !Array.isArray(value.resources)
      || !SHA256.test(String(value.record_digest ?? ''))) {
    throw new AdmissionPostgresProtocolError(`${operation}: malformed admission record`);
  }
  const { record_digest: recordDigest, ...body } = value;
  if (hash(`${ADMISSION_RECORD_VERSION}:DIGEST`, body) !== recordDigest) {
    throw new AdmissionPostgresProtocolError(`${operation}: admission record digest mismatch`);
  }
  return detached(value as unknown as AdmissionRecord);
}

function validateJournal(
  value: unknown,
  operation: string,
  tenantId: string,
  admissionId: string,
): readonly Readonly<AdmissionJournalEntry>[] {
  if (!Array.isArray(value)) {
    throw new AdmissionPostgresProtocolError(`${operation}: malformed journal`);
  }
  for (const entry of value) {
    if (!plain(entry)
        || entry['@version'] !== ADMISSION_JOURNAL_VERSION
        || entry.tenant_id !== tenantId
        || entry.admission_id !== admissionId) {
      throw new AdmissionPostgresProtocolError(`${operation}: malformed journal entry`);
    }
  }
  const checked = verifyAdmissionJournal(value as unknown as AdmissionJournalEntry[]);
  if (!checked.ok) {
    throw new AdmissionPostgresProtocolError(
      `${operation}: invalid journal at ${checked.at}: ${checked.reason}`,
    );
  }
  return detached(value as unknown as AdmissionJournalEntry[]);
}

function validateExecutionProgramRuntime(
  value: unknown,
  operation: string,
  tenantId: string,
  expectedDigest?: string,
  expectedProgram?: Readonly<VerifiedBoundedExecutionProgram>,
): Readonly<ExecutionProgramRuntimeState> {
  if (!plain(value)
      || value['@version'] !== EXECUTION_PROGRAM_RUNTIME_VERSION
      || value.tenant_id !== tenantId
      || !IDENTIFIER.test(String(value.program_id ?? ''))
      || !SHA256.test(String(value.program_digest ?? ''))
      || (expectedDigest !== undefined && value.program_digest !== expectedDigest)
      || !Number.isSafeInteger(value.version)
      || (value.version as number) < 1
      || !['ACTIVE', 'SUSPENDED', 'REVOKED', 'SUPERSEDED'].includes(String(value.status ?? ''))
      || !Number.isSafeInteger(value.status_sequence)
      || Number(value.status_sequence) < 0
      || typeof value.status_observed_at !== 'string'
      || !Number.isFinite(Date.parse(value.status_observed_at))
      || typeof value.status_expires_at !== 'string'
      || !Number.isFinite(Date.parse(value.status_expires_at))
      || !IDENTIFIER.test(String(value.authorizer_id ?? ''))
      || typeof value.registered_at !== 'string'
      || !Number.isFinite(Date.parse(value.registered_at))
      || (value.superseded_by_program_digest !== null
        && !SHA256.test(String(value.superseded_by_program_digest ?? '')))
      || !Number.isSafeInteger(value.total_occurrences)
      || Number(value.total_occurrences) < 0
      || !Array.isArray(value.budgets)
      || !plain(value.program)) {
    throw new AdmissionPostgresProtocolError(`${operation}: malformed execution program`);
  }
  const seen = new Set<string>();
  for (const budget of value.budgets) {
    if (!plain(budget)
        || !IDENTIFIER.test(String(budget.budget_id ?? ''))
        || !IDENTIFIER.test(String(budget.unit ?? ''))
        || seen.has(String(budget.budget_id))
        || !Number.isSafeInteger(budget.limit)
        || !Number.isSafeInteger(budget.reserved)
        || !Number.isSafeInteger(budget.consumed)
        || Number(budget.limit) < 1
        || Number(budget.reserved) < 0
        || Number(budget.consumed) < 0
        || Number(budget.reserved) + Number(budget.consumed) > Number(budget.limit)) {
      throw new AdmissionPostgresProtocolError(`${operation}: malformed execution program budget`);
    }
    seen.add(String(budget.budget_id));
  }
  if (value.program.tenant_id !== tenantId
      || value.program.program_id !== value.program_id
      || value.program.version !== value.version
      || (expectedProgram !== undefined
        && canonical(value.program as Json) !== canonical(expectedProgram as unknown as Json))) {
    throw new AdmissionPostgresProtocolError(`${operation}: execution program binding mismatch`);
  }
  return detached(value as unknown as ExecutionProgramRuntimeState);
}

function validateExecutionProgramOccurrence(
  value: unknown,
  operation: string,
  reference: ExecutionProgramReference & { occurrence_id: string },
): Readonly<ExecutionProgramOccurrence> {
  if (!plain(value)
      || value.tenant_id !== reference.tenant_id
      || value.program_digest !== reference.program_digest
      || value.occurrence_id !== reference.occurrence_id
      || !IDENTIFIER.test(String(value.node_id ?? ''))
      || !IDENTIFIER.test(String(value.admission_id ?? ''))
      || !SHA256.test(String(value.snapshot_digest ?? ''))
      || !['RESERVED', 'RELEASED', 'INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED']
        .includes(String(value.state ?? ''))
      || !Array.isArray(value.charges)
      || typeof value.created_at !== 'string'
      || !Number.isFinite(Date.parse(value.created_at))
      || typeof value.updated_at !== 'string'
      || !Number.isFinite(Date.parse(value.updated_at))) {
    throw new AdmissionPostgresProtocolError(`${operation}: malformed execution program occurrence`);
  }
  const seen = new Set<string>();
  for (const charge of value.charges) {
    if (!plain(charge)
        || !IDENTIFIER.test(String(charge.budget_id ?? ''))
        || seen.has(String(charge.budget_id))
        || !Number.isSafeInteger(charge.amount)
        || Number(charge.amount) < 1) {
      throw new AdmissionPostgresProtocolError(`${operation}: malformed execution program charge`);
    }
    seen.add(String(charge.budget_id));
  }
  return detached(value as unknown as ExecutionProgramOccurrence);
}

function validateExecutionProgramReportSnapshot(
  value: unknown,
  operation: string,
  reference: ExecutionProgramReference,
): Readonly<ExecutionProgramReportSnapshot> {
  const keys = [
    '@version', 'tenant_id', 'program_digest', 'runtime_state',
    'occurrences', 'snapshot_marker',
  ];
  if (!plain(value)
      || Reflect.ownKeys(value).length !== keys.length
      || !keys.every((key) => Object.hasOwn(value, key))
      || value['@version'] !== EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION
      || value.tenant_id !== reference.tenant_id
      || value.program_digest !== reference.program_digest
      || !Array.isArray(value.occurrences)
      || !SHA256.test(String(value.snapshot_marker ?? ''))) {
    throw new AdmissionPostgresProtocolError(`${operation}: malformed report snapshot`);
  }
  const runtimeState = validateExecutionProgramRuntime(
    value.runtime_state,
    operation,
    reference.tenant_id,
    reference.program_digest,
  );
  const maximum = runtimeState.program.max_total_occurrences;
  if (!Number.isSafeInteger(maximum) || maximum < 1
      || value.occurrences.length !== runtimeState.total_occurrences
      || value.occurrences.length > maximum) {
    throw new AdmissionPostgresProtocolError(`${operation}: occurrence bound violated`);
  }
  const occurrenceIds = new Set<string>();
  const admissionIds = new Set<string>();
  let previous: ExecutionProgramOccurrence | null = null;
  const occurrences = value.occurrences.map((entry) => {
    if (!plain(entry) || typeof entry.occurrence_id !== 'string') {
      throw new AdmissionPostgresProtocolError(`${operation}: malformed report occurrence`);
    }
    const occurrence = validateExecutionProgramOccurrence(entry, operation, {
      ...reference,
      occurrence_id: entry.occurrence_id,
    });
    if (occurrenceIds.has(occurrence.occurrence_id)
        || admissionIds.has(occurrence.admission_id)) {
      throw new AdmissionPostgresProtocolError(`${operation}: duplicate report occurrence`);
    }
    if (previous !== null && (
      Buffer.compare(Buffer.from(previous.node_id), Buffer.from(occurrence.node_id)) > 0
      || (previous.node_id === occurrence.node_id
        && Buffer.compare(
          Buffer.from(previous.occurrence_id),
          Buffer.from(occurrence.occurrence_id),
        ) >= 0)
    )) {
      throw new AdmissionPostgresProtocolError(`${operation}: report occurrences are not ordered`);
    }
    occurrenceIds.add(occurrence.occurrence_id);
    admissionIds.add(occurrence.admission_id);
    previous = occurrence;
    return occurrence;
  });
  const body: ExecutionProgramReportSnapshotBody = {
    '@version': EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION,
    tenant_id: reference.tenant_id,
    program_digest: reference.program_digest,
    runtime_state: runtimeState,
    occurrences,
  };
  if (value.snapshot_marker !== executionProgramReportSnapshotMarker(body)) {
    throw new AdmissionPostgresProtocolError(`${operation}: report snapshot marker mismatch`);
  }
  return detached({
    ...body,
    snapshot_marker: value.snapshot_marker,
  }) as Readonly<ExecutionProgramReportSnapshot>;
}

function sqlState(error: unknown): string | null {
  return plain(error) && typeof error.code === 'string' ? error.code : null;
}

function normalizeResultObject(value: unknown, operation: string): Record<string, unknown> {
  const parsed = parseJson(value, operation);
  if (!plain(parsed) || typeof parsed.ok !== 'boolean') {
    throw new AdmissionPostgresProtocolError(`${operation}: malformed PostgreSQL result`);
  }
  return parsed;
}

function validateReference(input: AdmissionReference): AdmissionReference {
  return {
    tenant_id: identifier(input.tenant_id, 'tenant_id'),
    admission_id: identifier(input.admission_id, 'admission_id'),
  };
}

function validateOperationReference(input: AdmissionOperationReference): AdmissionOperationReference {
  return {
    tenant_id: identifier(input.tenant_id, 'tenant_id'),
    operation_id: identifier(input.operation_id, 'operation_id'),
  };
}

function validateCas(input: AdmissionCas): AdmissionCas {
  return {
    ...validateReference(input),
    expected_revision: revision(input.expected_revision),
    owner_token: ownerToken(input.owner_token),
  };
}

/**
 * Creates a durable single-tenant store bound to one installed deployment row.
 * The SQL deliberately has no session-user-to-tenant mapping: database access
 * is the deployment boundary and every RPC rechecks the singleton binding.
 */
export function createAdmissionPostgresStore(
  options: CreateAdmissionPostgresStoreOptions,
): AdmissionPostgresStore {
  if (!plain(options) || typeof options.query !== 'function') {
    throw new TypeError('createAdmissionPostgresStore requires an async pg-style query function');
  }
  const query = options.query;
  const executionProgramVerifierQuery = options.executionProgramVerifierQuery;
  if (executionProgramVerifierQuery !== undefined
      && typeof executionProgramVerifierQuery !== 'function') {
    throw new TypeError('executionProgramVerifierQuery must be an async pg-style query function');
  }
  if (executionProgramVerifierQuery === query) {
    throw new TypeError('execution-program assertions require a distinct verifier-service query');
  }
  const deploymentId = identifier(options.deploymentId, 'deploymentId');
  const tenantId = identifier(options.tenantId, 'tenantId');
  const ownerFactory = options.ownerTokenFactory ?? defaultOwnerToken;
  const invocationFactory = options.invocationTokenFactory ?? defaultInvocationToken;
  const programTrust = executionProgramTrustPolicy(options.executionProgramVerificationPolicy);
  const maxExecutionProgramStatusAgeMs = options.maxExecutionProgramStatusAgeMs
    ?? ADMISSION_LIMITS.currentnessMaxAgeMs;
  if (!Number.isSafeInteger(maxExecutionProgramStatusAgeMs)
      || maxExecutionProgramStatusAgeMs < 1
      || maxExecutionProgramStatusAgeMs > 300_000) {
    throw new TypeError('max execution program status age is invalid');
  }
  const maxTransactionRetries = options.maxTransactionRetries ?? 3;
  if (!Number.isSafeInteger(maxTransactionRetries)
      || maxTransactionRetries < 0
      || maxTransactionRetries > 16) {
    throw new TypeError('maxTransactionRetries must be an integer from 0 through 16');
  }

  function assertTenant(value: string): void {
    if (value !== tenantId) throw new TypeError('tenant_id does not match the deployment binding');
  }

  async function rpcUsing(
    queryFunction: AdmissionPostgresQuery,
    operation: string,
    text: string,
    params: readonly unknown[],
  ): Promise<unknown> {
    for (let attempt = 0; ; attempt += 1) {
      try {
        const result = await queryFunction(text, params);
        if (!result
            || result.rowCount !== 1
            || !Array.isArray(result.rows)
            || result.rows.length !== 1
            || !Object.hasOwn(result.rows[0], 'result')) {
          throw new AdmissionPostgresProtocolError(`${operation}: malformed PostgreSQL result`);
        }
        return parseJson(result.rows[0].result, operation);
      } catch (error) {
        if (attempt < maxTransactionRetries && RETRYABLE_SQLSTATES.has(sqlState(error) ?? '')) {
          continue;
        }
        throw error;
      }
    }
  }

  async function rpc(
    operation: string,
    text: string,
    params: readonly unknown[],
  ): Promise<unknown> {
    return rpcUsing(query, operation, text, params);
  }

  async function verifierRpc(
    operation: string,
    text: string,
    params: readonly unknown[],
  ): Promise<unknown> {
    if (!executionProgramVerifierQuery) {
      throw new AdmissionPostgresProtocolError(
        `${operation}: executionProgramVerifierQuery is required for assertion-bearing RPCs`,
      );
    }
    return rpcUsing(executionProgramVerifierQuery, operation, text, params);
  }

  function transitionResult(value: unknown, operation: string): AdmissionTransitionResult {
    const result = normalizeResultObject(value, operation);
    if (!result.ok) return detached(result) as AdmissionTransitionResult;
    return {
      ok: true,
      record: validateRecord(result.record, operation, tenantId),
    };
  }

  async function read(input: AdmissionReference): Promise<Readonly<AdmissionRecord> | null> {
    const reference = validateReference(input);
    assertTenant(reference.tenant_id);
    const value = await rpc('admission read', ADMISSION_POSTGRES_SQL.read, [
      deploymentId,
      tenantId,
      reference.admission_id,
    ]);
    return value === null ? null : validateRecord(value, 'admission read', tenantId);
  }

  async function readSnapshot(
    snapshotDigest: AdmissionDigest,
  ): Promise<Readonly<AdmissionSnapshot> | null> {
    const normalized = digest(snapshotDigest, 'snapshot_digest');
    const value = await rpc('admission snapshot read', ADMISSION_POSTGRES_SQL.readSnapshot, [
      deploymentId,
      tenantId,
      normalized,
    ]);
    return value === null ? null : validateSnapshot(value, 'admission snapshot read');
  }

  async function readProgram(programDigest: string): Promise<Readonly<ExecutionProgramRuntimeState> | null> {
    const value = await rpc(
      'execution program read',
      ADMISSION_POSTGRES_SQL.readExecutionProgram,
      [deploymentId, tenantId, programDigest],
    );
    return value === null ? null : validateExecutionProgramRuntime(
      value,
      'execution program read',
      tenantId,
      programDigest,
    );
  }

  async function programStatusPayload(
    state: Readonly<ExecutionProgramRuntimeState>,
  ): Promise<string | null> {
    if (!options.executionProgramStatusOracle) return null;
    let observation: ExecutionProgramStatusObservation | null;
    try {
      observation = await options.executionProgramStatusOracle.read(detached({
        tenant_id: state.tenant_id,
        program_id: state.program_id,
        program_digest: state.program_digest,
        version: state.version,
      }));
    } catch {
      observation = null;
    }
    const validationNow = currentMs(options.now);
    const keys = [
      '@version', 'tenant_id', 'program_id', 'program_digest', 'version',
      'status', 'sequence', 'observed_at', 'expires_at',
    ];
    const observedAt = plain(observation) && typeof observation.observed_at === 'string'
      ? Date.parse(observation.observed_at) : NaN;
    const expiresAt = plain(observation) && typeof observation.expires_at === 'string'
      ? Date.parse(observation.expires_at) : NaN;
    if (!plain(observation)
        || Reflect.ownKeys(observation).length !== keys.length
        || !keys.every((key) => Object.hasOwn(observation, key))
        || observation['@version'] !== EXECUTION_PROGRAM_STATUS_VERSION
        || observation.tenant_id !== state.tenant_id
        || observation.program_id !== state.program_id
        || observation.program_digest !== state.program_digest
        || observation.version !== state.version
        || !['ACTIVE', 'SUSPENDED', 'REVOKED'].includes(String(observation.status ?? ''))
        || !Number.isSafeInteger(observation.sequence) || observation.sequence < 0
        || !Number.isFinite(observedAt) || !Number.isFinite(expiresAt)
        || observedAt > validationNow
        || validationNow - observedAt > maxExecutionProgramStatusAgeMs
        || expiresAt <= validationNow || observation.sequence < state.status_sequence
        || (observation.sequence === state.status_sequence
          && (observation.status !== state.status
            || observation.observed_at !== state.status_observed_at
            || observation.expires_at !== state.status_expires_at))) {
      return JSON.stringify(null);
    }
    return JSON.stringify(observation);
  }

  async function programActionMatch(
    state: Readonly<ExecutionProgramRuntimeState>,
    nodeId: string,
    snapshot: Readonly<AdmissionSnapshot>,
    evidence: unknown,
  ): Promise<{ ok: true; value: string | null } | { ok: false }> {
    const node = state.program.nodes.find((entry) => entry.node_id === nodeId);
    if (!node) return { ok: false };
    if (node.action.mode === 'exact') {
      return evidence === undefined
        && snapshot.body.caid === node.action.caid
        && snapshot.body.action_digest === node.action.action_digest
        ? { ok: true, value: null } : { ok: false };
    }
    const input = snapshot.body.inputs.find((entry) => entry.role === 'aeb');
    const verifier = options.executionProgramActionMatchVerifier;
    if (evidence === undefined || !verifier || !input
        || input.subject !== state.program.subject_id
        || input.profile_digest !== node.action.profile_digest) return { ok: false };
    const expected: ExecutionProgramActionMatchExpected = {
      tenant_id: state.tenant_id,
      profile_id: node.action.profile_id,
      profile_digest: node.action.profile_digest as AdmissionDigest,
      subject_id: state.program.subject_id,
      operation_id: snapshot.body.operation_id,
      caid: snapshot.body.caid,
      action_digest: snapshot.body.action_digest,
      verifier_id: input.verifier_id,
      evidence_payload_digest: input.payload_digest,
      evidence_trust_configuration_digest: input.trust_configuration_digest,
      trust_epoch: snapshot.body.trust_epoch,
      trust_configuration_digest: snapshot.body.trust_configuration_digest,
    };
    try {
      const result = await verifier.verify({ evidence, expected: detached(expected) });
      if (!plain(result)
          || Reflect.ownKeys(result).length !== Reflect.ownKeys(expected).length + 2
          || result.valid !== true || result.result !== 'MATCH'
          || !Object.entries(expected).every(([key, value]) => result[key] === value)) {
        return { ok: false };
      }
      return { ok: true, value: JSON.stringify(result) };
    } catch {
      return { ok: false };
    }
  }

  async function beginInvocation(
    input: AdmissionCas,
    operation: string,
    text: string,
    extraParams: readonly unknown[] = [],
    execute: (
      operation: string,
      text: string,
      params: readonly unknown[],
    ) => Promise<unknown> = rpc,
  ): Promise<AdmissionBeginResult> {
    const cas = validateCas(input);
    assertTenant(cas.tenant_id);
    const generatedInvocation = invocationToken(invocationFactory());
    const generatedDigest = tokenDigest(generatedInvocation);
    try {
      const value = await execute(operation, text, [
        deploymentId,
        tenantId,
        cas.admission_id,
        cas.expected_revision,
        tokenDigest(cas.owner_token),
        generatedDigest,
        ...extraParams,
      ]);
      const result = normalizeResultObject(value, operation);
      if (!result.ok) return detached(result) as AdmissionBeginResult;
      return {
        ok: true,
        snapshot: validateSnapshot(result.snapshot, operation),
        record: validateRecord(result.record, operation, tenantId),
        invocation_token: generatedInvocation,
      };
    } catch (error) {
      // Both begin RPCs atomically commit the admission and any linked program
      // occurrence. Exact admission-token readback therefore proves the whole
      // transaction without retrying provider entry.
      let current: Readonly<AdmissionRecord> | null;
      try {
        current = await read(cas);
      } catch (readError) {
        throw new AdmissionPostgresAmbiguousBeginError(
          cas.admission_id,
          `${operation} acknowledgement and authoritative readback are both unavailable`,
          { cause: readError },
        );
      }
      if (current
          && current.revision === cas.expected_revision + 1
          && current.state === 'INVOKING'
          && current.execution_right === 'CONSUMED'
          && current.provider_attempt === 'INVOKING'
          && current.owner_digest === tokenDigest(cas.owner_token)
          && current.invocation_token_digest === generatedDigest) {
        const snapshot = await readSnapshot(current.snapshot_digest);
        if (!snapshot) {
          throw new AdmissionPostgresAmbiguousBeginError(
            cas.admission_id,
            `${operation} committed but its authoritative snapshot is unavailable`,
            { cause: error },
          );
        }
        return {
          ok: true,
          snapshot,
          record: current,
          invocation_token: generatedInvocation,
        };
      }
      if (current
          && current.revision === cas.expected_revision
          && current.state === 'RESERVED'
          && current.execution_right === 'RESERVED') {
        throw error;
      }
      throw new AdmissionPostgresAmbiguousBeginError(
        cas.admission_id,
        `${operation} outcome is not provably attributable to this invocation token`,
        { cause: error },
      );
    }
  }

  const store: AdmissionPostgresStore = {
    durable: true,
    atomic: true,
    compareAndSwap: true,
    appendOnlyJournal: true,
    exclusiveActuation: true,
    transactionalCurrentness: true,
    guaranteeClass: 'local_atomic',
    singleTenant: true,
    deploymentBound: true,
    managedTenantPrincipalMapping: false,
    maxTransactionRetries,

    async reserve(raw): Promise<AdmissionReserveResult> {
      const snapshot = plain(raw) && Object.hasOwn(raw, 'snapshot_digest')
        ? validateSnapshot(raw, 'admission reserve input')
        : createAdmissionSnapshot(raw as AdmissionSnapshotInput);
      assertTenant(snapshot.body.tenant_id);
      const generatedOwner = ownerToken(ownerFactory());
      const value = await rpc('admission reserve', ADMISSION_POSTGRES_SQL.reserve, [
        deploymentId,
        tenantId,
        JSON.stringify(snapshot),
        tokenDigest(generatedOwner),
      ]);
      const result = normalizeResultObject(value, 'admission reserve');
      if (!result.ok) return detached(result) as AdmissionReserveResult;
      return {
        ok: true,
        snapshot: validateSnapshot(result.snapshot, 'admission reserve'),
        record: validateRecord(result.record, 'admission reserve', tenantId),
        owner_token: generatedOwner,
      };
    },

    async release(input, reason = 'released_before_invocation'): Promise<AdmissionTransitionResult> {
      const cas = validateCas(input);
      assertTenant(cas.tenant_id);
      return transitionResult(await rpc('admission release', ADMISSION_POSTGRES_SQL.release, [
        deploymentId,
        tenantId,
        cas.admission_id,
        cas.expected_revision,
        tokenDigest(cas.owner_token),
        reason,
      ]), 'admission release');
    },

    async expire(input): Promise<AdmissionTransitionResult> {
      const cas = validateCas(input);
      assertTenant(cas.tenant_id);
      return transitionResult(await rpc('admission expire', ADMISSION_POSTGRES_SQL.expire, [
        deploymentId,
        tenantId,
        cas.admission_id,
        cas.expected_revision,
        tokenDigest(cas.owner_token),
      ]), 'admission expire');
    },

    async reapExpiredReservation(
      input: AdmissionExpiredRecoveryInput,
    ): Promise<AdmissionTransitionResult> {
      const reference = validateReference(input);
      assertTenant(reference.tenant_id);
      const expectedRevision = revision(input.expected_revision);
      return transitionResult(await rpc(
        'admission reap expired reservation',
        ADMISSION_POSTGRES_SQL.reapExpiredReservation,
        [deploymentId, tenantId, reference.admission_id, expectedRevision],
      ), 'admission reap expired reservation');
    },

    async supersede(input: AdmissionSupersedeInput): Promise<AdmissionSupersedeResult> {
      const cas = validateCas(input);
      assertTenant(cas.tenant_id);
      const successor = createAdmissionSnapshot({
        ...input.successor,
        supersedes_admission_id: cas.admission_id,
        remedy_for: null,
      });
      assertTenant(successor.body.tenant_id);
      const successorOwner = ownerToken(ownerFactory());
      const value = await rpc('admission supersede', ADMISSION_POSTGRES_SQL.supersede, [
        deploymentId,
        tenantId,
        cas.admission_id,
        cas.expected_revision,
        tokenDigest(cas.owner_token),
        JSON.stringify(successor),
        tokenDigest(successorOwner),
      ]);
      const result = normalizeResultObject(value, 'admission supersede');
      if (!result.ok) return detached(result) as AdmissionSupersedeResult;
      return {
        ok: true,
        predecessor_record: validateRecord(
          result.predecessor_record,
          'admission supersede predecessor',
          tenantId,
        ),
        successor_snapshot: validateSnapshot(
          result.successor_snapshot,
          'admission supersede successor',
        ),
        successor_record: validateRecord(
          result.successor_record,
          'admission supersede successor',
          tenantId,
        ),
        successor_owner_token: successorOwner,
      };
    },

    beginInvocation(input): Promise<AdmissionBeginResult> {
      return beginInvocation(
        input,
        'admission begin invocation',
        ADMISSION_POSTGRES_SQL.beginInvocation,
      );
    },

    async recoverIndeterminate(input: AdmissionRecoveryInput): Promise<AdmissionRecoveryResult> {
      const reference = validateReference(input);
      assertTenant(reference.tenant_id);
      const recoveryOwner = ownerToken(input.owner_token);
      const reconciliationToken = invocationToken(invocationFactory());
      const value = await rpc(
        'admission recover indeterminate',
        ADMISSION_POSTGRES_SQL.recoverIndeterminate,
        [
          deploymentId,
          tenantId,
          reference.admission_id,
          tokenDigest(recoveryOwner),
          tokenDigest(reconciliationToken),
        ],
      );
      const result = normalizeResultObject(value, 'admission recover indeterminate');
      if (!result.ok) return detached(result) as AdmissionRecoveryResult;
      const record = validateRecord(
        result.record,
        'admission recover indeterminate',
        tenantId,
      );
      if (record.invocation_token_digest !== tokenDigest(reconciliationToken)) {
        throw new AdmissionPostgresProtocolError(
          'admission recover indeterminate: reconciliation token digest mismatch',
        );
      }
      return { ok: true, record, reconciliation_token: reconciliationToken };
    },

    async recordProviderOutcome(input: AdmissionProviderOutcomeInput): Promise<AdmissionTransitionResult> {
      const cas = validateCas(input);
      assertTenant(cas.tenant_id);
      const token = invocationToken(input.invocation_token);
      const evidence = input.evidence_digest === null
        ? null
        : digest(input.evidence_digest, 'evidence_digest');
      const observed = instant(input.observed_at, 'observed_at');
      return transitionResult(await rpc(
        'admission provider outcome',
        ADMISSION_POSTGRES_SQL.recordProviderOutcome,
        [
          deploymentId,
          tenantId,
          cas.admission_id,
          cas.expected_revision,
          tokenDigest(cas.owner_token),
          tokenDigest(token),
          input.value,
          evidence,
          observed,
        ],
      ), 'admission provider outcome');
    },

    async recordEffectRelation(input: AdmissionEffectRelationInput): Promise<AdmissionTransitionResult> {
      const cas = validateCas(input);
      assertTenant(cas.tenant_id);
      const token = invocationToken(input.invocation_token);
      const evidence = input.evidence_digest === null
        ? null
        : digest(input.evidence_digest, 'evidence_digest');
      const observed = instant(input.observed_at, 'observed_at');
      return transitionResult(await rpc(
        'admission effect relation',
        ADMISSION_POSTGRES_SQL.recordEffectRelation,
        [
          deploymentId,
          tenantId,
          cas.admission_id,
          cas.expected_revision,
          tokenDigest(cas.owner_token),
          tokenDigest(token),
          input.value,
          evidence,
          observed,
        ],
      ), 'admission effect relation');
    },

    async registerExecutionProgram(
      artifact: unknown,
      context: ExecutionProgramRegistrationContext,
    ): Promise<ExecutionProgramRegistrationResult> {
      const normalizedContext = registrationContext(context);
      if (!normalizedContext) return { ok: false, reason: 'context_binding_required' };
      const keyId = plain(artifact) && plain(artifact.issuer)
        && typeof artifact.issuer.key_id === 'string' ? artifact.issuer.key_id : '';
      const verified = verifyBoundedExecutionProgram(artifact, {
        ...normalizedContext,
        expected_authorizer_id: programTrust.activeAuthorizers.get(keyId) ?? '',
        trusted_keys: programTrust.trustedKeys,
        now: currentMs(options.now),
      });
      if (!verified.accepted || !verified.program || !verified.program_digest) {
        return { ok: false, reason: verified.reason as ExecutionProgramRefusalReason };
      }
      assertTenant(verified.program.tenant_id);
      if (verified.program.version !== 1 || verified.program.supersedes_program_digest !== null) {
        return { ok: false, reason: 'program_supersession_invalid' };
      }
      const value = await verifierRpc(
        'execution program register',
        ADMISSION_POSTGRES_SQL.registerExecutionProgram,
        [
          deploymentId,
          tenantId,
          verified.program_digest,
          JSON.stringify(artifact),
          JSON.stringify(verified.program),
          verified.authorizer_id,
        ],
      );
      const result = normalizeResultObject(value, 'execution program register');
      if (!result.ok) return detached(result) as ExecutionProgramRegistrationResult;
      return {
        ok: true,
        program: validateExecutionProgramRuntime(
          result.program,
          'execution program register',
          tenantId,
          verified.program_digest,
          verified.program,
        ),
      };
    },

    async reserveExecutionProgramAdmission(
      input: ExecutionProgramReserveInput,
    ): Promise<ExecutionProgramReserveResult> {
      const programDigest = digest(input.program_digest, 'program_digest');
      const nodeId = identifier(input.node_id, 'node_id');
      const occurrenceId = identifier(input.occurrence_id, 'occurrence_id');
      const prebuilt = plain(input.admission) && Object.hasOwn(input.admission, 'snapshot_digest');
      const initialSnapshot = prebuilt
        ? validateSnapshot(input.admission, 'execution program admission input')
        : createAdmissionSnapshot(input.admission as AdmissionSnapshotInput);
      assertTenant(initialSnapshot.body.tenant_id);
      const program = await readProgram(programDigest);
      if (!program) return { ok: false, reason: 'program_not_found' };
      const statusPayload = await programStatusPayload(program);
      const matched = await programActionMatch(
        program,
        nodeId,
        initialSnapshot,
        input.action_match_evidence,
      );
      if (!matched.ok) return { ok: false, reason: 'program_binding_mismatch' };
      if (Date.parse(initialSnapshot.body.expires_at) > Date.parse(program.program.expires_at)) {
        return { ok: false, reason: 'program_expiration_mismatch' };
      }
      const binding = createExecutionProgramAdmissionBinding({
        tenant_id: tenantId,
        program_digest: programDigest,
        node_id: nodeId,
        occurrence_id: occurrenceId,
        expires_at: initialSnapshot.body.expires_at,
      });
      const existing = initialSnapshot.body.resource_reservations.filter(
        (resource) => resource.kind === 'execution_program',
      );
      if (existing.length > 1
          || (existing.length === 1
            && canonical(existing[0] as unknown as Json) !== canonical(binding as unknown as Json))
          || (prebuilt && existing.length === 0)) {
        return { ok: false, reason: 'program_binding_mismatch' };
      }
      let snapshot = initialSnapshot;
      if (existing.length === 0) {
        const { '@version': _version, ...body } = initialSnapshot.body;
        snapshot = createAdmissionSnapshot({
          ...body,
          resource_reservations: [...body.resource_reservations, binding],
        });
      }
      const generatedOwner = ownerToken(ownerFactory());
      const value = await verifierRpc(
        'execution program admission reserve',
        ADMISSION_POSTGRES_SQL.reserveExecutionProgramAdmission,
        [
          deploymentId,
          tenantId,
          programDigest,
          nodeId,
          occurrenceId,
          JSON.stringify(snapshot),
          matched.value,
          tokenDigest(generatedOwner),
          statusPayload,
        ],
      );
      const result = normalizeResultObject(value, 'execution program admission reserve');
      if (!result.ok) return detached(result) as ExecutionProgramReserveResult;
      return {
        ok: true,
        snapshot: validateSnapshot(result.snapshot, 'execution program admission reserve'),
        record: validateRecord(result.record, 'execution program admission reserve', tenantId),
        owner_token: generatedOwner,
      };
    },

    async beginExecutionProgramInvocation(input): Promise<AdmissionBeginResult> {
      const reference = validateCas(input);
      assertTenant(reference.tenant_id);
      const linked = await rpc(
        'execution program read by admission',
        ADMISSION_POSTGRES_SQL.readExecutionProgramByAdmission,
        [deploymentId, tenantId, reference.admission_id],
      );
      const program = linked === null ? null : validateExecutionProgramRuntime(
        linked,
        'execution program read by admission',
        tenantId,
      );
      const statusPayload = program === null ? null : await programStatusPayload(program);
      return beginInvocation(
        input,
        'execution program begin invocation',
        ADMISSION_POSTGRES_SQL.beginExecutionProgramInvocation,
        [statusPayload],
        verifierRpc,
      );
    },

    async releaseExecutionProgramAdmission(
      input: AdmissionCas,
      reason = 'program_released_before_invocation',
    ): Promise<AdmissionTransitionResult> {
      const cas = validateCas(input);
      assertTenant(cas.tenant_id);
      return transitionResult(await rpc(
        'execution program admission release',
        ADMISSION_POSTGRES_SQL.releaseExecutionProgramAdmission,
        [
          deploymentId,
          tenantId,
          cas.admission_id,
          cas.expected_revision,
          tokenDigest(cas.owner_token),
          reason,
        ],
      ), 'execution program admission release');
    },

    async expireExecutionProgramAdmission(input): Promise<AdmissionTransitionResult> {
      const cas = validateCas(input);
      assertTenant(cas.tenant_id);
      return transitionResult(await rpc(
        'execution program admission expire',
        ADMISSION_POSTGRES_SQL.expireExecutionProgramAdmission,
        [
          deploymentId,
          tenantId,
          cas.admission_id,
          cas.expected_revision,
          tokenDigest(cas.owner_token),
        ],
      ), 'execution program admission expire');
    },

    async supersedeExecutionProgram(
      artifact: unknown,
      context: ExecutionProgramRegistrationContext,
    ): Promise<ExecutionProgramRegistrationResult> {
      const normalizedContext = registrationContext(context);
      if (!normalizedContext) return { ok: false, reason: 'context_binding_required' };
      const keyId = plain(artifact) && plain(artifact.issuer)
        && typeof artifact.issuer.key_id === 'string' ? artifact.issuer.key_id : '';
      const verified = verifyBoundedExecutionProgram(artifact, {
        ...normalizedContext,
        expected_authorizer_id: programTrust.activeAuthorizers.get(keyId) ?? '',
        trusted_keys: programTrust.trustedKeys,
        now: currentMs(options.now),
      });
      if (!verified.accepted || !verified.program || !verified.program_digest) {
        return { ok: false, reason: verified.reason as ExecutionProgramRefusalReason };
      }
      assertTenant(verified.program.tenant_id);
      if (verified.program.version < 2 || verified.program.supersedes_program_digest === null) {
        return { ok: false, reason: 'program_supersession_invalid' };
      }
      const value = await verifierRpc(
        'execution program supersede',
        ADMISSION_POSTGRES_SQL.supersedeExecutionProgram,
        [
          deploymentId,
          tenantId,
          verified.program_digest,
          JSON.stringify(artifact),
          JSON.stringify(verified.program),
          verified.authorizer_id,
        ],
      );
      const result = normalizeResultObject(value, 'execution program supersede');
      if (!result.ok) return detached(result) as ExecutionProgramRegistrationResult;
      return {
        ok: true,
        program: validateExecutionProgramRuntime(
          result.program,
          'execution program supersede',
          tenantId,
          verified.program_digest,
          verified.program,
        ),
      };
    },

    async readExecutionProgram(
      input: ExecutionProgramReference,
    ): Promise<Readonly<ExecutionProgramRuntimeState> | null> {
      const reference = {
        tenant_id: identifier(input.tenant_id, 'tenant_id'),
        program_digest: digest(input.program_digest, 'program_digest'),
      };
      assertTenant(reference.tenant_id);
      const value = await rpc(
        'execution program read',
        ADMISSION_POSTGRES_SQL.readExecutionProgram,
        [deploymentId, tenantId, reference.program_digest],
      );
      return value === null ? null : validateExecutionProgramRuntime(
        value,
        'execution program read',
        tenantId,
        reference.program_digest,
      );
    },

    async readExecutionProgramReportSnapshot(
      input: ExecutionProgramReference,
    ): Promise<Readonly<ExecutionProgramReportSnapshot> | null> {
      const reference = {
        tenant_id: identifier(input.tenant_id, 'tenant_id'),
        program_digest: digest(input.program_digest, 'program_digest'),
      };
      assertTenant(reference.tenant_id);
      const value = await rpc(
        'execution program report snapshot read',
        ADMISSION_POSTGRES_SQL.readExecutionProgramReportSnapshot,
        [deploymentId, tenantId, reference.program_digest],
      );
      return value === null ? null : validateExecutionProgramReportSnapshot(
        value,
        'execution program report snapshot read',
        reference,
      );
    },

    async readExecutionProgramOccurrence(input): Promise<Readonly<ExecutionProgramOccurrence> | null> {
      const reference = {
        tenant_id: identifier(input.tenant_id, 'tenant_id'),
        program_digest: digest(input.program_digest, 'program_digest'),
        occurrence_id: identifier(input.occurrence_id, 'occurrence_id'),
      };
      assertTenant(reference.tenant_id);
      const value = await rpc(
        'execution program occurrence read',
        ADMISSION_POSTGRES_SQL.readExecutionProgramOccurrence,
        [deploymentId, tenantId, reference.program_digest, reference.occurrence_id],
      );
      return value === null ? null : validateExecutionProgramOccurrence(
        value,
        'execution program occurrence read',
        reference,
      );
    },

    read,

    async readByOperation(input): Promise<Readonly<AdmissionRecord> | null> {
      const reference = validateOperationReference(input);
      assertTenant(reference.tenant_id);
      const value = await rpc(
        'admission operation read',
        ADMISSION_POSTGRES_SQL.readByOperation,
        [deploymentId, tenantId, reference.operation_id],
      );
      return value === null
        ? null
        : validateRecord(value, 'admission operation read', tenantId);
    },

    readSnapshot,

    async journal(input): Promise<readonly Readonly<AdmissionJournalEntry>[]> {
      const reference = validateReference(input);
      assertTenant(reference.tenant_id);
      const value = await rpc('admission journal', ADMISSION_POSTGRES_SQL.journal, [
        deploymentId,
        tenantId,
        reference.admission_id,
      ]);
      return validateJournal(value, 'admission journal', tenantId, reference.admission_id);
    },

    async checkInvariants(): Promise<AdmissionInvariantCheck> {
      const value = normalizeResultObject(await rpc(
        'admission invariant check',
        ADMISSION_POSTGRES_SQL.checkInvariants,
        [deploymentId, tenantId],
      ), 'admission invariant check');
      if (!Array.isArray(value.violations)
          || value.violations.some((violation) => typeof violation !== 'string')
          || value.ok !== (value.violations.length === 0)) {
        throw new AdmissionPostgresProtocolError('admission invariant check: malformed result');
      }
      return detached(value as unknown as AdmissionInvariantCheck);
    },
  };

  return Object.freeze(store);
}

/** Compatibility alias following the noun-first naming used by some stores. */
export const createPostgresAdmissionStore = createAdmissionPostgresStore;

export default createAdmissionPostgresStore;
