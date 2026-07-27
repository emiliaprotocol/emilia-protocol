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

import {
  ADMISSION_JOURNAL_VERSION,
  ADMISSION_RECORD_VERSION,
  createAdmissionSnapshot,
  verifyAdmissionJournal,
  type AdmissionBeginResult,
  type AdmissionCas,
  type AdmissionDigest,
  type AdmissionEffectRelationInput,
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
  type AdmissionStore,
  type AdmissionSupersedeInput,
  type AdmissionSupersedeResult,
  type AdmissionTransitionResult,
} from './admission-store.js';

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
  query: AdmissionPostgresQuery;
  deploymentId: string;
  tenantId: string;
  /** Test seam only. Production callers should use the cryptographic default. */
  ownerTokenFactory?: () => string;
  /** Test seam only. Production callers should use the cryptographic default. */
  invocationTokenFactory?: () => string;
  /** Number of retries after the first attempt for SQLSTATE 40001/40P01. */
  maxTransactionRetries?: number;
}

export interface AdmissionPostgresStore extends AdmissionStore {
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
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new AdmissionPostgresProtocolError('non-finite JSON number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (!plain(value)) throw new AdmissionPostgresProtocolError('non-plain JSON object');
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonical(value[key] as Json)}`
  )).join(',')}}`;
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
  const deploymentId = identifier(options.deploymentId, 'deploymentId');
  const tenantId = identifier(options.tenantId, 'tenantId');
  const ownerFactory = options.ownerTokenFactory ?? defaultOwnerToken;
  const invocationFactory = options.invocationTokenFactory ?? defaultInvocationToken;
  const maxTransactionRetries = options.maxTransactionRetries ?? 3;
  if (!Number.isSafeInteger(maxTransactionRetries)
      || maxTransactionRetries < 0
      || maxTransactionRetries > 16) {
    throw new TypeError('maxTransactionRetries must be an integer from 0 through 16');
  }

  function assertTenant(value: string): void {
    if (value !== tenantId) throw new TypeError('tenant_id does not match the deployment binding');
  }

  async function rpc(
    operation: string,
    text: string,
    params: readonly unknown[],
  ): Promise<unknown> {
    for (let attempt = 0; ; attempt += 1) {
      try {
        const result = await query(text, params);
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

    async beginInvocation(input): Promise<AdmissionBeginResult> {
      const cas = validateCas(input);
      assertTenant(cas.tenant_id);
      const generatedInvocation = invocationToken(invocationFactory());
      const generatedDigest = tokenDigest(generatedInvocation);
      try {
        const value = await rpc(
          'admission begin invocation',
          ADMISSION_POSTGRES_SQL.beginInvocation,
          [
            deploymentId,
            tenantId,
            cas.admission_id,
            cas.expected_revision,
            tokenDigest(cas.owner_token),
            generatedDigest,
          ],
        );
        const result = normalizeResultObject(value, 'admission begin invocation');
        if (!result.ok) return detached(result) as AdmissionBeginResult;
        return {
          ok: true,
          snapshot: validateSnapshot(result.snapshot, 'admission begin invocation'),
          record: validateRecord(result.record, 'admission begin invocation', tenantId),
          invocation_token: generatedInvocation,
        };
      } catch (error) {
        // The write acknowledgement can be lost after commit.  Only the exact
        // token digest generated above can turn readback into a successful begin.
        let current: Readonly<AdmissionRecord> | null;
        try {
          current = await read(cas);
        } catch (readError) {
          throw new AdmissionPostgresAmbiguousBeginError(
            cas.admission_id,
            'beginInvocation acknowledgement and authoritative readback are both unavailable',
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
              'beginInvocation committed but its authoritative snapshot is unavailable',
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
          'beginInvocation outcome is not provably attributable to this invocation token',
          { cause: error },
        );
      }
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
