// SPDX-License-Identifier: Apache-2.0
/**
 * Open Exposure Ledger v1.
 *
 * The ledger reserves fixed minor-unit exposure before provider entry. A
 * reservation remains open while RESERVED, INVOKING, or INDETERMINATE and can
 * be closed only by a separately authenticated reconciliation authority. The
 * in-memory implementation is a linearizable conformance/reference store; it
 * is not a durability claim.
 */

import crypto from 'node:crypto';

export const OPEN_EXPOSURE_LEDGER_VERSION = 'EP-OPEN-EXPOSURE-LEDGER-v1';
export const OPEN_EXPOSURE_HISTORY_VERSION = 'EP-OPEN-EXPOSURE-HISTORY-v1';

export type OpenExposureRole =
  | 'POLICY_ADMIN'
  | 'ORIGIN'
  | 'EXECUTOR'
  | 'RECONCILER'
  | 'READER';

export interface OpenExposureAuth {
  role: OpenExposureRole;
  authorityId: string;
  credential: string;
}

export type OpenExposureCeilingScope =
  | 'TENANT'
  | 'PROGRAM'
  | 'COUNTERPARTY'
  | 'ACTION_CLASS';

export interface OpenExposureCeilingInput {
  tenantId: string;
  ceilingId: string;
  scope: OpenExposureCeilingScope;
  scopeValue: string;
  currency: string;
  windowStart: string;
  windowEnd: string;
  limitMinor: bigint;
  policyDigest: string;
}

export interface OpenExposureCeiling extends OpenExposureCeilingInput {
  '@version': typeof OPEN_EXPOSURE_LEDGER_VERSION;
  ceilingDigest: string;
}

export interface OpenExposureReserveInput {
  tenantId: string;
  exposureId: string;
  operationToken: string;
  programId: string;
  counterpartyId: string;
  actionClass: string;
  amountMinor: bigint;
  currency: string;
  windowStart: string;
  windowEnd: string;
  reservedAt: string;
  invokeBy: string;
  reconcileBy: string;
  originAuthorityId: string;
  executorAuthorityId: string;
  reconciliationAuthorityId: string;
  reservationEvidenceDigest: string;
}

export type OpenExposureStatus =
  | 'RESERVED'
  | 'INVOKING'
  | 'INDETERMINATE'
  | 'CLOSED_COMMITTED'
  | 'CLOSED_PROVEN_NOT_COMMITTED';

export type OpenExposureReconciliationOutcome =
  | 'COMMITTED'
  | 'PROVEN_NOT_COMMITTED'
  | 'INDETERMINATE';

export interface OpenExposureRecord {
  '@version': typeof OPEN_EXPOSURE_LEDGER_VERSION;
  tenantId: string;
  exposureId: string;
  operationTokenDigest: string;
  reservationDigest: string;
  programId: string;
  counterpartyId: string;
  actionClass: string;
  amountMinor: bigint;
  currency: string;
  windowStart: string;
  windowEnd: string;
  reservedAt: string;
  invokeBy: string;
  reconcileBy: string;
  originAuthorityId: string;
  executorAuthorityId: string;
  reconciliationAuthorityId: string;
  reservationEvidenceDigest: string;
  ceilingDigests: readonly string[];
  revision: number;
  status: OpenExposureStatus;
  invokedAt: string | null;
  indeterminateEvidenceDigest: string | null;
  reconciliationOutcome: OpenExposureReconciliationOutcome | null;
  reconciliationEvidenceDigest: string | null;
  lastChangedAt: string;
  predecessorRecordDigest: string | null;
  recordDigest: string;
}

export type OpenExposureHistoryEvent =
  | 'RESERVED'
  | 'INVOKING'
  | 'INDETERMINATE'
  | 'RECONCILED_INDETERMINATE'
  | 'CLOSED_COMMITTED'
  | 'CLOSED_PROVEN_NOT_COMMITTED';

export interface OpenExposureHistoryEntry {
  '@version': typeof OPEN_EXPOSURE_HISTORY_VERSION;
  tenantId: string;
  exposureId: string;
  sequence: number;
  event: OpenExposureHistoryEvent;
  recordDigest: string;
  evidenceDigest: string;
  recordedAt: string;
  predecessorEntryDigest: string | null;
  entryDigest: string;
}

export type OpenExposureRefusalReason =
  | 'unauthenticated'
  | 'wrong_authority'
  | 'authority_separation_required'
  | 'ceiling_not_configured'
  | 'ceiling_exceeded'
  | 'ceiling_id_conflict'
  | 'ceiling_scope_conflict'
  | 'exposure_exists'
  | 'exposure_not_found'
  | 'operation_token_conflict'
  | 'reconciliation_token_conflict'
  | 'state_conflict'
  | 'reconciliation_required'
  | 'already_closed';

export type OpenExposureRefusal = {
  ok: false;
  reason: OpenExposureRefusalReason;
};

export type OpenExposureCeilingResult =
  | { ok: true; ceiling: Readonly<OpenExposureCeiling>; replayed: boolean }
  | OpenExposureRefusal;

export type OpenExposureRecordResult =
  | { ok: true; record: Readonly<OpenExposureRecord>; replayed: boolean }
  | OpenExposureRefusal;

export interface OpenExposureReference {
  tenantId: string;
  exposureId: string;
}

export interface OpenExposureBeginInput extends OpenExposureReference {
  operationToken: string;
  invokedAt: string;
}

export interface OpenExposureIndeterminateInput extends OpenExposureReference {
  operationToken: string;
  evidenceDigest: string;
  observedAt: string;
}

export interface OpenExposureReconciliationInput extends OpenExposureReference {
  operationToken: string;
  reconciliationToken: string;
  outcome: OpenExposureReconciliationOutcome;
  evidenceDigest: string;
  observedAt: string;
}

export interface OpenExposureSumInput {
  tenantId: string;
  currency: string;
  windowStart: string;
  windowEnd: string;
  programId?: string;
  counterpartyId?: string;
  actionClass?: string;
}

export interface OpenExposureBreakdown {
  key: string;
  amountMinor: bigint;
}

export type OpenExposureReadResult =
  | { ok: true; record: Readonly<OpenExposureRecord> | null }
  | OpenExposureRefusal;

export type OpenExposureHistoryResult =
  | { ok: true; entries: readonly Readonly<OpenExposureHistoryEntry>[] }
  | OpenExposureRefusal;

export type OpenExposureSumResult =
  | {
      ok: true;
      totalMinor: bigint;
      byProgram: readonly Readonly<OpenExposureBreakdown>[];
      byCounterparty: readonly Readonly<OpenExposureBreakdown>[];
      byActionClass: readonly Readonly<OpenExposureBreakdown>[];
      byStatus: readonly Readonly<OpenExposureBreakdown>[];
    }
  | OpenExposureRefusal;

export interface OpenExposureAgingInput {
  tenantId: string;
  asOf: string;
  minimumAgeMs: number;
  limit: number;
}

export interface OpenExposureDeadlineInput {
  tenantId: string;
  dueAtOrBefore: string;
  limit: number;
}

export type OpenExposureListResult =
  | { ok: true; records: readonly Readonly<OpenExposureRecord>[] }
  | OpenExposureRefusal;

export interface OpenExposureAuthenticationInput {
  tenantId: string;
  auth: Readonly<OpenExposureAuth>;
}

export interface CreateMemoryOpenExposureLedgerOptions {
  authenticate: (
    input: Readonly<OpenExposureAuthenticationInput>,
  ) => boolean | Promise<boolean>;
}

export interface OpenExposureLedger {
  readonly durable: boolean;
  readonly atomicReserve: true;
  readonly appendOnlyHistory: true;
  readonly blindRelease: false;
  readonly reconciliationOnlyCloseout: true;
  readonly testOnly?: true;
  registerCeiling(
    input: OpenExposureCeilingInput,
    auth: OpenExposureAuth,
  ): Promise<OpenExposureCeilingResult>;
  reserve(
    input: OpenExposureReserveInput,
    auth: OpenExposureAuth,
  ): Promise<OpenExposureRecordResult>;
  beginInvocation(
    input: OpenExposureBeginInput,
    auth: OpenExposureAuth,
  ): Promise<OpenExposureRecordResult>;
  markIndeterminate(
    input: OpenExposureIndeterminateInput,
    auth: OpenExposureAuth,
  ): Promise<OpenExposureRecordResult>;
  reconcile(
    input: OpenExposureReconciliationInput,
    auth: OpenExposureAuth,
  ): Promise<OpenExposureRecordResult>;
  read(
    input: OpenExposureReference,
    auth: OpenExposureAuth,
  ): Promise<OpenExposureReadResult>;
  history(
    input: OpenExposureReference,
    auth: OpenExposureAuth,
  ): Promise<OpenExposureHistoryResult>;
  sumOpen(
    input: OpenExposureSumInput,
    auth: OpenExposureAuth,
  ): Promise<OpenExposureSumResult>;
  listAging(
    input: OpenExposureAgingInput,
    auth: OpenExposureAuth,
  ): Promise<OpenExposureListResult>;
  listDeadlines(
    input: OpenExposureDeadlineInput,
    auth: OpenExposureAuth,
  ): Promise<OpenExposureListResult>;
}

export class OpenExposureValidationError extends TypeError {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'OpenExposureValidationError';
    this.code = code;
  }
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{0,511}$/;
const CURRENCY = /^[A-Z]{3}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const OPERATION_TOKEN = /^open-exposure-op:v1:[A-Za-z0-9_-]{32,128}$/;
const RECONCILIATION_TOKEN = /^open-exposure-reconcile:v1:[A-Za-z0-9_-]{32,128}$/;
const OPEN_STATUSES = new Set<OpenExposureStatus>([
  'RESERVED', 'INVOKING', 'INDETERMINATE',
]);
const SCOPES: readonly OpenExposureCeilingScope[] = [
  'TENANT', 'PROGRAM', 'COUNTERPARTY', 'ACTION_CLASS',
];

type Jsonish = null | boolean | number | bigint | string | Jsonish[] | {
  [key: string]: Jsonish;
};

function fail(code: string, message: string): never {
  throw new OpenExposureValidationError(code, message);
}

function canonical(value: Jsonish): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('invalid_number', 'numbers must be finite');
    return JSON.stringify(value);
  }
  if (typeof value === 'bigint') return JSON.stringify({ '@bigint': value.toString(10) });
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail('invalid_object', 'values must be plain objects');
  }
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonical(value[key] as Jsonish)}`
  )).join(',')}}`;
}

function digest(domain: string, value: unknown): string {
  return `sha256:${crypto.createHash('sha256')
    .update(domain)
    .update('\0')
    .update(canonical(value as Jsonish))
    .digest('hex')}`;
}

function frozenCopy<T>(value: T): Readonly<T> {
  return deepFreeze(structuredClone(value));
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function identifier(value: unknown, field: string): asserts value is string {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    fail('invalid_identifier', `${field} is invalid`);
  }
}

function sha256(value: unknown, field: string): asserts value is string {
  if (typeof value !== 'string' || !SHA256.test(value)) {
    fail('invalid_digest', `${field} must be a sha256 digest`);
  }
}

function instant(value: unknown, field: string): number {
  if (typeof value !== 'string') fail('invalid_time', `${field} must be an RFC3339 instant`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    fail('invalid_time', `${field} must be a canonical millisecond UTC instant`);
  }
  return parsed;
}

function positiveBigInt(value: unknown, field: string): asserts value is bigint {
  if (typeof value !== 'bigint' || value <= 0n || value > 9_223_372_036_854_775_807n) {
    fail('invalid_amount', `${field} must be a positive signed 64-bit bigint`);
  }
}

function nonNegativeBigInt(value: unknown, field: string): asserts value is bigint {
  if (typeof value !== 'bigint' || value < 0n || value > 9_223_372_036_854_775_807n) {
    fail('invalid_amount', `${field} must be a non-negative signed 64-bit bigint`);
  }
}

function validateAuth(auth: OpenExposureAuth): void {
  if (!auth || !['POLICY_ADMIN', 'ORIGIN', 'EXECUTOR', 'RECONCILER', 'READER'].includes(auth.role)) {
    fail('invalid_auth', 'auth role is invalid');
  }
  identifier(auth.authorityId, 'auth.authorityId');
  if (typeof auth.credential !== 'string' || auth.credential.length < 1 || auth.credential.length > 4096) {
    fail('invalid_auth', 'auth credential is invalid');
  }
}

function validateWindow(windowStart: string, windowEnd: string): void {
  if (instant(windowStart, 'windowStart') >= instant(windowEnd, 'windowEnd')) {
    fail('invalid_window', 'windowStart must precede windowEnd');
  }
}

function validateCeiling(input: OpenExposureCeilingInput): void {
  identifier(input.tenantId, 'tenantId');
  identifier(input.ceilingId, 'ceilingId');
  if (!SCOPES.includes(input.scope)) fail('invalid_scope', 'ceiling scope is invalid');
  if (!(input.scope === 'TENANT' && input.scopeValue === '*')) {
    identifier(input.scopeValue, 'scopeValue');
  }
  if (input.scope === 'TENANT' && input.scopeValue !== '*') {
    fail('invalid_scope', 'TENANT scopeValue must be *');
  }
  if (input.scope !== 'TENANT' && input.scopeValue === '*') {
    fail('invalid_scope', 'non-tenant scopeValue cannot be *');
  }
  if (!CURRENCY.test(input.currency)) fail('invalid_currency', 'currency must be ISO-like uppercase ASCII');
  validateWindow(input.windowStart, input.windowEnd);
  nonNegativeBigInt(input.limitMinor, 'limitMinor');
  sha256(input.policyDigest, 'policyDigest');
}

function validateReservation(input: OpenExposureReserveInput): void {
  for (const [field, value] of Object.entries({
    tenantId: input.tenantId,
    exposureId: input.exposureId,
    programId: input.programId,
    counterpartyId: input.counterpartyId,
    actionClass: input.actionClass,
    originAuthorityId: input.originAuthorityId,
    executorAuthorityId: input.executorAuthorityId,
    reconciliationAuthorityId: input.reconciliationAuthorityId,
  })) identifier(value, field);
  if (!OPERATION_TOKEN.test(input.operationToken)) fail('invalid_operation_token', 'operationToken is invalid');
  positiveBigInt(input.amountMinor, 'amountMinor');
  if (!CURRENCY.test(input.currency)) fail('invalid_currency', 'currency must be ISO-like uppercase ASCII');
  validateWindow(input.windowStart, input.windowEnd);
  const reservedAt = instant(input.reservedAt, 'reservedAt');
  const invokeBy = instant(input.invokeBy, 'invokeBy');
  const reconcileBy = instant(input.reconcileBy, 'reconcileBy');
  if (reservedAt < instant(input.windowStart, 'windowStart')
      || reservedAt >= instant(input.windowEnd, 'windowEnd')) {
    fail('invalid_time', 'reservedAt must be inside the ceiling window');
  }
  if (invokeBy < reservedAt || reconcileBy < invokeBy) {
    fail('invalid_time', 'deadlines must be monotonic');
  }
  sha256(input.reservationEvidenceDigest, 'reservationEvidenceDigest');
}

function validateReference(input: OpenExposureReference): void {
  identifier(input.tenantId, 'tenantId');
  identifier(input.exposureId, 'exposureId');
}

function tokenDigest(token: string): string {
  return digest('EP-OPEN-EXPOSURE-TOKEN-v1', token);
}

function key(...parts: string[]): string {
  return parts.join('\u0000');
}

function ceilingScopeValue(input: OpenExposureReserveInput, scope: OpenExposureCeilingScope): string {
  if (scope === 'TENANT') return '*';
  if (scope === 'PROGRAM') return input.programId;
  if (scope === 'COUNTERPARTY') return input.counterpartyId;
  return input.actionClass;
}

function ceilingScopeKey(input: OpenExposureCeilingInput): string {
  return key(
    input.tenantId,
    input.scope,
    input.scopeValue,
    input.currency,
    input.windowStart,
    input.windowEnd,
  );
}

function recordBody(record: Omit<OpenExposureRecord, 'recordDigest'>): Omit<OpenExposureRecord, 'recordDigest'> {
  return record;
}

function makeRecord(body: Omit<OpenExposureRecord, 'recordDigest'>): Readonly<OpenExposureRecord> {
  return frozenCopy({
    ...body,
    recordDigest: digest('EP-OPEN-EXPOSURE-RECORD-v1', recordBody(body)),
  });
}

function isOpen(record: OpenExposureRecord): boolean {
  return OPEN_STATUSES.has(record.status);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function addBreakdown(
  source: ReadonlyMap<string, bigint>,
): readonly Readonly<OpenExposureBreakdown>[] {
  return frozenCopy([...source.entries()]
    .sort(([left], [right]) => compareText(left, right))
    .map(([breakdownKey, amountMinor]) => ({ key: breakdownKey, amountMinor })));
}

export function createMemoryOpenExposureLedger(
  options: CreateMemoryOpenExposureLedgerOptions,
): OpenExposureLedger {
  if (!options || typeof options.authenticate !== 'function') {
    fail('authenticator_required', 'authenticate is required');
  }

  const ceilingsById = new Map<string, Readonly<OpenExposureCeiling>>();
  const ceilingsByScope = new Map<string, Readonly<OpenExposureCeiling>>();
  const records = new Map<string, Readonly<OpenExposureRecord>>();
  const operations = new Map<string, {
    reservationDigest: string;
    record: Readonly<OpenExposureRecord>;
  }>();
  const histories = new Map<string, Readonly<OpenExposureHistoryEntry>[]>();
  const reconciliationTokens = new Map<string, {
    requestDigest: string;
    record: Readonly<OpenExposureRecord>;
  }>();
  let mutexTail: Promise<void> = Promise.resolve();

  async function exclusive<T>(operation: () => T | Promise<T>): Promise<T> {
    let release!: () => void;
    const mine = new Promise<void>((resolve) => { release = resolve; });
    const previous = mutexTail;
    mutexTail = mine;
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  async function authenticated(
    tenantId: string,
    auth: OpenExposureAuth,
    expectedRole?: OpenExposureRole,
    expectedAuthority?: string,
  ): Promise<OpenExposureRefusal | null> {
    validateAuth(auth);
    let accepted = false;
    try {
      accepted = await options.authenticate(frozenCopy({ tenantId, auth }));
    } catch {
      accepted = false;
    }
    if (!accepted) return { ok: false, reason: 'unauthenticated' };
    if ((expectedRole && auth.role !== expectedRole)
        || (expectedAuthority && auth.authorityId !== expectedAuthority)) {
      return { ok: false, reason: 'wrong_authority' };
    }
    return null;
  }

  function appendHistory(
    record: Readonly<OpenExposureRecord>,
    event: OpenExposureHistoryEvent,
    evidenceDigest: string,
    recordedAt: string,
  ): void {
    const recordKey = key(record.tenantId, record.exposureId);
    const existing = histories.get(recordKey) ?? [];
    const predecessor = existing.at(-1)?.entryDigest ?? null;
    const body = {
      '@version': OPEN_EXPOSURE_HISTORY_VERSION,
      tenantId: record.tenantId,
      exposureId: record.exposureId,
      sequence: existing.length,
      event,
      recordDigest: record.recordDigest,
      evidenceDigest,
      recordedAt,
      predecessorEntryDigest: predecessor,
    } as const;
    const entry = frozenCopy({
      ...body,
      entryDigest: digest('EP-OPEN-EXPOSURE-HISTORY-ENTRY-v1', body),
    });
    histories.set(recordKey, [...existing, entry]);
  }

  function replaceRecord(
    current: Readonly<OpenExposureRecord>,
    update: Partial<Omit<OpenExposureRecord,
      '@version' | 'tenantId' | 'exposureId' | 'operationTokenDigest'
      | 'reservationDigest' | 'programId' | 'counterpartyId' | 'actionClass'
      | 'amountMinor' | 'currency' | 'windowStart' | 'windowEnd' | 'reservedAt'
      | 'invokeBy' | 'reconcileBy' | 'originAuthorityId' | 'executorAuthorityId'
      | 'reconciliationAuthorityId' | 'reservationEvidenceDigest'
      | 'ceilingDigests' | 'recordDigest'>>,
  ): Readonly<OpenExposureRecord> {
    const { recordDigest: predecessorRecordDigest, ...body } = current;
    return makeRecord({
      ...body,
      ...update,
      revision: current.revision + 1,
      predecessorRecordDigest,
    });
  }

  function recordFor(input: OpenExposureReference): Readonly<OpenExposureRecord> | null {
    return records.get(key(input.tenantId, input.exposureId)) ?? null;
  }

  function operationMatches(record: OpenExposureRecord, operationToken: string): boolean {
    return record.operationTokenDigest === tokenDigest(operationToken);
  }

  return {
    durable: false,
    atomicReserve: true,
    appendOnlyHistory: true,
    blindRelease: false,
    reconciliationOnlyCloseout: true,
    testOnly: true,

    async registerCeiling(input, auth) {
      validateCeiling(input);
      const denied = await authenticated(input.tenantId, auth, 'POLICY_ADMIN');
      if (denied) return denied;
      return exclusive(() => {
        const idKey = key(input.tenantId, input.ceilingId);
        const scopeKey = ceilingScopeKey(input);
        const body = {
          '@version': OPEN_EXPOSURE_LEDGER_VERSION,
          ...structuredClone(input),
        } as const;
        const candidate = frozenCopy({
          ...body,
          ceilingDigest: digest('EP-OPEN-EXPOSURE-CEILING-v1', body),
        });
        const byId = ceilingsById.get(idKey);
        if (byId) {
          return byId.ceilingDigest === candidate.ceilingDigest
            ? { ok: true as const, ceiling: byId, replayed: true }
            : { ok: false as const, reason: 'ceiling_id_conflict' as const };
        }
        const byScope = ceilingsByScope.get(scopeKey);
        if (byScope) {
          return byScope.ceilingDigest === candidate.ceilingDigest
            ? { ok: true as const, ceiling: byScope, replayed: true }
            : { ok: false as const, reason: 'ceiling_scope_conflict' as const };
        }
        ceilingsById.set(idKey, candidate);
        ceilingsByScope.set(scopeKey, candidate);
        return { ok: true as const, ceiling: candidate, replayed: false };
      });
    },

    async reserve(input, auth) {
      validateReservation(input);
      const denied = await authenticated(
        input.tenantId, auth, 'ORIGIN', input.originAuthorityId,
      );
      if (denied) return denied;
      if (new Set([
        input.originAuthorityId,
        input.executorAuthorityId,
        input.reconciliationAuthorityId,
      ]).size !== 3) {
        return { ok: false, reason: 'authority_separation_required' };
      }

      const operationTokenDigest = tokenDigest(input.operationToken);
      const { operationToken: _operationToken, ...reservationInput } = structuredClone(input);
      const reservationBody = { ...reservationInput, operationTokenDigest };
      const reservationDigest = digest('EP-OPEN-EXPOSURE-RESERVATION-v1', reservationBody);

      return exclusive(() => {
        const operationKey = key(input.tenantId, operationTokenDigest);
        const existingOperation = operations.get(operationKey);
        if (existingOperation) {
          return existingOperation.reservationDigest === reservationDigest
            ? { ok: true as const, record: existingOperation.record, replayed: true }
            : { ok: false as const, reason: 'operation_token_conflict' as const };
        }
        const recordKey = key(input.tenantId, input.exposureId);
        if (records.has(recordKey)) return { ok: false, reason: 'exposure_exists' } as const;

        const applicable: Readonly<OpenExposureCeiling>[] = [];
        for (const scope of SCOPES) {
          const configured = ceilingsByScope.get(key(
            input.tenantId,
            scope,
            ceilingScopeValue(input, scope),
            input.currency,
            input.windowStart,
            input.windowEnd,
          ));
          if (!configured) return { ok: false, reason: 'ceiling_not_configured' } as const;
          applicable.push(configured);
        }

        const open = [...records.values()].filter((record) => (
          record.tenantId === input.tenantId
          && record.currency === input.currency
          && record.windowStart === input.windowStart
          && record.windowEnd === input.windowEnd
          && isOpen(record)
        ));
        for (const configured of applicable) {
          const used = open
            .filter((record) => {
              if (configured.scope === 'TENANT') return true;
              if (configured.scope === 'PROGRAM') return record.programId === configured.scopeValue;
              if (configured.scope === 'COUNTERPARTY') return record.counterpartyId === configured.scopeValue;
              return record.actionClass === configured.scopeValue;
            })
            .reduce((sum, record) => sum + record.amountMinor, 0n);
          if (used > configured.limitMinor
              || input.amountMinor > configured.limitMinor - used) {
            return { ok: false, reason: 'ceiling_exceeded' } as const;
          }
        }

        const record = makeRecord({
          '@version': OPEN_EXPOSURE_LEDGER_VERSION,
          tenantId: input.tenantId,
          exposureId: input.exposureId,
          operationTokenDigest,
          reservationDigest,
          programId: input.programId,
          counterpartyId: input.counterpartyId,
          actionClass: input.actionClass,
          amountMinor: input.amountMinor,
          currency: input.currency,
          windowStart: input.windowStart,
          windowEnd: input.windowEnd,
          reservedAt: input.reservedAt,
          invokeBy: input.invokeBy,
          reconcileBy: input.reconcileBy,
          originAuthorityId: input.originAuthorityId,
          executorAuthorityId: input.executorAuthorityId,
          reconciliationAuthorityId: input.reconciliationAuthorityId,
          reservationEvidenceDigest: input.reservationEvidenceDigest,
          ceilingDigests: applicable.map((entry) => entry.ceilingDigest).sort(compareText),
          revision: 0,
          status: 'RESERVED',
          invokedAt: null,
          indeterminateEvidenceDigest: null,
          reconciliationOutcome: null,
          reconciliationEvidenceDigest: null,
          lastChangedAt: input.reservedAt,
          predecessorRecordDigest: null,
        });
        records.set(recordKey, record);
        operations.set(operationKey, { reservationDigest, record });
        appendHistory(record, 'RESERVED', input.reservationEvidenceDigest, input.reservedAt);
        return { ok: true, record, replayed: false } as const;
      });
    },

    async beginInvocation(input, auth) {
      validateReference(input);
      if (!OPERATION_TOKEN.test(input.operationToken)) fail('invalid_operation_token', 'operationToken is invalid');
      instant(input.invokedAt, 'invokedAt');
      const initial = recordFor(input);
      if (!initial) {
        const denied = await authenticated(input.tenantId, auth, 'EXECUTOR');
        return denied ?? { ok: false, reason: 'exposure_not_found' };
      }
      const denied = await authenticated(
        input.tenantId, auth, 'EXECUTOR', initial.executorAuthorityId,
      );
      if (denied) return denied;
      return exclusive(() => {
        const current = recordFor(input);
        if (!current) return { ok: false, reason: 'exposure_not_found' } as const;
        if (!operationMatches(current, input.operationToken)) {
          return { ok: false, reason: 'operation_token_conflict' } as const;
        }
        if (current.status === 'INVOKING') {
          return current.invokedAt === input.invokedAt
            ? { ok: true as const, record: current, replayed: true }
            : { ok: false as const, reason: 'state_conflict' as const };
        }
        if (current.status === 'INDETERMINATE') {
          return { ok: false, reason: 'reconciliation_required' } as const;
        }
        if (!isOpen(current)) return { ok: false, reason: 'already_closed' } as const;
        if (current.status !== 'RESERVED') return { ok: false, reason: 'state_conflict' } as const;
        if (instant(input.invokedAt, 'invokedAt') < instant(current.reservedAt, 'reservedAt')
            || instant(input.invokedAt, 'invokedAt') > instant(current.invokeBy, 'invokeBy')) {
          return { ok: false, reason: 'state_conflict' } as const;
        }
        const next = replaceRecord(current, {
          status: 'INVOKING',
          invokedAt: input.invokedAt,
          lastChangedAt: input.invokedAt,
        });
        records.set(key(input.tenantId, input.exposureId), next);
        appendHistory(next, 'INVOKING', current.reservationEvidenceDigest, input.invokedAt);
        return { ok: true, record: next, replayed: false } as const;
      });
    },

    async markIndeterminate(input, auth) {
      validateReference(input);
      if (!OPERATION_TOKEN.test(input.operationToken)) fail('invalid_operation_token', 'operationToken is invalid');
      sha256(input.evidenceDigest, 'evidenceDigest');
      instant(input.observedAt, 'observedAt');
      const initial = recordFor(input);
      if (!initial) {
        const denied = await authenticated(input.tenantId, auth, 'EXECUTOR');
        return denied ?? { ok: false, reason: 'exposure_not_found' };
      }
      const denied = await authenticated(
        input.tenantId, auth, 'EXECUTOR', initial.executorAuthorityId,
      );
      if (denied) return denied;
      return exclusive(() => {
        const current = recordFor(input);
        if (!current) return { ok: false, reason: 'exposure_not_found' } as const;
        if (!operationMatches(current, input.operationToken)) {
          return { ok: false, reason: 'operation_token_conflict' } as const;
        }
        if (current.status === 'INDETERMINATE') {
          return current.indeterminateEvidenceDigest === input.evidenceDigest
              && current.lastChangedAt === input.observedAt
            ? { ok: true as const, record: current, replayed: true }
            : { ok: false as const, reason: 'state_conflict' as const };
        }
        if (!isOpen(current)) return { ok: false, reason: 'already_closed' } as const;
        if (current.status !== 'INVOKING') return { ok: false, reason: 'state_conflict' } as const;
        if (current.invokedAt && instant(input.observedAt, 'observedAt') < instant(current.invokedAt, 'invokedAt')) {
          return { ok: false, reason: 'state_conflict' } as const;
        }
        const next = replaceRecord(current, {
          status: 'INDETERMINATE',
          indeterminateEvidenceDigest: input.evidenceDigest,
          lastChangedAt: input.observedAt,
        });
        records.set(key(input.tenantId, input.exposureId), next);
        appendHistory(next, 'INDETERMINATE', input.evidenceDigest, input.observedAt);
        return { ok: true, record: next, replayed: false } as const;
      });
    },

    async reconcile(input, auth) {
      validateReference(input);
      if (!OPERATION_TOKEN.test(input.operationToken)) fail('invalid_operation_token', 'operationToken is invalid');
      if (!RECONCILIATION_TOKEN.test(input.reconciliationToken)) {
        fail('invalid_reconciliation_token', 'reconciliationToken is invalid');
      }
      if (!['COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'].includes(input.outcome)) {
        fail('invalid_outcome', 'reconciliation outcome is invalid');
      }
      sha256(input.evidenceDigest, 'evidenceDigest');
      instant(input.observedAt, 'observedAt');
      const initial = recordFor(input);
      if (!initial) {
        const denied = await authenticated(input.tenantId, auth, 'RECONCILER');
        return denied ?? { ok: false, reason: 'exposure_not_found' };
      }
      const denied = await authenticated(
        input.tenantId, auth, 'RECONCILER', initial.reconciliationAuthorityId,
      );
      if (denied) return denied;
      const reconciliationTokenDigest = tokenDigest(input.reconciliationToken);
      const {
        operationToken: _operationToken,
        reconciliationToken: _reconciliationToken,
        ...reconciliationInput
      } = structuredClone(input);
      const requestDigest = digest('EP-OPEN-EXPOSURE-RECONCILIATION-v1', {
        ...reconciliationInput,
        operationTokenDigest: tokenDigest(input.operationToken),
        reconciliationTokenDigest,
      });

      return exclusive(() => {
        const reconciliationKey = key(input.tenantId, reconciliationTokenDigest);
        const prior = reconciliationTokens.get(reconciliationKey);
        if (prior) {
          return prior.requestDigest === requestDigest
            ? { ok: true as const, record: prior.record, replayed: true }
            : { ok: false as const, reason: 'reconciliation_token_conflict' as const };
        }
        const current = recordFor(input);
        if (!current) return { ok: false, reason: 'exposure_not_found' } as const;
        if (!operationMatches(current, input.operationToken)) {
          return { ok: false, reason: 'operation_token_conflict' } as const;
        }
        if (!isOpen(current)) return { ok: false, reason: 'already_closed' } as const;
        if (instant(input.observedAt, 'observedAt') < instant(current.lastChangedAt, 'lastChangedAt')) {
          return { ok: false, reason: 'state_conflict' } as const;
        }
        if (input.outcome === 'COMMITTED' && current.status === 'RESERVED') {
          return { ok: false, reason: 'state_conflict' } as const;
        }
        if (input.outcome === 'INDETERMINATE' && current.status === 'RESERVED') {
          return { ok: false, reason: 'state_conflict' } as const;
        }

        const status: OpenExposureStatus = input.outcome === 'COMMITTED'
          ? 'CLOSED_COMMITTED'
          : input.outcome === 'PROVEN_NOT_COMMITTED'
            ? 'CLOSED_PROVEN_NOT_COMMITTED'
            : 'INDETERMINATE';
        const next = replaceRecord(current, {
          status,
          indeterminateEvidenceDigest: input.outcome === 'INDETERMINATE'
            ? input.evidenceDigest
            : current.indeterminateEvidenceDigest,
          reconciliationOutcome: input.outcome,
          reconciliationEvidenceDigest: input.evidenceDigest,
          lastChangedAt: input.observedAt,
        });
        records.set(key(input.tenantId, input.exposureId), next);
        const event: OpenExposureHistoryEvent = input.outcome === 'COMMITTED'
          ? 'CLOSED_COMMITTED'
          : input.outcome === 'PROVEN_NOT_COMMITTED'
            ? 'CLOSED_PROVEN_NOT_COMMITTED'
            : 'RECONCILED_INDETERMINATE';
        appendHistory(next, event, input.evidenceDigest, input.observedAt);
        reconciliationTokens.set(reconciliationKey, { requestDigest, record: next });
        return { ok: true, record: next, replayed: false } as const;
      });
    },

    async read(input, auth) {
      validateReference(input);
      const denied = await authenticated(input.tenantId, auth);
      if (denied) return denied;
      return { ok: true, record: recordFor(input) };
    },

    async history(input, auth) {
      validateReference(input);
      const denied = await authenticated(input.tenantId, auth);
      if (denied) return denied;
      return {
        ok: true,
        entries: frozenCopy(histories.get(key(input.tenantId, input.exposureId)) ?? []),
      };
    },

    async sumOpen(input, auth) {
      identifier(input.tenantId, 'tenantId');
      if (!CURRENCY.test(input.currency)) fail('invalid_currency', 'currency is invalid');
      validateWindow(input.windowStart, input.windowEnd);
      if (input.programId !== undefined) identifier(input.programId, 'programId');
      if (input.counterpartyId !== undefined) identifier(input.counterpartyId, 'counterpartyId');
      if (input.actionClass !== undefined) identifier(input.actionClass, 'actionClass');
      const denied = await authenticated(input.tenantId, auth);
      if (denied) return denied;

      const selected = [...records.values()].filter((record) => (
        record.tenantId === input.tenantId
        && record.currency === input.currency
        && record.windowStart === input.windowStart
        && record.windowEnd === input.windowEnd
        && (input.programId === undefined || record.programId === input.programId)
        && (input.counterpartyId === undefined || record.counterpartyId === input.counterpartyId)
        && (input.actionClass === undefined || record.actionClass === input.actionClass)
        && isOpen(record)
      ));
      const maps = {
        program: new Map<string, bigint>(),
        counterparty: new Map<string, bigint>(),
        actionClass: new Map<string, bigint>(),
        status: new Map<string, bigint>(),
      };
      for (const record of selected) {
        maps.program.set(record.programId, (maps.program.get(record.programId) ?? 0n) + record.amountMinor);
        maps.counterparty.set(record.counterpartyId, (maps.counterparty.get(record.counterpartyId) ?? 0n) + record.amountMinor);
        maps.actionClass.set(record.actionClass, (maps.actionClass.get(record.actionClass) ?? 0n) + record.amountMinor);
        maps.status.set(record.status, (maps.status.get(record.status) ?? 0n) + record.amountMinor);
      }
      return {
        ok: true,
        totalMinor: selected.reduce((sum, record) => sum + record.amountMinor, 0n),
        byProgram: addBreakdown(maps.program),
        byCounterparty: addBreakdown(maps.counterparty),
        byActionClass: addBreakdown(maps.actionClass),
        byStatus: addBreakdown(maps.status),
      };
    },

    async listAging(input, auth) {
      identifier(input.tenantId, 'tenantId');
      const asOf = instant(input.asOf, 'asOf');
      if (!Number.isSafeInteger(input.minimumAgeMs) || input.minimumAgeMs < 0) {
        fail('invalid_age', 'minimumAgeMs must be a non-negative safe integer');
      }
      if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 10_000) {
        fail('invalid_limit', 'limit is invalid');
      }
      const denied = await authenticated(input.tenantId, auth);
      if (denied) return denied;
      const selected = [...records.values()]
        .filter((record) => record.tenantId === input.tenantId
          && isOpen(record)
          && asOf - instant(record.reservedAt, 'reservedAt') >= input.minimumAgeMs)
        .sort((left, right) => compareText(left.reservedAt, right.reservedAt)
          || compareText(left.exposureId, right.exposureId))
        .slice(0, input.limit);
      return { ok: true, records: frozenCopy(selected) };
    },

    async listDeadlines(input, auth) {
      identifier(input.tenantId, 'tenantId');
      const dueAtOrBefore = instant(input.dueAtOrBefore, 'dueAtOrBefore');
      if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 10_000) {
        fail('invalid_limit', 'limit is invalid');
      }
      const denied = await authenticated(input.tenantId, auth);
      if (denied) return denied;
      const deadline = (record: OpenExposureRecord): string => (
        record.status === 'RESERVED' ? record.invokeBy : record.reconcileBy
      );
      const selected = [...records.values()]
        .filter((record) => record.tenantId === input.tenantId
          && isOpen(record)
          && instant(deadline(record), 'deadline') <= dueAtOrBefore)
        .sort((left, right) => compareText(deadline(left), deadline(right))
          || compareText(left.exposureId, right.exposureId))
        .slice(0, input.limit);
      return { ok: true, records: frozenCopy(selected) };
    },
  };
}
