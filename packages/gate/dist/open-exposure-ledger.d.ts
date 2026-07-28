/**
 * Open Exposure Ledger v1.
 *
 * The ledger reserves fixed minor-unit exposure before provider entry. A
 * reservation remains open while RESERVED, INVOKING, or INDETERMINATE and can
 * be closed only by a separately authenticated reconciliation authority. The
 * in-memory implementation is a linearizable conformance/reference store; it
 * is not a durability claim.
 */
export declare const OPEN_EXPOSURE_LEDGER_VERSION = "EP-OPEN-EXPOSURE-LEDGER-v1";
export declare const OPEN_EXPOSURE_HISTORY_VERSION = "EP-OPEN-EXPOSURE-HISTORY-v1";
export type OpenExposureRole = 'POLICY_ADMIN' | 'ORIGIN' | 'EXECUTOR' | 'RECONCILER' | 'READER';
export interface OpenExposureAuth {
    role: OpenExposureRole;
    authorityId: string;
    credential: string;
}
export type OpenExposureCeilingScope = 'TENANT' | 'PROGRAM' | 'COUNTERPARTY' | 'ACTION_CLASS';
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
export type OpenExposureStatus = 'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'CLOSED_COMMITTED' | 'CLOSED_PROVEN_NOT_COMMITTED';
export type OpenExposureReconciliationOutcome = 'COMMITTED' | 'PROVEN_NOT_COMMITTED' | 'INDETERMINATE';
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
export type OpenExposureHistoryEvent = 'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'RECONCILED_INDETERMINATE' | 'CLOSED_COMMITTED' | 'CLOSED_PROVEN_NOT_COMMITTED';
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
export type OpenExposureRefusalReason = 'unauthenticated' | 'wrong_authority' | 'authority_separation_required' | 'ceiling_not_configured' | 'ceiling_exceeded' | 'ceiling_id_conflict' | 'ceiling_scope_conflict' | 'exposure_exists' | 'exposure_not_found' | 'operation_token_conflict' | 'reconciliation_token_conflict' | 'state_conflict' | 'reconciliation_required' | 'already_closed';
export type OpenExposureRefusal = {
    ok: false;
    reason: OpenExposureRefusalReason;
};
export type OpenExposureCeilingResult = {
    ok: true;
    ceiling: Readonly<OpenExposureCeiling>;
    replayed: boolean;
} | OpenExposureRefusal;
export type OpenExposureRecordResult = {
    ok: true;
    record: Readonly<OpenExposureRecord>;
    replayed: boolean;
} | OpenExposureRefusal;
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
export type OpenExposureReadResult = {
    ok: true;
    record: Readonly<OpenExposureRecord> | null;
} | OpenExposureRefusal;
export type OpenExposureHistoryResult = {
    ok: true;
    entries: readonly Readonly<OpenExposureHistoryEntry>[];
} | OpenExposureRefusal;
export type OpenExposureSumResult = {
    ok: true;
    totalMinor: bigint;
    byProgram: readonly Readonly<OpenExposureBreakdown>[];
    byCounterparty: readonly Readonly<OpenExposureBreakdown>[];
    byActionClass: readonly Readonly<OpenExposureBreakdown>[];
    byStatus: readonly Readonly<OpenExposureBreakdown>[];
} | OpenExposureRefusal;
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
export type OpenExposureListResult = {
    ok: true;
    records: readonly Readonly<OpenExposureRecord>[];
} | OpenExposureRefusal;
export interface OpenExposureAuthenticationInput {
    tenantId: string;
    auth: Readonly<OpenExposureAuth>;
}
export interface CreateMemoryOpenExposureLedgerOptions {
    authenticate: (input: Readonly<OpenExposureAuthenticationInput>) => boolean | Promise<boolean>;
}
export interface OpenExposureLedger {
    readonly durable: boolean;
    readonly atomicReserve: true;
    readonly appendOnlyHistory: true;
    readonly blindRelease: false;
    readonly reconciliationOnlyCloseout: true;
    readonly testOnly?: true;
    registerCeiling(input: OpenExposureCeilingInput, auth: OpenExposureAuth): Promise<OpenExposureCeilingResult>;
    reserve(input: OpenExposureReserveInput, auth: OpenExposureAuth): Promise<OpenExposureRecordResult>;
    beginInvocation(input: OpenExposureBeginInput, auth: OpenExposureAuth): Promise<OpenExposureRecordResult>;
    markIndeterminate(input: OpenExposureIndeterminateInput, auth: OpenExposureAuth): Promise<OpenExposureRecordResult>;
    reconcile(input: OpenExposureReconciliationInput, auth: OpenExposureAuth): Promise<OpenExposureRecordResult>;
    read(input: OpenExposureReference, auth: OpenExposureAuth): Promise<OpenExposureReadResult>;
    history(input: OpenExposureReference, auth: OpenExposureAuth): Promise<OpenExposureHistoryResult>;
    sumOpen(input: OpenExposureSumInput, auth: OpenExposureAuth): Promise<OpenExposureSumResult>;
    listAging(input: OpenExposureAgingInput, auth: OpenExposureAuth): Promise<OpenExposureListResult>;
    listDeadlines(input: OpenExposureDeadlineInput, auth: OpenExposureAuth): Promise<OpenExposureListResult>;
}
export declare class OpenExposureValidationError extends TypeError {
    readonly code: string;
    constructor(code: string, message: string);
}
export declare function createMemoryOpenExposureLedger(options: CreateMemoryOpenExposureLedgerOptions): OpenExposureLedger;
//# sourceMappingURL=open-exposure-ledger.d.ts.map