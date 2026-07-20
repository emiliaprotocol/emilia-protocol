/** Canonical JSON (recursive sorted keys) — matches @emilia-protocol/verify. */
export declare function canonicalEvidenceJson(v: any): any;
export declare function createEvidenceLog({ sink, strict }?: {
    sink?: (record: any) => any;
    strict?: boolean;
}): {
    durable: boolean;
    persisted: boolean;
    strict: boolean;
    forkAware: boolean;
    atomicAppend: boolean;
    record(entry: any): Promise<any>;
    all(): Record<string, any>[];
    /** Recompute the chain; detects any altered or removed record. */
    verify(): {
        ok: boolean;
        at: any;
        reason: string;
        length?: undefined;
        head?: undefined;
    } | {
        ok: boolean;
        length: number;
        head: string | null;
        at?: undefined;
        reason?: undefined;
    };
};
/**
 * Verify one logger acknowledgement independently of the logger that emitted it.
 */
export declare function verifyEvidenceRecord(record: any, { atomicRequired, expectedEntry }?: {
    atomicRequired?: boolean;
    expectedEntry?: any;
}): boolean;
declare function assertLogEntry(entry: any): void;
declare function validateAtomicRecord(record: any, expectedId: any, expectedEntry: any, expectedRecord?: null): boolean;
declare function validHead(head: any): boolean;
/**
 * Fleet-safe, fail-closed evidence log over an atomic shared-head backend.
 *
 * Backend contract (all operations are scoped by streamId):
 *   readHead(streamId) -> null | { seq, hash }
 *   getById(streamId, recordId) -> null | record
 *   appendIfHead(streamId, expectedHeadHash|null, record) -> boolean
 *   readAll(streamId) -> record[]                    // optional, for verify/all
 *
 * appendIfHead MUST atomically compare the current head, append the immutable
 * record, reject duplicate record_id, and advance the head in one durable
 * transaction. A true return MUST provide immediate read-after-write visibility
 * through getById. `backend.durable === true` is a deployment capability
 * assertion; this module tests the protocol but cannot prove storage hardware
 * semantics.
 */
export declare function createAtomicEvidenceLog(backend: any, { streamId, maxRetries, recordIdFactory, }?: {
    streamId?: string | undefined;
    maxRetries?: number | undefined;
    recordIdFactory?: (() => `${string}-${string}-${string}-${string}-${string}`) | undefined;
}): {
    durable: boolean;
    persisted: boolean;
    strict: boolean;
    forkAware: boolean;
    atomicAppend: boolean;
    streamId: string;
    health(): Promise<any>;
    record(entry: any): Promise<any>;
    all(): Promise<any[]>;
    verify(): Promise<{
        ok: boolean;
        reason: string;
        at?: undefined;
        length?: undefined;
        head?: undefined;
    } | {
        ok: boolean;
        at: number;
        reason: string;
        length?: undefined;
        head?: undefined;
    } | {
        ok: boolean;
        length: number;
        head: string | null;
        reason?: undefined;
        at?: undefined;
    }>;
};
/** In-memory contract model for tests. It is intentionally not durable. */
export declare function createMemoryAtomicEvidenceBackend(): {
    durable: boolean;
    readHead(streamId: any): Promise<{
        seq: any;
        hash: any;
    } | null>;
    getById(streamId: any, recordId: any): Promise<any>;
    appendIfHead(streamId: any, expectedHeadHash: any, record: any): Promise<boolean>;
    readAll(streamId: any): Promise<any>;
};
export declare const __atomicEvidenceSecurityInternals: Readonly<{
    canonical: typeof canonicalEvidenceJson;
    assertLogEntry: typeof assertLogEntry;
    validateAtomicRecord: typeof validateAtomicRecord;
    validHead: typeof validHead;
}>;
declare const _default: {
    createEvidenceLog: typeof createEvidenceLog;
    verifyEvidenceRecord: typeof verifyEvidenceRecord;
    createAtomicEvidenceLog: typeof createAtomicEvidenceLog;
    createMemoryAtomicEvidenceBackend: typeof createMemoryAtomicEvidenceBackend;
};
export default _default;
//# sourceMappingURL=evidence.d.ts.map