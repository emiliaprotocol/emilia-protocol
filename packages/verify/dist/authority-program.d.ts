type Obj = Record<string, any>;
type VerificationCallback = (context: Readonly<Obj>) => unknown;
export declare const AUTHORITY_PROGRAM_VERSION = "EP-AUTHORITY-PROGRAM-v1";
export declare const AUTHORITY_PROGRAM_DOMAIN = "EP-AUTHORITY-PROGRAM-v1\0";
export declare const AUTHORITY_STAGE_RECEIPT_VERSION = "EP-AUTHORITY-STAGE-RECEIPT-v1";
export declare const AUTHORITY_STAGE_RECEIPT_DOMAIN = "EP-AUTHORITY-STAGE-RECEIPT-v1\0";
export declare const AUTHORITY_PROGRAM_RESULT_VERSION = "EP-AUTHORITY-PROGRAM-VERIFY-RESULT-v1";
/** Digest of the exact signed authority-program envelope. */
export declare function authorityProgramDigest(program: unknown): string;
/** Digest of the exact signed immutable stage receipt. */
export declare function authorityStageReceiptDigest(receipt: unknown): string;
/**
 * Derive each stage's immediate predecessor stage IDs from a recursive
 * series/parallel expression. Arbitrary DAG edges are never accepted.
 */
export declare function deriveAuthorityProgramPredecessors(expression: unknown): Record<string, string[]>;
export declare function verifyAuthorityProgram(program: unknown, stageReceipts: unknown, options?: {
    programPin?: Obj;
    stageKeys?: Obj;
    verifyAec?: VerificationCallback;
    verifyAom?: VerificationCallback;
    verifyCapabilityNarrowing?: VerificationCallback;
    verifyParallelAllocation?: VerificationCallback;
}): Obj;
export {};
//# sourceMappingURL=authority-program.d.ts.map