type RecordLike = Record<string, any>;
type Verifier = (value: any, context: RecordLike) => any;
export interface PinnedEvidenceAdapterOptions {
    policyDigest: string;
    verify: Verifier;
    trustedConfiguration?: RecordLike;
    metadata?: (result: RecordLike, context: RecordLike) => any;
}
/**
 * Wrap any evidence verifier in the Trust Program stage-verifier contract.
 * Runtime artifacts have a closed three-field envelope, so trust configuration
 * cannot ride beside the evidence and influence verification.
 */
export declare function createPinnedEvidenceAdapter({ policyDigest, verify, trustedConfiguration, metadata, }: PinnedEvidenceAdapterOptions): ({ artifact, requirement, program }: RecordLike) => Promise<Readonly<{
    valid: false;
    reason: string;
}> | Readonly<{
    valid: true;
    reason: null;
    binding_digest: any;
    policy_digest: any;
    subjects: string[];
    key_fingerprints: string[];
    issued_at: string;
    expires_at: string;
    revocation_checked_at: string | null;
}>>;
/** Canonical SHA-256 fingerprint of an SPKI public key. */
export declare function canonicalKeyFingerprint(value: unknown): string | null;
export interface QuorumTrustProgramAdapterOptions {
    policy: RecordLike;
    policyDigest: string;
    approverKeys: Record<string, unknown>;
    verificationOptions?: RecordLike;
    revocationCheckedAt: string | (() => string);
    verifyQuorum?: (quorum: any, options?: any) => any;
}
/** Compose Trust Program with the repository's Quorum verifier. */
export declare function createQuorumTrustProgramAdapter(options: QuorumTrustProgramAdapterOptions): ({ artifact, requirement, program }: RecordLike) => Promise<Readonly<{
    valid: false;
    reason: string;
}> | Readonly<{
    valid: true;
    reason: null;
    binding_digest: any;
    policy_digest: any;
    subjects: string[];
    key_fingerprints: string[];
    issued_at: string;
    expires_at: string;
    revocation_checked_at: string | null;
}>>;
export interface AecTrustProgramAdapterOptions {
    policyDigest: string;
    requirement: string;
    keysByType: RecordLike;
    policiesByType: RecordLike;
    verifiers?: Record<string, (...args: any[]) => any>;
    verificationTime: string | (() => string);
    verifyAuthorizationChain?: (chain: any, options?: any) => any;
    metadata?: (result: RecordLike, context: RecordLike) => any;
}
/** Compose Trust Program with AEC under RP-owned policy, action, and trust roots. */
export declare function createAecTrustProgramAdapter(options: AecTrustProgramAdapterOptions): ({ artifact, requirement, program }: RecordLike) => Promise<Readonly<{
    valid: false;
    reason: string;
}> | Readonly<{
    valid: true;
    reason: null;
    binding_digest: any;
    policy_digest: any;
    subjects: string[];
    key_fingerprints: string[];
    issued_at: string;
    expires_at: string;
    revocation_checked_at: string | null;
}>>;
/** Explicitly detect and refuse Action Escrow nested under Receipt Program. */
export declare function containsActionEscrowConsequence(value: unknown): boolean;
export interface ReceiptProgramTerminalOptions {
    programId: string;
    programDigest?: string;
    trustedCertificateKeys: Record<string, string>;
    expectedContext: RecordLike;
    resolveCaid: (action: any) => any;
    verifyReceiptProgramCertificate?: (certificate: any, options?: any) => any;
}
export type TerminalVerifier = ((input: RecordLike) => Promise<RecordLike>) & {
    readonly options: RecordLike;
};
/** Verify and normalize one Receipt Program terminal certificate. */
export declare function createReceiptProgramTerminalOutcomeVerifier(options: ReceiptProgramTerminalOptions): TerminalVerifier;
/** Trust Program executionOutcomeVerifier wrapper for Receipt Program. */
export declare function createReceiptProgramExecutionOutcomeVerifier(options: ReceiptProgramTerminalOptions): (input: RecordLike) => Promise<boolean>;
export interface ActionEscrowTerminalOptions {
    agreementId: string;
    operationId: string;
    releaseActionDigest: string;
    profileDigest: string;
    componentVerifiers: Record<string, (...args: any[]) => any>;
    now?: Date | number | string | (() => Date | number | string);
    maxDocumentBytes?: number;
    maxProjectRecordBytes?: number;
    verifyActionEscrowEvidencePackage?: (pkg: any, options?: any) => any;
}
/** Verify and normalize one Action Escrow authenticated terminal package. */
export declare function createActionEscrowTerminalOutcomeVerifier(options: ActionEscrowTerminalOptions): TerminalVerifier;
/** Trust Program executionOutcomeVerifier wrapper for Action Escrow. */
export declare function createActionEscrowExecutionOutcomeVerifier(options: ActionEscrowTerminalOptions): (input: RecordLike) => Promise<boolean>;
declare const _default: {
    canonicalKeyFingerprint: typeof canonicalKeyFingerprint;
    containsActionEscrowConsequence: typeof containsActionEscrowConsequence;
    createPinnedEvidenceAdapter: typeof createPinnedEvidenceAdapter;
    createQuorumTrustProgramAdapter: typeof createQuorumTrustProgramAdapter;
    createAecTrustProgramAdapter: typeof createAecTrustProgramAdapter;
    createReceiptProgramTerminalOutcomeVerifier: typeof createReceiptProgramTerminalOutcomeVerifier;
    createReceiptProgramExecutionOutcomeVerifier: typeof createReceiptProgramExecutionOutcomeVerifier;
    createActionEscrowTerminalOutcomeVerifier: typeof createActionEscrowTerminalOutcomeVerifier;
    createActionEscrowExecutionOutcomeVerifier: typeof createActionEscrowExecutionOutcomeVerifier;
};
export default _default;
//# sourceMappingURL=trust-program-adapters.d.ts.map