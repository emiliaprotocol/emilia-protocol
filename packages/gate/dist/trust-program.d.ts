/**
 * EMILIA Gate Trust Program Profile v1.
 *
 * A relying-party-controlled, fail-closed authorization DAG for consequential
 * actions. This module composes evidence verifiers; it does not redefine the
 * Handshake, Quorum, AEC, capability, or Action Escrow wire formats.
 */
import crypto from 'node:crypto';
export declare const TRUST_PROGRAM_VERSION = "EP-GATE-TRUST-PROGRAM-PROFILE-v1";
export declare const TRUST_STAGE_RECEIPT_VERSION = "EP-GATE-TRUST-STAGE-RECEIPT-v1";
export type TrustJson = null | boolean | number | string | TrustJson[] | {
    [key: string]: TrustJson;
};
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
    get(input: {
        tenantId: string;
        instanceId: string;
    }): Promise<TrustProgramResult>;
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
    start(input: {
        instanceId: string;
        action?: unknown;
    }): Promise<TrustProgramResult>;
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
/** Validate the closed, bounded DAG before any state is created. */
export declare function validateTrustProgram(program: unknown): {
    valid: boolean;
    reason: string;
    digest: null;
} | {
    valid: boolean;
    reason: null;
    digest: string;
};
export declare function trustProgramDigest(program: unknown): string;
/** Independently verify one stage receipt and optional relying-party bindings. */
export declare function verifyTrustStageReceipt(receipt: unknown, options?: {
    trustedKeys?: Readonly<Record<string, string | crypto.KeyObject>>;
    expected?: Readonly<Record<string, unknown>>;
    expectedIssuer?: Readonly<Record<string, unknown>>;
}): {
    valid: boolean;
    reason: string;
    checks: {
        structure: boolean;
        digest: boolean;
        key: boolean;
        signature: boolean;
        issuer: boolean;
        expected: boolean;
    };
    receipt_digest?: undefined;
    payload?: undefined;
} | {
    valid: boolean;
    reason: null;
    checks: {
        structure: boolean;
        digest: boolean;
        key: boolean;
        signature: boolean;
        issuer: boolean;
        expected: boolean;
    };
    receipt_digest: any;
    payload: any;
};
/**
 * In-process compare-and-swap store. Deliberately rejected by the kernel unless
 * allowEphemeralState is explicit; production must use a durable atomic store.
 */
export declare function createMemoryTrustProgramStore(): TrustProgramStore;
export declare function createTrustProgramKernel(options: TrustProgramKernelConfig): TrustProgramKernel;
declare const _default: {
    TRUST_PROGRAM_VERSION: string;
    TRUST_STAGE_RECEIPT_VERSION: string;
    validateTrustProgram: typeof validateTrustProgram;
    trustProgramDigest: typeof trustProgramDigest;
    verifyTrustStageReceipt: typeof verifyTrustStageReceipt;
    createMemoryTrustProgramStore: typeof createMemoryTrustProgramStore;
    createTrustProgramKernel: typeof createTrustProgramKernel;
};
export default _default;
//# sourceMappingURL=trust-program.d.ts.map