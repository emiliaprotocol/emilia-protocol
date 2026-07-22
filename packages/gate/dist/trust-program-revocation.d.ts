export declare const TRUST_PROGRAM_REVOCATION_TARGET_VERSION = "EP-GATE-TRUST-PROGRAM-REVOCATION-TARGET-v1";
type DataRecord = Record<string, any>;
export interface TrustProgramReceiptContext {
    issuer: string;
    tenant: string;
    environment: string;
    audience: string;
    key_id: string;
}
export interface TrustProgramExecutionAuthorizationBinding {
    instance_id: string;
    operation_id: string;
    program_digest: string;
    root_caid: string;
    action_digest: string;
    receipt_context_digest: string;
    terminal_stage_receipt_digests: string[];
    consequence_mode: 'receipt-program' | 'action-escrow';
    capability_template_digest: string | null;
    escrow_profile_digest: string | null;
}
export interface TrustProgramRevocationDerivationInput {
    authorizationBinding: TrustProgramExecutionAuthorizationBinding;
    programVersion: number;
    receiptContext: TrustProgramReceiptContext;
}
export interface TrustProgramRevocationTargetObject {
    '@version': typeof TRUST_PROGRAM_REVOCATION_TARGET_VERSION;
    instance_id: string;
    program_digest: string;
    program_version: number;
    root_caid: string;
    action_digest: string;
    operation_id: string;
    receipt_context_digest: string;
    terminal_stage_receipt_digests: readonly string[];
    consequence_mode: 'receipt-program' | 'action-escrow';
    capability_template_digest: string | null;
    escrow_profile_digest: string | null;
}
export interface TrustProgramRevocationTarget {
    target_type: 'commit';
    target_id: string;
    action_hash: string;
}
export interface TrustProgramRevocationVerificationInput extends TrustProgramRevocationDerivationInput {
    statement: unknown;
    revokerKeys: Record<string, {
        public_key: string;
        key_id?: string;
    }>;
    now: number | string | Date;
}
export interface TrustProgramRevocationKernel {
    status(instanceId: string): Promise<unknown>;
    invalidate(input: {
        instanceId: string;
        expectedRevision: number;
        reason: string;
    }): Promise<unknown>;
}
export interface TrustProgramRevocationApplyInput extends TrustProgramRevocationVerificationInput {
    expectedRevision: number;
    kernel: TrustProgramRevocationKernel;
}
/** Derive the complete closed projection whose JCS SHA-256 is action_hash. */
export declare function deriveTrustProgramRevocationTargetObject(input: TrustProgramRevocationDerivationInput): Readonly<TrustProgramRevocationTargetObject>;
/** Derive the EP-REVOCATION-v1 commit target; no statement field is consulted. */
export declare function deriveTrustProgramRevocationTarget(input: TrustProgramRevocationDerivationInput): Readonly<TrustProgramRevocationTarget>;
export declare function verifyTrustProgramRevocation(input: TrustProgramRevocationVerificationInput): {
    valid: boolean;
    checks: {
        target_derived: boolean;
        statement_structure: boolean;
        pinned_verifier_inputs: boolean;
        portable_verifier_completed: boolean;
    };
    errors: string[];
    target: Readonly<TrustProgramRevocationTarget> | null;
    target_object: Readonly<TrustProgramRevocationTargetObject> | null;
};
export declare function applyTrustProgramRevocation(input: TrustProgramRevocationApplyInput): Promise<{
    verified: boolean;
    applied: boolean;
    blocks_claim: boolean;
    claim_permitted: boolean;
    future_authority_only: boolean;
    retry_required: boolean;
    must_fail_closed: boolean;
    disposition: "refused";
    reason: string;
    verification: {
        valid: boolean;
        checks: {
            target_derived: boolean;
            statement_structure: boolean;
            pinned_verifier_inputs: boolean;
            portable_verifier_completed: boolean;
        };
        errors: string[];
        target: Readonly<TrustProgramRevocationTarget> | null;
        target_object: Readonly<TrustProgramRevocationTargetObject> | null;
    } | null;
    state: null;
} | {
    verified: boolean;
    applied: boolean;
    blocks_claim: boolean;
    claim_permitted: boolean;
    future_authority_only: boolean;
    retry_required: boolean;
    must_fail_closed: boolean;
    disposition: "late_future_authority_only";
    reason: string;
    verification: {
        valid: boolean;
        checks: {
            target_derived: boolean;
            statement_structure: boolean;
            pinned_verifier_inputs: boolean;
            portable_verifier_completed: boolean;
        };
        errors: string[];
        target: Readonly<TrustProgramRevocationTarget> | null;
        target_object: Readonly<TrustProgramRevocationTargetObject> | null;
    };
    state: unknown;
} | {
    verified: boolean;
    applied: boolean;
    blocks_claim: boolean;
    claim_permitted: boolean;
    future_authority_only: boolean;
    retry_required: boolean;
    must_fail_closed: boolean;
    disposition: "indeterminate_retry_required";
    reason: string;
    verification: {
        valid: boolean;
        checks: {
            target_derived: boolean;
            statement_structure: boolean;
            pinned_verifier_inputs: boolean;
            portable_verifier_completed: boolean;
        };
        errors: string[];
        target: Readonly<TrustProgramRevocationTarget> | null;
        target_object: Readonly<TrustProgramRevocationTargetObject> | null;
    };
    state: unknown;
} | {
    verified: boolean;
    applied: boolean;
    blocks_claim: boolean;
    claim_permitted: boolean;
    future_authority_only: boolean;
    retry_required: boolean;
    must_fail_closed: boolean;
    disposition: "already_invalidated";
    reason: string;
    verification: {
        valid: boolean;
        checks: {
            target_derived: boolean;
            statement_structure: boolean;
            pinned_verifier_inputs: boolean;
            portable_verifier_completed: boolean;
        };
        errors: string[];
        target: Readonly<TrustProgramRevocationTarget> | null;
        target_object: Readonly<TrustProgramRevocationTargetObject> | null;
    };
    state: DataRecord;
} | {
    verified: boolean;
    applied: boolean;
    blocks_claim: boolean;
    claim_permitted: boolean;
    future_authority_only: boolean;
    retry_required: boolean;
    must_fail_closed: boolean;
    disposition: "invalidated_before_claim";
    reason: string;
    verification: {
        valid: boolean;
        checks: {
            target_derived: boolean;
            statement_structure: boolean;
            pinned_verifier_inputs: boolean;
            portable_verifier_completed: boolean;
        };
        errors: string[];
        target: Readonly<TrustProgramRevocationTarget> | null;
        target_object: Readonly<TrustProgramRevocationTargetObject> | null;
    };
    state: DataRecord;
}>;
declare const _default: {
    TRUST_PROGRAM_REVOCATION_TARGET_VERSION: string;
    deriveTrustProgramRevocationTargetObject: typeof deriveTrustProgramRevocationTargetObject;
    deriveTrustProgramRevocationTarget: typeof deriveTrustProgramRevocationTarget;
    verifyTrustProgramRevocation: typeof verifyTrustProgramRevocation;
    applyTrustProgramRevocation: typeof applyTrustProgramRevocation;
};
export default _default;
//# sourceMappingURL=trust-program-revocation.d.ts.map