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
/**
 * A revoker pin usable by the any-version (v1-or-v2) statement path.
 * public_key is the Ed25519 half, required for both statement versions.
 * pq_public_key (ML-DSA-65, raw bytes, base64url) is required ONLY to accept
 * an EP-REVOCATION-v2 statement from this revoker; a pin that omits it still
 * verifies a v1 statement from the same revoker_id exactly as before.
 */
export interface TrustProgramRevokerKeyPin {
    public_key: string;
    key_id?: string;
    pq_public_key?: string;
    pq_key_id?: string;
}
export interface TrustProgramRevocationStatementVerificationInput extends TrustProgramRevocationDerivationInput {
    statement: unknown;
    revokerKeys: Record<string, TrustProgramRevokerKeyPin>;
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
export interface TrustProgramRevocationApplyStatementInput extends TrustProgramRevocationStatementVerificationInput {
    expectedRevision: number;
    kernel: TrustProgramRevocationKernel;
}
/** Derive the complete closed projection whose JCS SHA-256 is action_hash. */
export declare function deriveTrustProgramRevocationTargetObject(input: TrustProgramRevocationDerivationInput): Readonly<TrustProgramRevocationTargetObject>;
/** Derive the EP-REVOCATION-v1 commit target; no statement field is consulted. */
export declare function deriveTrustProgramRevocationTarget(input: TrustProgramRevocationDerivationInput): Readonly<TrustProgramRevocationTarget>;
/** Test-only hook: force re-resolution (e.g. after swapping module mocks). */
export declare function _resetRevocationStatementVerifierCacheForTests(): void;
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
/**
 * EP-REVOCATION-v1-or-v2 verification. ADOPTS the published EP-REVOCATION-v2
 * router (verifyRevocationStatement) so a relying party that has pinned BOTH
 * halves for a revoker (public_key AND pq_public_key) accepts a hybrid
 * statement from that revoker, while a revoker pinned with only public_key
 * still verifies a v1 statement from the same revoker_id exactly as
 * verifyTrustProgramRevocation does.
 *
 * SEPARATE ASYNC ENTRY POINT, not a signature change to the sync
 * verifyTrustProgramRevocation above: that function keeps composing the
 * v1-only synchronous verifier, byte-for-byte unchanged, per EP-REVOCATION-v2's
 * own migration template ("V1 COMPATIBILITY",
 * packages/verify/src/revocation.ts) -- ML-DSA verification is inherently
 * async, so v2 acceptance is additive, never a change to an existing sync
 * caller's contract.
 */
export declare function verifyTrustProgramRevocationStatement(input: TrustProgramRevocationStatementVerificationInput): Promise<{
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
}>;
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
export declare function applyTrustProgramRevocationStatement(input: TrustProgramRevocationApplyStatementInput): Promise<{
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
    verifyTrustProgramRevocationStatement: typeof verifyTrustProgramRevocationStatement;
    applyTrustProgramRevocation: typeof applyTrustProgramRevocation;
    applyTrustProgramRevocationStatement: typeof applyTrustProgramRevocationStatement;
};
export default _default;
//# sourceMappingURL=trust-program-revocation.d.ts.map