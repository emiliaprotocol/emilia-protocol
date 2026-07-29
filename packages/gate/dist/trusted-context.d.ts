/**
 * EMILIA Trusted Context Pack.
 *
 * A provider verifies its native memory artifact and emits a signed projection
 * commitment. EMILIA then binds that commitment to one exact proposed action,
 * evaluates relying-party policy, and carries the digests into independently
 * verified execution and outcome evidence. None of these steps authorizes an
 * action by itself.
 */
import crypto from 'node:crypto';
type RecordLike = Record<string, any>;
export declare const CONTEXT_PROJECTION_COMPONENT = "ep-memory-projection";
export declare const TRUSTED_CONTEXT_BINDING_VERSION = "EP-TRUSTED-CONTEXT-BINDING-v1";
export type ContextVerificationState = 'VERIFIED' | 'NOT_VERIFIED' | 'INDETERMINATE';
export interface ContextProviderClaims {
    projection_id: string;
    projection_record_digest: string;
    projection_digest: string;
    created_at: string;
    trust_evaluated_at: string;
    adapter_status_checked_at: string;
    adapter_id: string;
    adapter_key_id: string;
    delivered_trust: readonly string[];
    excluded_by_reason: Readonly<Record<string, number>>;
}
export interface ContextProviderVerification {
    state: ContextVerificationState;
    reason: string | null;
    claims?: ContextProviderClaims;
}
export interface ContextEvidenceProvider {
    readonly providerId: string;
    readonly profileId: string;
    verifyProjection(record: unknown, context: {
        verificationTime: string;
        maxSignerStatusAgeSec: number;
    }): ContextProviderVerification;
}
export interface TrustedContextPolicy extends RecordLike {
    policy_id: string;
    provider_id: string;
    provider_profile: string;
    max_projection_age_sec: number;
    max_keyring_age_sec: number;
    max_signer_status_age_sec: number;
    allowed_trust: string[];
    allowed_exclusion_reasons: string[];
    max_excluded_objects: number;
    require_current_signer_status: boolean;
}
export interface TrustedContextEvaluatorOptions {
    providers: ContextEvidenceProvider[];
    policy: TrustedContextPolicy;
    bindingKeys: Record<string, unknown>;
    bindingStatusCheckedAt: string | (() => string);
    expectedBindingNonce: string | (() => string);
    verificationTime: string | (() => string);
}
export declare function trustedContextActionSubjectDigest(action: unknown): string | null;
export declare function canonicalContextRecordDigest(record: unknown): string;
export declare function canonicalContextBindingDigest(binding: unknown): string;
export declare function trustedContextPolicyDigest(policy: unknown): string;
export interface SignTrustedContextBindingInput {
    providerId: string;
    providerProfile: string;
    projectionRecord: RecordLike;
    action: RecordLike;
    policyDigest: string;
    nonce: string;
    issuedAt: string;
    expiresAt: string;
    binderId: string;
    keyId: string;
    privateKey: crypto.KeyLike;
}
/** Sign a context-to-action join without creating an authorization claim. */
export declare function signTrustedContextBinding(input: SignTrustedContextBindingInput): Readonly<{
    proof: {
        alg: string;
        key_id: string;
        signature_b64u: string;
    };
    '@version': string;
    provider_id: string;
    provider_profile: string;
    projection_record_digest: string;
    projection_digest: any;
    action_subject_digest: string;
    policy_digest: string;
    nonce: string;
    issued_at: string | null;
    expires_at: string | null;
    binder: {
        id: string;
        key_id: string;
    };
}>;
/**
 * Create a relying-party-owned context evaluator. Provider implementations,
 * policy, signer keys, and status snapshots are all constructor-pinned.
 */
export declare function createTrustedContextEvaluator(options: TrustedContextEvaluatorOptions): (input: RecordLike) => Readonly<{
    state: "INDETERMINATE" | "NOT_VERIFIED";
    reason: string;
    authorizes: false;
}> | Readonly<{
    state: "VERIFIED";
    reason: null;
    authorizes: false;
    provider_id: string;
    provider_profile: string;
    projection_id: string;
    projection_record_digest: string;
    projection_digest: string;
    context_binding_digest: string;
    action_digest: string;
    policy_digest: string;
}>;
export declare function createTrustedContextAecVerifier({ evaluator }: {
    evaluator: ReturnType<typeof createTrustedContextEvaluator>;
}): (evidence: unknown, context: RecordLike) => Readonly<{
    valid: boolean;
    action_digest: string | null;
    detail: Readonly<{
        state: "INDETERMINATE" | "NOT_VERIFIED";
        reason: string;
        authorizes: false;
    }> | Readonly<{
        state: "VERIFIED";
        reason: null;
        authorizes: false;
        provider_id: string;
        provider_profile: string;
        projection_id: string;
        projection_record_digest: string;
        projection_digest: string;
        context_binding_digest: string;
        action_digest: string;
        policy_digest: string;
    }>;
}>;
/**
 * Compare already-verified execution and outcome evidence to a verified context
 * decision. This is a digest-continuity check, not a signature verifier and not
 * an authorization decision.
 */
export declare function verifyTrustedContextContinuity({ verifiedContext, execution, outcome, }: RecordLike): Readonly<{
    status: "INDETERMINATE";
    reason: "context_not_verified";
    authorizes: false;
}> | Readonly<{
    status: "INDETERMINATE";
    reason: "execution_not_verified";
    authorizes: false;
}> | Readonly<{
    status: "BROKEN";
    reason: "context_execution_binding_mismatch";
    authorizes: false;
}> | Readonly<{
    status: "INDETERMINATE";
    reason: "outcome_not_verified";
    authorizes: false;
}> | Readonly<{
    status: "BROKEN";
    reason: "execution_outcome_binding_mismatch";
    authorizes: false;
}> | Readonly<{
    status: "CONTINUOUS";
    reason: null;
    authorizes: false;
    projection_record_digest: any;
    action_digest: any;
    execution_digest: any;
    outcome_digest: any;
}>;
declare const _default: Readonly<{
    CONTEXT_PROJECTION_COMPONENT: "ep-memory-projection";
    TRUSTED_CONTEXT_BINDING_VERSION: "EP-TRUSTED-CONTEXT-BINDING-v1";
    canonicalContextRecordDigest: typeof canonicalContextRecordDigest;
    canonicalContextBindingDigest: typeof canonicalContextBindingDigest;
    trustedContextActionSubjectDigest: typeof trustedContextActionSubjectDigest;
    trustedContextPolicyDigest: typeof trustedContextPolicyDigest;
    signTrustedContextBinding: typeof signTrustedContextBinding;
    createTrustedContextEvaluator: typeof createTrustedContextEvaluator;
    createTrustedContextAecVerifier: typeof createTrustedContextAecVerifier;
    verifyTrustedContextContinuity: typeof verifyTrustedContextContinuity;
}>;
export default _default;
//# sourceMappingURL=trusted-context.d.ts.map