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
import { type AgileSignature, type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
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
        maxProjectionAgeSec: number;
        maxTrustAgeSec: number;
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
    state: "NOT_VERIFIED" | "INDETERMINATE";
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
        state: "NOT_VERIFIED" | "INDETERMINATE";
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
export declare const TRUSTED_CONTEXT_BINDING_V2_VERSION = "EP-TRUSTED-CONTEXT-BINDING-v2";
export declare const TRUSTED_CONTEXT_BINDING_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface SignTrustedContextBindingV2Input {
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
    pqKeyId: string;
    /** ML-DSA-65 raw secret key (4032 bytes), Uint8Array or base64url. */
    pqPrivateKey: Uint8Array | string;
}
/** Mint a hybrid (Ed25519 + ML-DSA-65) context-to-action binding. */
export declare function signTrustedContextBindingV2(input: SignTrustedContextBindingV2Input, options?: AgilityOptions): Promise<Readonly<{
    proof: Readonly<{
        required_algorithms: ("Ed25519" | "ML-DSA-65")[];
        signatures: AgileSignature[];
    }>;
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
        pq_key_id: string;
    };
}>>;
export interface TrustedContextBindingV2Pin {
    /** Ed25519 base64url SPKI DER, or a node crypto public KeyObject. */
    public_key: string | crypto.KeyObject;
    /** ML-DSA-65 raw public key (1952 bytes), Uint8Array or base64url. */
    pq_public_key: string | Uint8Array;
}
export interface VerifyTrustedContextBindingV2Options extends AgilityOptions {
    action: RecordLike;
    projectionRecordDigest: string;
    projectionDigest: string;
    policyDigest: string;
    expectedNonce: string;
    verificationTime: string;
    /** BOTH key halves for the exact binder key id the binding presents. */
    pin: TrustedContextBindingV2Pin;
}
/**
 * FAIL-CLOSED hybrid verify of one EP-TRUSTED-CONTEXT-BINDING-v2 artifact. A
 * v2 binding NEVER verifies on one leg alone; an absent ML-DSA backend is a
 * refusal, never a skipped check and never a pass on the surviving classical
 * leg. See the SCOPE note above the version constant for what this does not
 * check (binder-key directory status/revocation).
 */
export declare function verifyTrustedContextBindingV2(binding: unknown, options: VerifyTrustedContextBindingV2Options): Promise<Readonly<{
    state: "NOT_VERIFIED";
    reason: string;
    authorizes: false;
}> | Readonly<{
    state: "VERIFIED";
    reason: null;
    authorizes: false;
}>>;
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
    TRUSTED_CONTEXT_BINDING_V2_VERSION: "EP-TRUSTED-CONTEXT-BINDING-v2";
    signTrustedContextBindingV2: typeof signTrustedContextBindingV2;
    verifyTrustedContextBindingV2: typeof verifyTrustedContextBindingV2;
}>;
export default _default;
//# sourceMappingURL=trusted-context.d.ts.map