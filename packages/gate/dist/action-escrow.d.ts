export declare const ACTION_ESCROW_STATE_VERSION = "EP-ACTION-ESCROW-STATE-v1";
export declare const ACTION_ESCROW_OUTCOME_VERSION = "EP-ACTION-ESCROW-OUTCOME-v1";
export declare const ACTION_ESCROW_PROFILE_VERSION = "EP-ACTION-ESCROW-PROFILE-v1";
export declare const ACTION_ESCROW_STATES: readonly string[];
export declare const ACTION_ESCROW_TRANSITIONS: Readonly<{
    draft: readonly string[];
    awaiting_acceptance: readonly string[];
    effective: readonly string[];
    awaiting_funding: readonly string[];
    funded: readonly string[];
    milestone_submitted: readonly string[];
    release_reserved: readonly string[];
    released: readonly string[];
    disputed: readonly never[];
    amendment_pending: readonly string[];
    cancelled: readonly never[];
    completed: readonly never[];
    release_indeterminate: readonly string[];
}>;
/**
 * Build the exact human-facing envelope signed by an Action Escrow approver.
 *
 * The release action digest remains the normative machine-action binding. This
 * envelope binds the document, evidence, and material release fields that the
 * approver reviews before selecting the approval option.
 */
export declare function createActionEscrowReleaseBindingMoment(input: any): any;
export declare function computeActionEscrowReleaseBindingMomentDigest(input: any): string | null;
/**
 * Return the relying-party-pinned nonce for one party and one exact release.
 *
 * It is stable while both parties approve, changes with any material action or
 * evidence change, and is consumed by the durable approval CAS.
 */
export declare function computeActionEscrowResolutionNonce(input: any, partyId: any): string | null;
/**
 * The escrow release's provider-facing replay key.
 *
 * Derived through the shared provider replay-key rule so this key and the key
 * an adapter puts in a third-party slot (a Stripe Idempotency-Key, an ERC-3009
 * nonce, an ISO 20022 EndToEndId) are produced by ONE versioned derivation.
 * The tuple it commits to is unchanged from EP-ACTION-ESCROW-PROVIDER-
 * IDEMPOTENCY-v1: agreement, document-action binding, milestone, release
 * action and profile. The output shape is unchanged too:
 * `ep-ae-release:<64 lowercase hex>`.
 *
 * The attempt group is the constant '1'. Escrow releases one milestone once;
 * there is no second attempt group, and introducing one would release the
 * provider-side fence for an already-authorized release.
 *
 * Returns null when the context cannot produce a key. Every caller here has
 * already validated the context, so a null is a programming error rather than
 * an input refusal; the callers convert it into their own stated failure.
 *
 * BREAKING for records reserved before this change. The tuple is the same but
 * the derivation is not, so the emitted VALUE differs from the one
 * EP-ACTION-ESCROW-PROVIDER-IDEMPOTENCY-v1 produced. A release record already
 * in `release_reserved` under the old derivation fails the key check and
 * reports `release_binding_corrupt`. Drain reserved releases before upgrading;
 * do not accept both derivations, because a verifier that accepts two keys for
 * one release no longer proves which one the provider saw.
 */
export declare function computeActionEscrowProviderReplayKey(context: any): string | null;
type ActionEscrowVerifierFn = (artifact: any, expected: any) => any;
type ActionEscrowKernelOptions = {
    store?: Record<string, any>;
    provider?: Record<string, any>;
    verifyDocumentActionBinding?: ActionEscrowVerifierFn;
    verifyAgreementAcceptance?: ActionEscrowVerifierFn;
    verifyMilestoneEvidence?: ActionEscrowVerifierFn;
    verifyResolutionReceipt?: ActionEscrowVerifierFn;
    verifyProviderStatement?: ActionEscrowVerifierFn;
    verifyStateCommand?: ActionEscrowVerifierFn;
    profilesById?: Record<string, any>;
    resolveProfile?: (profileId: string, context: Record<string, any>) => any;
    now?: () => (Date | number | string);
    providerTimeoutMs?: number;
};
/**
 * Create a fail-closed Action Escrow kernel.
 *
 * Store contract:
 *   durable === true
 *   atomicExpectedRevisionCas === true
 *   linearizableReads === true
 *   monotonicRevisions === true
 *   nonExpiring === true
 *   read(key) -> null | { revision, value: canonicalJsonText }
 *   compareAndSwap(key, expectedRevision|null, nextValue)
 *     -> { applied, revision }
 */
export declare function createActionEscrowKernel(options?: ActionEscrowKernelOptions): Readonly<{
    create: (input?: {}) => Promise<any>;
    beginAcceptance: (input?: {}) => Promise<any>;
    acceptAgreement: (input?: {}) => Promise<any>;
    requestFunding: (input?: {}) => Promise<any>;
    recordFunding: (input?: {}) => Promise<any>;
    submitMilestone: (input?: {}) => Promise<any>;
    approveRelease: (input?: {}) => Promise<any>;
    release: (input?: {}) => Promise<any>;
    reconcileRelease: (input?: {}) => Promise<any>;
    openDispute: (input?: {}) => Promise<any>;
    proposeAmendment: (input?: {}) => Promise<any>;
    acceptAmendment: (input?: {}) => Promise<any>;
    cancel: (input?: {}) => Promise<any>;
    complete: (input?: {}) => Promise<any>;
    ready: boolean;
    configuration: Readonly<{
        ok: boolean;
        reason: string | null;
    }>;
    apply: (operation: any, input?: {}) => Promise<any>;
}>;
declare const _default: Readonly<{
    ACTION_ESCROW_STATE_VERSION: "EP-ACTION-ESCROW-STATE-v1";
    ACTION_ESCROW_OUTCOME_VERSION: "EP-ACTION-ESCROW-OUTCOME-v1";
    ACTION_ESCROW_PROFILE_VERSION: "EP-ACTION-ESCROW-PROFILE-v1";
    ACTION_ESCROW_STATES: readonly string[];
    ACTION_ESCROW_TRANSITIONS: Readonly<{
        draft: readonly string[];
        awaiting_acceptance: readonly string[];
        effective: readonly string[];
        awaiting_funding: readonly string[];
        funded: readonly string[];
        milestone_submitted: readonly string[];
        release_reserved: readonly string[];
        released: readonly string[];
        disputed: readonly never[];
        amendment_pending: readonly string[];
        cancelled: readonly never[];
        completed: readonly never[];
        release_indeterminate: readonly string[];
    }>;
    createActionEscrowReleaseBindingMoment: typeof createActionEscrowReleaseBindingMoment;
    computeActionEscrowReleaseBindingMomentDigest: typeof computeActionEscrowReleaseBindingMomentDigest;
    computeActionEscrowResolutionNonce: typeof computeActionEscrowResolutionNonce;
    createActionEscrowKernel: typeof createActionEscrowKernel;
}>;
export default _default;
//# sourceMappingURL=action-escrow.d.ts.map