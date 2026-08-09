import { type AebDigest } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
export declare const AUTHORIZATION_BUNDLE_VERSION = "EP-AUTHORIZATION-BUNDLE-v1";
export declare const OAUTH_RAR_AUTHORIZATION_BINDING_VERSION = "EP-OAUTH-RAR-AUTHORIZATION-BINDING-v1";
export type AuthorizationBundleVerdict = 'SATISFIED' | 'REFUSE' | 'INDETERMINATE';
export interface AuthorizationBundleKeyEntry {
    approver_id: string;
    public_key: string;
    key_class: 'A' | 'B' | 'C';
    valid_from: string;
    valid_to: string;
    compromised_at?: string | null;
}
export interface AuthorizationBundleCurrentStatus {
    checked_at: string;
    expires_at: string;
    unavailable?: boolean;
    revoked_key_ids: readonly string[];
}
export interface AuthorizationBundleCurrentPolicy {
    policy_hash: AebDigest;
    decision: 'PERMIT' | 'REFUSE';
    checked_at: string;
    expires_at: string;
    unavailable?: boolean;
}
export interface AuthorizationBundleVerificationOptions {
    now: string | number | Date;
    audience: string;
    approverKeys: Record<string, AuthorizationBundleKeyEntry>;
    /** Approvers independently selected by the authorization server or policy. */
    expectedApprovers: readonly string[];
    /** Key custody classes accepted by the relying party for this action. */
    acceptedKeyClasses: readonly AuthorizationBundleKeyEntry['key_class'][];
    /** Current local policy evaluation; a bundle never freezes policy. */
    currentPolicy: AuthorizationBundleCurrentPolicy;
    /** Exact action independently derived by the relying party. */
    expectedAction: unknown;
    /** Native-verified OAuth/RAR projection. Required when the contexts bind one. */
    expectedAuthorizationBinding?: unknown;
    requireAuthorizationBinding?: boolean;
    /** Required when relying-party policy demands current revocation status. */
    currentStatus?: AuthorizationBundleCurrentStatus;
    requireCurrentStatus?: boolean;
    /** Class-A verification hook, normally backed by verifyWebAuthnSignoff. */
    verifyClassASignoff?: (input: {
        signoff: Obj;
        context: Obj;
        contextDigest: AebDigest;
        key: AuthorizationBundleKeyEntry;
    }) => boolean;
    /** Optional directory-proof verifier when keys are not accepted as direct pins. */
    verifyKeyProofs?: (proofs: readonly unknown[], keys: Record<string, AuthorizationBundleKeyEntry>) => boolean;
    /** Optional presentation-evidence verifier selected by relying-party policy. */
    verifyPresentationEvidence?: (evidence: readonly unknown[], contexts: readonly Obj[]) => boolean;
    requirePresentationEvidence?: boolean;
}
export interface AuthorizationBundleVerificationResult {
    verdict: AuthorizationBundleVerdict;
    evidence_satisfied: boolean;
    authorization_decision: false;
    bundle_digest: AebDigest | null;
    checks: Record<string, boolean>;
    reasons: string[];
}
/**
 * Verify an EP-AUTHORIZATION-BUNDLE-v1 as pre-execution evidence.
 * SATISFIED never means AUTHORIZED; the caller still needs a native grant or
 * PDP decision and executor-side atomic consumption.
 */
export declare function verifyAuthorizationBundle(bundle: unknown, options: AuthorizationBundleVerificationOptions): AuthorizationBundleVerificationResult;
export interface AuthorizationBundleGrantBindingState {
    bundle_digest: AebDigest;
    grant_id: string;
}
export interface AuthorizationBundleGrantBindingResult {
    outcome: 'BOUND' | 'IDEMPOTENT' | 'REFUSE';
    state: AuthorizationBundleGrantBindingState;
    reason: string | null;
}
/**
 * Deterministic compare-and-set transition for AS-side bundle-to-grant state.
 * The caller MUST execute this transition atomically in its authoritative
 * store; this pure helper does not claim distributed or cross-domain locking.
 */
export declare function bindAuthorizationBundleToGrant(current: AuthorizationBundleGrantBindingState | null, requested: AuthorizationBundleGrantBindingState): AuthorizationBundleGrantBindingResult;
export {};
//# sourceMappingURL=authorization-bundle.d.ts.map