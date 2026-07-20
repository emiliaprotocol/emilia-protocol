/**
 * EP-RESOLUTION-v1 -- a durable, four-outcome record of a human resolution.
 *
 * This profile composes with draft-morrison-binding-moment-envelope without
 * changing either artifact's job. The Morrison envelope defines the transient
 * question and answer space. This record proves, under a relying-party-pinned
 * principal key, how that exact envelope was resolved for an exact action.
 *
 * The signed context carries every security-relevant field. The surrounding
 * object carries no presenter-supplied key. Verification fails closed unless
 * the relying party supplies the original binding_moment value, its expected
 * action digest, a role-pinned principal key, the expected WebAuthn RP ID, and
 * an exact WebAuthn origin allowlist.
 */
type Obj = Record<string, any>;
interface ResolutionOptions {
    bindingMoment?: Obj;
    expectedActionHash?: string;
    principalKeys?: Record<string, Obj>;
    rpId?: string;
    allowedOrigins?: string[];
    expectedSelectedOption?: number;
    expectedNonce?: string;
    expectedInitiator?: string;
    evaluationTime?: number | string | Date;
}
export declare const RESOLUTION_VERSION = "EP-RESOLUTION-v1";
export declare const RESOLUTION_CONTEXT_TYPE = "ep.resolution.v1";
export declare const RESOLUTION_OUTCOMES: readonly string[];
/** Hash the exact value of the draft's `binding_moment` field. */
export declare function computeBindingMomentHash(bindingMoment: unknown): string | null;
/** Hash a principal-authored amendment or objection without forcing disclosure. */
export declare function computeResolutionResponseHash(response: unknown): string | null;
/** Return the WebAuthn challenge for an already-built resolution context. */
export declare function computeResolutionChallenge(context: unknown): string | null;
/**
 * Verify a four-outcome resolution receipt fully offline.
 *
 * Required relying-party inputs:
 *   - bindingMoment: the exact value of the Morrison `binding_moment` field;
 *   - expectedActionHash: the digest of the action the executor may perform;
 *   - principalKeys: { key_id: { principal, public_key } } role-scoped pins;
 *   - rpId: the WebAuthn relying-party identifier expected by the verifier.
 *   - allowedOrigins: exact WebAuthn client origins accepted by the verifier.
 *
 * expectedSelectedOption, expectedNonce, expectedInitiator, and evaluationTime
 * are optional for authentic-evidence verification but all are mandatory before
 * the result can set authorizes_action:true.
 */
export declare function verifyResolutionReceipt(receipt: Obj, opts?: ResolutionOptions): {
    valid: boolean;
    authorizes_action: boolean;
    outcome: string | null;
    requires_successor: boolean;
    checks: Record<string, boolean>;
    reason: string;
} | {
    valid: boolean;
    authorizes_action: boolean;
    outcome: any;
    requires_successor: boolean;
    checks: Record<string, boolean>;
};
declare const _default: {
    RESOLUTION_VERSION: string;
    RESOLUTION_CONTEXT_TYPE: string;
    RESOLUTION_OUTCOMES: readonly string[];
    computeBindingMomentHash: typeof computeBindingMomentHash;
    computeResolutionResponseHash: typeof computeResolutionResponseHash;
    computeResolutionChallenge: typeof computeResolutionChallenge;
    verifyResolutionReceipt: typeof verifyResolutionReceipt;
};
export default _default;
//# sourceMappingURL=resolution.d.ts.map