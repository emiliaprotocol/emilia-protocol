/**
 * Reliance refusal bridge.
 *
 * `createRelianceKernel` denies with an unsigned `application/problem+json`
 * challenge. `EP-ACTION-REFUSAL-STATEMENT-v1` is a signed, offline-verifiable
 * statement of that same refusal. Before this module the two were never
 * connected: `signActionRefusalStatement` had no caller outside its own test,
 * so a running Gate produced no signed artifact when it said no.
 *
 * This module is the adapter. It maps one closed reliance verdict onto the
 * refusal statement's closed `refusal_class` and semantic axes, and signs it.
 *
 * What this module does NOT do, deliberately:
 *   - It does not decide. It reports a decision the kernel already made.
 *   - It never emits a statement for an ALLOW. The statement format requires
 *     at least one failed requirement and rejects `satisfaction: SATISFIED`.
 *   - It does not invent evidence. Evidence and challenge digests are supplied
 *     by the caller, which is the only party that saw the artifacts.
 *
 * Claim boundary: a signed refusal proves the relying party refused this exact
 * action under this exact program. It is not a legal or benefit determination,
 * and it is not proof that the action did not occur by some other path.
 */
type Json = Record<string, any>;
/** Closed mapping of a reliance verdict. Exported for tests and for callers that want to inspect coverage. */
export declare function relianceRefusalClass(verdict: string): {
    refusal_class: string;
    semantics: Json;
    mapped: boolean;
};
export interface RelianceRefusalContext {
    /** The kernel result. Only a non-`rely` verdict may be signed. */
    decision: {
        verdict: string;
        reasons?: string[];
        allow?: boolean;
    };
    /** Compiled reliance program: supplies program_id, version, source_digest, program_digest. */
    program: {
        program_id: string;
        version: number;
        source_digest: string;
        program_digest: string;
    };
    relying_party_id: string;
    caid: string;
    action_digest: string;
    refusal_id: string;
    nonce: string;
    refused_at: string;
    expires_at: string;
    /** Digests of the evidence actually evaluated. The caller saw the artifacts; this module does not invent them. */
    evidence_digests: string[];
    /** Digest(s) of the challenge issued. Exactly one of these two is supplied, per the statement contract. */
    challenge_digest?: string;
    challenge_digests?: string[];
    /** Requirement ids that actually failed in the pinned program. Required; the bridge never invents them. */
    failed_requirement_ids: string[];
    delivery?: Json;
    custody?: Json;
    transparency_anchor?: Json;
}
export interface RelianceRefusalSigner {
    issuer_id: string;
    key_id: string;
    private_key: any;
}
/**
 * Build and sign an `EP-ACTION-REFUSAL-STATEMENT-v1` for a reliance refusal.
 *
 * Throws when the verdict is an allow, because a refusal statement asserting a
 * satisfied requirement set is a contradiction the format refuses to carry.
 */
export declare function signRelianceRefusal(context: RelianceRefusalContext, signer: RelianceRefusalSigner): import("./reliance-risk-crypto.js").RiskRecord;
/** The verdicts this bridge maps explicitly. Anything else refuses as indeterminate. */
export declare const MAPPED_RELIANCE_VERDICTS: readonly string[];
export {};
//# sourceMappingURL=reliance-refusal-bridge.d.ts.map