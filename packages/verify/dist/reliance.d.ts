type Obj = Record<string, any>;
export declare const RELIANCE_KERNEL_VERSION = "EP-RELIANCE-KERNEL-v1";
export declare const RELIANCE_PROFILE_VERSION = "EP-RELIANCE-PROFILE-v1";
/** The CLOSED reliance verdict set. `rely` is the only success. */
export declare const RELIANCE_VERDICTS: readonly string[];
declare function strictInstantMs(value: unknown): number;
declare function toMs(t: unknown): number;
declare function pubKeyB64u(pub: unknown): string | null;
declare function spkiFingerprint(value: string): string | null;
declare function validateQuorumPolicy(policy: Obj): string[];
declare function digestHex(value: unknown): string | null;
declare function parseNonNegativeDecimal(value: unknown): {
    coefficient: bigint;
    scale: number;
} | null;
declare function decimalGreaterThan(left: unknown, right: unknown): boolean | null;
declare function decimalEqual(left: unknown, right: unknown): boolean | null;
declare function exactMaterial(candidates: any[]): {
    value: any;
    ambiguous: boolean;
};
declare function decimalMaterial(candidates: any[]): {
    value: any;
    ambiguous: boolean;
};
/** Extract authority/policy material only from bytes already covered by receipt verification. */
declare function signedActionMaterial(receipt: Obj, approvalContexts: Obj[]): Obj;
/**
 * Evaluate whether a relying party may rely on an evidence packet under its own
 * pinned profile. Returns a single closed verdict, fail-closed, deterministic.
 *
 * @param {object} [input]
 * @param {object} [input.action]             { action_type, amount?, currency?, policy_hash?, action_hash? }
 * @param {object} [input.receipt]            the EP trust receipt (verifyTrustReceipt input)
 * @param {object} [input.quorum]             EP-QUORUM-v1 doc (required when required_assurance==='quorum')
 * @param {object} [input.authority_proof]    EP-AUTHORITY-PROOF-v1
 * @param {object} [input.revocation_state]   { checked_at, statement?, target? } freshness attestation
 * @param {object} [input.consumption]        { consumed:boolean, proof?:<EP-SMT-CONSUME bundle> }
 * @param {object} [input.relying_party_profile] EP-RELIANCE-PROFILE-v1 (the pins)
 * @param {number|string|Date} [input.now]
 * @param {object} [opts]                     { approverKeys, logPublicKey, rpId, revokerKeys,
 *                                              isConsumed({receipt_id, action_hash}): boolean }
 * @returns {{ verdict:string, rely:boolean, reasons:string[], checks:object, profile:object }}
 */
export declare function evaluateReliance(input?: Obj, opts?: Obj): Obj;
/** Structural validation of an EP-RELIANCE-PROFILE-v1. Evaluation gates on this. */
export declare function validateRelianceProfile(profile: Obj): {
    ok: boolean;
    issues: string[];
};
export declare const __relianceSecurityInternals: Readonly<{
    strictInstantMs: typeof strictInstantMs;
    toMs: typeof toMs;
    pubKeyB64u: typeof pubKeyB64u;
    spkiFingerprint: typeof spkiFingerprint;
    validateQuorumPolicy: typeof validateQuorumPolicy;
    digestHex: typeof digestHex;
    parseNonNegativeDecimal: typeof parseNonNegativeDecimal;
    decimalGreaterThan: typeof decimalGreaterThan;
    decimalEqual: typeof decimalEqual;
    exactMaterial: typeof exactMaterial;
    decimalMaterial: typeof decimalMaterial;
    signedActionMaterial: typeof signedActionMaterial;
}>;
export {};
//# sourceMappingURL=reliance.d.ts.map