export declare const CLAIM_ASSURANCE_ADMISSIBILITY_RESULT_VERSION: "EP-CLAIM-ASSURANCE-ADMISSIBILITY-v1";
type JsonObject = Record<string, unknown>;
export interface ClaimAssuranceResultValidationOptions {
    expectedProfile?: {
        id: string;
        profile_hash: string;
    } | null;
    expectedActionDigest?: string | null;
    requireAdmissible?: boolean;
}
export type ClaimAssuranceResultValidation = {
    ok: true;
    reason: null;
    block: Readonly<JsonObject>;
} | {
    ok: false;
    reason: string;
    block: null;
};
/**
 * Return the nested/direct result only when it explicitly identifies itself as
 * Claim Assurance. Accessor properties and malformed containers are ignored;
 * the strict validator will reject malformed direct Claim Assurance values.
 */
export declare function claimAssuranceResultCandidate(value: unknown): unknown | null;
/**
 * Strictly clone and validate the closed Claim Assurance result contract.
 * Success returns a deeply frozen plain-data snapshot, closing post-validation
 * mutation and getter/proxy-shaped result attacks.
 */
export declare function validateClaimAssuranceAdmissibilityResult(value: unknown, { expectedProfile, expectedActionDigest, requireAdmissible, }?: ClaimAssuranceResultValidationOptions): ClaimAssuranceResultValidation;
export {};
//# sourceMappingURL=claim-assurance-result.d.ts.map