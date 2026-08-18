/** Signed period reconciliation of supplied populations; never proof that the supplied population is complete. */
import { type RiskRecord, type TrustedRiskKeys, type TrustedRiskKeysV2, type RiskHybridSigner, type RiskV2Options } from './reliance-risk-crypto.js';
export declare const COVERAGE_RECONCILIATION_ATTESTATION_VERSION = "EP-COVERAGE-RECONCILIATION-ATTESTATION-v2";
export declare const COVERAGE_RECONCILIATION_CLAIM_BOUNDARY = "signed_reconciliation_of_supplied_populations_not_population_completeness";
export declare function signCoverageReconciliationAttestation(input: RiskRecord, signer: {
    issuer_id: string;
    key_id: string;
    private_key: any;
}): RiskRecord;
export declare function verifyCoverageReconciliationAttestation(attestation: unknown, options?: {
    trusted_keys?: TrustedRiskKeys;
    now?: string | number;
    expected_program?: RiskRecord;
    expected_census_digest?: string;
    expected_relying_party_id?: string;
    expected_coverage_report_hash?: string;
}): {
    accepted: boolean;
    verified: boolean;
    reason: string;
    attestation_digest: string | null;
    claim_boundary: string;
} | {
    accepted: boolean;
    verified: boolean;
    reason: null;
    attestation_digest: string | null;
    claim_boundary: string;
};
/**
 * REFERENCE-DERIVED HYBRID MIGRATION, applied through the SHARED EP-RISK-HYBRID-v2
 * helper (reliance-risk-crypto.ts: signRiskBodyV2 / verifyRiskBodyV2), which is
 * itself the shared-helper application of the reference migration documented
 * under "PATTERN: the reference hybrid migration" in
 * docs/protocol/pq-hybrid-program.md (EP-REVOCATION-v2 is the template). Five
 * moves, applied here:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. This artifact was already at -v2 for an
 *    unrelated reason (the join-bin rename documented in the module header),
 *    so the hybrid marker is a fresh -v3, never a reused -v2. The v2 verifier
 *    above (verifyCoverageReconciliationAttestation) is untouched: it calls
 *    verifyRiskBody(artifact, COVERAGE_RECONCILIATION_ATTESTATION_VERSION, ...),
 *    which refuses a -v3 artifact on `artifact['@version'] !== version`
 *    BEFORE inspecting any signature, and the -v3 hybrid proof shape (set of
 *    signatures) would fail the v2 flat-proof shape check even if the version
 *    string coincided. Never a leg pass, never a crash.
 * 2. SET SHAPE. The hybrid proof is exactly EP-RISK-HYBRID-v2's shape
 *    (profile, required_algorithms, key_id, body_digest, signatures[]), reused
 *    verbatim from the shared helper -- not reimplemented here.
 * 3. ANTI-STRIPPING BYTES. riskV2SigningBytes (inside reliance-risk-crypto.ts)
 *    commits the REGISTERED required_algorithms set and the EP-RISK-HYBRID-v2
 *    profile marker inside the signed bytes, rebuilt by the verifier from the
 *    PRESENTED body, never from anything the artifact chooses.
 * 4. V1/V2 COMPATIBILITY. The existing sync verify path stays synchronous and
 *    unchanged; -v3 verification is a SEPARATE async entry point (ML-DSA
 *    verification is async).
 * 5. NAMED REFUSALS. verifyCoverageReconciliationAttestationV3 never throws on
 *    caller input; an absent ML-DSA backend surfaces as 'pq_backend_unavailable',
 *    never a skipped check and never a pass on the classical leg alone.
 *
 * HONEST BOUNDARY: everything the v2 header says still holds (signed
 * reconciliation of SUPPLIED populations, never proof the supplied population
 * is complete). The ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, not independently audited and not a FIPS validated module.
 * -v3 does NOT retroactively protect attestations already issued under -v1/-v2.
 */
export declare const COVERAGE_RECONCILIATION_ATTESTATION_V3_VERSION = "EP-COVERAGE-RECONCILIATION-ATTESTATION-v3";
export declare function signCoverageReconciliationAttestationV3(input: RiskRecord, signer: RiskHybridSigner, options?: RiskV2Options): Promise<RiskRecord>;
/** FAIL-CLOSED hybrid verify; a -v3 attestation NEVER verifies on one leg alone. */
export declare function verifyCoverageReconciliationAttestationV3(attestation: unknown, options?: {
    trusted_keys?: TrustedRiskKeysV2;
    now?: string | number;
    expected_program?: RiskRecord;
    expected_census_digest?: string;
    expected_relying_party_id?: string;
    expected_coverage_report_hash?: string;
} & RiskV2Options): Promise<{
    accepted: boolean;
    verified: boolean;
    reason: string;
    attestation_digest: string | null;
    claim_boundary: string;
} | {
    accepted: boolean;
    verified: boolean;
    reason: null;
    attestation_digest: string | null;
    claim_boundary: string;
}>;
/** Route a statement of either -v2 (classical) or -v3 (hybrid) to its own verifier. */
export declare function verifyCoverageReconciliationAttestationAny(attestation: unknown, options?: Parameters<typeof verifyCoverageReconciliationAttestation>[1] & Parameters<typeof verifyCoverageReconciliationAttestationV3>[1]): Promise<{
    accepted: boolean;
    verified: boolean;
    reason: string;
    attestation_digest: string | null;
    claim_boundary: string;
} | {
    accepted: boolean;
    verified: boolean;
    reason: null;
    attestation_digest: string | null;
    claim_boundary: string;
}>;
//# sourceMappingURL=coverage-reconciliation-attestation.d.ts.map