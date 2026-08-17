/** Signed period reconciliation of supplied populations; never proof that the supplied population is complete. */
import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
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
//# sourceMappingURL=coverage-reconciliation-attestation.d.ts.map