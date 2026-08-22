/**
 * CAP-1 composition for EMILIA coverage reconciliation.
 *
 * CAP-1 carries a producer's declared coverage statement. EMILIA does not
 * reinterpret that statement. This module calls relying-party-selected CAP-1
 * and examined-set verifiers, then requires the exact CAP-1 document digest to
 * be the census_digest inside a hybrid coverage-reconciliation attestation. The same
 * signed attestation binds the supplied population roots and the relying
 * party's reconciliation program.
 *
 * Nothing here proves that a supplied population is complete, that an
 * enumeration was honest, or that an examination was technically adequate.
 */
import { type RiskRecord, type RiskV2Options, type TrustedRiskKeysV2 } from './reliance-risk-crypto.js';
export declare const CAP1_COVERAGE_COMPOSITION_PROFILE = "EP-CAP1-COVERAGE-COMPOSITION-v1";
export declare const CAP1_COVERAGE_SUBJECT_COMMITMENT_VERSION = "EP-CAP1-COVERAGE-SUBJECT-COMMITMENT-v1";
export declare const CAP1_DOCUMENT_DIGEST_PROFILE = "EP-CANONICAL-JSON-SHA256-v1";
export declare const CAP1_COVERAGE_COMPOSITION_CLAIM_BOUNDARY = "authenticated_cap1_statement_and_supplied_set_commitments_under_pinned_reconciliation_program_not_source_population_completeness_or_honest_enumeration_or_examination_quality";
/**
 * EMILIA's reproducibility pin for the exact public bundle reviewed here.
 * CAP-1 -00 does not normatively identify its repository schema, vectors,
 * implementations, or fixtures. This lock is therefore an EMILIA pin, not a
 * claim that CAP-1 retroactively made those files normative.
 */
export declare const CAP1_OBSERVED_BUNDLE_SOURCE_LOCK: {
    profile: string;
    repository: string;
    commit: string;
    tree_path: string;
    draft: {
        path: string;
        sha256: string;
    };
    schema: {
        path: string;
        sha256: string;
    };
    vector_manifest: {
        path: string;
        sha256: string;
    };
    vector_bundle_sha256: string;
    claim_boundary: string;
};
export declare const CAP1_OBSERVED_BUNDLE_SOURCE_LOCK_DIGEST: string;
export interface Cap1NativeVerificationResult {
    verdict: 'CONFORMS' | 'REFUSES';
    primary_rule: string | null;
    source: RiskRecord;
    document_digest: string | null;
    violations: unknown[];
}
export type Cap1NativeVerifier = (document: unknown) => Cap1NativeVerificationResult | Promise<Cap1NativeVerificationResult>;
export interface Cap1ExaminedSetVerificationResult {
    verdict: 'SATISFIED' | 'REFUSES';
    verified?: Array<{
        stratum: string;
        eligible_set_digest: string;
        examined_set_digest: string;
        result_bindings: number;
    }>;
    reason?: string;
    stratum?: string;
    cap1?: unknown;
}
export type Cap1ExaminedSetVerifier = (document: unknown, evidence: unknown) => Cap1ExaminedSetVerificationResult | Promise<Cap1ExaminedSetVerificationResult>;
export interface Cap1CoveragePopulationPin {
    inventory_id: string;
    /** Root authenticated in the EMILIA source inventory and reconciliation. */
    population_root: string;
    /** Commitment to the unit identifiers counted as CAP-1 eligible. */
    eligible_set_root: string;
    /** Supplied commitment to the units counted as examined. */
    examined_set_root: string;
    eligible_count: number;
    examined_count: number;
    /** CAP-1 stratum whose counts this population pin binds. */
    stratum_id: string;
}
export interface Cap1CoverageCompositionOptions extends RiskV2Options {
    trusted_keys: TrustedRiskKeysV2;
    now: string | number;
    expected_relying_party_id: string;
    expected_program: RiskRecord;
    system_of_record: Cap1CoveragePopulationPin;
    receipt_population: Cap1CoveragePopulationPin;
    /** Stable relying-party claim class, bound with the reconciliation program. */
    claim_class_id: string;
    /** Pinned technique and depth profile; CAP-1 -00 has no native fields for either. */
    examination_profile: RiskRecord;
    /** Trusted local adapter. Never take this function from the presented artifact. */
    verify_cap1: Cap1NativeVerifier;
    /** Strict set-membership adapter, kept separate from native CAP-1 conformance. */
    verify_examined_set_evidence: Cap1ExaminedSetVerifier;
}
/**
 * Canonical commitment referenced by CAP-1 subject.digest. It binds the exact
 * observed CAP-1 bundle pin, named reconciliation program, and both supplied
 * eligible and examined set commitments.
 */
export declare function cap1CoverageSubjectCommitment(input: {
    program: RiskRecord;
    claim_class_id: string;
    examination_profile: RiskRecord;
    system_of_record: Cap1CoveragePopulationPin;
    receipt_population: Cap1CoveragePopulationPin;
}): RiskRecord;
/** SHA-256 digest shape required in CAP-1 subject.digest for this composition. */
export declare function cap1CoverageSubjectDigest(input: Parameters<typeof cap1CoverageSubjectCommitment>[0]): {
    algorithm: string;
    value: string;
};
/**
 * Verify CAP-1 and EMILIA as two distinct legs joined by exact commitments.
 * The CAP-1 verifier establishes native conformance only. The hybrid EMILIA
 * attestation authenticates the exact CAP-1 bytes, roots, counts, program, and
 * report hash under the relying party's pinned Ed25519 and ML-DSA-65 keys.
 */
export declare function verifyCap1CoverageComposition(input: {
    cap1_document: unknown;
    examined_set_evidence: unknown;
    coverage_report: unknown;
    coverage_attestation: unknown;
}, options: Cap1CoverageCompositionOptions): Promise<{
    accepted: boolean;
    verified: boolean;
    reason: string;
    profile: string;
    cap1_document_digest: string | null;
    claim_boundary: string;
} | {
    accepted: boolean;
    verified: boolean;
    reason: null;
    profile: string;
    cap1: {
        native_conformance: boolean;
        examined_set_evidence: boolean;
        document_digest: string;
        document_digest_profile: string;
        observed_bundle: {
            profile: string;
            repository: string;
            commit: string;
            tree_path: string;
            draft: {
                path: string;
                sha256: string;
            };
            schema: {
                path: string;
                sha256: string;
            };
            vector_manifest: {
                path: string;
                sha256: string;
            };
            vector_bundle_sha256: string;
            claim_boundary: string;
        };
        observed_bundle_source_lock_digest: string;
    };
    reconciliation: {
        relying_party_id: string;
        program: RiskRecord;
        claim_class_id: string;
        examination_profile: RiskRecord;
        report_hash: string;
        attestation_digest: string | null;
        system_of_record: RiskRecord;
        receipt_population: RiskRecord;
        signature_profile: string;
        required_algorithms: string[];
    };
    nonclaims: string[];
    claim_boundary: string;
}>;
//# sourceMappingURL=cap1-coverage-composition.d.ts.map