/**
 * Derive and reconcile two independently signed, privacy-minimized action
 * populations. The runner proves only what the supplied signed populations
 * contain; it never self-proves source-system completeness.
 */
import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
export declare const COVERAGE_SOURCE_INVENTORY_VERSION = "EP-COVERAGE-SOURCE-INVENTORY-v1";
export declare const COVERAGE_POPULATION_VERSION = "EP-COVERAGE-POPULATION-v1";
export declare const COVERAGE_RECONCILIATION_REPORT_VERSION = "EP-COVERAGE-RECONCILIATION-REPORT-v1";
export declare const COVERAGE_SOURCE_CLAIM_BOUNDARY = "signed_root_of_supplied_minimized_records_not_source_completeness";
export declare const COVERAGE_REPORT_CLAIM_BOUNDARY = "deterministic_join_of_two_verified_supplied_populations_not_source_completeness";
export type CoverageInventoryKind = 'system_of_record' | 'receipt_population';
export type CoverageRecordClassification = 'effect' | 'excluded' | 'exception' | 'receipt' | 'indeterminate';
export interface CoveragePopulationRecord {
    record_id: string;
    caid: string;
    action_digest: string;
    classification: CoverageRecordClassification;
}
export interface CoverageSourceInventoryInput {
    inventory_id: string;
    inventory_kind: CoverageInventoryKind;
    source_system_id: string;
    source_operator_id: string;
    period: {
        start: string;
        end: string;
    };
    mapping_profile_digest: string;
    issued_at: string;
    expires_at: string;
}
export interface CoverageSourcePin {
    source_system_id: string;
    mapping_profile_digest: string;
    source_operator_id?: string;
}
export interface CoverageRunnerOptions {
    trusted_keys: TrustedRiskKeys;
    now: string | number;
    system_of_record_pin: CoverageSourcePin;
    receipt_population_pin: CoverageSourcePin;
    require_independent_source_issuers?: boolean;
}
export declare function coveragePopulationRoot(kind: CoverageInventoryKind, records: readonly CoveragePopulationRecord[]): string;
/**
 * Verify only the digest binding between a report and an attestation envelope.
 * Callers MUST separately verify the attestation signature and relying-party
 * context with `verifyCoverageReconciliationAttestation`.
 */
export declare function verifyCoverageReconciliationReportBinding(report: unknown, attestation: unknown): {
    accepted: boolean;
    reason: string;
    report_hash: null;
} | {
    accepted: boolean;
    reason: string;
    report_hash: string;
} | {
    accepted: boolean;
    reason: null;
    report_hash: string;
};
export declare function signCoverageSourceInventory(input: CoverageSourceInventoryInput, records: readonly CoveragePopulationRecord[], signer: {
    issuer_id: string;
    key_id: string;
    private_key: any;
}): RiskRecord;
export declare function verifyCoverageSourceInventory(artifact: unknown, records: readonly CoveragePopulationRecord[], options?: {
    trusted_keys?: TrustedRiskKeys;
    now?: string | number;
    expected_inventory_kind?: CoverageInventoryKind;
    expected_source_system_id?: string;
    expected_mapping_profile_digest?: string;
    expected_source_operator_id?: string;
}): {
    accepted: boolean;
    verified: boolean;
    reason: string;
    inventory_digest: string | null;
    claim_boundary: string;
} | {
    accepted: boolean;
    verified: boolean;
    reason: null;
    inventory_digest: string | null;
    body: {
        [x: string]: any;
    };
    claim_boundary: string;
};
export declare function runCoverageReconciliation(input: {
    run_id: string;
    attestation_id: string;
    relying_party_id: string;
    program: RiskRecord;
    period: {
        start: string;
        end: string;
    };
    census_digest: string;
    system_of_record: {
        artifact: unknown;
        records: CoveragePopulationRecord[];
    };
    receipt_population: {
        artifact: unknown;
        records: CoveragePopulationRecord[];
    };
    generated_at: string;
    expires_at: string;
    timestamp_anchor: RiskRecord | null;
}, options: CoverageRunnerOptions, signer: {
    issuer_id: string;
    key_id: string;
    private_key: any;
}): {
    report: {
        '@version': string;
        run_id: string;
        relying_party_id: string;
        program: RiskRecord;
        period: {
            start: string;
            end: string;
        };
        system_of_record: {
            inventory_id: any;
            source_system_id: any;
            source_operator_id: any;
            inventory_digest: string | null;
            population_root: any;
            count: any;
        };
        receipt_population: {
            inventory_id: any;
            source_system_id: any;
            source_operator_id: any;
            inventory_digest: string | null;
            population_root: any;
            count: any;
        };
        joins: {
            matched: number;
            effect_without_receipt: number;
            receipt_without_effect: number;
            indeterminate: number;
            excluded: number;
            exception: number;
        };
        findings: {
            matched: RiskRecord[];
            effect_without_receipt: CoveragePopulationRecord[];
            receipt_without_effect: CoveragePopulationRecord[];
            indeterminate: CoveragePopulationRecord[];
            excluded: CoveragePopulationRecord[];
            exception: CoveragePopulationRecord[];
        };
        generated_at: string;
        claim_boundary: string;
    };
    report_hash: string;
    attestation: RiskRecord;
};
//# sourceMappingURL=coverage-reconciliation-runner.d.ts.map