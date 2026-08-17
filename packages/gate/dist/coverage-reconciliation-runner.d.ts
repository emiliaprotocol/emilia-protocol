/**
 * Derive and reconcile two independently signed, privacy-minimized action
 * populations. The runner proves only what the supplied signed populations
 * contain; it never self-proves source-system completeness.
 *
 * Schema family v2 (EP-COVERAGE-SOURCE-INVENTORY-v2, EP-COVERAGE-POPULATION-v2,
 * EP-COVERAGE-RECONCILIATION-REPORT-v2) changes, relative to v1:
 *
 * 1. The bin previously named `receipt_without_effect` is now
 *    `receipted_without_observation`. The runner only establishes that a
 *    receipt has no matching record in the supplied source population; it
 *    does not establish that no effect occurred. The old name claimed more
 *    than the code proves.
 * 2. Every `excluded` and `exception` record carries a
 *    `classification_rule_id` naming the rule, under the pinned mapping
 *    profile, that produced the classification. The field rides inside the
 *    record and is therefore covered by the signed population root. A record
 *    whose rule id is missing, unknown, or bound to a different
 *    classification is reclassified to the system-side indeterminate bin
 *    (`system_indeterminate`); an unresolvable rule never widens an
 *    exclusion.
 * 3. Emitted bin counts are asserted to sum back to the signed record counts
 *    of BOTH populations before any report is emitted (see
 *    `assertCoveragePopulationConservation`).
 */
import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
export declare const COVERAGE_SOURCE_INVENTORY_VERSION = "EP-COVERAGE-SOURCE-INVENTORY-v2";
export declare const COVERAGE_POPULATION_VERSION = "EP-COVERAGE-POPULATION-v2";
export declare const COVERAGE_RECONCILIATION_REPORT_VERSION = "EP-COVERAGE-RECONCILIATION-REPORT-v2";
export declare const COVERAGE_SOURCE_CLAIM_BOUNDARY = "signed_root_of_supplied_minimized_records_not_source_completeness";
export declare const COVERAGE_REPORT_CLAIM_BOUNDARY = "deterministic_join_of_two_verified_supplied_populations_not_source_completeness";
/**
 * Compiled-in classification-rule registry, version 1.
 *
 * Each `excluded` or `exception` record names the rule that produced its
 * classification via `classification_rule_id`. Ids are stable and versioned;
 * a semantic change to a rule requires a new id, never a redefinition. When
 * declared mapping-profile documents ship, the rules a pinned mapping profile
 * declares replace this compiled-in registry for populations under that
 * profile; until then the pinned `mapping_profile_digest` pins the source
 * mapping and this registry is the resolution set for rule ids.
 */
export declare const COVERAGE_CLASSIFICATION_RULE_REGISTRY_VERSION = "EP-COVERAGE-CLASSIFICATION-RULES-v1";
export declare const COVERAGE_CLASSIFICATION_RULES: Readonly<Record<string, {
    classification: 'excluded' | 'exception';
    summary: string;
}>>;
/**
 * A rule id resolves when it names a registry rule bound to the exact
 * classification the record carries. Anything else (missing id, unknown id,
 * or an id bound to the other classification) does not resolve, and the
 * record is reclassified to `system_indeterminate` by the runner.
 */
export declare function resolveCoverageClassificationRule(classification: 'excluded' | 'exception', ruleId: unknown): boolean;
export type CoverageInventoryKind = 'system_of_record' | 'receipt_population';
export type CoverageRecordClassification = 'effect' | 'excluded' | 'exception' | 'receipt' | 'indeterminate';
export interface CoveragePopulationRecord {
    record_id: string;
    caid: string;
    action_digest: string;
    classification: CoverageRecordClassification;
    /**
     * Required to sustain an `excluded` or `exception` classification and
     * forbidden on every other classification. It is part of the record, so it
     * is covered by the signed population root. A missing or unresolvable rule
     * id demotes the record to `system_indeterminate`; it never refuses the
     * population and never widens an exclusion.
     */
    classification_rule_id?: string;
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
export interface CoverageReconciliationJoins {
    matched: number;
    effect_without_receipt: number;
    receipted_without_observation: number;
    indeterminate: number;
    system_indeterminate: number;
    excluded: number;
    exception: number;
}
export declare function coveragePopulationRoot(kind: CoverageInventoryKind, records: readonly CoveragePopulationRecord[]): string;
/**
 * Population conservation: every supplied record must land in exactly one
 * emitted bin, and the emitted bin counts must sum back to the SIGNED record
 * counts of both populations.
 *
 *   system_of_record.record_count ==
 *     matched + effect_without_receipt + excluded + exception
 *     + system_indeterminate
 *
 *   receipt_population.record_count ==
 *     matched + receipted_without_observation + indeterminate
 *
 * `excluded`, `exception`, and `system_indeterminate` are system-side-only
 * bins; `indeterminate` (source-declared) and `receipted_without_observation`
 * are receipt-side-only bins; `matched` consumes one record from each side.
 * On violation this refuses with `population_conservation_violation:<side>`
 * instead of emitting a report. The runner calls this on every run; it is
 * exported so the refusal path stays directly testable, since the runner's
 * own verified-input path only reaches it with conserving sums.
 */
export declare function assertCoveragePopulationConservation(joins: CoverageReconciliationJoins, counts: {
    system_record_count: number;
    receipt_record_count: number;
}): void;
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
        joins: CoverageReconciliationJoins;
        findings: {
            matched: RiskRecord[];
            effect_without_receipt: CoveragePopulationRecord[];
            receipted_without_observation: CoveragePopulationRecord[];
            indeterminate: CoveragePopulationRecord[];
            system_indeterminate: RiskRecord[];
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