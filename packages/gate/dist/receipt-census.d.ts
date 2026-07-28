/** Governed-taxonomy aggregate receipt census with coarse primary suppression. */
import { type RiskRecord } from './reliance-risk-crypto.js';
export declare const RECEIPT_CENSUS_VERSION = "EP-RECEIPT-CENSUS-v1";
export declare const RECEIPT_CENSUS_CLAIM_BOUNDARY = "aggregate_observation_with_primary_suppression_not_differential_privacy_or_identifier_detection_not_causation_coverage_legal_liability_adjudication_solvency_payment_population_completeness_or_authorization";
export interface ReceiptCensusTaxonomy {
    taxonomy_id: string;
    allowed_action_classes: readonly string[];
    allowed_outcomes: readonly string[];
}
export declare function receiptCensusTaxonomyDigest(taxonomy: ReceiptCensusTaxonomy): string;
export declare function createReceiptCensus(input: RiskRecord, taxonomy: ReceiptCensusTaxonomy): RiskRecord;
export declare function validateReceiptCensus(value: unknown, taxonomy?: ReceiptCensusTaxonomy): {
    valid: boolean;
    reason: string;
    census_digest?: undefined;
} | {
    valid: boolean;
    reason: null;
    census_digest: any;
};
//# sourceMappingURL=receipt-census.d.ts.map