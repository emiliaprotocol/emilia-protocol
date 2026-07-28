/** Privacy-bounded aggregate receipt census and externally reported loss experience. */
import { type RiskRecord } from './reliance-risk-crypto.js';
export declare const RECEIPT_CENSUS_VERSION = "EP-RECEIPT-CENSUS-v1";
export declare const RECEIPT_CENSUS_CLAIM_BOUNDARY = "aggregate_observation_not_causation_coverage_or_adjudication";
export declare function createReceiptCensus(input: RiskRecord): RiskRecord;
export declare function validateReceiptCensus(value: unknown): {
    valid: boolean;
    reason: string;
    census_digest?: undefined;
} | {
    valid: boolean;
    reason: null;
    census_digest: any;
};
//# sourceMappingURL=receipt-census.d.ts.map