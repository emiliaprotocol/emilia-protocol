/**
 * Signed, privacy-bounded external loss-experience observations.
 *
 * The feed records what its issuer reports. It deliberately does not establish
 * causation, insurance coverage, legal liability, adjudicated loss, solvency,
 * payment, or authorization.
 */
import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
export declare const LOSS_EXPERIENCE_FEED_VERSION = "EP-LOSS-EXPERIENCE-FEED-v1";
export declare const LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY = "externally_reported_observation_not_verified_causation_not_insurance_coverage_not_legal_liability_not_adjudicated_loss_not_solvency_not_payment";
export interface VerifyLossExperienceFeedOptions {
    trusted_keys?: TrustedRiskKeys;
    now?: string | number;
    expected_program_digest?: string;
    expected_census_digest?: string;
    expected_relying_party_id?: string;
}
export declare function signLossExperienceFeed(input: RiskRecord, signer: {
    issuer_id: string;
    key_id: string;
    private_key: any;
}): RiskRecord;
export declare function verifyLossExperienceFeed(feed: unknown, options?: VerifyLossExperienceFeedOptions): {
    accepted: boolean;
    verified: boolean;
    reason: string;
    feed_digest: string | null;
    claim_boundary: string;
} | {
    accepted: boolean;
    verified: boolean;
    reason: null;
    feed_digest: string | null;
    claim_boundary: string;
};
//# sourceMappingURL=loss-experience-feed.d.ts.map