/**
 * Signed external loss-experience observations with governed action classes.
 *
 * The feed records what its issuer reports. It deliberately does not establish
 * causation, insurance coverage, legal liability, adjudicated loss, solvency,
 * payment, or authorization.
 */
import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
export declare const LOSS_EXPERIENCE_FEED_VERSION = "EP-LOSS-EXPERIENCE-FEED-v1";
export declare const LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY = "externally_reported_observation_not_verified_causation_not_insurance_coverage_not_legal_liability_not_adjudicated_loss_not_solvency_not_payment_not_authorization";
export interface VerifyLossExperienceFeedOptions {
    trusted_keys?: TrustedRiskKeys;
    now?: string | number;
    expected_program?: RiskRecord;
    expected_census_digest?: string;
    expected_taxonomy_digest?: string;
    expected_relying_party_id?: string;
    expected_action_classes?: readonly string[];
    commit_lineage_batch?: (request: Readonly<LossExperienceLineageCommitRequest>) => LossExperienceLineageCommitResult;
}
export interface LossExperiencePredecessorResolution {
    current_head: boolean;
    reporting_party_id: string;
    relying_party_id: string;
    program_digest: string;
    record: RiskRecord;
}
export interface LossExperienceLineageTransition {
    lineage_digest: string;
    event_type: 'OBSERVED' | 'CORRECTED' | 'WITHDRAWN';
    predecessor_digest: string | null;
    successor_digest: string;
    reporting_party_id: string;
    relying_party_id: string;
    program_digest: string;
    receipt_digest: string;
    action_class: string;
    currency: string;
    reported_at: string;
    record: Readonly<RiskRecord>;
}
export interface LossExperienceLineageCommitRequest {
    feed_digest: string;
    transitions: readonly LossExperienceLineageTransition[];
    /**
     * The lineage store MUST invoke this callback inside the same transaction
     * after locking/loading the current heads and before making successors
     * visible. A refusal MUST leave every lineage unchanged.
     */
    validate_predecessors: (predecessors: Readonly<Record<string, LossExperiencePredecessorResolution>>) => LossExperienceLineageValidationResult;
}
export type LossExperienceLineageValidationResult = {
    accepted: true;
} | {
    accepted: false;
    reason: string;
};
export type LossExperienceLineageCommitResult = {
    accepted: true;
} | {
    accepted: false;
    reason: string;
};
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
    feed_digest: string;
    claim_boundary: string;
};
//# sourceMappingURL=loss-experience-feed.d.ts.map