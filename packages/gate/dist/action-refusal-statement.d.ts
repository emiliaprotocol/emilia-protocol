/**
 * Exact-action technical refusal evidence. It is not a legal determination,
 * an adverse-benefit denial, an authorization grant, or proof of delivery.
 */
import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
export declare const ACTION_REFUSAL_STATEMENT_VERSION = "EP-ACTION-REFUSAL-STATEMENT-v1";
export declare const ACTION_REFUSAL_CLAIM_BOUNDARY = "technical_refusal_not_legal_or_benefit_determination";
export declare const ACTION_REFUSAL_CLASSES: readonly string[];
export type ActionRefusalExpectedBindings = {
    caid?: string;
    action_digest?: string;
    relying_party_id?: string;
    program_id?: string;
    program_version?: number;
    source_digest?: string;
    program_digest?: string;
    nonce?: string;
};
export type ActionRefusalReplayStore = {
    durable: boolean;
    consume(relyingPartyId: string, nonce: string, refusalDigest: string): Promise<{
        accepted: boolean;
        reason: string | null;
    }>;
};
export declare function signActionRefusalStatement(input: RiskRecord, signer: {
    issuer_id: string;
    key_id: string;
    private_key: any;
}): RiskRecord;
export declare function actionRefusalStatementDigest(statement: unknown): string;
export declare function verifyActionRefusalStatement(statement: unknown, options?: {
    trusted_keys?: TrustedRiskKeys;
    now?: string | number;
    max_future_skew_sec?: number;
    expected?: ActionRefusalExpectedBindings;
}): {
    accepted: false;
    verified: false;
    reason: string;
    refusal_digest: string | null;
    semantics: null;
    delivery_evidence: "NOT_EVIDENCED";
    custody_evidence: "NOT_EVIDENCED";
    transparency_anchor: "NOT_REFERENCED";
    claim_boundary: string;
} | {
    accepted: true;
    verified: true;
    reason: null;
    refusal_digest: string | null;
    relying_party_id: any;
    nonce: any;
    semantics: any;
    delivery_evidence: string;
    custody_evidence: string;
    transparency_anchor: string;
    claim_boundary: string;
};
export declare function createMemoryActionRefusalReplayStore(): ActionRefusalReplayStore;
export declare function acceptActionRefusalStatement(statement: unknown, options?: {
    trusted_keys?: TrustedRiskKeys;
    now?: string | number;
    max_future_skew_sec?: number;
    expected?: ActionRefusalExpectedBindings;
    replayStore?: ActionRefusalReplayStore;
    allowEphemeralReplayStore?: boolean;
}): Promise<{
    accepted: false;
    reason: string;
    replay_checked: boolean;
    replay_store_durable: boolean;
    verified: false;
    refusal_digest: string | null;
    semantics: null;
    delivery_evidence: "NOT_EVIDENCED";
    custody_evidence: "NOT_EVIDENCED";
    transparency_anchor: "NOT_REFERENCED";
    claim_boundary: string;
} | {
    accepted: false;
    reason: string;
    replay_checked: boolean;
    replay_store_durable: boolean;
    verified: true;
    refusal_digest: string | null;
    relying_party_id: any;
    nonce: any;
    semantics: any;
    delivery_evidence: string;
    custody_evidence: string;
    transparency_anchor: string;
    claim_boundary: string;
} | {
    accepted: true;
    replay_checked: boolean;
    replay_store_durable: boolean;
    verified: true;
    reason: null;
    refusal_digest: string | null;
    relying_party_id: any;
    nonce: any;
    semantics: any;
    delivery_evidence: string;
    custody_evidence: string;
    transparency_anchor: string;
    claim_boundary: string;
}>;
//# sourceMappingURL=action-refusal-statement.d.ts.map