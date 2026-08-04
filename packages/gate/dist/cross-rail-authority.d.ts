/**
 * Rail-neutral authority admission for agentic commerce.
 *
 * Payment providers retain credentials, custody, settlement, refunds, and
 * dispute handling. Gate decides only whether one exact provider request may
 * enter one configured connector, then issues an opaque permit consumed once
 * inside that connector.
 */
import crypto from 'node:crypto';
import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
export declare const HUMAN_INTERRUPTION_DECISION_VERSION = "EP-HUMAN-INTERRUPTION-DECISION-v1";
export declare const RAIL_ENTRY_PERMIT_VERSION = "EP-RAIL-ENTRY-PERMIT-v1";
export declare const CROSS_RAIL_OBSERVATION_VERSION = "EP-CROSS-RAIL-OBSERVATION-v1";
export declare const CROSS_RAIL_AUTHORITY_CLAIM_BOUNDARY: Readonly<{
    interruption_decision: "selects_whether_exact_action_requires_human_interruption_not_authorization_safety_identity_payment_custody_settlement_refund_or_effect";
    rail_entry_permit: "authorizes_one_entry_to_one_configured_connector_not_funds_availability_payment_custody_settlement_refund_reversibility_or_provider_effect";
    observation: "minimized_gate_outcome_observation_not_population_completeness_causation_loss_coverage_payment_or_effect_proof";
}>;
type Signer = {
    issuer_id: string;
    key_id: string;
    private_key: crypto.KeyLike;
};
type DecisionExpected = {
    decision_id: string;
    tenant_id: string;
    subject_id: string;
    connector_id: string;
    caid: string;
    action_digest: string;
    provider_request_digest: string;
    policy_digest: string;
    configuration_digest: string;
    mode: string;
    issued_at: string;
    expires_at: string;
};
export declare function signHumanInterruptionDecision(input: unknown, signer: Signer): RiskRecord;
export declare function verifyHumanInterruptionDecision(artifact: unknown, { trusted_keys, now, expected }?: {
    trusted_keys?: TrustedRiskKeys;
    now?: number | (() => number);
    expected?: Partial<DecisionExpected>;
}): RiskRecord;
export declare function createRailEntryPermitBroker({ signer, now, max_ttl_ms, max_active_permits, }?: {
    signer?: Signer;
    now?: number | (() => number);
    max_ttl_ms?: number;
    max_active_permits?: number;
}): object;
export declare function createCrossRailConnector({ connector_id, rail, action_class, action_type, project_request, resolve_caid, invoke, }?: {
    connector_id?: string;
    rail?: string;
    action_class?: string;
    action_type?: string;
    project_request?: (request: RiskRecord) => unknown;
    resolve_caid?: (action: RiskRecord) => unknown;
    invoke?: (providerRequest: RiskRecord, context: RiskRecord) => Promise<unknown> | unknown;
}): object;
/**
 * Authorize one exact request into one configured payment connector.
 * The provider invocation happens only after allowance verification, current
 * status, atomic reservation, optional exact human authorization, and an
 * internally consumed one-use permit.
 */
export declare function executeCrossRailAllowance(options?: RiskRecord): Promise<RiskRecord>;
declare const _default: {
    HUMAN_INTERRUPTION_DECISION_VERSION: string;
    RAIL_ENTRY_PERMIT_VERSION: string;
    CROSS_RAIL_OBSERVATION_VERSION: string;
    CROSS_RAIL_AUTHORITY_CLAIM_BOUNDARY: Readonly<{
        interruption_decision: "selects_whether_exact_action_requires_human_interruption_not_authorization_safety_identity_payment_custody_settlement_refund_or_effect";
        rail_entry_permit: "authorizes_one_entry_to_one_configured_connector_not_funds_availability_payment_custody_settlement_refund_reversibility_or_provider_effect";
        observation: "minimized_gate_outcome_observation_not_population_completeness_causation_loss_coverage_payment_or_effect_proof";
    }>;
    signHumanInterruptionDecision: typeof signHumanInterruptionDecision;
    verifyHumanInterruptionDecision: typeof verifyHumanInterruptionDecision;
    createRailEntryPermitBroker: typeof createRailEntryPermitBroker;
    createCrossRailConnector: typeof createCrossRailConnector;
    executeCrossRailAllowance: typeof executeCrossRailAllowance;
};
export default _default;
//# sourceMappingURL=cross-rail-authority.d.ts.map