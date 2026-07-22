/**
 * Proposal-to-Effect is a product orchestration profile over existing EMILIA
 * artifacts. A proposal is deliberately NOT a bearer authorization object.
 * Authority remains in EP-RECEIPT-v1 and the relying party's pinned AEB
 * requirement; consequence custody remains in Gate and its durable stores.
 */
import { EP_APPROVAL_FLOW } from '@emilia-protocol/require-receipt/acquisition';
import { type AebAdapter, type AebDigest, type AebDurableConsumptionStore, type AebEvaluationRecord, type AebPinnedConfig } from '@emilia-protocol/verify/aeb-adapter-contract';
export declare const PROPOSAL_TO_EFFECT_VERSION = "EMILIA-PROPOSAL-TO-EFFECT-v1";
type JsonObject = Record<string, any>;
type FetchLike = typeof fetch;
export interface ProposalToEffectProfile {
    id: string;
    action_type: string;
    selector: JsonObject;
    required_fields: readonly string[];
    authorization: {
        authorization_endpoint: string;
        flow: typeof EP_APPROVAL_FLOW;
    };
    aeb_requirement_ref: string;
    ttl_sec: number;
    /**
     * Relying-party-controlled canonicalization and CAID derivation. It runs on
     * both proposal creation and execution. Never select it from presented data.
     */
    canonicalize_action(input: unknown): {
        action: JsonObject;
        caid: string;
    };
    caid_selector?: {
        field: string;
    };
}
export interface ProposalToEffectProposal {
    '@version': typeof PROPOSAL_TO_EFFECT_VERSION;
    proposal_id: string;
    operation_id: string;
    initiator_id: string;
    profile_id: string;
    action: JsonObject;
    action_digest: string;
    aeb_action_digest: AebDigest;
    caid: string;
    created_at: string;
    expires_at: string;
    challenge: {
        action: string;
        action_hash: string;
        required_fields: string[];
        caid_selector?: {
            field: string;
        };
    };
    authorization: {
        authorization_endpoint: string;
        flow: typeof EP_APPROVAL_FLOW;
    };
    aeb: {
        requirement_ref: string;
        pinned_config_digest: AebDigest;
        consumption_nonce: AebDigest;
    };
}
export interface ProposalToEffectGate {
    check(input: JsonObject): Promise<JsonObject>;
    run(input: JsonObject, effect: (authorization: JsonObject) => unknown | Promise<unknown>): Promise<JsonObject>;
}
export interface ProposalToEffectProviderVerification {
    valid: boolean;
    outcome?: 'COMMITTED' | 'NOT_COMMITTED';
    evidence_digest?: AebDigest | null;
    reason?: string;
}
export interface ProposalToEffectOptions {
    gate: ProposalToEffectGate;
    profiles: Record<string, ProposalToEffectProfile>;
    aeb: {
        config: AebPinnedConfig;
        adapters: Record<string, AebAdapter>;
        store: AebDurableConsumptionStore;
        resolve_artifacts(input: {
            proposal: ProposalToEffectProposal;
            evaluation: AebEvaluationRecord;
        }): Promise<Record<string, unknown>> | Record<string, unknown>;
        verify_provider_evidence(input: {
            evidence: unknown;
            expected: {
                operation_id: string;
                caid: string;
                action_digest: AebDigest;
            };
        }): Promise<ProposalToEffectProviderVerification> | ProposalToEffectProviderVerification;
    };
    now?: () => number;
}
export declare function proposalToEffectConsumptionNonce(operationId: string, pinnedConfigDigest: AebDigest): AebDigest;
export declare function createProposalToEffect(options: ProposalToEffectOptions): Readonly<{
    prepare: (input: {
        proposal_id: string;
        profile_id: string;
        operation_id: string;
        initiator_id: string;
        action: unknown;
    }) => ProposalToEffectProposal;
    verifyProposal: (input: unknown, { allowExpired }?: {
        allowExpired?: boolean;
    }) => {
        proposal: ProposalToEffectProposal;
        profile: ProposalToEffectProfile;
    };
    beginApproval: (input: {
        proposal: unknown;
        approver_id: string;
        idempotency_key: string;
        requester_authorization: string | (() => string | Promise<string>);
        fetch_impl?: FetchLike;
    }) => Promise<JsonObject>;
    pollApproval: (input: {
        proposal: unknown;
        request_id: string;
        poll_token: string;
        fetch_impl?: FetchLike;
    }) => Promise<JsonObject>;
    execute: (input: {
        proposal: unknown;
        receipt: unknown;
        evaluation: unknown;
    }, effect: (input: {
        action: JsonObject;
        proposal: ProposalToEffectProposal;
        authorization: JsonObject;
    }) => unknown | Promise<unknown>) => Promise<JsonObject>;
    reconcile: (input: {
        proposal: unknown;
        evaluation: unknown;
        provider_evidence: unknown;
    }) => Promise<JsonObject>;
}>;
declare const _default: {
    PROPOSAL_TO_EFFECT_VERSION: string;
    proposalToEffectConsumptionNonce: typeof proposalToEffectConsumptionNonce;
    createProposalToEffect: typeof createProposalToEffect;
};
export default _default;
//# sourceMappingURL=proposal-to-effect.d.ts.map