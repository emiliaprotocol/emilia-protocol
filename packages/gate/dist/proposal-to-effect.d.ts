/**
 * Proposal-to-Effect is a product orchestration profile over existing EMILIA
 * artifacts. A proposal is deliberately NOT a bearer authorization object.
 * Authority remains in EP-RECEIPT-v1 and the relying party's pinned AEB
 * requirement; consequence custody remains in Gate and its durable stores.
 */
import { EP_APPROVAL_FLOW } from '@emilia-protocol/require-receipt/acquisition';
import { type AebAdapter, type AebDigest, type AebDurableConsumptionStore, type AebEvaluationRecord, type AebPinnedConfig, type AebStatusInput } from '@emilia-protocol/verify/aeb-adapter-contract';
export declare const PROPOSAL_TO_EFFECT_VERSION = "EMILIA-PROPOSAL-TO-EFFECT-v1";
type JsonObject = Record<string, any>;
type FetchLike = typeof fetch;
declare const CONSEQUENCE_ATTEMPT_OWNER: unique symbol;
export type ConsequenceAttemptOwnerHandle = string & {
    readonly [CONSEQUENCE_ATTEMPT_OWNER]: true;
};
export type ConsequenceAttemptState = 'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED' | 'ESCALATED';
export type ProposalToEffectProviderOutcome = 'COMMITTED' | 'NOT_COMMITTED' | 'ESCALATED';
export interface ConsequenceAttemptBinding {
    tenant_id: string;
    provider_id: string;
    provider_account_id: string;
    environment: string;
    attempt_id: string;
    request_digest: AebDigest;
}
export interface ConsequenceAttemptReference {
    tenant_id: string;
    attempt_id: string;
    owner: ConsequenceAttemptOwnerHandle;
}
export interface AuthenticatedProviderEvidenceBinding extends ConsequenceAttemptBinding {
    operation_id: string;
    caid: string;
    action_digest: AebDigest;
    evidence_id: string;
    observed_at: string;
    outcome: ProposalToEffectProviderOutcome;
    evidence_digest: AebDigest;
}
export type ConsequenceAttemptTransition = {
    expected_state: 'RESERVED';
    next_state: 'INVOKING';
} | {
    expected_state: 'INVOKING';
    next_state: 'INDETERMINATE';
} | {
    expected_state: 'INDETERMINATE';
    next_state: 'COMMITTED' | 'RELEASED' | 'ESCALATED';
};
/** Owner-fenced durable CAS custody for one provider invocation attempt. */
export interface ProposalToEffectConsequenceAttemptStore {
    durable: true;
    ownershipFenced: true;
    compareAndSwap: true;
    atomicEvidenceBinding: true;
    reserve(binding: ConsequenceAttemptBinding): Promise<{
        reserved: true;
        owner: ConsequenceAttemptOwnerHandle;
    } | {
        reserved: false;
        reason: string;
    }>;
    transition(input: ConsequenceAttemptReference & ConsequenceAttemptTransition): Promise<boolean>;
    reconcile(input: ConsequenceAttemptReference & {
        expected_state: 'INDETERMINATE';
        next_state: 'COMMITTED' | 'RELEASED' | 'ESCALATED';
        evidence: AuthenticatedProviderEvidenceBinding;
    }): Promise<boolean>;
    /** Read terminal custody without exposing owner material, for saga repair. */
    read?(binding: ConsequenceAttemptBinding): Promise<{
        state: ConsequenceAttemptState;
        evidence_digest?: AebDigest | null;
    } | null>;
}
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
    consequence: {
        tenant_id: string;
        provider_id: string;
        provider_account_id: string;
        environment: string;
        executor_id: string;
        request_digest: AebDigest;
    };
    aeb: {
        requirement_ref: string;
        pinned_config_digest: AebDigest;
        consumption_nonce: AebDigest;
    };
    integrity: {
        alg: 'HMAC-SHA256';
        value: string;
    };
}
export interface ProposalToEffectGate {
    check(input: JsonObject): Promise<JsonObject>;
    run(input: JsonObject, effect: (authorization: JsonObject) => unknown | Promise<unknown>): Promise<JsonObject>;
}
export interface ProposalToEffectProviderVerification {
    valid: boolean;
    outcome?: ProposalToEffectProviderOutcome;
    evidence_id?: string;
    observed_at?: string;
    tenant_id?: string;
    request_digest?: AebDigest;
    provider_id?: string;
    provider_account_id?: string;
    environment?: string;
    attempt_id?: string;
    operation_id?: string;
    caid?: string;
    action_digest?: AebDigest;
    evidence_digest?: AebDigest;
    reason?: string;
}
export interface ProposalToEffectCurrentStatusVerification {
    valid: boolean;
    outcome: 'current_not_revoked' | 'revoked' | 'indeterminate';
    /** Authenticated normalized AEB status; never raw presenter data. */
    status?: AebStatusInput | null;
    reason?: string;
}
export interface ProposalToEffectOptions {
    gate: ProposalToEffectGate;
    proposal_integrity: {
        /** Server-held key copied at controller construction; minimum 256 bits. */
        hmac_sha256_key: Uint8Array;
    };
    consequence: {
        tenant_id: string;
        provider_id: string;
        provider_account_id: string;
        environment: string;
        executor_id: string;
        store: ProposalToEffectConsequenceAttemptStore;
        /** Server-side allocator. Presented execute input never selects attempt_id. */
        create_attempt_id?: (input: {
            tenant_id: string;
            request_digest: AebDigest;
        }) => Promise<string> | string;
    };
    profiles: Record<string, ProposalToEffectProfile>;
    aeb: {
        config: AebPinnedConfig;
        adapters: Record<string, AebAdapter>;
        store: AebDurableConsumptionStore;
        resolve_artifacts(input: {
            proposal: ProposalToEffectProposal;
            evaluation: AebEvaluationRecord;
        }): Promise<Record<string, unknown>> | Record<string, unknown>;
        currentStatusResolver(input: {
            proposal: ProposalToEffectProposal;
            evaluation: AebEvaluationRecord;
            leg: AebEvaluationRecord['legs'][number];
        }): Promise<unknown> | unknown;
        /** Configure this around EP-STATUS-v1 verifyStatusArtifact and server pins. */
        statusVerifier(input: {
            status_artifact: unknown;
            expected: {
                tenant_id: string;
                executor_id: string;
                operation_id: string;
                caid: string;
                artifact_ref: string;
                evidence_digest: AebDigest;
                replay_unit: AebDigest;
            };
            now: string;
        }): Promise<ProposalToEffectCurrentStatusVerification> | ProposalToEffectCurrentStatusVerification;
        verify_provider_evidence(input: {
            evidence: unknown;
            expected: {
                operation_id: string;
                caid: string;
                action_digest: AebDigest;
                tenant_id: string;
                request_digest: AebDigest;
                provider_id: string;
                provider_account_id: string;
                environment: string;
                attempt_id: string;
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
        /** Provider request binding; the opaque store owner never crosses the effect boundary. */
        attempt: ConsequenceAttemptBinding;
    }) => unknown | Promise<unknown>) => Promise<JsonObject>;
    reconcile: (input: {
        proposal: unknown;
        evaluation: unknown;
        attempt: ConsequenceAttemptReference | (ConsequenceAttemptBinding & {
            owner: ConsequenceAttemptOwnerHandle;
        });
        provider_evidence: unknown;
        aeb_recovery_authorization?: unknown;
    }) => Promise<JsonObject>;
    repairAeb: (input: {
        proposal: unknown;
        evaluation: unknown;
        attempt: unknown;
        aeb_recovery_authorization?: unknown;
    }) => Promise<JsonObject>;
    getReconciliationHandle: (target: object) => ConsequenceAttemptReference | null;
}>;
declare const _default: {
    PROPOSAL_TO_EFFECT_VERSION: string;
    proposalToEffectConsumptionNonce: typeof proposalToEffectConsumptionNonce;
    createProposalToEffect: typeof createProposalToEffect;
};
export default _default;
//# sourceMappingURL=proposal-to-effect.d.ts.map