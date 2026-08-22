/**
 * Neutral consequence boundary over CAID, AEC, and AEB.
 *
 * Native evidence stays native. A relying party pins the adapters, evidence
 * requirement, and local authorization policy. This module verifies the AEB
 * join against one frozen action, durably fences every native replay unit,
 * records dispatch custody, and invokes one provider adapter. It does not
 * acquire approvals, mint authority, or require an EMILIA receipt.
 */
import { type AebAdapter, type AebDigest, type AebDurableConsumptionStore, type AebEvaluationRecord, type AebPinnedConfig, type AebStatusInput } from '@emilia-protocol/verify/aeb-adapter-contract';
import type { AebExecutionConditionsResult } from '@emilia-protocol/verify/aeb-execution-conditions';
import type { ConsequenceEnvelopeBoundary } from './consequence-envelope.js';
export declare const CONSEQUENCE_BOUNDARY_VERSION = "EMILIA-CONSEQUENCE-BOUNDARY-v1";
export declare const CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN = "EMILIA-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1";
export interface ConsequenceBoundaryProvider {
    tenant_id: string;
    provider_id: string;
    provider_account_id: string;
    environment: string;
}
export interface ConsequenceBoundaryAttemptBinding extends ConsequenceBoundaryProvider {
    attempt_id: string;
    request_digest: AebDigest;
    /**
     * Stable for retries and reconciliation of this authorization instance.
     * A provider adapter MUST pass it unchanged to any native idempotency API.
     * The key alone does not assert that the provider offers such semantics.
     */
    provider_idempotency_key: string;
}
declare const CONSEQUENCE_BOUNDARY_OWNER: unique symbol;
export type ConsequenceBoundaryOwnerHandle = string & {
    readonly [CONSEQUENCE_BOUNDARY_OWNER]: true;
};
export interface ConsequenceBoundaryAttemptReference extends ConsequenceBoundaryAttemptBinding {
    /** Opaque custody capability. It MUST NOT cross an untrusted API boundary. */
    owner: ConsequenceBoundaryOwnerHandle;
}
export type ConsequenceBoundaryAttemptTransition = {
    expected_state: 'RESERVED';
    next_state: 'INVOKING';
} | {
    expected_state: 'RESERVED';
    next_state: 'RELEASED';
} | {
    expected_state: 'INVOKING';
    next_state: 'INDETERMINATE';
};
export interface ConsequenceBoundaryProviderEvidence extends ConsequenceBoundaryAttemptBinding {
    operation_id: string;
    caid: string;
    action_digest: AebDigest;
    evidence_id: string;
    observed_at: string;
    outcome: 'COMMITTED' | 'NOT_COMMITTED';
    evidence_digest: AebDigest;
}
/** Durable, owner-fenced dispatch custody. */
export interface ConsequenceBoundaryAttemptStore {
    durable: true;
    ownershipFenced: true;
    compareAndSwap: true;
    atomicEvidenceBinding: true;
    reserve(binding: ConsequenceBoundaryAttemptBinding): Promise<{
        reserved: true;
        owner: ConsequenceBoundaryOwnerHandle;
    } | {
        reserved: false;
        reason: string;
    }>;
    transition(input: ConsequenceBoundaryAttemptReference & ConsequenceBoundaryAttemptTransition): Promise<boolean>;
    reconcile(input: ConsequenceBoundaryAttemptReference & {
        expected_state: 'INDETERMINATE';
        next_state: 'COMMITTED' | 'RELEASED';
        evidence: ConsequenceBoundaryProviderEvidence;
    }): Promise<boolean>;
}
export interface ConsequenceBoundaryEvidence {
    evidence_id: string;
    observed_at: string;
    evidence_digest: AebDigest;
}
export type ConsequenceBoundaryEffectOutcome<TResult> = {
    state: 'EXECUTED';
    /** Authenticated provider evidence for this exact attempt and action. */
    evidence: ConsequenceBoundaryEvidence;
    result: TResult;
} | {
    state: 'FAILED';
    /** Authoritative evidence that the protected effect did not occur. */
    evidence: ConsequenceBoundaryEvidence;
    reason: string;
} | {
    state: 'INDETERMINATE';
    reason: string;
};
export interface ConsequenceBoundaryEffectContext {
    action: unknown;
    operation_id: string;
    caid: string;
    evaluation_digest: AebDigest;
    authorization_program_digest: AebDigest;
    provider_idempotency_key: string;
    attempt: Readonly<ConsequenceBoundaryAttemptBinding>;
}
export interface ConsequenceBoundaryAuthorizationContext {
    action: unknown;
    evaluation: Readonly<AebEvaluationRecord>;
    evaluation_digest: AebDigest;
    provider: Readonly<ConsequenceBoundaryProvider>;
}
export interface ConsequenceBoundaryOptions<TResult> {
    executor_id: string;
    provider: ConsequenceBoundaryProvider;
    aeb: {
        config: AebPinnedConfig;
        adapters: Record<string, AebAdapter>;
        store: AebDurableConsumptionStore;
    };
    attempts: {
        store: ConsequenceBoundaryAttemptStore;
        create_id?: (input: {
            operation_id: string;
            request_digest: AebDigest;
        }) => string | Promise<string>;
        /** Recover owner-fenced custody under a separate authenticated path. */
        recover(input: {
            attempt: Readonly<ConsequenceBoundaryAttemptBinding>;
            recovery_authorization: unknown;
        }): ConsequenceBoundaryAttemptReference | null | Promise<ConsequenceBoundaryAttemptReference | null>;
    };
    local_authorize(context: Readonly<ConsequenceBoundaryAuthorizationContext>): boolean | Promise<boolean>;
    invoke(context: Readonly<ConsequenceBoundaryEffectContext>): ConsequenceBoundaryEffectOutcome<TResult> | Promise<ConsequenceBoundaryEffectOutcome<TResult>>;
    /** Optional state-domain-owned capacity reservation before provider entry. */
    consequence_envelope?: ConsequenceEnvelopeBoundary;
    /** Conformance-only escape hatch for a process-local envelope reference. */
    allow_test_consequence_envelope?: true;
    now?: () => string;
}
export interface ConsequenceBoundaryRunInput {
    evaluation: unknown;
    action: unknown;
    artifacts: Record<string, unknown>;
    current_statuses: Record<string, AebStatusInput>;
    execution_conditions?: AebExecutionConditionsResult;
    additional_replay_keys?: readonly string[];
}
export interface ConsequenceBoundaryReconcileInput<TResult> {
    evaluation: unknown;
    action: unknown;
    artifacts: Record<string, unknown>;
    attempt: unknown;
    outcome: ConsequenceBoundaryEffectOutcome<TResult>;
    recovery_authorization: unknown;
}
export type ConsequenceBoundaryResult<TResult> = {
    state: 'REFUSED';
    invoked: false;
    retry_allowed: false;
    reason: string;
} | {
    state: 'EXECUTED';
    invoked: true;
    retry_allowed: false;
    result: TResult;
    evidence: ConsequenceBoundaryEvidence;
    attempt: ConsequenceBoundaryAttemptBinding;
} | {
    state: 'FAILED';
    invoked: true;
    retry_allowed: false;
    reason: string;
    evidence: ConsequenceBoundaryEvidence;
    attempt: ConsequenceBoundaryAttemptBinding;
} | {
    state: 'INDETERMINATE';
    invoked: boolean;
    retry_allowed: false;
    reason: string;
    attempt?: ConsequenceBoundaryAttemptBinding;
};
export declare function consequenceBoundaryRequestDigest(input: {
    provider: ConsequenceBoundaryProvider;
    operation_id: string;
    caid: string;
    action: unknown;
    evaluation_digest: AebDigest;
    provider_idempotency_key: string;
}): AebDigest;
/**
 * Derive the provider retry/reconciliation key from one exact action and one
 * authorization instance. Canonical encoding avoids ambiguous concatenation;
 * provider coordinates prevent the same key from crossing provider domains.
 *
 * A deployment may claim provider-side duplicate suppression only when its
 * pinned adapter profile establishes native idempotency, a sufficient
 * retention horizon, payload-mismatch refusal, and lookup by this exact key.
 */
export declare function consequenceBoundaryProviderIdempotencyKey(input: {
    provider: ConsequenceBoundaryProvider;
    caid: string;
    action_digest: AebDigest;
    authorization_instance: string;
}): string;
/**
 * Build one relying-party-controlled consequence boundary. Presented evidence
 * never selects adapters, trust roots, requirements, or local policy.
 */
export declare function createConsequenceBoundary<TResult>(options: ConsequenceBoundaryOptions<TResult>): Readonly<{
    version: "EMILIA-CONSEQUENCE-BOUNDARY-v1";
    executor_id: string;
    provider: ConsequenceBoundaryProvider;
    run: (input: ConsequenceBoundaryRunInput) => Promise<ConsequenceBoundaryResult<TResult>>;
    reconcile: (input: ConsequenceBoundaryReconcileInput<TResult>) => Promise<ConsequenceBoundaryResult<TResult>>;
}>;
declare const _default: Readonly<{
    CONSEQUENCE_BOUNDARY_VERSION: "EMILIA-CONSEQUENCE-BOUNDARY-v1";
    CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN: "EMILIA-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1";
    consequenceBoundaryProviderIdempotencyKey: typeof consequenceBoundaryProviderIdempotencyKey;
    consequenceBoundaryRequestDigest: typeof consequenceBoundaryRequestDigest;
    createConsequenceBoundary: typeof createConsequenceBoundary;
}>;
export default _default;
//# sourceMappingURL=consequence-boundary.d.ts.map