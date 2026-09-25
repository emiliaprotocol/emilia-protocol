/**
 * Neutral consequence boundary over CAID, AEC, and AEB.
 *
 * Native evidence stays native. The direct path verifies a relying-party-
 * pinned gateway handoff; it does not re-verify the native permit or artifact.
 * The boundary durably fences every native replay unit, records dispatch
 * custody, and invokes one provider adapter. It does not acquire approvals,
 * mint authority, or require an EMILIA receipt.
 */
import { type AebAdapter, type AebConsumptionState, type AebDigest, type AebDurableConsumptionStore, type AebEvaluationRecord, type AebPinnedConfig, type AebStatusInput } from '@emilia-protocol/verify/aeb-adapter-contract';
import type { AebExecutionConditionsResult } from '@emilia-protocol/verify/aeb-execution-conditions';
import { type AebNativeAuthorizationDigest, type AebNativeAuthorizationHandoff, type AebNativeAuthorizationHandoffVerification, type AebNativeAuthorizationPins, type AebNativeAuthorizationStatus } from '@emilia-protocol/verify/aeb';
import type { ConsequenceEnvelopeBoundary } from './consequence-envelope.js';
export declare const CONSEQUENCE_BOUNDARY_VERSION = "EMILIA-CONSEQUENCE-BOUNDARY-v1";
export declare const CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN = "EMILIA-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1";
export declare const NATIVE_CONSEQUENCE_BOUNDARY_VERSION = "EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-v1";
export declare const NATIVE_CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN = "EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1";
export declare const NATIVE_CONSEQUENCE_BOUNDARY_TRUST_SNAPSHOT_DOMAIN = "EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-TRUST-SNAPSHOT-v1";
export declare const NATIVE_CONSEQUENCE_BOUNDARY_LOCAL_DECISION_DOMAIN = "EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-LOCAL-DECISION-v1";
type JsonObject = Record<string, unknown>;
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
} | {
    expected_state: 'INVOKING';
    next_state: 'RELEASED';
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
export interface ConsequenceBoundaryAttemptStore<TProviderEvidence = ConsequenceBoundaryProviderEvidence> {
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
        evidence: TProviderEvidence;
    }): Promise<boolean>;
    /** Required by the direct-native path for idempotent close after lost acks. */
    state?(input: ConsequenceBoundaryAttemptReference): Promise<{
        state: 'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED';
        evidence?: TProviderEvidence;
    }>;
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
export interface NativeConsequenceBoundaryProviderEvidence extends NativeConsequenceBoundaryAttemptBinding {
    evidence_id: string;
    observed_at: string;
    outcome: 'COMMITTED' | 'NOT_COMMITTED';
    evidence_digest: AebDigest;
}
export interface NativeConsequenceBoundaryLocalDecision {
    decision: 'PERMIT';
    decided_at: string;
    program_digest: AebDigest;
    decision_digest: AebDigest;
}
export interface NativeConsequenceBoundaryAttemptBinding extends ConsequenceBoundaryAttemptBinding {
    operation_id: string;
    action_digest: AebNativeAuthorizationDigest;
    handoff_digest: AebNativeAuthorizationDigest;
    native_replay_unit: AebNativeAuthorizationDigest;
    trust_snapshot_id: string;
    trust_snapshot_digest: AebDigest;
    authorization_program_digest: AebDigest;
    local_authorization_program_digest: AebDigest;
    local_decision_digest: AebDigest;
    local_decided_at: string;
    provider_outcome_verification_program_digest: AebDigest;
}
export interface NativeConsequenceBoundaryAttemptReference extends NativeConsequenceBoundaryAttemptBinding {
    owner: ConsequenceBoundaryOwnerHandle;
}
export interface NativeConsequenceBoundaryProviderOutcomeVerificationContext<TResult> {
    provider: Readonly<ConsequenceBoundaryProvider>;
    operation_id: string;
    action_digest: AebNativeAuthorizationDigest;
    native_replay_unit: AebNativeAuthorizationDigest;
    verification_program_digest: AebDigest;
    attempt: Readonly<NativeConsequenceBoundaryAttemptBinding>;
    outcome: Readonly<Exclude<ConsequenceBoundaryEffectOutcome<TResult>, {
        state: 'INDETERMINATE';
    }>>;
}
export interface NativeConsequenceBoundaryAuthorizationContext {
    action: unknown;
    handoff: Readonly<AebNativeAuthorizationHandoff>;
    verification: Readonly<AebNativeAuthorizationHandoffVerification>;
    provider: Readonly<ConsequenceBoundaryProvider>;
    local_authorization_program_digest: AebDigest;
}
export interface NativeConsequenceBoundaryEffectContext {
    action: unknown;
    operation_id: string;
    action_digest: AebNativeAuthorizationDigest;
    handoff_digest: AebNativeAuthorizationDigest;
    native_replay_unit: AebNativeAuthorizationDigest;
    authorization_program_digest: AebDigest;
    local_authorization: Readonly<NativeConsequenceBoundaryLocalDecision>;
    trust_snapshot_id: string;
    trust_snapshot_digest: AebDigest;
    provider_outcome_verification_program_digest: AebDigest;
    provider_idempotency_key: string;
    attempt: Readonly<NativeConsequenceBoundaryAttemptBinding>;
}
export interface NativeConsequenceBoundaryOptions<TResult> {
    executor_id: string;
    provider: ConsequenceBoundaryProvider;
    native_authorization: {
        pins: AebNativeAuthorizationPins;
        /** Stable operator identifier for the exact accepted pins below. */
        trust_snapshot_id: string;
        store: AebDurableConsumptionStore & {
            state(key: string): AebConsumptionState | Promise<AebConsumptionState>;
        };
        /** Trusted status source. It receives only a preverified pinned handoff. */
        resolve_status(handoff: Readonly<AebNativeAuthorizationHandoff>): AebNativeAuthorizationStatus | Promise<AebNativeAuthorizationStatus>;
        /** Retrieve an archived trust snapshot during authenticated reconciliation. */
        resolve_historical_pins(input: {
            trust_snapshot_id: string;
            trust_snapshot_digest: AebDigest;
        }): AebNativeAuthorizationPins | null | Promise<AebNativeAuthorizationPins | null>;
    };
    attempts: {
        store: ConsequenceBoundaryAttemptStore<NativeConsequenceBoundaryProviderEvidence> & {
            state(input: NativeConsequenceBoundaryAttemptReference): Promise<{
                state: 'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED';
                evidence?: NativeConsequenceBoundaryProviderEvidence;
            }>;
        };
        create_id?: (input: {
            operation_id: string;
            request_digest: AebDigest;
        }) => string | Promise<string>;
        recover(input: {
            attempt: Readonly<ConsequenceBoundaryAttemptBinding>;
            recovery_authorization: unknown;
        }): ConsequenceBoundaryAttemptReference | null | Promise<ConsequenceBoundaryAttemptReference | null>;
    };
    /** Digest of the operator-pinned local admission policy/program. */
    local_authorization_program_digest: AebDigest;
    local_authorize(context: Readonly<NativeConsequenceBoundaryAuthorizationContext>): boolean | Promise<boolean>;
    invoke(context: Readonly<NativeConsequenceBoundaryEffectContext>): ConsequenceBoundaryEffectOutcome<TResult> | Promise<ConsequenceBoundaryEffectOutcome<TResult>>;
    provider_outcomes: {
        /** Digest of the pinned provider-evidence verification program/profile. */
        verification_program_digest: AebDigest;
        verify(context: Readonly<NativeConsequenceBoundaryProviderOutcomeVerificationContext<TResult>>): boolean | Promise<boolean>;
    };
    now?: () => string;
}
export interface NativeConsequenceBoundaryRunInput {
    operation_id: string;
    handoff: unknown;
    action: unknown;
}
export interface NativeConsequenceBoundaryReconcileInput<TResult> {
    operation_id: string;
    handoff: unknown;
    action: unknown;
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
export declare function nativeConsequenceBoundaryReservationKey(input: {
    relying_party_id: string;
    operation_id: string;
    action_digest: AebNativeAuthorizationDigest;
}): string;
export declare function nativeConsequenceBoundaryProviderIdempotencyKey(input: {
    provider: ConsequenceBoundaryProvider;
    action_digest: AebNativeAuthorizationDigest;
    native_replay_unit: AebNativeAuthorizationDigest;
}): string;
export declare function nativeConsequenceBoundaryRequestDigest(input: {
    provider: ConsequenceBoundaryProvider;
    operation_id: string;
    action: unknown;
    action_digest: AebNativeAuthorizationDigest;
    handoff_digest: AebNativeAuthorizationDigest;
    native_replay_unit: AebNativeAuthorizationDigest;
    trust_snapshot_id: string;
    trust_snapshot_digest: AebDigest;
    authorization_program_digest: AebDigest;
    local_authorization: NativeConsequenceBoundaryLocalDecision;
    provider_outcome_verification_program_digest: AebDigest;
    provider_idempotency_key: string;
}): AebDigest;
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
/**
 * Build the direct native path. The native system has already made the policy
 * decision; Gate verifies the pinned gateway handoff, not the native permit or
 * artifact. It applies its own operational authorization and atomically fences
 * the operation and native replay unit.
 */
export declare function createNativeConsequenceBoundary<TResult>(options: NativeConsequenceBoundaryOptions<TResult>): Readonly<{
    version: "EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-v1";
    executor_id: string;
    provider: ConsequenceBoundaryProvider & JsonObject;
    run: (input: NativeConsequenceBoundaryRunInput) => Promise<ConsequenceBoundaryResult<TResult>>;
    reconcile: (input: NativeConsequenceBoundaryReconcileInput<TResult>) => Promise<ConsequenceBoundaryResult<TResult>>;
}>;
declare const _default: Readonly<{
    CONSEQUENCE_BOUNDARY_VERSION: "EMILIA-CONSEQUENCE-BOUNDARY-v1";
    CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN: "EMILIA-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1";
    consequenceBoundaryProviderIdempotencyKey: typeof consequenceBoundaryProviderIdempotencyKey;
    consequenceBoundaryRequestDigest: typeof consequenceBoundaryRequestDigest;
    createConsequenceBoundary: typeof createConsequenceBoundary;
    NATIVE_CONSEQUENCE_BOUNDARY_VERSION: "EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-v1";
    NATIVE_CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN: "EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1";
    NATIVE_CONSEQUENCE_BOUNDARY_TRUST_SNAPSHOT_DOMAIN: "EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-TRUST-SNAPSHOT-v1";
    NATIVE_CONSEQUENCE_BOUNDARY_LOCAL_DECISION_DOMAIN: "EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-LOCAL-DECISION-v1";
    nativeConsequenceBoundaryReservationKey: typeof nativeConsequenceBoundaryReservationKey;
    nativeConsequenceBoundaryProviderIdempotencyKey: typeof nativeConsequenceBoundaryProviderIdempotencyKey;
    nativeConsequenceBoundaryRequestDigest: typeof nativeConsequenceBoundaryRequestDigest;
    createNativeConsequenceBoundary: typeof createNativeConsequenceBoundary;
}>;
export default _default;
//# sourceMappingURL=consequence-boundary.d.ts.map