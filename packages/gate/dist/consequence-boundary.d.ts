/**
 * Neutral consequence boundary over CAID, AEC, and AEB.
 *
 * Native evidence stays native. The direct path verifies a relying-party-
 * pinned gateway handoff; it does not re-verify the native permit or artifact.
 * Both boundaries durably fence every native replay unit, and every exact
 * action at one provider target while an attempt for it is in flight, record
 * dispatch custody, and invoke one provider adapter. They do not acquire
 * approvals, mint authority, or require an EMILIA receipt.
 *
 * Reservation ownership: every reservation a native attempt can release or
 * close is keyed by its attempt ID (the diagnostic executed marker is only
 * ever committed), so a release, close, or recovery claim can only reach rows
 * that attempt created. On the composed boundary the action-fence holder is
 * keyed the same way; the evaluation reservation is keyed by the evaluation,
 * and an attempt commits it only while its own holder is still held, which
 * marks it as that reservation's owner. The durable attempt record is written
 * before any attempt-keyed reservation, so an attempt that stops before
 * provider entry can be found and recovered through reconcile().
 *
 * Release ordering: an attempt's reservations are released, closed, or
 * committed only after its durable record has confirmably reached a terminal
 * state or RELEASED without evidence (not entered). Pre-entry recovery and
 * terminal reconciliation are separate reconcile() modes, and a pre-entry
 * recovery that loses its RESERVED -> RELEASED transition to the live run
 * releases nothing.
 */
import { type AebAdapter, type AebConsumptionState, type AebDigest, type AebDurableConsumptionStore, type AebEvaluationRecord, type AebPinnedConfig, type AebStatusInput } from '@emilia-protocol/verify/aeb-adapter-contract';
import type { AebExecutionConditionsResult } from '@emilia-protocol/verify/aeb-execution-conditions';
import { type AebNativeAuthorizationDigest, type AebNativeAuthorizationHandoff, type AebNativeAuthorizationHandoffVerification, type AebNativeAuthorizationPins, type AebNativeAuthorizationStatus } from '@emilia-protocol/verify/aeb';
import type { AebRecoveryClaimScope } from './aeb-consumption-store.js';
import type { ConsequenceEnvelopeBoundary } from './consequence-envelope.js';
export declare const CONSEQUENCE_BOUNDARY_VERSION = "EMILIA-CONSEQUENCE-BOUNDARY-v1";
export declare const CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN = "EMILIA-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1";
export declare const NATIVE_CONSEQUENCE_BOUNDARY_VERSION = "EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-v1";
export declare const NATIVE_CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN = "EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1";
export declare const NATIVE_CONSEQUENCE_BOUNDARY_TRUST_SNAPSHOT_DOMAIN = "EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-TRUST-SNAPSHOT-v1";
export declare const NATIVE_CONSEQUENCE_BOUNDARY_LOCAL_DECISION_DOMAIN = "EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-LOCAL-DECISION-v1";
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
        /**
         * Durable consumption store. Besides the evaluation reservation it holds
         * one action-fence holder per attempt, keyed by the evaluation
         * reservation and the attempt (consequenceBoundaryActionFenceHolderKey),
         * which fences the exact action at this provider under
         * `config.relying_party_id` and marks that attempt as the evaluation
         * reservation's owner. A durable `state()` read confirms lost
         * acknowledgements and lets reconciliation check that marker;
         * `recoveryClaimSupported` (the shipped PostgreSQL store) lets
         * reconcile() finish after a restart.
         */
        store: AebDurableConsumptionStore & {
            state?(key: string): AebConsumptionState | Promise<AebConsumptionState>;
            recoveryClaimSupported?: true;
            claimReservation?(key: string, authorization: unknown, scope?: AebRecoveryClaimScope): Promise<boolean>;
        };
    };
    attempts: {
        /**
         * Durable attempt custody. With `state()`, every transition is confirmed
         * by a durable read; without it (attempt stores written for 0.26.0) only
         * an answer that is exactly `true` counts, and pre-entry recovery proves
         * a stop only through its own acknowledged RESERVED -> RELEASED.
         */
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
/**
 * Which recovery reconcile() performs. The two never fall through into each
 * other.
 *
 * `terminal` (the default): close an attempt that reached INVOKING with the
 * provider's terminal outcome for it (EXECUTED, or FAILED meaning the effect
 * did not and will not occur). A record that never reached INVOKING is
 * `INDETERMINATE` `pre_entry_recovery_required` and nothing changes.
 *
 * `pre_entry`: close an attempt that stopped before provider entry. The
 * outcome is the provider's lookup for this attempt: FAILED ("not found"),
 * or INDETERMINATE when no lookup exists; EXECUTED contradicts the record.
 * It succeeds only through this call's own RESERVED -> RELEASED transition
 * (or an earlier one, recorded as RELEASED without evidence). If the attempt
 * reached INVOKING first, the lookup is discarded and the result is
 * `INDETERMINATE` `recovery_lost_to_live_attempt` with nothing released.
 */
export type ConsequenceBoundaryReconcileMode = 'terminal' | 'pre_entry';
export interface ConsequenceBoundaryReconcileInput<TResult> {
    evaluation: unknown;
    action: unknown;
    artifacts: Record<string, unknown>;
    attempt: unknown;
    outcome: ConsequenceBoundaryEffectOutcome<TResult>;
    recovery_authorization: unknown;
    mode?: ConsequenceBoundaryReconcileMode;
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
    /**
     * `provider_outcome`: the provider's terminal result for this attempt (the
     * provider call, or terminal reconciliation). `pre_entry_lookup`: the
     * provider's lookup for an attempt Gate recorded as never entered (pre-entry
     * recovery), where FAILED means "not found". A lookup that an in-flight call
     * could still overtake is not a terminal NOT_COMMITTED, so a verification
     * program should accept it only for `pre_entry_lookup`.
     */
    purpose: 'provider_outcome' | 'pre_entry_lookup';
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
        /** `pins.relying_party_id` must also satisfy the Gate identifier grammar. */
        pins: AebNativeAuthorizationPins;
        /** Stable operator identifier for the exact accepted pins below. */
        trust_snapshot_id: string;
        /**
         * Durable consumption store. Each attempt writes three reservations, all
         * keyed by its attempt ID (nativeConsequenceBoundaryAttemptReservationKeys):
         * the operation reservation fences the operation identity, the
         * authority reservation fences the native replay key, and the holder
         * reservation fences the exact action at this provider. `state()` must be
         * a durable read. A store whose commit and release are fenced to the
         * reserving process (the shipped PostgreSQL store) must also declare
         * `recoveryClaimSupported: true` so reconciliation after a restart can
         * claim them. Every claim for one attempt carries the same
         * `recovery_authorization` and a scope naming the attempt, and the store
         * refuses a key that is not one of that attempt's rows
         * (consequenceBoundaryRecoveryClaimKey), so one credential bound to the
         * attempt ID covers all three and no other attempt's rows.
         */
        store: AebDurableConsumptionStore & {
            state(key: string): AebConsumptionState | Promise<AebConsumptionState>;
            recoveryClaimSupported?: true;
            claimReservation?(key: string, authorization: unknown, scope?: AebRecoveryClaimScope): Promise<boolean>;
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
    /** See ConsequenceBoundaryReconcileMode; `terminal` when omitted. */
    mode?: ConsequenceBoundaryReconcileMode;
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
 * Operation identity of one (relying party, operation ID, exact action). The
 * native boundary holds it as a fence inside the attempt's operation
 * reservation, so a second attempt with the same operation ID and action is
 * refused as `consumption_conflict` while the first holds it, and forever once
 * the first reached the provider. It is also the operation key a recovery
 * claim scope names for every reservation of one attempt.
 */
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
 * Durable identity of one exact action at one effecting target: the relying
 * party, the provider coordinates the boundary invokes, and the canonical
 * action digest (digestAebNativeAuthorizationAction). While an attempt for
 * this identity is RESERVED, INVOKING, or INDETERMINATE, a new attempt is
 * refused as `native_action_in_flight` even when it carries a fresh native
 * authorization and a fresh operation ID; after EXECUTED it is refused as
 * `native_action_already_executed`. Both boundaries derive the same key, so
 * they fence each other when they share a store and a relying party ID.
 *
 * Identity is byte-level. Gate does not canonicalize amounts, case,
 * whitespace, or Unicode, and does not know which fields are material: two
 * encodings of one logical action are two actions, and provider coordinates
 * are compared exactly as configured. Callers and profiles must canonicalize
 * the action and configure one spelling per provider account. Intentional
 * repeats must differ in the canonical action itself, for example through a
 * caller-chosen instance field that the action digest covers.
 */
export declare function nativeConsequenceBoundaryActionFenceKey(input: {
    relying_party_id: string;
    provider: ConsequenceBoundaryProvider;
    action_digest: AebNativeAuthorizationDigest;
}): string;
/** Keys of the three reservations one native attempt writes, plus its fences. */
export interface NativeConsequenceBoundaryAttemptReservationKeys {
    /** Operation identity fence (nativeConsequenceBoundaryReservationKey). */
    operation_fence: string;
    /** Exact-action fence (nativeConsequenceBoundaryActionFenceKey). */
    action_fence: string;
    /** Attempt-bound reservation that holds `operation_fence`. */
    operation: string;
    /** Attempt-bound reservation that holds the native replay key. */
    authority: string;
    /** Attempt-bound reservation that holds `action_fence`. */
    holder: string;
}
/**
 * Consumption-store keys of one native attempt. Every row key includes the
 * attempt ID, and the authority and holder keys are derived from the
 * attempt's operation key, so a release, close, or recovery claim for one
 * attempt can never reach a row another attempt wrote, even when both carry
 * the same caller-chosen operation ID.
 */
export declare function nativeConsequenceBoundaryAttemptReservationKeys(input: {
    relying_party_id: string;
    provider: ConsequenceBoundaryProvider;
    operation_id: string;
    action_digest: AebNativeAuthorizationDigest;
    attempt_id: string;
}): NativeConsequenceBoundaryAttemptReservationKeys;
/**
 * The exact consumption-store row a recovery claim scope names, derived the
 * way the boundaries derive it: from the scope's recovery operation key (the
 * native operation fence, or the composed evaluation reservation key), its
 * attempt ID, and which reservation it names. Null for a scope no boundary
 * produces. A store that is given a scope refuses a claim on any other row,
 * so a credential bound to one attempt cannot claim another attempt's row.
 */
export declare function consequenceBoundaryRecoveryClaimKey(scope: unknown): string | null;
/**
 * For a scope whose row is shared by every attempt of one evaluation (the
 * composed evaluation reservation), the row that marks this attempt as its
 * current owner: the attempt's action-fence holder. Null for a row keyed by
 * the attempt itself, which needs no marker.
 */
export declare function consequenceBoundaryRecoveryClaimMarkerKey(scope: unknown): string | null;
/**
 * Key of the reservation that holds the action fence for one native attempt.
 * It is derived from that attempt's operation key, which includes the attempt
 * ID, so reconciliation can only ever close the holder of its own attempt.
 */
export declare function nativeConsequenceBoundaryActionFenceHolderKey(input: {
    relying_party_id: string;
    provider: ConsequenceBoundaryProvider;
    operation_id: string;
    action_digest: AebNativeAuthorizationDigest;
    attempt_id: string;
}): string;
/**
 * Key of the reservation that holds the action fence for one attempt on the
 * composed (AEB evaluation) boundary: derived from the evaluation's
 * consumption reservation key and the attempt ID.
 */
export declare function consequenceBoundaryActionFenceHolderKey(input: {
    reservation_key: string;
    attempt_id: string;
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
/**
 * Build the direct native path. The native system has already made the policy
 * decision; Gate verifies the pinned gateway handoff, not the native permit or
 * artifact. It applies its own operational authorization and atomically fences
 * the operation, the native replay unit, and the exact action at this
 * provider, each in a reservation keyed by the attempt.
 */
export declare function createNativeConsequenceBoundary<TResult>(options: NativeConsequenceBoundaryOptions<TResult>): Readonly<{
    version: "EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-v1";
    executor_id: string;
    provider: ConsequenceBoundaryProvider;
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
    consequenceBoundaryActionFenceHolderKey: typeof consequenceBoundaryActionFenceHolderKey;
    consequenceBoundaryRecoveryClaimKey: typeof consequenceBoundaryRecoveryClaimKey;
    consequenceBoundaryRecoveryClaimMarkerKey: typeof consequenceBoundaryRecoveryClaimMarkerKey;
    nativeConsequenceBoundaryReservationKey: typeof nativeConsequenceBoundaryReservationKey;
    nativeConsequenceBoundaryActionFenceKey: typeof nativeConsequenceBoundaryActionFenceKey;
    nativeConsequenceBoundaryAttemptReservationKeys: typeof nativeConsequenceBoundaryAttemptReservationKeys;
    nativeConsequenceBoundaryActionFenceHolderKey: typeof nativeConsequenceBoundaryActionFenceHolderKey;
    nativeConsequenceBoundaryProviderIdempotencyKey: typeof nativeConsequenceBoundaryProviderIdempotencyKey;
    nativeConsequenceBoundaryRequestDigest: typeof nativeConsequenceBoundaryRequestDigest;
    createNativeConsequenceBoundary: typeof createNativeConsequenceBoundary;
}>;
export default _default;
//# sourceMappingURL=consequence-boundary.d.ts.map