/**
 * AEB-ADAPTER-v1 — relying-party-pinned evidence adapter contract.
 *
 * This module is intentionally a composition boundary, not another receipt
 * format. An adapter verifies a native artifact and projects it into a named
 * CAID mapping profile. The relying party, not the presenter, pins the
 * adapter version, trust roots, mapping profile, and evidence requirement.
 *
 * The evaluator keeps four decisions separate:
 *   VERIFIED    native artifact verification succeeded
 *   ACCEPTED    the relying party accepts that native result under its pins
 *   SATISFIED   the complete pinned requirement is met for one CAID
 *   AUTHORIZED  a local execution policy has allowed the effect
 *
 * A signed evaluation record is useful for evidence transport, but it is not
 * blindly trusted: verifyAebEvaluation re-derives the result from the pinned
 * configuration, adapter registry, and artifacts supplied by the relying party.
 */
import { type KeyObject } from 'node:crypto';
import { AEC_VERSION } from './evidence-chain.js';
export declare const AEB_ADAPTER_VERSION = "AEB-ADAPTER-v1";
export declare const AEB_EVALUATION_VERSION = "AEB-EVALUATION-v1";
export declare const AEB_EVALUATION_DOMAIN = "AEB-EVALUATION-v1\0";
export declare const AEB_REQUIREMENT_VERSION = "AEB-REQUIREMENT-v1";
export declare const AEB_REGISTRY_VERSION = "EP-EVIDENCE-REGISTRY-v1";
export declare const AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION = "EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v1";
export declare const AEB_NATIVE_VERIFICATION_ATTESTATION_DOMAIN = "EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v1\0";
export type NativeVerification = 'VERIFIED' | 'FAILED';
export type Acceptance = 'ACCEPTED' | 'REJECTED' | 'INDETERMINATE';
export type MappingVerdict = 'MATCH' | 'MISMATCH' | 'INDETERMINATE';
export type AebVerdict = 'SATISFIED' | 'UNSATISFIED' | 'INDETERMINATE';
export type AebLegVerdict = AebVerdict;
export type AebVerificationMode = 'execution' | 'historical';
export type AebJson = null | boolean | string | number | AebJson[] | {
    [key: string]: AebJson;
};
export type AebDigest = `sha256:${string}`;
export interface AebStatusInput {
    checked_at: string;
    expires_at: string;
    revocation_checked: boolean;
    revoked: boolean;
    consumed: boolean;
    /** A status source that could not be authenticated or reached. */
    unavailable?: boolean;
}
export interface AebNativeResult {
    native_verification: NativeVerification;
    acceptance: Acceptance;
    evidence_digest: AebDigest;
    /** Binds the adapter result to the status input it evaluated. */
    status_digest: AebDigest;
    evidence_role: string;
    subject: AebEvidenceSubject;
    /** Stable native authorization identity, independent of an AEB operation wrapper. */
    replay_unit: AebDigest;
    reasons: string[];
}
export interface AebEvidenceSubject {
    id: string;
    kind: 'human' | 'workload' | 'organization' | 'system';
}
export interface AebMappingResult {
    mapping: MappingVerdict;
    /** CAID derived by the adapter under the selected profile. */
    caid: string | null;
    action_digest: AebDigest | null;
    reasons: string[];
}
export interface AebAdapterInput {
    artifact: unknown;
    artifact_ref: string;
    status: AebStatusInput;
    trust_roots: readonly unknown[];
    /** Immutable relying-party configuration pinned by adapterConfigDigest. */
    adapter_config: unknown;
    profile: AebPinnedProfile;
    /** Exact action the relying party is deciding whether to execute. */
    expected_action: unknown;
    now: string;
}
export interface AebAdapter {
    readonly id: string;
    readonly version: string;
    /** Pure, deterministic native verification. No network or ambient trust. */
    verifyNative(input: Omit<AebAdapterInput, 'profile'>): AebNativeResult;
    /** Pure, deterministic projection and CAID derivation under a pinned profile. */
    mapAction(input: AebAdapterInput & {
        native: AebNativeResult;
    }): AebMappingResult;
}
export interface AebNativeVerificationAttestationBody {
    '@version': typeof AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION;
    protocol_id: string;
    audience: string;
    native_artifact_ref: string;
    native_artifact_digest: AebDigest;
    evidence_role: string;
    subject: AebEvidenceSubject;
    verified_at: string;
    expires_at: string;
    mapping: {
        profile_digest: AebDigest;
        mapper_id: string;
        resolver_digest: AebDigest;
        caid: string;
        normalized_action_digest: AebDigest;
    };
}
export interface AebNativeVerificationAttestation extends AebNativeVerificationAttestationBody {
    signature: {
        alg: 'Ed25519';
        key_id: string;
        value: string;
    };
}
export interface AebNativeVerificationAttestationSigner {
    key_id: string;
    private_key: KeyObject;
}
export interface AebPinnedAdapter {
    version: string;
    trust_roots: readonly unknown[];
    /** Adapter-specific immutable parameters, if any. */
    config?: unknown;
    /** Must equal adapterConfigDigest(id, this). */
    config_digest: AebDigest;
    /** Maximum age of the authenticated status input. */
    max_status_age_sec: number;
}
export interface AebPinnedProfile {
    version: string;
    definition?: unknown;
    registry_entry_ref: string;
    mapper_id: string;
    resolver: {
        id: string;
        version: string;
        implementation_digest: AebDigest;
    };
    semantic_equivalence: {
        assertion: 'EQUIVALENT_UNDER_PROFILE';
        loss_policy: 'NO_MATERIAL_FIELD_LOSS';
        omitted_material_fields: readonly string[];
        omitted_nonmaterial_fields: readonly string[];
    };
    /** Must equal profileDigest(id, this). */
    profile_digest: AebDigest;
}
export interface AebDistinctHumanQuorumTerm {
    type: 'distinct-human-quorum';
    role: string;
    threshold: number;
}
export interface AebInitiatorExclusionTerm {
    type: 'initiator-exclusion';
    roles: readonly string[];
}
export interface AebExecutorExclusionTerm {
    type: 'executor-exclusion';
    roles: readonly string[];
}
export interface AebOneTimeConsumptionTerm {
    type: 'one-time-consumption';
}
export type AebRequirementTerm = AebDistinctHumanQuorumTerm | AebInitiatorExclusionTerm | AebExecutorExclusionTerm | AebOneTimeConsumptionTerm;
export interface AebRequirement {
    '@version': typeof AEB_REQUIREMENT_VERSION;
    /** Every listed role must have a satisfied leg. */
    all_of: readonly string[];
    /** Each group requires at least one satisfied role. */
    any_of?: readonly (readonly string[])[];
    /** Authority and execution predicates evaluated in addition to the AEC role expression. */
    terms: readonly AebRequirementTerm[];
}
export type AebRegistryEntryKind = 'mapping-profile' | 'evidence-role' | 'receipt-extension';
export interface AebRegistryEntry {
    kind: AebRegistryEntryKind;
    version: string;
    status: 'active' | 'deprecated';
    definition: unknown;
    definition_digest: AebDigest;
}
export interface AebUnifiedRegistry {
    '@version': typeof AEB_REGISTRY_VERSION;
    registry_id: string;
    epoch: number;
    entries: Record<string, AebRegistryEntry>;
    registry_digest: AebDigest;
}
export interface AebEvaluatorKey {
    public_key: string;
}
export interface AebPinnedConfig {
    '@version': typeof AEB_ADAPTER_VERSION;
    relying_party_id: string;
    evaluator_keys: Record<string, AebEvaluatorKey>;
    registry: AebUnifiedRegistry;
    accepted_mappers: readonly string[];
    adapters: Record<string, AebPinnedAdapter>;
    profiles: Record<string, AebPinnedProfile>;
    requirements: Record<string, AebRequirement>;
}
export interface AebEvidenceLegInput {
    adapter_id: string;
    profile_id: string;
    artifact_ref: string;
    artifact: unknown;
    status: AebStatusInput;
}
export interface AebEvaluationSigner {
    key_id: string;
    private_key: KeyObject;
}
export interface AebEvaluationLeg {
    adapter_id: string;
    adapter_version: string;
    profile_id: string;
    profile_version: string;
    profile_digest: AebDigest;
    artifact_ref: string;
    evidence_digest: AebDigest;
    status_digest: AebDigest;
    replay_unit: AebDigest;
    evidence_role: string;
    subject: AebEvidenceSubject | null;
    mapper_id: string;
    resolver_digest: AebDigest;
    native_verification: NativeVerification;
    acceptance: Acceptance;
    mapping: MappingVerdict;
    action_digest: AebDigest | null;
    caid: string | null;
    freshness: AebFreshness;
    verdict: AebLegVerdict;
    reasons: string[];
}
export interface AebFreshness {
    checked_at: string;
    expires_at: string;
    revocation_checked: boolean;
    revoked: boolean;
    consumed: boolean;
    unavailable: boolean;
    age_seconds: number | null;
    fresh: boolean;
}
export interface AebEvaluationRecord {
    '@type': typeof AEB_EVALUATION_VERSION;
    operation_id: string;
    consumption_nonce: string;
    initiator_id: string;
    executor_id?: string;
    evaluator: {
        id: string;
        key_id: string;
        pinned_config_digest: AebDigest;
    };
    requirement_ref: string;
    requirement_digest: AebDigest;
    registry_digest: AebDigest;
    caid: string;
    legs: AebEvaluationLeg[];
    composition: {
        engine: typeof AEC_VERSION;
        requirement_expression: string;
        action_digest: AebDigest;
        satisfied: boolean;
    };
    authority_constraints: {
        distinct_human_quorum: boolean;
        initiator_exclusion: boolean;
        executor_exclusion: boolean;
        one_time_consumption: boolean;
    };
    verdict: AebVerdict;
    evaluated_at: string;
    evidence_digest: AebDigest;
    reasons: string[];
    signature?: {
        alg: 'Ed25519';
        key_id: string;
        value: string;
    };
}
export interface AebEvaluationResult {
    record: AebEvaluationRecord;
    valid: boolean;
    reasons: string[];
}
export interface AebEvaluationOptions {
    config: AebPinnedConfig;
    adapters: Record<string, AebAdapter>;
    operation_id: string;
    consumption_nonce: string;
    initiator_id: string;
    executor_id?: string;
    requirement_ref: string;
    caid: string;
    expected_action?: unknown;
    legs: readonly AebEvidenceLegInput[];
    evaluated_at: string;
    signer?: AebEvaluationSigner;
    /** Internal re-derivation input; callers should use signer instead. */
    evaluator_key_id?: string;
}
export interface AebVerificationOptions {
    config: AebPinnedConfig;
    adapters: Record<string, AebAdapter>;
    artifacts: Record<string, unknown>;
    /**
     * Historical verification can re-derive evidence but can never authorize
     * execution. Omission retains the PTE-compatible split: execution inputs
     * select execution mode; otherwise verification is historical.
     */
    mode?: AebVerificationMode;
    expected_action?: unknown;
    /** Fresh status results authenticated by the relying party at execution time. */
    current_statuses?: Record<string, AebStatusInput>;
    now?: string;
}
export interface AebEvaluationVerification {
    valid: boolean;
    /** True only for a complete, fresh execution-mode verification. */
    execution_authorizing: boolean;
    checks: {
        schema: boolean;
        signature: boolean;
        pinned_config: boolean;
        rederived: boolean;
        current_status: boolean;
        verdict: boolean;
    };
    reasons: string[];
}
export interface AebExecutionDecision {
    allowed: boolean;
    invoke_allowed: boolean;
    state: 'AUTHORIZED' | 'REFUSED' | 'RECONCILIATION_REQUIRED';
    reason: string;
    reservation_key?: string;
}
export interface AebConsumptionStore {
    reserve(key: string, replayKeys: readonly string[]): boolean;
    commit(key: string): boolean;
    release(key: string): boolean;
    state(key: string): 'AVAILABLE' | 'RESERVED' | 'CONSUMED';
}
/** Fleet-safe store contract implemented by @emilia-protocol/gate durable stores. */
export interface AebDurableConsumptionStore {
    durable: true;
    ownershipFenced: true;
    permanentConsumption: true;
    atomicReplayFenced: true;
    reserve(key: string, replayKeys: readonly string[]): Promise<boolean | AebReservationResult>;
    commit(key: string): Promise<boolean>;
    release(key: string): Promise<boolean>;
}
export type AebReservationResult = 'RESERVED' | 'CONSUMPTION_CONFLICT' | 'NATIVE_REPLAY_CONFLICT';
/** Small synchronous reference store. Production stores must provide an atomic equivalent. */
export declare class InMemoryAebConsumptionStore implements AebConsumptionStore {
    private readonly entries;
    private readonly replayOwners;
    reserve(key: string, replayKeys?: readonly string[]): boolean;
    commit(key: string): boolean;
    release(key: string): boolean;
    state(key: string): 'AVAILABLE' | 'RESERVED' | 'CONSUMED';
}
declare function canonicalize(value: unknown, seen?: WeakSet<object>): string;
declare function digest(value: unknown): AebDigest;
/** Sign the exact result emitted by a native verifier or protocol gateway. */
export declare function signAebNativeVerificationAttestation(body: AebNativeVerificationAttestationBody, signer: AebNativeVerificationAttestationSigner): AebNativeVerificationAttestation;
/**
 * Concrete bridge for WIMSE, RATS, permit, receipt, and other native verifiers.
 * The bridge verifies a pinned verifier's signed result; presenter assertions
 * and unsigned gateway headers never become evidence.
 */
export declare function createAebNativeVerificationAttestationAdapter(options: {
    id: string;
    version: string;
}): AebAdapter;
export declare function pinnedConfigDigest(config: AebPinnedConfig): AebDigest;
export declare function adapterPinDigest(id: string, pin: AebPinnedAdapter): AebDigest;
export declare function mappingProfileDigest(id: string, pin: AebPinnedProfile): AebDigest;
export declare function registryEntryDigest(id: string, entry: AebRegistryEntry): AebDigest;
export declare function unifiedRegistryDigest(registry: AebUnifiedRegistry): AebDigest;
export declare function evaluateAebEvidence(options: AebEvaluationOptions): AebEvaluationResult;
export declare function verifyAebEvaluation(record: unknown, options: AebVerificationOptions): AebEvaluationVerification;
export declare function authorizeAebExecution(record: AebEvaluationRecord, options: {
    verification: Pick<AebEvaluationVerification, 'valid' | 'execution_authorizing'>;
    local_authorization: boolean;
    store: AebConsumptionStore;
}): AebExecutionDecision;
/** Stable native approval identities that must be fenced with the operation reservation. */
export declare function aebNativeReplayKeys(record: Pick<AebEvaluationRecord, 'evaluator' | 'legs'>): string[];
/** Collision-resistant, tenant-scoped key used by both reference and durable stores. */
export declare function aebReservationKey(record: Pick<AebEvaluationRecord, 'evaluator' | 'composition' | 'caid' | 'operation_id' | 'consumption_nonce'>): string;
export declare function reconcileAebExecution(store: AebConsumptionStore, reservationKey: string, outcome: 'COMMITTED' | 'NOT_COMMITTED' | 'INDETERMINATE'): {
    state: 'CONSUMED' | 'AVAILABLE' | 'RECONCILIATION_REQUIRED';
    retry_allowed: boolean;
    reason: string;
};
/** Production authorization path for shared Postgres/Redis/DynamoDB-backed custody. */
export declare function authorizeAebExecutionDurable(record: AebEvaluationRecord, options: {
    verification: Pick<AebEvaluationVerification, 'valid' | 'execution_authorizing'>;
    local_authorization: boolean;
    store: unknown;
}): Promise<AebExecutionDecision>;
export declare function reconcileAebExecutionDurable(store: unknown, reservationKey: string, outcome: 'COMMITTED' | 'NOT_COMMITTED' | 'INDETERMINATE'): Promise<{
    state: 'CONSUMED' | 'AVAILABLE' | 'RECONCILIATION_REQUIRED';
    retry_allowed: boolean;
    reason: string;
}>;
export { canonicalize as canonicalizeAeb, digest as digestAeb };
//# sourceMappingURL=aeb-adapter-contract.d.ts.map