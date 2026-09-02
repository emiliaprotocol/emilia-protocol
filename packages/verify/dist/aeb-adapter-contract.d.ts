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
import { type AgilityOptions } from './pq-signature-agility.js';
import type { AebExecutionConditionsResult } from './aeb-execution-conditions.js';
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
    /**
     * Native, signature-verified links to other evidence roles. These links do
     * not satisfy those roles; an `evidence-binding` requirement must still
     * match them to independently verified AEB legs.
     */
    evidence_bindings?: readonly AebEvidenceBinding[];
    reasons: string[];
}
export interface AebEvidenceBinding {
    role: string;
    evidence_digest: AebDigest;
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
export interface AebEvidenceBindingTerm {
    type: 'evidence-binding';
    source_role: string;
    target_role: string;
    require_same_subject: true;
}
export type AebRequirementTerm = AebDistinctHumanQuorumTerm | AebInitiatorExclusionTerm | AebExecutorExclusionTerm | AebEvidenceBindingTerm | AebOneTimeConsumptionTerm;
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
    evidence_bindings?: AebEvidenceBinding[];
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
    /** Digest of the exact signed record this verification result covers. */
    record_digest: AebDigest | null;
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
    /** Relying-party-pinned AEB program/configuration that made the decision. */
    program_digest: AebDigest;
    reservation_key?: string;
}
export interface AebConsumptionStore {
    reserve(key: string, replayKeys: readonly string[]): boolean;
    commit(key: string): boolean;
    /**
     * NON-TERMINAL abort for an attempt that provably never reached the
     * provider, observed locally before any invocation (a refused gate decision,
     * an unavailable attempt store). The action instance is untouched, so the
     * same evaluation record may be presented again.
     */
    release(key: string): boolean;
    /**
     * TERMINAL released-not-entered marker for an AUTHORITATIVE serialized
     * non-entry. draft-schrock-action-evidence-boundary-04 s5.11: reconciliation
     * never resurrects the original authorization and never silently releases its
     * one-time replay unit, so the key stays permanently unreservable and
     * uncommittable and the native replay fences it installed stay installed. A
     * later attempt permitted by policy MUST carry a new action instance.
     */
    releaseTerminal(key: string): boolean;
    state(key: string): AebConsumptionState;
}
export type AebConsumptionState = 'AVAILABLE' | 'RESERVED' | 'CONSUMED' | 'RELEASED_NOT_ENTERED';
/** Fleet-safe store contract implemented by @emilia-protocol/gate durable stores. */
export interface AebDurableConsumptionStore {
    durable: true;
    ownershipFenced: true;
    permanentConsumption: true;
    atomicReplayFenced: true;
    /**
     * Declares that releaseTerminal() installs a permanent released-not-entered
     * marker. A store that does not declare it cannot reconcile an authoritative
     * NOT_COMMITTED result at all: reconcileAebExecutionDurable() refuses rather
     * than falling back to the non-terminal release() that would hand the same
     * one-time unit back to the same action instance.
     */
    terminalRelease?: true;
    reserve(key: string, replayKeys: readonly string[]): Promise<boolean | AebReservationResult>;
    commit(key: string): Promise<boolean>;
    release(key: string): Promise<boolean>;
    releaseTerminal?(key: string): Promise<boolean>;
}
export type AebReservationResult = 'RESERVED' | 'CONSUMPTION_CONFLICT' | 'NATIVE_REPLAY_CONFLICT';
/**
 * Outcome of reconciling one reservation against an authenticated provider
 * result. `retry_requires_new_instance` is unconditionally true: no
 * reconciliation outcome ever re-authorizes the action instance that was
 * already presented, so a policy-permitted later attempt has to carry a new
 * consumption nonce and operation identifier, which derives a new key.
 */
export interface AebReconciliationResult {
    state: 'CONSUMED' | 'RELEASED_NOT_ENTERED' | 'RECONCILIATION_REQUIRED';
    retry_allowed: boolean;
    retry_requires_new_instance: true;
    reason: string;
}
/** Small synchronous reference store. Production stores must provide an atomic equivalent. */
export declare class InMemoryAebConsumptionStore implements AebConsumptionStore {
    private readonly entries;
    private readonly replayOwners;
    reserve(key: string, replayKeys?: readonly string[]): boolean;
    commit(key: string): boolean;
    release(key: string): boolean;
    releaseTerminal(key: string): boolean;
    state(key: string): AebConsumptionState;
}
declare function canonicalize(value: unknown): string;
declare function digest(value: unknown): AebDigest;
declare function typedDigest(value: unknown, domainTag: string): AebDigest;
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
    verification: Pick<AebEvaluationVerification, 'valid' | 'execution_authorizing' | 'record_digest'>;
    local_authorization: boolean;
    store: AebConsumptionStore;
    /** Locally evaluated, relying-party-pinned execution conditions. */
    execution_conditions?: AebExecutionConditionsResult;
    /** Extra profile replay identities reserved atomically with native evidence. */
    additional_replay_keys?: readonly string[];
}): AebExecutionDecision;
/** Stable native approval identities that must be fenced with the operation reservation. */
export declare function aebNativeReplayKeys(record: Pick<AebEvaluationRecord, 'evaluator' | 'legs'>): string[];
/** Collision-resistant, tenant-scoped key used by both reference and durable stores. */
export declare function aebReservationKey(record: Pick<AebEvaluationRecord, 'evaluator' | 'composition' | 'caid' | 'operation_id' | 'consumption_nonce'>): string;
/**
 * Reconcile one reservation against an authenticated provider outcome.
 *
 * draft-schrock-action-evidence-boundary-04 s5.10 and s5.11 govern this
 * function. An INDETERMINATE outcome preserves the reservation and refuses a
 * blind replay. An authoritative NOT_COMMITTED outcome does not hand the
 * one-time replay unit back: it marks the reservation permanently
 * RELEASED_NOT_ENTERED, so the same authorization and operation identifier can
 * never be reserved again and a late COMMITTED for that attempt stays refused.
 */
export declare function reconcileAebExecution(store: AebConsumptionStore, reservationKey: string, outcome: 'COMMITTED' | 'NOT_COMMITTED' | 'INDETERMINATE'): AebReconciliationResult;
/** Production authorization path for shared Postgres/Redis/DynamoDB-backed custody. */
export declare function authorizeAebExecutionDurable(record: AebEvaluationRecord, options: {
    verification: Pick<AebEvaluationVerification, 'valid' | 'execution_authorizing' | 'record_digest'>;
    local_authorization: boolean;
    store: unknown;
    /** Locally evaluated, relying-party-pinned execution conditions. */
    execution_conditions?: AebExecutionConditionsResult;
    /** Extra profile replay identities reserved atomically with native evidence. */
    additional_replay_keys?: readonly string[];
}): Promise<AebExecutionDecision>;
/** Production reconciliation path. Same s5.10/s5.11 semantics as the reference path. */
export declare function reconcileAebExecutionDurable(store: unknown, reservationKey: string, outcome: 'COMMITTED' | 'NOT_COMMITTED' | 'INDETERMINATE'): Promise<AebReconciliationResult>;
export { canonicalize as canonicalizeAeb, digest as digestAeb, typedDigest as digestAebTyped };
/**
 * SCOPE. This migrates the ONE signature surface in this module that EP owns
 * and mints: the native verification attestation a pinned native verifier or
 * protocol gateway signs. The AEB ADAPTER halves (aeb-aps, aeb-ccs, aeb-chap,
 * aeb-mcgraw, aeb-oasnt, aeb-oauth-transaction-challenge, aeb-psea, aeb-wag,
 * aeb-wimse-oauth, ap2-native, fido-ap2-bridge) verify artifacts minted by
 * FOREIGN signers under foreign wire formats and are deliberately excluded:
 * the foreign signer chooses the algorithm, so there is no EP leg to add.
 *
 * The five moves from EP-REVOCATION-v2 (docs/protocol/pq-hybrid-program.md),
 * applied here:
 *
 * 1. VERSION BUMP. A second signature changes the SHAPE of `signature`, so the
 *    attestation takes a new `@version`. `nativeAttestationShape()` above is
 *    untouched and pins `@version` to the v1 marker, so the SYNCHRONOUS v1
 *    adapter (createAebNativeVerificationAttestationAdapter) refuses a v2
 *    attestation with `native_attestation_malformed` BEFORE it inspects any
 *    signature, and it does not throw. That refusal is asserted by test.
 *
 * 2. SET SHAPE. `proof` carries `required_algorithms` plus a `signatures`
 *    array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }), one entry per registered algorithm. Ed25519
 *    keeps its base64url SPKI DER public key; ML-DSA-65 carries raw base64url
 *    public key bytes.
 *
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is inside the signed
 *    bytes. The verifier rebuilds those bytes from the REGISTERED set and from
 *    the body it re-derived itself, so a narrowed `required_algorithms` both
 *    fails structurally AND breaks the surviving classical signature.
 *
 * 4. V1 COMPATIBILITY. The v1 signer/verifier and the v1 AebAdapter are
 *    unchanged and stay SYNCHRONOUS. ML-DSA verification is asynchronous, and
 *    the AebAdapter contract's verifyNative() is synchronous by definition, so
 *    v2 is a SEPARATE async entry point rather than a new adapter. There is no
 *    hybrid AebAdapter in this release, and that is a contract limit, not an
 *    oversight.
 *
 * 5. NAMED REFUSALS. Every failure names a check and pushes an error; nothing
 *    throws on caller input. An absent ML-DSA backend surfaces as
 *    `pq_backend_unavailable` through the agility result and is never a pass
 *    on the classical leg.
 *
 * HONEST BOUNDARY. A verified v2 attestation proves a pinned verifier signed
 * exactly this native result under BOTH algorithms. It does not make the
 * FOREIGN artifact the verifier examined post-quantum secure: that artifact's
 * own signature is whatever its issuer used. This profile is opt-in and is not
 * deployed, default, or certified anywhere.
 */
export declare const AEB_NATIVE_VERIFICATION_ATTESTATION_V2_VERSION = "EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v2";
export declare const AEB_NATIVE_VERIFICATION_ATTESTATION_V2_DOMAIN = "EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v2\0";
/** The registered required algorithm set, in canonical order. */
export declare const AEB_NATIVE_ATTESTATION_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface AebNativeVerificationAttestationV2Body extends Omit<AebNativeVerificationAttestationBody, '@version'> {
    '@version': typeof AEB_NATIVE_VERIFICATION_ATTESTATION_V2_VERSION;
}
export interface AebNativeAttestationV2Signature {
    alg?: unknown;
    sig?: unknown;
    key_id?: unknown;
}
export interface AebNativeAttestationV2Proof {
    profile?: unknown;
    required_algorithms?: unknown;
    /** Ed25519: base64url SPKI DER. */
    public_key?: unknown;
    /** ML-DSA-65: base64url of the raw 1952-byte public key. */
    pq_public_key?: unknown;
    signatures?: unknown;
    [key: string]: unknown;
}
export interface AebNativeVerificationAttestationV2 extends AebNativeVerificationAttestationV2Body {
    proof: AebNativeAttestationV2Proof;
}
/** A v2 verifier pin: BOTH public halves, pinned out of band by the relying party. */
export interface AebNativeAttestationV2KeyPin {
    key_id: string;
    /** Ed25519 base64url SPKI DER. */
    public_key: string;
    pq_key_id: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key: string;
}
export interface AebNativeAttestationV2Signer {
    key_id: string;
    private_key: KeyObject;
    pq_key_id: string;
    /** ML-DSA-65 raw 4032-byte secret key (Uint8Array or base64url). */
    pq_secret_key: Uint8Array | string;
    /** ML-DSA-65 raw 1952-byte public key, base64url. Placed in the proof. */
    pq_public_key: string;
}
export interface AebNativeAttestationV2Result {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
}
/**
 * The bytes BOTH legs sign: the domain tag, the attestation body, and the
 * REGISTERED algorithm set. Recomputed independently by the verifier; the
 * presented attestation never chooses what it is checked against.
 */
export declare function aebNativeAttestationV2SigningBytes(body: AebNativeVerificationAttestationV2Body, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * Sign a v2 native verification attestation under BOTH registered algorithms.
 * Issuer-side misuse throws (a programming error, not attacker input); an
 * unavailable ML-DSA backend throws rather than silently minting a v2
 * attestation with one leg.
 */
export declare function signAebNativeVerificationAttestationV2(body: AebNativeVerificationAttestationV2Body, signer: AebNativeAttestationV2Signer, options?: AgilityOptions): Promise<AebNativeVerificationAttestationV2>;
/**
 * verifyAebNativeVerificationAttestationV2 -- FAIL-CLOSED hybrid check.
 * Never throws on caller input. A v2 attestation NEVER verifies on one leg.
 */
export declare function verifyAebNativeVerificationAttestationV2(attestation: unknown, pin: AebNativeAttestationV2KeyPin | null | undefined, options?: AgilityOptions): Promise<AebNativeAttestationV2Result>;
//# sourceMappingURL=aeb-adapter-contract.d.ts.map