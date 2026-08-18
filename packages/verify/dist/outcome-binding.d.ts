import { type AgilityOptions } from './pq-signature-agility.js';
type Obj = Record<string, any>;
interface OutcomeOptions {
    executorKeys?: Record<string, Obj>;
    now?: string;
    receiptOptions?: Obj;
    policyPredictedEffects?: any[];
}
interface OutcomeSetOptions extends OutcomeOptions {
    sourceKeys?: Record<string, Obj>;
    sourceRequirements?: Obj[];
    observationWindows?: Obj[];
    expectedReceiptId?: string;
    expectedReceiptDigest?: string;
    expectedActionHash?: string;
    expectedConsumptionNonce?: string;
    expectedActionCaid?: string;
    expectedOperationId?: string;
    expectedFacilityId?: string;
}
export declare const OUTCOME_ATTESTATION_VERSION = "EP-OUTCOME-ATTESTATION-v1";
export declare const OUTCOME_ATTESTATION_DOMAIN = "EP-OUTCOME-ATTESTATION-v1\0";
export declare const OUTCOME_BINDING_VERSION = "EP-OUTCOME-BINDING-v1";
export declare const OUTCOME_BINDING_RESULT_VERSION = "EP-OUTCOME-BINDING-RESULT-v1";
export declare const OUTCOME_OBSERVATION_VERSION = "EP-OUTCOME-OBSERVATION-v1";
export declare const OUTCOME_OBSERVATION_DOMAIN = "EP-OUTCOME-OBSERVATION-v1\0";
export declare const OUTCOME_BINDING_SET_VERSION = "EP-OUTCOME-BINDING-SET-v1";
export declare const OUTCOME_BINDING_SET_RESULT_VERSION = "EP-OUTCOME-BINDING-SET-RESULT-v1";
/** Digest over the exact observed_effects array carried by the attestation. */
export declare function observedEffectsDigest(observedEffects: unknown): string;
/** Digest of the exact Trust Receipt object the attestation references. */
export declare function trustReceiptDigest(receipt: unknown): string;
/**
 * Canonical digest preimage for an Outcome Binding verifier result.
 *
 * The core commits the exact inputs by digest, every independent binding
 * check, all refusal reasons and evaluations, the acceptance bit, and the
 * reported verdict. It deliberately excludes result_digest itself.
 */
export declare function outcomeBindingResultCore(result: unknown): Obj;
/** sha256:<hex> over the canonical Outcome Binding result core. */
export declare function outcomeBindingResultDigest(result: unknown): string;
/**
 * Recompute and constant-time compare an Outcome Binding result digest.
 *
 * This verifies result integrity only. Call verifyOutcomeBinding to verify the
 * receipt, attestation, policy composition, and exact receipt/action/nonce
 * bindings that produced the result.
 */
export declare function verifyOutcomeBindingResultDigest(result: unknown, claimedDigest?: unknown): boolean;
/**
 * Build an executor-signed observed-effects attestation.
 *
 * @param {{
 *   receipt_id?: string,
 *   receipt_digest?: string,
 *   action_hash?: string,
 *   consumption_nonce?: string,
 *   execution_id?: string,
 *   executor_id?: string,
 *   executed_at?: string,
 *   observed_effects?: Array<object>,
 *   signer?: {
 *     privateKey?: import('node:crypto').KeyObject,
 *     publicKey?: string,
 *     key_id?: string
 *   }
 * }} [args]
 */
export declare function buildOutcomeAttestation({ receipt_id, receipt_digest, action_hash, consumption_nonce, execution_id, executor_id, executed_at, observed_effects, signer, }?: Obj): Obj;
/**
 * Verify the executor attestation under a relying-party-pinned executor key.
 *
 * @param {object} attestation
 * @param {{
 *   executorKeys?: Record<string, {public_key?: string, key_id?: string}>,
 *   now?: string
 * }} [opts]
 */
export declare function verifyOutcomeAttestation(attestation: Obj, opts?: OutcomeOptions): {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
};
/** Build a signed observation from an executor, system of record, or independent observer. */
export declare function buildOutcomeObservation({ receipt_id, receipt_digest, action_hash, action_caid, consumption_nonce, operation_id, source, observed_from, observed_until, attested_at, observed_effects, signer, }?: Obj): Obj;
/** Verify one signed outcome observation under a relying-party-pinned source identity. */
export declare function verifyOutcomeObservation(observation: Obj, opts?: OutcomeSetOptions): {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
};
export declare function outcomeBindingSetResultDigest(result: unknown): string;
/**
 * Verify, route, and reconcile a set of signed source observations against
 * signed predictions. This function is authorization-format neutral; callers
 * must separately verify and bind the authorization artifact itself.
 */
export declare function verifyOutcomeObservationSet(predictedEffects: any[], observations: Obj[], opts?: OutcomeSetOptions): Obj;
/** Verify a Trust Receipt and then reconcile all required signed outcome sources. */
export declare function verifyOutcomeBindingSetCore(receipt: Obj, observations: Obj[], opts: OutcomeSetOptions | undefined, verifyReceipt: any): Obj;
/**
 * Core composition. `verifyReceipt` must perform the full Trust Receipt
 * cryptographic verification; the main package export injects
 * verifyTrustReceipt. This shape keeps the module independently testable.
 */
export declare function verifyOutcomeBindingCore(receipt: Obj, attestation: Obj, opts: OutcomeOptions | undefined, verifyReceipt: any): {
    result_digest: string;
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
    input_commitments: {
        receipt_digest: string | null;
        attestation_digest: string | null;
        signed_predictions_digest: string | null;
        signed_predictions_commitment: string | null;
        policy_predictions_present: boolean;
        policy_predictions_digest: string | null;
    };
    receipt: Obj;
    attestation: Obj;
    commitments: {
        receipt_id: string | null;
        attested_receipt_id: string | null;
        receipt_digest: string | null;
        attested_receipt_digest: string | null;
        action_hash: string | null;
        attested_action_hash: string | null;
        consumption_nonce: any;
        attested_consumption_nonce: string | null;
        execution_id: string | null;
        executor_id: string | null;
        executor_key_id: any;
        observed_effects_digest: string | null;
    };
    receipt_result: any;
    attestation_result: any;
    outcome_binding: {
        '@version': string;
        outcome: string;
        evaluations: never[];
        reasons: string[];
    };
} | {
    result_digest: string;
    valid: boolean;
    checks: Record<string, boolean>;
    errors: any[];
    input_commitments: {
        receipt_digest: string | null;
        attestation_digest: string | null;
        signed_predictions_digest: string | null;
        signed_predictions_commitment: string | null;
        policy_predictions_present: boolean;
        policy_predictions_digest: string | null;
    };
    receipt: Obj;
    attestation: Obj;
    commitments: {
        receipt_id: string | null;
        attested_receipt_id: string | null;
        receipt_digest: string | null;
        attested_receipt_digest: string | null;
        action_hash: string | null;
        attested_action_hash: string | null;
        consumption_nonce: any;
        attested_consumption_nonce: string | null;
        execution_id: string | null;
        executor_id: string | null;
        executor_key_id: any;
        observed_effects_digest: string | null;
    };
    receipt_result: any;
    attestation_result: any;
    outcome_binding: Obj;
};
/**
 * Reference hybrid migration for both signed artifacts in this file. Copies
 * the five moves from EP-REVOCATION-v2 (packages/verify/src/revocation.ts):
 *
 * 1. VERSION BUMP. `@version` moves -v1 to -v2 for each artifact.
 *    verifyOutcomeAttestation/verifyOutcomeObservation above are UNCHANGED
 *    and refuse a v2 artifact on the `@version` marker (via `exactKeys`
 *    against the unchanged v1 key sets, since `required_algorithms` is not a
 *    v1 field) before any signature is inspected.
 * 2. SET SHAPE. `proof.signatures` carries exactly the two AgileSignature
 *    entries ({alg, sig, key_id}) for Ed25519 and ML-DSA-65, reusing
 *    EP-SIG-AGILITY-v1's shape verbatim.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is a TOP-LEVEL field of the
 *    artifact (inside the signed bytes via the existing `unsigned()` helper,
 *    which strips only `proof`), independently recomputed from the
 *    registered set.
 * 4. V1 COMPATIBILITY. v1 artifacts keep verifying, unchanged, through the
 *    sync functions above. v2 verification is a separate ASYNC entry point.
 * 5. NAMED REFUSALS. Nothing throws on caller input; a missing ML-DSA backend
 *    is 'pq_backend_unavailable' from the agility module, never a pass on the
 *    Ed25519 leg alone.
 *
 * SCOPE BOUNDARY: only the two SIGNED leaves (executor attestation, source
 * observation) are hybridized here. verifyOutcomeObservationSet /
 * verifyOutcomeBindingCore / verifyOutcomeBindingSetCore are COMPOSITIONS
 * that reconcile predictions against already-verified observations; they
 * take a caller-injected verifyReceipt and operate on whichever version's
 * verify* function opts route to. Rewiring those compositions to accept a
 * mixed v1/v2 observation bag is a separate, larger change left to the
 * receipt-issuance hybridization workstream (packages/issue,
 * packages/verify/src/index.ts) that owns EP-RECEIPT-v1/v2 itself; this file
 * adds the leaves purely additively so lib/evidence/evidence-graph.ts's
 * existing EP-OUTCOME-BINDING-v1 consumption is unaffected.
 */
export declare const OUTCOME_ATTESTATION_V2_VERSION = "EP-OUTCOME-ATTESTATION-v2";
export declare const OUTCOME_ATTESTATION_V2_DOMAIN = "EP-OUTCOME-ATTESTATION-v2\0";
export declare const OUTCOME_OBSERVATION_V2_VERSION = "EP-OUTCOME-OBSERVATION-v2";
export declare const OUTCOME_OBSERVATION_V2_DOMAIN = "EP-OUTCOME-OBSERVATION-v2\0";
/** The registered required algorithm set, in canonical order. */
export declare const OUTCOME_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
interface OutcomeV2Options extends AgilityOptions {
    executorKeys?: Record<string, {
        public_key?: string;
        pq_public_key?: string;
        key_id?: string;
        pq_key_id?: string;
    }>;
    now?: string;
}
/** Build an executor-signed hybrid observed-effects attestation. */
export declare function buildOutcomeAttestationV2({ receipt_id, receipt_digest, action_hash, consumption_nonce, execution_id, executor_id, executed_at, observed_effects, signer, }?: Obj): Promise<Obj>;
/** Verify a hybrid executor attestation. Async; never verifies on one leg alone. */
export declare function verifyOutcomeAttestationV2(attestation: Obj, opts?: OutcomeV2Options): Promise<{
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
}>;
/** Build a hybrid-signed observation from an executor, system of record, or independent observer. */
export declare function buildOutcomeObservationV2({ receipt_id, receipt_digest, action_hash, action_caid, consumption_nonce, operation_id, source, observed_from, observed_until, attested_at, observed_effects, signer, }?: Obj): Promise<Obj>;
/** Verify one hybrid-signed outcome observation. Async; never verifies on one leg alone. */
export declare function verifyOutcomeObservationV2(observation: Obj, opts?: OutcomeSetOptions & AgilityOptions): Promise<{
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
}>;
export declare const OUTCOME_BINDING_OUTCOMES: readonly string[];
export {};
//# sourceMappingURL=outcome-binding.d.ts.map