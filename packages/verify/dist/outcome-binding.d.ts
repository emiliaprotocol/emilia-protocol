type Obj = Record<string, any>;
interface OutcomeOptions {
    executorKeys?: Record<string, Obj>;
    now?: string;
    receiptOptions?: Obj;
    policyPredictedEffects?: any[];
}
export declare const OUTCOME_ATTESTATION_VERSION = "EP-OUTCOME-ATTESTATION-v1";
export declare const OUTCOME_ATTESTATION_DOMAIN = "EP-OUTCOME-ATTESTATION-v1\0";
export declare const OUTCOME_BINDING_VERSION = "EP-OUTCOME-BINDING-v1";
/** Digest over the exact observed_effects array carried by the attestation. */
export declare function observedEffectsDigest(observedEffects: unknown): string;
/** Digest of the exact Trust Receipt object the attestation references. */
export declare function trustReceiptDigest(receipt: unknown): string;
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
export declare const OUTCOME_BINDING_OUTCOMES: readonly string[];
export {};
//# sourceMappingURL=outcome-binding.d.ts.map