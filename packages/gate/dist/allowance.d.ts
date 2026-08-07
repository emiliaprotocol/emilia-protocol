/**
 * Gate Allowance v1.
 *
 * A Gate allowance is a customer-signed, time-bounded authorization envelope
 * for one typed connector action. It does not hold provider credentials and it
 * does not authorize arbitrary tools. The capability store remains the atomic
 * budget, replay, and post-entry uncertainty boundary.
 */
import { type KeyLike, type KeyObject } from 'node:crypto';
import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
export declare const GATE_ALLOWANCE_VERSION = "EP-GATE-ALLOWANCE-v1";
export declare const GATE_ALLOWANCE_CLAIM_BOUNDARY = "one_bounded_period_and_typed_connector_not_recurring_schedule_generic_tool_safety_or_complete_mediation";
type AllowanceSigner = {
    issuer_id: string;
    key_id: string;
    private_key: KeyLike;
};
type CapabilityKeyMaterial = KeyObject | string | Buffer;
type ExpectedAllowanceContext = {
    allowance_id: string;
    tenant_id: string;
    subject_id: string;
    audience: string;
    connector_id: string;
    authorizer_id: string;
};
/** Sign a closed Gate allowance with a customer-controlled Ed25519 key. */
export declare function signGateAllowance(input: unknown, signer: AllowanceSigner): RiskRecord;
/** Digest the signed allowance, including its proof. */
export declare function allowanceDigest(artifact: unknown): string;
/** Verify signature, closed shape, validity, and relying-party context. */
export declare function verifyGateAllowance(artifact: unknown, { trusted_keys, now, expected_allowance_id, expected_tenant_id, expected_subject_id, expected_audience, expected_connector_id, expected_authorizer_id, }?: {
    trusted_keys?: TrustedRiskKeys;
    now?: number | (() => number);
    expected_allowance_id?: string;
    expected_tenant_id?: string;
    expected_subject_id?: string;
    expected_audience?: string;
    expected_connector_id?: string;
    expected_authorizer_id?: string;
}): RiskRecord;
/**
 * Issue the signed allowance and its atomic monetary capability.
 *
 * The caller still owns verification of the authorizing receipt. This function
 * binds the exact receipt bytes to both artifacts; it does not claim that the
 * receipt is trustworthy merely because it exists.
 */
export declare function issueGateAllowance({ authorizationReceipt, allowance, predecessorAllowance, signer, capabilityIssuerPrivateKey, capabilityRevocationMode, capabilityId, secret, }?: {
    authorizationReceipt?: RiskRecord;
    allowance?: RiskRecord;
    predecessorAllowance?: RiskRecord;
    signer?: AllowanceSigner;
    capabilityIssuerPrivateKey?: CapabilityKeyMaterial;
    capabilityRevocationMode?: 'direct' | 'cascade';
    capabilityId?: string;
    secret?: Buffer | string;
}): RiskRecord;
/**
 * Execute one typed, in-envelope action through the existing capability ledger.
 */
export declare function executeWithGateAllowance({ allowance, capabilityReceipt, secret, action, operationId, store, executeAction, verifyAuthorizationReceipt, verifyAllowanceStatus, trustedAllowanceKeys, trustedCapabilityIssuerKeys, expected, providerEntryGuard, now, }?: {
    allowance?: RiskRecord;
    capabilityReceipt?: RiskRecord;
    secret?: Buffer | string;
    action?: RiskRecord;
    operationId?: string;
    store?: RiskRecord;
    executeAction?: (...args: any[]) => any;
    verifyAuthorizationReceipt?: ((receipt: RiskRecord, allowance: RiskRecord) => any) | null;
    verifyAllowanceStatus?: ((allowance: RiskRecord, context: {
        allowance_digest: string;
        revision: number;
        supersedes_allowance_digest: string | null;
    }) => {
        ok: boolean;
        reason?: string;
        status_epoch?: number;
        status_head_digest?: string;
    } | Promise<{
        ok: boolean;
        reason?: string;
        status_epoch?: number;
        status_head_digest?: string;
    }>) | null;
    trustedAllowanceKeys?: TrustedRiskKeys;
    trustedCapabilityIssuerKeys?: string[];
    expected?: ExpectedAllowanceContext;
    providerEntryGuard?: ((context: RiskRecord) => any) | null;
    now?: number | (() => number);
}): Promise<RiskRecord>;
declare const _default: {
    GATE_ALLOWANCE_VERSION: string;
    GATE_ALLOWANCE_CLAIM_BOUNDARY: string;
    allowanceDigest: typeof allowanceDigest;
    signGateAllowance: typeof signGateAllowance;
    verifyGateAllowance: typeof verifyGateAllowance;
    issueGateAllowance: typeof issueGateAllowance;
    executeWithGateAllowance: typeof executeWithGateAllowance;
};
export default _default;
//# sourceMappingURL=allowance.d.ts.map