import crypto from 'node:crypto';
import type { ProviderEntryContext, ProviderEntryGuard } from './provider-entry.js';
import { type AgileSignature, type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
export declare const EXECUTION_VALUE_ATTESTATION_VERSION = "EP-EXECUTION-VALUE-ATTESTATION-v1";
type ExecutionValuePayload = Readonly<{
    version: typeof EXECUTION_VALUE_ATTESTATION_VERSION;
    action_digest: string;
    asset_currency: string;
    quote_currency: 'USD';
    value_minor: number;
    source: string;
    key_id: string;
    observed_at: string;
    expires_at: string;
}>;
export type ExecutionValueAttestation = Readonly<{
    payload: ExecutionValuePayload;
    signature: Readonly<{
        algorithm: 'Ed25519';
        value: string;
    }>;
}>;
/** Mint a role-specific value observation; the issuer key never rides in it. */
export declare function signExecutionValueAttestation(input: Omit<ExecutionValuePayload, 'version'>, privateKey: crypto.KeyLike): ExecutionValueAttestation;
export declare function verifyExecutionValueAttestation(attestation: unknown, { action, trustedKeys, allowedSources, maxValueMinor, maxAgeMs, now, }: {
    action: Record<string, any>;
    trustedKeys: Record<string, string>;
    allowedSources: readonly string[];
    maxValueMinor: number;
    maxAgeMs?: number;
    now?: number | (() => number);
}): {
    ok: boolean;
    reason: string;
    payload?: ExecutionValuePayload;
};
export declare const EXECUTION_VALUE_ATTESTATION_V2_VERSION = "EP-EXECUTION-VALUE-ATTESTATION-v2";
export declare const EXECUTION_VALUE_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
type ExecutionValuePayloadV2 = Readonly<{
    version: typeof EXECUTION_VALUE_ATTESTATION_V2_VERSION;
    action_digest: string;
    asset_currency: string;
    quote_currency: 'USD';
    value_minor: number;
    source: string;
    key_id: string;
    observed_at: string;
    expires_at: string;
}>;
export interface ExecutionValueAttestationV2Proof {
    required_algorithms: readonly string[];
    signatures: AgileSignature[];
}
export interface ExecutionValueAttestationV2 {
    payload: ExecutionValuePayloadV2;
    proof: ExecutionValueAttestationV2Proof;
}
/** Ed25519 SPKI DER + ML-DSA-65 raw public key, both base64url, pinned per key_id. */
export interface ExecutionValueTrustedKeyV2 {
    public_key: string;
    pq_public_key: string;
}
/** Mint a hybrid (Ed25519 + ML-DSA-65) role-specific value observation. */
export declare function signExecutionValueAttestationV2(input: Omit<ExecutionValuePayloadV2, 'version'>, keys: {
    privateKey: crypto.KeyLike;
    /** ML-DSA-65 raw secret key (4032 bytes), Uint8Array or base64url. */
    pqPrivateKey: Uint8Array | string;
}, options?: AgilityOptions): Promise<ExecutionValueAttestationV2>;
/**
 * FAIL-CLOSED hybrid verify. A v2 attestation NEVER verifies on one leg
 * alone; an absent ML-DSA backend is a refusal, never a skipped check and
 * never a pass on the surviving classical leg.
 */
export declare function verifyExecutionValueAttestationV2(attestation: unknown, { action, trustedKeys, allowedSources, maxValueMinor, maxAgeMs, now, ...agilityOptions }: {
    action: Record<string, any>;
    trustedKeys: Record<string, ExecutionValueTrustedKeyV2>;
    allowedSources: readonly string[];
    maxValueMinor: number;
    maxAgeMs?: number;
    now?: number | (() => number);
} & AgilityOptions): Promise<{
    ok: boolean;
    reason: string;
    payload?: ExecutionValuePayloadV2;
}>;
/**
 * Create the runtime value guard. USD actions are checked directly from the
 * exact observed action; every non-USD action requires a fresh signed oracle
 * observation bound to that action digest. Oracle outage fails closed.
 */
export declare function createExecutionValueProviderEntryGuard({ maxValueMinor, trustedKeys, allowedSources, resolveAttestation, maxAgeMs, now, }: {
    maxValueMinor: number;
    trustedKeys: Record<string, string>;
    allowedSources: readonly string[];
    resolveAttestation: (context: ProviderEntryContext) => unknown | Promise<unknown>;
    maxAgeMs?: number;
    now?: number | (() => number);
}): ProviderEntryGuard;
declare const _default: {
    EXECUTION_VALUE_ATTESTATION_VERSION: string;
    signExecutionValueAttestation: typeof signExecutionValueAttestation;
    verifyExecutionValueAttestation: typeof verifyExecutionValueAttestation;
    createExecutionValueProviderEntryGuard: typeof createExecutionValueProviderEntryGuard;
    EXECUTION_VALUE_ATTESTATION_V2_VERSION: string;
    signExecutionValueAttestationV2: typeof signExecutionValueAttestationV2;
    verifyExecutionValueAttestationV2: typeof verifyExecutionValueAttestationV2;
};
export default _default;
//# sourceMappingURL=execution-value.d.ts.map