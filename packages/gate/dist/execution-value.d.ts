import crypto from 'node:crypto';
import type { ProviderEntryContext, ProviderEntryGuard } from './provider-entry.js';
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
};
export default _default;
//# sourceMappingURL=execution-value.d.ts.map