/**
 * MEMORY-PROJECTION-RECORD-v1.
 *
 * Provider-neutral producer and verifier for
 * draft-ferro-schrock-memory-projection-record-00.
 *
 * The envelope verifier proves the closed record shape, adapter signature,
 * key status, freshness, and nonclaims. The full verifier additionally
 * rehashes the exact request, policy, trust snapshot, source objects,
 * fragments, and complete projection bytes, and delegates native source
 * verification to the source-profile implementation selected by the relying
 * party.
 */
import crypto from 'node:crypto';
type Obj = Record<string, any>;
export declare const MEMORY_PROJECTION_RECORD_VERSION = "MEMORY-PROJECTION-RECORD-v1";
export declare const MEMORY_PROJECTION_RECORD_DOMAIN = "MEMORY-PROJECTION-RECORD-v1\0";
export declare const MEMORY_PROJECTION_NONCLAIMS: Readonly<{
    model_use: "NOT_ESTABLISHED";
    action_linkage: "NOT_ESTABLISHED";
    action_authorization: "NOT_ESTABLISHED";
    execution_outcome: "NOT_ESTABLISHED";
}>;
export type MemoryProjectionTrust = 'self' | 'trusted' | 'unverified';
export type MemoryProjectionAuthorship = 'signed' | 'attested' | 'unknown';
export interface MemoryProjectionAdapterKey {
    public_key_spki_b64u: string;
    status: 'active' | 'revoked' | 'superseded';
    valid_from: string;
    valid_to: string;
    revoked_at: string | null;
}
export interface MemoryProjectionDeliveredInput {
    formatVersion: number;
    sealedObjectBytes: Uint8Array;
    contextFragmentBytes: Uint8Array;
    derivedTrust: MemoryProjectionTrust;
    authorship: MemoryProjectionAuthorship;
    authorKeyIdB64u: string | null;
    custodyPresent: boolean;
}
export interface MemoryProjectionProducerInput {
    sourceProfile: string;
    projectionId: string;
    createdAt: string;
    adapter: {
        id: string;
        keyId: string;
    };
    selectionContext: {
        recallRequestBytes: Uint8Array;
        selectionPolicyBytes: Uint8Array;
        trustSnapshotBytes: Uint8Array;
        trustEvaluatedAt: string;
        contextFrameProfile: string;
    };
    delivered: MemoryProjectionDeliveredInput[];
    exclusions: {
        authenticationFailed: number;
        schemaInvalid: number;
        policyFiltered: number;
        contextLimit: number;
    };
    privateKey: crypto.KeyLike;
}
export interface MemoryProjectionVerificationPolicy {
    adapterKeys: Record<string, MemoryProjectionAdapterKey>;
    verificationTime: string;
    maxProjectionAgeSec: number;
    maxTrustAgeSec: number;
    expectedSourceProfile?: string;
    expectedContextFrameProfile?: string;
}
export interface MemoryProjectionNativeSourceResult {
    valid: true;
    formatVersion: number;
    sealedObjectDigest: string;
    derivedTrust: MemoryProjectionTrust;
    authorship: MemoryProjectionAuthorship;
    authorKeyIdB64u: string | null;
    custodyPresent: boolean;
}
export interface MemoryProjectionVerificationMaterial {
    recallRequestBytes: Uint8Array;
    selectionPolicyBytes: Uint8Array;
    trustSnapshotBytes: Uint8Array;
    sourceObjectBytesByPosition: Uint8Array[];
    fragmentBytesByPosition: Uint8Array[];
    projectionBytes: Uint8Array;
    verifySourceEntry: (input: {
        sourceProfile: string;
        position: number;
        sourceObjectBytes: Uint8Array;
        deliveredEntry: Readonly<Obj>;
    }) => MemoryProjectionNativeSourceResult;
}
export interface MemoryProjectionIdRegistry {
    /**
     * Atomically register one projection identifier.
     * Return false when it was already registered.
     */
    register(projectionId: string): boolean;
}
export declare class MemoryProjectionVerificationError extends Error {
    readonly code: string;
    constructor(code: string, message: string);
}
/**
 * Verify the closed signed envelope without requiring plaintext memory,
 * request, policy, trust-snapshot, fragment, or projection bytes.
 *
 * This is the correct boundary for a downstream Gate that receives only the
 * adapter's signed commitments. It does not claim those commitment preimages
 * were independently rehashed.
 */
export declare function verifyMemoryProjectionRecordV1Envelope(record: unknown, policy: MemoryProjectionVerificationPolicy): {
    valid: true;
    verification_scope: 'SIGNED_ENVELOPE_ONLY';
    projection_id: string;
    projection_digest: string;
    delivered_count: number;
    excluded_count: number;
    created_at: string;
    trust_evaluated_at: string;
};
/**
 * Fully verify every commitment preimage and native source result.
 */
export declare function verifyMemoryProjectionRecordV1(record: unknown, material: MemoryProjectionVerificationMaterial, policy: MemoryProjectionVerificationPolicy, options?: {
    projectionIdRegistry?: MemoryProjectionIdRegistry;
    requireSingleUse?: boolean;
}): {
    valid: true;
    verification_scope: 'FULL_PROJECTION_AND_NATIVE_SOURCE_RESULTS';
    projection_id: string;
    projection_digest: string;
    delivered_count: number;
    excluded_count: number;
};
/**
 * Construct and sign one v1 record from exact source and projection bytes.
 */
export declare function createMemoryProjectionRecordV1(input: MemoryProjectionProducerInput): {
    record: Obj;
    verificationMaterial: Omit<MemoryProjectionVerificationMaterial, 'verifySourceEntry'>;
};
export declare function memoryProjectionRecordDigest(record: unknown): string;
declare const _default: Readonly<{
    MEMORY_PROJECTION_RECORD_VERSION: "MEMORY-PROJECTION-RECORD-v1";
    MEMORY_PROJECTION_RECORD_DOMAIN: "MEMORY-PROJECTION-RECORD-v1\0";
    createMemoryProjectionRecordV1: typeof createMemoryProjectionRecordV1;
    verifyMemoryProjectionRecordV1Envelope: typeof verifyMemoryProjectionRecordV1Envelope;
    verifyMemoryProjectionRecordV1: typeof verifyMemoryProjectionRecordV1;
    memoryProjectionRecordDigest: typeof memoryProjectionRecordDigest;
}>;
export default _default;
//# sourceMappingURL=memory-projection.d.ts.map