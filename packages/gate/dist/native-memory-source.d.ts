/** Internal helpers for bounded native-memory source envelopes. */
import crypto from 'node:crypto';
import { type MemoryProjectionNativeSourceResult, type MemoryProjectionVerificationMaterial } from '@emilia-protocol/verify/memory-projection';
type RecordLike = Record<string, any>;
export interface NativeSourceClassificationInput {
    providerId: string;
    sourceProfile: string;
    sourceEnvelope: Readonly<RecordLike>;
    sourceBytes: Uint8Array;
    sealedObjectDigest: string;
}
export type NativeSourceVerifier = (input: NativeSourceClassificationInput) => MemoryProjectionNativeSourceResult;
export type NativeSourceEnvelopeValidator = (sourceEnvelope: Readonly<RecordLike>) => void;
export interface NativeMemoryProjectionSource {
    sourceEnvelope: RecordLike;
    contextFragmentBytes: Uint8Array;
}
export interface NativeMemoryProjectionInput {
    providerId: string;
    sourceProfile: string;
    contextFrameProfile: string;
    projectionId: string;
    createdAt: string;
    adapter: {
        id: string;
        keyId: string;
        privateKey: crypto.KeyLike;
    };
    selectionContext: {
        recallRequestBytes: Uint8Array;
        selectionPolicyBytes: Uint8Array;
        trustSnapshotBytes: Uint8Array;
        trustEvaluatedAt: string;
    };
    sources: NativeMemoryProjectionSource[];
    verifyNativeSource?: NativeSourceVerifier;
    validateSourceEnvelope: NativeSourceEnvelopeValidator;
    exclusions?: {
        authenticationFailed?: number;
        schemaInvalid?: number;
        policyFiltered?: number;
        contextLimit?: number;
    };
}
export interface NativeMemoryProjectionOutput {
    record: RecordLike;
    verificationMaterial: MemoryProjectionVerificationMaterial;
}
export declare function sha256(bytes: Uint8Array): string;
export declare function isDataRecord(value: unknown): value is RecordLike;
export declare function boundedString(value: unknown, maximum?: number): value is string;
export declare function absoluteUri(value: unknown): value is string;
export declare function canonicalBytes(value: unknown): Buffer;
export declare function decodeCanonicalSourceEnvelope(bytes: Uint8Array): RecordLike;
export declare function createNativeMemoryProjection(input: NativeMemoryProjectionInput): NativeMemoryProjectionOutput;
export {};
//# sourceMappingURL=native-memory-source.d.ts.map