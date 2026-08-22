/**
 * EMILIA-owned interop profile for Justin Kintzele's documented SHEESH/SOMA
 * repository boundary. This is not a SHEESH standard or conformance claim.
 */
import crypto from 'node:crypto';
import type { MemoryProjectionAdapterKey } from '@emilia-protocol/verify/memory-projection';
import { type NativeMemoryProjectionOutput, type NativeSourceVerifier } from './native-memory-source.js';
export declare const SHEESH_PROVIDER_ID = "sheesh-soma";
export declare const SHEESH_SOURCE_PROFILE = "urn:emilia:source-profile:sheesh-soma:v0.1";
export declare const SHEESH_CONTEXT_FRAME_PROFILE = "urn:emilia:context-frame:sheesh-soma:v0.1";
export declare const SHEESH_SOURCE_ENVELOPE_VERSION = "EMILIA-SHEESH-SOURCE-v0.1";
export declare const SHEESH_PROFILE_STATUS = "EMILIA_INTEROP_PROFILE_NOT_SHEESH_STANDARD";
export interface SheeshContextProviderOptions {
    adapterKeys: Record<string, MemoryProjectionAdapterKey>;
    statusCheckedAt: string | (() => string);
}
export interface SheeshMemorySourceInput {
    repositoryUri: string;
    revision: string;
    path: string;
    sourceBytes: Uint8Array;
    contextFragmentBytes: Uint8Array;
}
export interface SheeshMemoryProjectionInput {
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
    sources: SheeshMemorySourceInput[];
    verifyNativeSource?: NativeSourceVerifier;
    exclusions?: {
        authenticationFailed?: number;
        schemaInvalid?: number;
        policyFiltered?: number;
        contextLimit?: number;
    };
}
export declare function createSheeshContextProvider(options: SheeshContextProviderOptions): import("./trusted-context.js").ContextEvidenceProvider;
/** Produce one signed Memory Projection Record from exact SHEESH/SOMA files. */
export declare function createSheeshMemoryProjection(input: SheeshMemoryProjectionInput): NativeMemoryProjectionOutput;
/** Stable bytes for independent adapter tests and offline packet inspection. */
export declare function sheeshSourceEnvelopeBytes(source: SheeshMemorySourceInput): Buffer;
declare const _default: Readonly<{
    createSheeshContextProvider: typeof createSheeshContextProvider;
    createSheeshMemoryProjection: typeof createSheeshMemoryProjection;
}>;
export default _default;
//# sourceMappingURL=sheesh-context.d.ts.map