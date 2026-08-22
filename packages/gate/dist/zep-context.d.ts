/**
 * EMILIA-owned interop profile for exact Zep graph or episode result bytes.
 * This is not a Zep standard or a claim that Zep signed the source bytes.
 */
import crypto from 'node:crypto';
import type { MemoryProjectionAdapterKey } from '@emilia-protocol/verify/memory-projection';
import { type NativeMemoryProjectionOutput, type NativeSourceVerifier } from './native-memory-source.js';
export declare const ZEP_PROVIDER_ID = "zep";
export declare const ZEP_SOURCE_PROFILE = "urn:emilia:source-profile:zep-context:v0.1";
export declare const ZEP_CONTEXT_FRAME_PROFILE = "urn:emilia:context-frame:zep-context:v0.1";
export declare const ZEP_SOURCE_ENVELOPE_VERSION = "EMILIA-ZEP-SOURCE-v0.1";
export declare const ZEP_PROFILE_STATUS = "EMILIA_INTEROP_PROFILE_NOT_ZEP_STANDARD";
export interface ZepContextProviderOptions {
    adapterKeys: Record<string, MemoryProjectionAdapterKey>;
    statusCheckedAt: string | (() => string);
}
export interface ZepMemorySourceInput {
    projectId: string;
    graphId: string;
    episodeUuid: string;
    sourceBytes: Uint8Array;
    contextFragmentBytes: Uint8Array;
}
export interface ZepMemoryProjectionInput {
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
    sources: ZepMemorySourceInput[];
    verifyNativeSource?: NativeSourceVerifier;
    exclusions?: {
        authenticationFailed?: number;
        schemaInvalid?: number;
        policyFiltered?: number;
        contextLimit?: number;
    };
}
export declare function createZepContextProvider(options: ZepContextProviderOptions): import("./trusted-context.js").ContextEvidenceProvider;
/** Produce one signed Memory Projection Record from exact Zep response bytes. */
export declare function createZepMemoryProjection(input: ZepMemoryProjectionInput): NativeMemoryProjectionOutput;
declare const _default: Readonly<{
    createZepContextProvider: typeof createZepContextProvider;
    createZepMemoryProjection: typeof createZepMemoryProjection;
}>;
export default _default;
//# sourceMappingURL=zep-context.d.ts.map