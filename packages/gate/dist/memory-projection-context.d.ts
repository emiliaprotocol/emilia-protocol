/**
 * Provider-neutral Trusted Context Pack adapter for
 * MEMORY-PROJECTION-RECORD-v1.
 *
 * This verifies only the signed projection envelope at the Gate boundary.
 * Native source bytes are rechecked by the full Memory Projection verifier
 * before an adapter signs the record. An adapter signature authenticates the
 * adapter's assertion. It does not make the underlying source true.
 */
import { type MemoryProjectionAdapterKey } from '@emilia-protocol/verify/memory-projection';
import { type ContextEvidenceProvider } from './trusted-context.js';
export interface MemoryProjectionContextProviderOptions {
    adapterKeys: Record<string, MemoryProjectionAdapterKey>;
    statusCheckedAt: string | (() => string);
    providerId: string;
    profileId: string;
    contextFrameProfile: string;
    maxDeliveredEntries?: number;
}
/** Create one relying-party-pinned Memory Projection provider. */
export declare function createMemoryProjectionContextProvider(options: MemoryProjectionContextProviderOptions): ContextEvidenceProvider;
declare const _default: Readonly<{
    createMemoryProjectionContextProvider: typeof createMemoryProjectionContextProvider;
}>;
export default _default;
//# sourceMappingURL=memory-projection-context.d.ts.map