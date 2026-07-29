import { type ContextEvidenceProvider } from './trusted-context.js';
export interface ApertoMemoryAdapterKey {
    public_key_spki_b64u: string;
    status: 'active' | 'revoked' | 'superseded';
    valid_from: string;
    valid_to: string;
    revoked_at: string | null;
}
export interface ApertoMemoryContextProviderOptions {
    adapterKeys: Record<string, ApertoMemoryAdapterKey>;
    statusCheckedAt: string | (() => string);
    providerId?: string;
    profileId?: string;
}
/** Construct the first provider plug-in for the Trusted Context Pack. */
export declare function createApertoMemoryContextProvider(options: ApertoMemoryContextProviderOptions): ContextEvidenceProvider;
declare const _default: Readonly<{
    createApertoMemoryContextProvider: typeof createApertoMemoryContextProvider;
}>;
export default _default;
//# sourceMappingURL=apertomemory-context.d.ts.map