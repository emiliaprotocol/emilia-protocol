/**
 * Address-pinned, manually redirected resolver for Discovery-to-Permit
 * Continuity. No global or plain fetch path exists.
 */
import { type DiscoveryPermitResolution, type DiscoveryPermitTrustPins, type DiscoveryPermitTrustPinsInput } from '@emilia-protocol/verify/discovery-permit-contract';
export interface AddressPinnedFetchContext {
    hostname: string;
    approvedAddresses: readonly string[];
}
export interface AddressPinnedFetchResult {
    response: any;
    connectedAddress: string;
}
export interface AddressPinnedTransport {
    resolveAddresses(hostname: string, context: {
        signal?: AbortSignal;
    }): readonly string[] | Promise<readonly string[]>;
    fetchPinned(url: string, init: RequestInit, context: AddressPinnedFetchContext): AddressPinnedFetchResult | Promise<AddressPinnedFetchResult>;
}
export interface DiscoveryPermitResolverOptions {
    pins: DiscoveryPermitTrustPins | DiscoveryPermitTrustPinsInput;
    transport: AddressPinnedTransport;
    clock?: () => number;
    timeout_ms?: number;
    max_body_bytes?: number;
    max_json_depth?: number;
}
export interface DiscoveryPermitResolveInput {
    caid: string;
    action: unknown;
}
export declare class DiscoveryPermitResolverError extends Error {
    readonly code: string;
    constructor(code: string, message?: string);
}
export declare class DiscoveryPermitResolver {
    #private;
    readonly pins: DiscoveryPermitTrustPins;
    readonly timeout_ms: number;
    readonly max_body_bytes: number;
    readonly max_json_depth: number;
    constructor(options: DiscoveryPermitResolverOptions);
    resolve(input: DiscoveryPermitResolveInput): Promise<DiscoveryPermitResolution>;
}
export declare function createDiscoveryPermitResolver(options: DiscoveryPermitResolverOptions): DiscoveryPermitResolver;
//# sourceMappingURL=discovery-permit-resolver.d.ts.map