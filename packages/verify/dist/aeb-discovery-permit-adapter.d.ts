/**
 * Native AEB adapter for Discovery-to-Permit Continuity.
 *
 * The adapter emits one evidence role. It deliberately has no invocation,
 * reservation, permit-consumption, or authorization operation.
 */
import { type AebAdapter, type AebAdapterInput, type AebDigest, type AebNativeResult } from './aeb-adapter-contract.js';
export declare const AEB_DISCOVERY_PERMIT_ADAPTER_ID = "native:discovery-permit-continuity";
export declare const AEB_DISCOVERY_PERMIT_ADAPTER_VERSION = "1";
export declare const AEB_DISCOVERY_PERMIT_CONFIG_VERSION = "AEB-DISCOVERY-PERMIT-CONFIG-v1";
export declare const DISCOVERY_PERMIT_EVIDENCE_ROLE = "discovery-permit-continuity";
export interface AebDiscoveryPermitConfig {
    '@version': typeof AEB_DISCOVERY_PERMIT_CONFIG_VERSION;
    source: {
        origin: string;
        discovery_url: string;
        permit_url: string;
    };
    schema_digests: {
        discovery: AebDigest;
        permit_binding: AebDigest;
    };
    mapping_digest: AebDigest;
    max_age_seconds: number;
    redirect_map: Record<string, string>;
    resolver: {
        id: string;
        key_id: string;
        public_key: string;
        max_attestation_age_seconds: number;
    };
    evidence_role: typeof DISCOVERY_PERMIT_EVIDENCE_ROLE;
}
export interface DiscoveryPermitAebNativeResult extends AebNativeResult {
    /** Explicitly prevents a native evidence result from being mistaken for Gate authorization. */
    authorization: 'EVIDENCE_ONLY';
    authorizes_action: false;
}
export interface AebDiscoveryPermitAdapter extends Omit<AebAdapter, 'verifyNative'> {
    verifyNative(input: Omit<AebAdapterInput, 'profile'>): DiscoveryPermitAebNativeResult;
}
export declare function createAebDiscoveryPermitAdapter(): AebDiscoveryPermitAdapter;
//# sourceMappingURL=aeb-discovery-permit-adapter.d.ts.map