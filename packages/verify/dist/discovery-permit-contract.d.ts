/**
 * EP Discovery-to-Permit Continuity contract.
 *
 * Discovery establishes bounded, content-addressed evidence about a configured
 * source. It never authorizes an action. Trust inputs are pinned outside this
 * pure contract by the resolver and are repeated here so adapters can recheck
 * the complete source/action/mapping join.
 */
import { type KeyObject } from 'node:crypto';
import { type AebDigest, type AebJson } from './aeb-adapter-contract.js';
export declare const DISCOVERY_PERMIT_DISCOVERY_VERSION = "EP-DISCOVERY-PERMIT-DISCOVERY-v1";
export declare const DISCOVERY_PERMIT_BINDING_VERSION = "EP-DISCOVERY-PERMIT-BINDING-v1";
export declare const DISCOVERY_PERMIT_RESOLUTION_VERSION = "EP-DISCOVERY-PERMIT-RESOLUTION-v1";
export declare const DISCOVERY_PERMIT_RESOLVER_ATTESTATION_VERSION = "EP-DISCOVERY-PERMIT-RESOLVER-ATTESTATION-v1";
export declare const DISCOVERY_PERMIT_RESOLVER_ATTESTATION_DOMAIN = "EP-DISCOVERY-PERMIT-RESOLVER-ATTESTATION-v1\0";
export type DiscoveryPermitDigest = AebDigest;
export type DiscoveryPermitJson = AebJson;
export type DiscoveryPermitSourceStatus = 'active' | 'unknown' | 'deprecated';
export type DiscoveryPermitDisposition = 'current' | 'stale' | 'unknown' | 'deprecated';
export type DiscoveryPermitDocumentRole = 'discovery' | 'permit';
export interface DiscoveryPermitSource {
    origin: string;
    discovery_url: string;
    permit_url: string;
}
export interface DiscoveryPermitSchemaDigests {
    discovery: DiscoveryPermitDigest;
    permit_binding: DiscoveryPermitDigest;
}
export interface DiscoveryPermitTrustPinsInput {
    origin: string;
    discovery_url: string;
    permit_url: string;
    discovery_schema_digest: DiscoveryPermitDigest | string;
    permit_schema_digest: DiscoveryPermitDigest | string;
    mapping_digest: DiscoveryPermitDigest | string;
    max_age_seconds: number;
    redirect_map: Record<string, string>;
}
export interface DiscoveryPermitTrustPins {
    readonly origin: string;
    readonly discovery_url: string;
    readonly permit_url: string;
    readonly discovery_schema_digest: DiscoveryPermitDigest;
    readonly permit_schema_digest: DiscoveryPermitDigest;
    readonly mapping_digest: DiscoveryPermitDigest;
    readonly max_age_seconds: number;
    readonly redirect_map: Readonly<Record<string, string>>;
}
export interface DiscoveryPermitDiscoveryDocument {
    '@type': typeof DISCOVERY_PERMIT_DISCOVERY_VERSION;
    source: DiscoveryPermitSource;
    schema_digests: DiscoveryPermitSchemaDigests;
    mapping_digest: DiscoveryPermitDigest;
    status: DiscoveryPermitSourceStatus;
    issued_at: string;
}
export interface DiscoveryPermitBinding {
    '@type': typeof DISCOVERY_PERMIT_BINDING_VERSION;
    source: DiscoveryPermitSource;
    schema_digests: DiscoveryPermitSchemaDigests;
    mapping_digest: DiscoveryPermitDigest;
    status: DiscoveryPermitSourceStatus;
    issued_at: string;
    caid: string;
    action_digest: DiscoveryPermitDigest;
}
export interface DiscoveryPermitDocumentProvenance {
    role: DiscoveryPermitDocumentRole;
    requested_url: string;
    resolved_url: string;
    connected_address: string;
    media_type: 'application/json';
    byte_length: number;
    raw_digest: DiscoveryPermitDigest;
    canonical_digest: DiscoveryPermitDigest;
    redirect_chain: readonly string[];
}
export interface DiscoveryPermitProvenance {
    discovery: DiscoveryPermitDocumentProvenance;
    permit: DiscoveryPermitDocumentProvenance;
}
export interface DiscoveryPermitResolution {
    '@type': typeof DISCOVERY_PERMIT_RESOLUTION_VERSION;
    disposition: DiscoveryPermitDisposition;
    usable_for_permit: boolean;
    /** Discovery evidence is never itself action authorization. */
    authorizes_action: false;
    source: DiscoveryPermitSource;
    schema_digests: DiscoveryPermitSchemaDigests;
    mapping_digest: DiscoveryPermitDigest;
    max_age_seconds: number;
    discovery: DiscoveryPermitDiscoveryDocument;
    binding: DiscoveryPermitBinding;
    age_seconds: number;
    provenance: DiscoveryPermitProvenance;
}
export interface DiscoveryPermitResolverAttestationBody {
    '@type': typeof DISCOVERY_PERMIT_RESOLVER_ATTESTATION_VERSION;
    resolver_id: string;
    evaluated_at: string;
    expires_at: string;
    configuration_digest: DiscoveryPermitDigest;
    caid: string;
    action_digest: DiscoveryPermitDigest;
    source_digest: DiscoveryPermitDigest;
    provenance_digest: DiscoveryPermitDigest;
    resolution_digest: DiscoveryPermitDigest;
    resolution: DiscoveryPermitResolution;
}
export interface DiscoveryPermitResolverAttestation extends DiscoveryPermitResolverAttestationBody {
    signature: {
        alg: 'Ed25519';
        key_id: string;
        value: string;
    };
}
export interface DiscoveryPermitResolverAttestationSigner {
    key_id: string;
    private_key: KeyObject;
}
export interface DiscoveryPermitResolverPin {
    resolver_id: string;
    key_id: string;
    public_key: string;
}
export interface SignDiscoveryPermitResolverAttestationOptions {
    resolver_id: string;
    evaluated_at: string;
    expires_at: string;
    configuration_digest: DiscoveryPermitDigest;
    resolution: DiscoveryPermitResolution;
}
export interface EvaluateDiscoveryPermitContinuityOptions {
    pins: DiscoveryPermitTrustPins | DiscoveryPermitTrustPinsInput;
    discovery: unknown;
    binding: unknown;
    caid: string;
    action: unknown;
    now: number | string | Date;
    provenance: DiscoveryPermitProvenance;
}
export interface RederiveDiscoveryPermitResolutionOptions {
    pins: DiscoveryPermitTrustPins | DiscoveryPermitTrustPinsInput;
    resolution: unknown;
    now: number | string | Date;
}
export declare class DiscoveryPermitContractError extends Error {
    readonly code: string;
    constructor(code: string, message?: string);
}
/**
 * Snapshot and validate every relying-party trust pin. The returned object has
 * no references to caller-owned maps.
 */
export declare function pinDiscoveryPermitTrust(input: DiscoveryPermitTrustPins | DiscoveryPermitTrustPinsInput): DiscoveryPermitTrustPins;
export declare function canonicalizeDiscoveryPermit(value: unknown): string;
export declare function digestDiscoveryPermit(value: unknown): DiscoveryPermitDigest;
export declare function digestDiscoveryPermitRaw(raw: string | Uint8Array): DiscoveryPermitDigest;
/**
 * Join the two source documents to constructor pins and the executor-owned
 * CAID/action. This function never returns action authorization.
 */
export declare function evaluateDiscoveryPermitContinuity(options: EvaluateDiscoveryPermitContinuityOptions): DiscoveryPermitResolution;
/**
 * Strict shape and self-consistency check for serialized resolver output.
 * Pin agreement remains the adapter's responsibility.
 */
export declare function isDiscoveryPermitResolution(value: unknown): value is DiscoveryPermitResolution;
/**
 * Recompute a serialized resolution from the source documents and provenance
 * under relying-party pins. This authenticates no presenter by itself; callers
 * must first verify the resolver attestation that carries the resolution.
 */
export declare function rederiveDiscoveryPermitResolutionFromPinnedDocuments(options: RederiveDiscoveryPermitResolutionOptions): DiscoveryPermitResolution;
export declare function isDiscoveryPermitResolverAttestation(value: unknown): value is DiscoveryPermitResolverAttestation;
/**
 * Produce a domain-separated Ed25519 resolver statement over the exact
 * resolution body and every relying-party-relevant join digest.
 */
export declare function signDiscoveryPermitResolverAttestation(options: SignDiscoveryPermitResolverAttestationOptions, signer: DiscoveryPermitResolverAttestationSigner): DiscoveryPermitResolverAttestation;
export declare function verifyDiscoveryPermitResolverAttestationSignature(attestation: unknown, pin: DiscoveryPermitResolverPin): attestation is DiscoveryPermitResolverAttestation;
//# sourceMappingURL=discovery-permit-contract.d.ts.map