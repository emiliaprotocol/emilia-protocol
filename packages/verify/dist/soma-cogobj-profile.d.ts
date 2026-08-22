import { type StateDigest, type StatePayloadAdapter, type StateSensitivity, type StateDisposition } from './portable-state-handoff.js';
export declare const SOMA_COGOBJ_VERSION = "SOMA-COGOBJ-v0.1";
export declare const SOMA_COGOBJ_PAYLOAD_PROFILE = "EP-STATE-PAYLOAD-SOMA-COGOBJ-v0.1";
export interface SomaCogobj {
    '@version': typeof SOMA_COGOBJ_VERSION;
    object_id: string;
    domain: string;
    schema_uri: string;
    snapshot: {
        asserted_at: string;
        source_mutability: 'IMMUTABLE' | 'MUTABLE' | 'UNKNOWN';
        observed_at: string | null;
        freshness_basis_digest: StateDigest | null;
    };
    sensitivity: StateSensitivity;
    protection: {
        mode: 'PLAINTEXT' | 'OPAQUE-CIPHERTEXT';
        profile: string | null;
        key_reference_digest: StateDigest | null;
    };
    disposition: StateDisposition;
    origin: {
        assertion_class: 'operator-pinned' | 'approver-supplied' | 'agent-generated' | 'imported' | 'derived';
        issuer: string;
        asserted_at: string;
        source_digest: StateDigest | null;
        transform_id: string | null;
    };
    lineage: {
        generation: number;
        predecessor_digest: StateDigest | null;
    };
    authority_semantics: 'NONE';
    content: unknown;
}
export declare function validateSomaCogobj(value: unknown): {
    valid: boolean;
    reasons: string[];
};
export declare const somaCogobjPayloadAdapter: StatePayloadAdapter;
//# sourceMappingURL=soma-cogobj-profile.d.ts.map