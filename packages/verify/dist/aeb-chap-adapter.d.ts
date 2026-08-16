import { type AebAdapter, type AebDigest } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
export declare const CHAP_SOURCE_REPOSITORY = "https://github.com/BrightbeamAI/chap";
export declare const CHAP_SOURCE_COMMIT = "9e7af2b811d3368b4afba7c6d318764959c2fd0d";
export declare const CHAP_REVIEW_PROFILE_SHA256 = "sha256:2a971b084ea192daafcdac275b5aa1b9e6ceb60d0cb3879db0df06ee7b430539";
export declare const CHAP_SECURITY_SIGNED_PROFILE_SHA256 = "sha256:83f455763b08d0d9993fecf3c5ddf94d2cd6266d79b42a574f52ce94a313aee2";
export declare const CHAP_PATCH_IMPLEMENTATION_SHA256 = "sha256:78ff3b3d898f58e5d043582705e46c06833336f411ef0caf08d11221148da7ff";
export declare const CHAP_AEB_ADAPTER_ID = "native:chap";
export declare const CHAP_AEB_ADAPTER_VERSION = "1";
export declare const CHAP_AEB_CONFIG_VERSION = "AEB-CHAP-CONFIG-v1";
export declare const CHAP_TRUST_ROOT_VERSION = "AEB-CHAP-ED25519-ROOT-v1";
export declare const CHAP_CAID_MAPPING_VERSION = "AEB-CHAP-CAID-MAPPING-v1";
export declare const CHAP_CAID_MAPPER_ID = "mapper:chap-human-decision-exact-action-v1";
declare const WIRE_PROFILE = "chap-jsonrpc-security-signed-1.0";
export interface ChapAdapterConfig {
    '@version': typeof CHAP_AEB_CONFIG_VERSION;
    wire_profile: typeof WIRE_PROFILE;
    evidence_role: string;
    subject: {
        id: string;
        kind: 'human';
        native_id: string;
    };
    action_type: string;
    approve_binding_field: 'approved_artefact_digest';
    max_decision_age_seconds: number;
    max_status_age_seconds: number;
}
export interface ChapTrustRoot {
    '@version': typeof CHAP_TRUST_ROOT_VERSION;
    use: 'chap-participant-signing-key';
    participant_id: string;
    kid: string;
    public_jwk: {
        kty: 'OKP';
        crv: 'Ed25519';
        x: string;
    };
    valid_from: string;
    valid_until: string;
    revoked_at?: string;
    identity_binding: {
        method: string;
        evidence_digest: AebDigest;
    };
}
export interface ChapConstructorPins {
    config: ChapAdapterConfig;
    trust_roots: readonly ChapTrustRoot[];
}
export declare function applyChapJsonPatch(document: unknown, patch: unknown): unknown;
export declare function createChapActionDefinition(actionType: string): Obj;
export declare function createChapAebAdapter(constructorPins: ChapConstructorPins): AebAdapter;
export {};
//# sourceMappingURL=aeb-chap-adapter.d.ts.map