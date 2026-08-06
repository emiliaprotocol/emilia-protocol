import { type AebAdapter, type AebDigest } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
export declare const OASNT_DRAFT_REVISION = "draft-thallapelly-oasnt-01";
export declare const OASNT_AEB_ADAPTER_ID = "native:oasnt";
export declare const OASNT_AEB_ADAPTER_VERSION = "1";
export declare const OASNT_AEB_CONFIG_VERSION = "AEB-OASNT-CONFIG-v1";
export declare const OASNT_TRUST_ROOT_VERSION = "AEB-OASNT-ENROLLED-P256-ROOT-v1";
export declare const OASNT_CAID_MAPPING_VERSION = "AEB-OASNT-CAID-MAPPING-v1";
export declare const OASNT_CAID_MAPPER_ID = "mapper:oasnt-exact-action-v1";
export interface OasntAdapterConfig {
    '@version': typeof OASNT_AEB_CONFIG_VERSION;
    evidence_role: string;
    subject: {
        id: string;
        kind: 'human';
        native_id: string;
    };
    /** Relying-party-selected EMILIA action type, never selected by the token. */
    action_type: string;
    require_request_binding: boolean;
    clock_skew_seconds: number;
    max_token_lifetime_seconds: number;
    max_status_age_seconds: number;
}
export interface OasntTrustRoot {
    '@version': typeof OASNT_TRUST_ROOT_VERSION;
    use: 'enrolled-oasnt-signing-key';
    native_subject: string;
    public_jwk: {
        kty: 'EC';
        crv: 'P-256';
        x: string;
        y: string;
    };
    jwk_thumbprint: string;
    enrollment: {
        /** False is not a weaker mode: this adapter refuses it at construction. */
        hardware_attested: true;
        evidence_digest: AebDigest;
    };
}
export interface OasntConstructorPins {
    config: OasntAdapterConfig;
    trust_roots: readonly OasntTrustRoot[];
}
export interface OasntRequestBinding {
    method: string;
    path: string;
    org_id: string;
    scope: string;
    /** Lowercase hexadecimal SHA-256 over the exact HTTP request body bytes. */
    body_sha256: string;
}
export declare function computeOasntActionDigest(type: string, parameters: Record<string, string>): string;
export declare function computeOasntDisplayDigest(type: string, parameters: Record<string, string>): string;
export declare function computeOasntRequestFingerprint(request: OasntRequestBinding): string;
export declare function createOasntActionDefinition(actionType: string, requireRequestBinding: boolean): Obj;
export declare function createOasntAebAdapter(constructorPins: OasntConstructorPins): AebAdapter;
export {};
//# sourceMappingURL=aeb-oasnt-adapter.d.ts.map