import { type AebAdapter, type AebDigest } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
export declare const OASNT_DRAFT_REVISION = "draft-thallapelly-oasnt-02";
export declare const OASNT_DRAFT_TXT_SHA256 = "sha256:3a134b635d5101cd91ac885fb4867bf1a7fd37bc52fc4f8405467ed66c397603";
export declare const OASNT_AEB_ADAPTER_ID = "native:oasnt";
export declare const OASNT_AEB_ADAPTER_VERSION = "2";
export declare const OASNT_AEB_CONFIG_VERSION = "AEB-OASNT-CONFIG-v2";
/**
 * The "OASNT Assurance Levels" registry, initial contents (draft sec 10.2).
 * Compared by rank; larger is stronger. Values are case-sensitive and match
 * [a-z][a-z0-9-]*. An asl value outside this table is syntactically legal but
 * carries NO assurance statement (sec 5.4.2): never inferred, never floored.
 */
export declare const OASNT_ASSURANCE_LEVELS: Readonly<Record<string, number>>;
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
    /**
     * Relying-party assurance floor (draft sec 5.4: "A threshold is not a
     * property of the token"). A registered level name, or null for an
     * explicit, deliberate "no assurance requirement" (sec 5.4.2: a relying
     * party with no requirement evaluates neither absent nor unrecognized asl).
     */
    required_assurance_level: string | null;
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