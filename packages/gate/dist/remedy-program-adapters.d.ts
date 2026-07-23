export declare const REMEDY_PROGRAM_EVIDENCE_VERSION = "EP-GATE-REMEDY-EVIDENCE-v1";
export declare const REMEDY_PROGRAM_EVIDENCE_DOMAIN = "EP-GATE-REMEDY-EVIDENCE-v1\0";
type DataRecord = Record<string, any>;
export interface RemedyProgramEvidenceSource {
    get(input: Readonly<{
        tenantId: string;
        evidenceId: string;
        evidenceDigest: string;
    }>): unknown | Promise<unknown>;
}
export interface RemedyProgramPinnedAuthority {
    authorityId: string;
    trustedKeys: Record<string, string>;
}
export interface RemedyProgramOriginalEffectBinding {
    agreementId: string;
    caid: string;
    bindingDigest: string;
    profileDigest: string;
    amendmentDigests: string[];
}
export interface RemedyProgramAdapterOptions {
    tenantId: string;
    environment: string;
    audience: string;
    evidenceSource: RemedyProgramEvidenceSource;
    actionEscrow: {
        trustedKeys: Record<string, {
            operator_id: string;
            public_key: string;
        }>;
        originalEffects: Record<string, RemedyProgramOriginalEffectBinding>;
    };
    revokerKeys: Record<string, {
        public_key: string;
        key_id?: string;
    }>;
    disputeAuthority: RemedyProgramPinnedAuthority;
    remedyAuthority: RemedyProgramPinnedAuthority;
    providerAuthority: RemedyProgramPinnedAuthority;
    now?: () => number | string | Date;
}
/** Digest an exact evidence artifact for use as the kernel's evidence reference. */
export declare function remedyProgramEvidenceDigest(value: unknown): string;
/** Domain-separated canonical bytes for the closed signed evidence envelope. */
export declare function remedyProgramEvidenceSigningBytes(value: unknown): Buffer;
/**
 * Build all required Remedy Program callbacks using only pinned configuration
 * and concrete repository verifiers. There are intentionally no verifier
 * override hooks.
 */
export declare function createRemedyProgramAdapters(options: RemedyProgramAdapterOptions): Readonly<{
    verifyOriginalEffect: (input: Readonly<DataRecord>) => Promise<Readonly<{
        ok: false;
    }> | Readonly<{
        evidence_digest: any;
        ok: true;
    }>>;
    verifyRevocation: (input: Readonly<DataRecord>) => Promise<Readonly<{
        ok: false;
    }> | Readonly<{
        ok: true;
        evidence_id: string;
        evidence_digest: string;
        target_operation_id: any;
        action_digest: any;
        authority_id: any;
        revoked_at: any;
    }>>;
    verifyDispute: (input: Readonly<DataRecord>) => Promise<Readonly<{
        ok: false;
    }> | Readonly<{
        ok: true;
        dispute_id: any;
        evidence_id: any;
        evidence_digest: string;
        challenger_id: any;
        requested_units: any;
        opened_at: any;
        original_operation_id: any;
        original_action_digest: any;
    }>>;
    verifyRemedyAuthorization: (input: Readonly<DataRecord>) => Promise<Readonly<{
        ok: false;
    }> | Readonly<{
        ok: true;
        evidence_id: any;
        evidence_digest: string;
        remedy_operation_id: any;
        remedy_caid: any;
        remedy_action_digest: any;
        consequence_mode: any;
        capability_template_digest: any;
        escrow_profile_digest: any;
        units: any;
        authorized_at: any;
        dispute_id: any;
        original_operation_id: any;
        destination_binding_digest: any;
        unit: any;
    }>>;
    verifyRemedyOutcome: (input: Readonly<DataRecord>) => Promise<Readonly<{
        ok: false;
    }> | Readonly<{
        ok: true;
        evidence_id: any;
        evidence_digest: string;
        remedy_operation_id: any;
        remedy_action_digest: any;
        destination_binding_digest: any;
        units: any;
        unit: any;
        outcome: any;
        observed_at: any;
    }>>;
    verifyOriginalReconciliation: (input: Readonly<DataRecord>) => Promise<Readonly<{
        ok: false;
    }> | Readonly<{
        ok: true;
        evidence_id: any;
        evidence_digest: string;
        original_operation_id: any;
        original_action_digest: any;
        terminal_evidence_digest: any;
        outcome: any;
        observed_at: any;
    }>>;
}>;
declare const _default: Readonly<{
    REMEDY_PROGRAM_EVIDENCE_VERSION: "EP-GATE-REMEDY-EVIDENCE-v1";
    REMEDY_PROGRAM_EVIDENCE_DOMAIN: "EP-GATE-REMEDY-EVIDENCE-v1\0";
    remedyProgramEvidenceDigest: typeof remedyProgramEvidenceDigest;
    remedyProgramEvidenceSigningBytes: typeof remedyProgramEvidenceSigningBytes;
    createRemedyProgramAdapters: typeof createRemedyProgramAdapters;
}>;
export default _default;
//# sourceMappingURL=remedy-program-adapters.d.ts.map