/**
 * Customer-owned Reliance Program source and deterministic compiler.
 *
 * The signed source is the relying party's policy artifact. Compilation emits
 * the existing Gate Trust Program wire format; it does not create another
 * authorization engine or let a presenter select the acceptance bar.
 */
import crypto from 'node:crypto';
export declare const RELIANCE_PROGRAM_SOURCE_VERSION = "EP-RELIANCE-PROGRAM-SOURCE-v1";
export declare const RELIANCE_PROGRAM_VERSION = "EP-RELIANCE-PROGRAM-v1";
export declare const RELIANCE_PROGRAM_SIGNATURE_ALGORITHM = "Ed25519";
export declare const RELIANCE_PROGRAM_ADMISSIBILITY_EVIDENCE = "ep-admissibility-evaluation";
export declare const RELIANCE_PROGRAM_ADMISSIBILITY_VERIFIER = "ep-admissibility-profile:v1";
type JsonRecord = Record<string, any>;
export interface CompiledRelianceProgram {
    version: typeof RELIANCE_PROGRAM_VERSION;
    source_digest: string;
    relying_party_id: string;
    program: JsonRecord;
    program_digest: string;
    trace: Array<{
        stage_id: string;
        requirement_id: string;
        profile_id: string;
        profile_hash: string;
    }>;
    claim_boundary: string;
}
export interface AdmissibilityProfileTrustAdapterOptions {
    profile: JsonRecord;
    evaluate: (profile: JsonRecord, bundle: unknown, context: {
        now?: string | number;
        expectedProfileHash: string;
    }) => any | Promise<any>;
    project: (input: {
        evaluation: Readonly<JsonRecord>;
        bundle: unknown;
    }) => {
        subjects: string[];
        key_fingerprints: string[];
        issued_at: string;
        expires_at: string;
        revocation_checked_at?: string | null;
    } | Promise<{
        subjects: string[];
        key_fingerprints: string[];
        issued_at: string;
        expires_at: string;
        revocation_checked_at?: string | null;
    }>;
    now?: string | number | (() => string | number);
}
export declare class RelianceProgramValidationError extends TypeError {
    readonly code: string;
    constructor(code: string, message: string);
}
export declare function relianceProgramSourceDigest(source: unknown): string;
export declare function signRelianceProgram(source: unknown, privateKey: crypto.KeyLike): JsonRecord;
export declare function verifyRelianceProgram(envelope: unknown, { trustedKeys }?: {
    trustedKeys?: Record<string, unknown>;
}): JsonRecord;
/**
 * Adapt the existing Admissibility Profile evaluator into one constructor-
 * pinned Trust Program verifier. The runtime artifact supplies evidence only;
 * the profile, evaluator, projection, and clock are all relying-party owned.
 */
export declare function createAdmissibilityProfileTrustAdapter({ profile, evaluate, project, now, }: AdmissibilityProfileTrustAdapterOptions): ({ artifact, requirement, program }: {
    [x: string]: any;
}) => Promise<Readonly<{
    valid: false;
    reason: string;
}> | Readonly<{
    valid: true;
    reason: null;
    binding_digest: any;
    policy_digest: any;
    subjects: string[];
    key_fingerprints: string[];
    issued_at: string;
    expires_at: string;
    revocation_checked_at: string | null;
}>>;
export declare function compileRelianceProgram(envelope: unknown, { trustedKeys, profiles }?: {
    trustedKeys?: Record<string, unknown>;
    profiles?: unknown[];
}): CompiledRelianceProgram;
export {};
//# sourceMappingURL=reliance-program.d.ts.map