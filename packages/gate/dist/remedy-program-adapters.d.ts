/**
 * Constructor-pinned production adapters for the Remedy Program kernel.
 *
 * The kernel deliberately stores evidence references for every post-create
 * transition. These adapters resolve those references from a relying-party
 * evidence source and perform the concrete cryptographic verification here.
 * Presenters cannot supply verifier functions, tenants, or trust keys.
 */
import crypto from 'node:crypto';
import { type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
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
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the pinned-authority evidence
 * envelope these adapters resolve for every post-create transition.
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. `signature: {algorithm, value}` becomes
 *    `signature: {profile, required_algorithms, public_key, key_id,
 *    pq_public_key, pq_key_id, signatures}`, a wire-format change, so the
 *    envelope takes a new `version` (-v1 -> -v2). verifiedSignedEvidence (the
 *    v1 path) is UNCHANGED and refuses a v2 envelope on the version marker
 *    (`evidence.version !== REMEDY_PROGRAM_EVIDENCE_VERSION`) before it
 *    inspects any signature, returning null rather than throwing.
 * 2. SET SHAPE. `signature.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
 *    array ({ alg, sig, key_id? }), one entry per registered algorithm, in the
 *    registered order, reused verbatim.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is INSIDE the signed bytes
 *    (remedyProgramEvidenceV2SigningBytes). Drop the ML-DSA leg and narrow the
 *    set and the surviving Ed25519 signature no longer verifies; leave the set
 *    intact and the missing leg is a structural refusal. The verifier rebuilds
 *    the bytes from the REGISTERED set and the body it recomputed itself.
 * 4. V1 COMPATIBILITY. createRemedyProgramAdapters is UNCHANGED in behavior:
 *    it is now one call into a shared body with the v1 seam injected, and the
 *    v1 seam is the same verifiedSignedEvidence / verifyRevocation /
 *    verifyActionEscrowStateStatement calls it always made.
 *    createRemedyProgramAdaptersV2 injects the hybrid seam instead.
 * 5. NAMED REFUSALS. Every verification path returns null / `{ok:false}`;
 *    nothing throws on presented evidence. An absent ML-DSA backend surfaces
 *    as a refusal through the agility result, never a skipped check and never
 *    a pass on the classical leg.
 *
 * THE TWO CONSUMED ARTIFACTS, STATED PRECISELY.
 *   - EP-ACTION-ESCROW-STATE-STATEMENT: the v2 adapters call the ALREADY
 *     SHIPPED router (verifyActionEscrowStateStatementAny), not a v2-only
 *     verifier, so a v1 escrow statement keeps verifying exactly as it does
 *     today and a v2 one is additionally accepted. The escrow STATE RECORD's
 *     own marker is still EP-ACTION-ESCROW-STATE-v1 in this repository, and
 *     the snapshot pin here is unchanged for that reason.
 *   - EP-REVOCATION: the v2 adapters call the EP-REVOCATION-v2 router
 *     (verifyRevocationStatement), which gives a v1 statement the exact v1
 *     verdict and a v2 statement the hybrid check.
 *
 * HONEST BOUNDARY. The ML-DSA-65 backend is @noble/post-quantum's pure-JS FIPS
 * 204 implementation, not independently audited and not a FIPS validated
 * module. This profile is opt-in and is not on in any deployment.
 */
export declare const REMEDY_PROGRAM_EVIDENCE_V2_VERSION = "EP-GATE-REMEDY-EVIDENCE-v2";
export declare const REMEDY_PROGRAM_EVIDENCE_V2_DOMAIN = "EP-GATE-REMEDY-EVIDENCE-v2\0";
/** The registered required algorithm set, in canonical order. */
export declare const REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/** A v2 authority pin: BOTH public halves per key id, pinned out of band. */
export interface RemedyProgramEvidenceV2KeyPin {
    /** Ed25519 base64url SPKI DER. */
    public_key: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key: string;
}
export interface RemedyProgramPinnedAuthorityV2 {
    authorityId: string;
    trustedKeys: Record<string, RemedyProgramEvidenceV2KeyPin>;
}
/**
 * Domain-separated canonical bytes for the closed hybrid evidence envelope:
 * the same signing body as v1 under the v2 domain tag, plus the committed
 * `required_algorithms` set. See move 3 above.
 */
export declare function remedyProgramEvidenceV2SigningBytes(value: unknown, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * Issuer-side helper: mint one hybrid evidence envelope. Throws on invalid
 * input or an unavailable ML-DSA backend -- an envelope missing the ML-DSA leg
 * must never be emitted, only refused.
 */
export declare function signRemedyProgramEvidenceV2({ kind, issuer, payload }: {
    kind: string;
    issuer: {
        authority_id: string;
        key_id: string;
    };
    payload: unknown;
}, keys: {
    ed: {
        privateKey: crypto.KeyObject;
        publicKey?: string;
    };
    pq: {
        secretKey: Uint8Array | string;
        publicKey: string;
    };
}): Promise<DataRecord>;
/** Test-only hook: force re-resolution (e.g. after swapping module mocks). */
export declare function _resetRemedyRevocationRouterCacheForTests(): void;
/**
 * Build the Remedy Program callbacks against the HYBRID evidence profile.
 * Identical adapter body to createRemedyProgramAdapters (see
 * buildRemedyProgramAdapters); only the pinned verifier seam differs, so the
 * transition rules, tenant/context pins, and binding checks cannot drift
 * between the two profiles.
 *
 * `disputeAuthority`, `remedyAuthority`, and `providerAuthority` take
 * RemedyProgramPinnedAuthorityV2 pins (both public halves per key id).
 * `actionEscrow.trustedKeys` accepts EITHER the v1 pin
 * ({operator_id, public_key}) or the v2 pin
 * ({operator_id, public_key, pq_public_key}), because the escrow leg is a
 * ROUTER: a relying party mid-migration holds a mixed bag of escrow
 * statements and must be able to pin for both.
 */
export declare function createRemedyProgramAdaptersV2(options: Omit<RemedyProgramAdapterOptions, 'disputeAuthority' | 'remedyAuthority' | 'providerAuthority'> & {
    disputeAuthority: RemedyProgramPinnedAuthorityV2;
    remedyAuthority: RemedyProgramPinnedAuthorityV2;
    providerAuthority: RemedyProgramPinnedAuthorityV2;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Readonly<{
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
    REMEDY_PROGRAM_EVIDENCE_V2_VERSION: "EP-GATE-REMEDY-EVIDENCE-v2";
    REMEDY_PROGRAM_EVIDENCE_V2_DOMAIN: "EP-GATE-REMEDY-EVIDENCE-v2\0";
    REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
    remedyProgramEvidenceDigest: typeof remedyProgramEvidenceDigest;
    remedyProgramEvidenceSigningBytes: typeof remedyProgramEvidenceSigningBytes;
    remedyProgramEvidenceV2SigningBytes: typeof remedyProgramEvidenceV2SigningBytes;
    signRemedyProgramEvidenceV2: typeof signRemedyProgramEvidenceV2;
    createRemedyProgramAdapters: typeof createRemedyProgramAdapters;
    createRemedyProgramAdaptersV2: typeof createRemedyProgramAdaptersV2;
}>;
export default _default;
//# sourceMappingURL=remedy-program-adapters.d.ts.map