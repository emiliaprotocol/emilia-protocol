/**
 * Customer-owned Reliance Program source and deterministic compiler.
 *
 * The signed source is the relying party's policy artifact. Compilation emits
 * the existing Gate Trust Program wire format; it does not create another
 * authorization engine or let a presenter select the acceptance bar.
 */
import crypto from 'node:crypto';
import { type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
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
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the customer-owned Reliance Program
 * source, and moves the SOURCE marker with the envelope: an
 * EP-RELIANCE-PROGRAM-v2 envelope carries an EP-RELIANCE-PROGRAM-SOURCE-v2
 * source, and compiles to an EP-GATE-TRUST-PROGRAM-PROFILE-v2 program.
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. `signature: {algorithm, key_id, value}`
 *    becomes `proof: {profile, required_algorithms, key_id, public_key,
 *    pq_key_id, pq_public_key, signatures}` -- a wire-format change, so the
 *    envelope takes a new `@version` (-v1 -> -v2), and the source it wraps
 *    takes one too, because the source's own `@version` is inside the signed
 *    bytes. verifyRelianceProgram above is UNCHANGED: handed a v2 envelope it
 *    refuses at `envelope_schema_invalid`, structurally, because a v2 envelope
 *    carries no `signature` member for it to inspect at all. It does not
 *    crash, and it never accepts a hybrid envelope on the strength of the one
 *    leg it understands.
 * 2. SET SHAPE. `proof.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
 *    array ({ alg, sig, key_id? }), one entry per registered algorithm, in the
 *    registered order, reused verbatim. Ed25519 keeps its base64url SPKI DER
 *    public key; ML-DSA-65 carries raw base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is INSIDE the signed bytes
 *    (relianceProgramV2SigningBytes). Drop the ML-DSA leg and narrow the set
 *    to ["Ed25519"] and the surviving Ed25519 signature no longer verifies.
 *    Leave the set intact and the missing leg is a structural refusal. The
 *    verifier rebuilds the bytes from the REGISTERED set and the source it
 *    independently re-validated and re-digested.
 * 4. V1 COMPATIBILITY. verifyRelianceProgram and compileRelianceProgram stay
 *    SYNCHRONOUS and untouched. verifyRelianceProgramV2 /
 *    compileRelianceProgramV2 are SEPARATE async entry points (ML-DSA
 *    verification is inherently async); verifyRelianceProgramEnvelope routes
 *    on `@version` for callers holding a mixed bag.
 * 5. NAMED REFUSALS. Verification never throws on caller input; every failure
 *    is `{valid:false, reason}` with the same reason vocabulary as v1 plus the
 *    hybrid-specific ones. An absent ML-DSA backend surfaces as
 *    `pq_backend_unavailable`, never a skipped check and never a pass on the
 *    classical leg. Compilation keeps v1's throw-on-refusal contract, because
 *    a compiler is issuer-side.
 *
 * HONEST BOUNDARY, UNCHANGED FROM V1: compilation proves a pinned RP program
 * maps to the existing Trust Program. It does not prove evidence sufficiency,
 * authorization, or execution. The ML-DSA-65 backend is @noble/post-quantum's
 * pure-JS FIPS 204 implementation, not independently audited and not a FIPS
 * validated module; signing or verifying under this profile is not a
 * certification claim, and this profile is opt-in.
 */
export declare const RELIANCE_PROGRAM_SOURCE_V2_VERSION = "EP-RELIANCE-PROGRAM-SOURCE-v2";
export declare const RELIANCE_PROGRAM_V2_VERSION = "EP-RELIANCE-PROGRAM-v2";
/** The registered required algorithm set, in canonical order. */
export declare const RELIANCE_PROGRAM_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/** A v2 relying-party pin: BOTH public halves, pinned out of band by key_id. */
export interface RelianceProgramV2KeyPin {
    relying_party_id: string;
    /** Ed25519 base64url SPKI DER. */
    public_key: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key: string;
}
export interface RelianceProgramV2SigningKeys {
    ed: {
        privateKey: crypto.KeyLike;
        publicKey?: string;
    };
    pq: {
        secretKey: Uint8Array | string;
        publicKey: string;
    };
}
/**
 * The bytes BOTH legs sign: the same domain-separated canonical source as v1
 * under the v2 domain tag, plus the committed `required_algorithms` set.
 * Recomputed independently by the verifier from the PRESENTED source and the
 * REGISTERED set. See move 3 above.
 */
export declare function relianceProgramV2SigningBytes(source: JsonRecord, requiredAlgorithms?: readonly string[]): Buffer;
/** Digest a v2 relying-party source. Refuses an invalid or v1-marked source. */
export declare function relianceProgramSourceV2Digest(source: unknown): string;
/**
 * Sign a v2 source under BOTH registered algorithms. Throws on an invalid
 * source, malformed keys, or an unavailable ML-DSA backend: an envelope
 * missing the ML-DSA leg must never be emitted, only refused.
 */
export declare function signRelianceProgramV2(source: unknown, keys: RelianceProgramV2SigningKeys): Promise<JsonRecord>;
/**
 * FAIL-CLOSED hybrid verifier for one EP-RELIANCE-PROGRAM-v2 envelope. Never
 * throws on caller input; an envelope NEVER verifies on one leg alone. The
 * result shape matches verifyRelianceProgram exactly so callers can route.
 */
export declare function verifyRelianceProgramV2(envelope: unknown, { trustedKeys, mldsaBackend, mldsaBackendLoader }?: {
    trustedKeys?: Record<string, unknown>;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Promise<JsonRecord>;
/**
 * Route an envelope of EITHER version to its verifier. v1 envelopes keep the
 * exact v1 verdict; v2 envelopes get the hybrid check. An envelope whose
 * `@version` is neither refuses through the v1 verifier, which is the
 * fail-closed answer.
 */
export declare function verifyRelianceProgramEnvelope(envelope: unknown, options?: {
    trustedKeys?: Record<string, unknown>;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Promise<JsonRecord>;
/**
 * Compile a verified v2 envelope into an EP-GATE-TRUST-PROGRAM-PROFILE-v2
 * program. Same compilation body as v1 (compileVerifiedSource); only the
 * emitted profile marker and its validator differ. Refuses by throwing, like
 * v1: a compiler is issuer-side, not attacker-facing.
 */
export declare function compileRelianceProgramV2(envelope: unknown, { trustedKeys, profiles, mldsaBackend, mldsaBackendLoader }?: {
    trustedKeys?: Record<string, unknown>;
    profiles?: unknown[];
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Promise<CompiledRelianceProgram>;
export {};
//# sourceMappingURL=reliance-program.d.ts.map