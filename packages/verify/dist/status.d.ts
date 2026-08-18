import { type AgilityOptions } from './pq-signature-agility.js';
export declare const STATUS_VERSION = "EP-STATUS-v1";
export declare const STATUS_DOMAIN = "EP-STATUS-v1\0";
export declare const REVOCER_AUTHORITY_VERSION = "EP-REVOKER-AUTHORITY-v1";
export declare const REVOCER_AUTHORITY_DOMAIN = "EP-REVOKER-AUTHORITY-v1\0";
export declare const STATUS_TARGET_TYPES: readonly ["receipt", "commit", "delegation"];
export declare const STATUS_TARGET_USAGES: readonly ["authorization", "execution", "delegation"];
export type StatusTargetType = typeof STATUS_TARGET_TYPES[number];
export type StatusTargetUsage = typeof STATUS_TARGET_USAGES[number];
export type StatusState = 'not_revoked' | 'revoked';
export type StatusOutcome = 'current_not_revoked' | 'revoked' | 'indeterminate';
export interface StatusTarget {
    /**
     * Core names are exposed through StatusTargetType for convenience, but a
     * relying party may pin additional names through StatusTargetRegistry.
     * Runtime validation remains fail-closed when no registry is supplied.
     */
    type: string;
    id: string;
    digest: string;
    usage: string;
}
export interface RevokerAuthorityPin {
    authority_domain: string;
    authority_id: string;
    key_id: string;
    public_key: string;
}
/** A relying-party-pinned target vocabulary.
 *
 * draft-schrock-ep-revocation-statement-00 enumerates three recognized target
 * types and says extending the set is "a matter for a future version, not for
 * unilateral verifier behavior." This carries that constraint: the core three
 * are always recognized, and a wider set is honored only when the relying
 * party pins one here, the same way it pins revoker keys. A verifier never
 * widens its own vocabulary, and an unconfigured verifier behaves exactly as
 * the published version specifies. */
export interface StatusTargetRegistry {
    readonly types?: readonly string[];
    readonly usages?: readonly string[];
}
export interface RevokerAuthorityOptions {
    authorityPin?: RevokerAuthorityPin;
    now?: number | string | Date;
    /** Pinned target vocabulary. Omitted means the core set only (fail-closed). */
    targetRegistry?: StatusTargetRegistry;
}
export interface StatusVerificationOptions extends RevokerAuthorityOptions {
    certificate?: unknown;
    /** The relying party's previously accepted head, never presenter state. */
    previousStatus?: unknown;
}
export interface RevokerAuthorityVerification {
    valid: boolean;
    checks: {
        structure: boolean;
        authority: boolean;
        scope: boolean;
        validity: boolean;
        signature: boolean;
    };
    reasons: string[];
    certificate_digest: string | null;
}
export interface StatusVerification {
    outcome: StatusOutcome;
    valid: boolean;
    checks: {
        structure: boolean;
        certificate: boolean;
        authority: boolean;
        target: boolean;
        scope: boolean;
        signature: boolean;
        freshness: boolean;
        sequence: boolean;
        terminal: boolean;
    };
    reasons: string[];
    status_digest: string | null;
    sequence: number | null;
    next_update: string | null;
}
/** Digest of the exact closed, signed revoker-authority certificate envelope. */
export declare function revokerAuthorityCertificateDigest(certificate: unknown): string;
/** Digest of the exact closed, signed status envelope. */
export declare function statusArtifactDigest(status: unknown): string;
/** Verify one root-signed, time-bounded, target-scoped status-key certificate. */
export declare function verifyRevokerAuthorityCertificate(certificate: unknown, options?: RevokerAuthorityOptions): RevokerAuthorityVerification;
/**
 * Verify current status for one exact target.
 *
 * Sequence > 0 requires the relying party's previously accepted status head.
 * This prevents a presenter from rolling the verifier back to an older signed
 * non-revocation artifact or severing the signed predecessor digest chain.
 */
export declare function verifyStatusArtifact(expectedTarget: unknown, status: unknown, options?: StatusVerificationOptions): StatusVerification;
/**
 * REFERENCE HYBRID MIGRATION for this file, following the exact template set
 * by packages/verify/src/revocation.ts's EP-REVOCATION-v2 section (read that
 * comment block first). Five moving parts, applied to TWO artifacts here
 * because status.ts issues a certificate (root-signed) and status heads
 * (delegate-signed):
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. `@version` moves from EP-REVOKER-
 *    AUTHORITY-v1 to EP-REVOKER-AUTHORITY-v2, and from EP-STATUS-v1 to
 *    EP-STATUS-v2. The v1 verifiers above (verifyRevokerAuthorityCertificate,
 *    verifyStatusArtifact) are untouched: each one's structural check is
 *    `value['@version'] !== EP-*-v1`, and certificateStructure()/
 *    statusStructure() are exact-key-set checks, so a v2 object (different
 *    key set, different '@version') fails structure immediately and every
 *    later line in the v1 function reads through options/pins that a v2
 *    caller never populated -- it cannot crash, only refuse.
 *
 * 2. SET SHAPE. `revoker_key` (the certificate's delegated status-signing
 *    key) and the certificate's own root `proof` both carry BOTH halves:
 *    an Ed25519 SPKI-DER key/key_id (unchanged encoding) plus an ML-DSA-65
 *    raw-bytes key/key_id (`pq_public_key`/`pq_key_id`). `proof.signatures`
 *    (both the certificate's root proof and each status head's delegate
 *    proof) is the closed EP-SIG-AGILITY-v1 AgileSignature array shape
 *    (`{alg, sig, key_id?}`), reused verbatim from pq-signature-agility.ts.
 *
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is a top-level field on
 *    BOTH the certificate and every status head, INSIDE `unsigned(value)`
 *    (i.e. not under `proof`), so it is part of what every signature in the
 *    set covers. The verifier never trusts the presented required_algorithms
 *    for what to check the signatures against -- it always requires the
 *    presented array to literally equal the registered constant, and always
 *    passes the REGISTERED constant as `requiredAlgorithms` to
 *    verifyAgileSignatureSet. Narrowing the field (to make a stripped leg
 *    self-consistent) fails structurally AND breaks the surviving
 *    signature, because the signed bytes (signingBytes(unsigned(value),
 *    domain) -- the same generic helper the v1 artifacts already use) changed.
 *
 * 4. V1 COMPATIBILITY. Both v1 functions stay synchronous and unchanged.
 *    verifyRevokerAuthorityCertificateV2 / verifyStatusArtifactV2 are NEW,
 *    separate, ASYNC entry points (ML-DSA-65 verification is async), and
 *    verifyRevokerAuthorityCertificateStatement / verifyStatusArtifactStatement
 *    route on '@version' for callers holding a mixed bag, exactly mirroring
 *    verifyRevocationStatement.
 *
 * 5. NAMED REFUSALS. Every failure sets a named check to false and pushes a
 *    reason string; nothing throws on caller input (both entry points keep
 *    the v1 discipline of a *Core function wrapped in try/catch that returns
 *    an indeterminate result on any exception). An unavailable ML-DSA backend
 *    surfaces through verifyAgileSignatureSet as a refusal
 *    ('pq_backend_unavailable' folded into the reason string), never a
 *    skipped check and never a pass on the Ed25519 leg alone.
 *
 * CHAIN BOUNDARY (new, specific to this file): a v2 status head's
 * previousStatus must ALSO be EP-STATUS-v2-shaped. This module does not
 * accept a v1 predecessor for a v2 successor (or vice versa) -- the
 * sequence/predecessor-digest chain stays within one profile. A deployment
 * transitioning from v1 to v2 issues its first v2 head at sequence 0 (no
 * previousStatus), the same way genesis works today; it does not attempt to
 * splice a hybrid head onto a classical chain.
 *
 * HONEST BOUNDARIES -- everything the v1 header says still holds. Verifying a
 * v2 certificate/status additionally proves both algorithms committed to the
 * exact same content; it does not certify the ML-DSA-65 implementation (see
 * fips-mode.ts and pq-signature-agility.ts's own honesty notes) and does not
 * make either artifact "deployed" or "default" anywhere in this repository.
 */
export declare const REVOCER_AUTHORITY_V2_VERSION = "EP-REVOKER-AUTHORITY-v2";
export declare const REVOCER_AUTHORITY_V2_DOMAIN = "EP-REVOKER-AUTHORITY-v2\0";
export declare const STATUS_V2_VERSION = "EP-STATUS-v2";
export declare const STATUS_V2_DOMAIN = "EP-STATUS-v2\0";
/** The registered required algorithm set, in canonical order. Shared by both
 * v2 artifacts in this file -- there is exactly one hybrid profile here. */
export declare const REVOCER_AUTHORITY_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export declare const STATUS_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface RevokerAuthorityPinV2 {
    authority_domain: string;
    authority_id: string;
    key_id: string;
    public_key: string;
    pq_key_id: string;
    pq_public_key: string;
}
export interface RevokerAuthorityOptionsV2 extends AgilityOptions {
    authorityPin?: RevokerAuthorityPinV2;
    now?: number | string | Date;
    targetRegistry?: StatusTargetRegistry;
}
export interface StatusVerificationOptionsV2 extends RevokerAuthorityOptionsV2 {
    certificate?: unknown;
    previousStatus?: unknown;
}
export interface RevokerAuthorityVerificationV2 {
    valid: boolean;
    checks: {
        structure: boolean;
        algorithm_set: boolean;
        authority: boolean;
        scope: boolean;
        validity: boolean;
        signature: boolean;
    };
    reasons: string[];
    certificate_digest: string | null;
}
export interface StatusVerificationV2 {
    outcome: StatusOutcome;
    valid: boolean;
    checks: {
        structure: boolean;
        algorithm_set: boolean;
        certificate: boolean;
        authority: boolean;
        target: boolean;
        scope: boolean;
        signature: boolean;
        freshness: boolean;
        sequence: boolean;
        terminal: boolean;
    };
    reasons: string[];
    status_digest: string | null;
    sequence: number | null;
    next_update: string | null;
}
/** Verify one root-signed, time-bounded, target-scoped, HYBRID
 * (Ed25519 + ML-DSA-65) status-key certificate. Never throws. */
export declare function verifyRevokerAuthorityCertificateV2(certificate: unknown, options?: RevokerAuthorityOptionsV2): Promise<RevokerAuthorityVerificationV2>;
/**
 * Verify current status for one exact target under the HYBRID
 * (Ed25519 + ML-DSA-65) profile. Never throws. Same sequence/predecessor
 * discipline as verifyStatusArtifact, restricted to an EP-STATUS-v2 chain
 * (see the CHAIN BOUNDARY note above the v2 section header).
 */
export declare function verifyStatusArtifactV2(expectedTarget: unknown, status: unknown, options?: StatusVerificationOptionsV2): Promise<StatusVerificationV2>;
/**
 * Route a certificate of EITHER version to its verifier. A v1 certificate
 * keeps the exact v1 verdict; a v2 certificate gets the hybrid check. A
 * certificate whose '@version' is neither refuses on the version marker,
 * through the v1 verifier, which is the fail-closed answer.
 */
export declare function verifyRevokerAuthorityCertificateStatement(certificate: unknown, options?: RevokerAuthorityOptions | RevokerAuthorityOptionsV2): Promise<RevokerAuthorityVerification | RevokerAuthorityVerificationV2>;
/**
 * Route a status head of EITHER version to its verifier. Same fail-closed
 * dispatch as verifyRevokerAuthorityCertificateStatement above.
 */
export declare function verifyStatusArtifactStatement(expectedTarget: unknown, status: unknown, options?: StatusVerificationOptions | StatusVerificationOptionsV2): Promise<StatusVerification | StatusVerificationV2>;
//# sourceMappingURL=status.d.ts.map