import { type AgilityOptions } from './pq-signature-agility.js';
export declare const AUTHORITY_PROOF_VERSION = "EP-AUTHORITY-PROOF-v1";
export declare const AUTHORITY_PROOF_DOMAIN = "EP-AUTHORITY-PROOF-v1\0";
export interface AuthorityProof {
    '@type'?: unknown;
    authority_id?: unknown;
    registry_head?: unknown;
    registry_epoch?: unknown;
    signature?: {
        algorithm?: unknown;
        public_key?: unknown;
        signature_b64u?: unknown;
        key_id?: unknown;
        proof_digest?: unknown;
        [key: string]: unknown;
    } | null;
    [key: string]: unknown;
}
export interface PinnedRegistryKey {
    issuer_id: string;
    key_id?: string;
    public_key: string;
}
export interface AuthorityProofOptions {
    pinnedRegistryKeys?: PinnedRegistryKey[];
    expectRegistryHead?: string;
    expectMinEpoch?: number;
}
/** Digest of the signed proof body, excluding the signature envelope. */
export declare function authorityProofDigest(proof: AuthorityProof): string;
/**
 * Verify an EP-AUTHORITY-PROOF-v1 against pinned registry issuer keys.
 * @param {object} proof
 * @param {object} opts
 * @param {Array<{issuer_id:string,key_id?:string,public_key:string}>} [opts.pinnedRegistryKeys]
 * @param {string} [opts.expectRegistryHead]  proof.registry_head must equal this (equivocation)
 * @param {number} [opts.expectMinEpoch]      proof.registry_epoch must be >= this (staleness)
 * @returns {{verified:boolean, accepted:boolean, checks:object, reason?:string, proof_digest?:string, key_id?:string}}
 */
export declare function verifyAuthorityProof(proof: AuthorityProof | null | undefined, opts?: AuthorityProofOptions): {
    proof_digest?: string | undefined;
    verified: boolean;
    accepted: boolean;
    checks: {
        [x: string]: boolean;
    };
    reason: string;
} | {
    verified: boolean;
    accepted: boolean;
    checks: Record<string, boolean>;
    key_id: string;
    proof_digest: string;
};
/**
 * HYBRID MIGRATION of EP-AUTHORITY-PROOF, following the reference pattern in
 * docs/protocol/pq-hybrid-program.md ("PATTERN: the reference hybrid
 * migration") and packages/verify/src/revocation.ts's EP-REVOCATION-v2. Five
 * moving parts, in order:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    the `signature` block, which is a wire-format change, so the artifact
 *    takes a new `@type` (EP-AUTHORITY-PROOF-v1 -> EP-AUTHORITY-PROOF-v2). The
 *    v1 verifiers above are untouched and refuse a v2 proof on the version
 *    marker BEFORE inspecting any signature (`unsupported_version`): a deployed
 *    v1 verifier must never accept a hybrid proof on the strength of the one
 *    leg it understands, and it must not crash.
 * 2. SET SHAPE. `signature` carries `required_algorithms` plus a `signatures`
 *    array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }), one entry per algorithm in the registered order.
 *    Ed25519 keeps its base64url SPKI DER public key; ML-DSA-65 carries raw
 *    base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is inside the signed
 *    bytes (authorityProofV2SignedBytes below). Drop the ML-DSA leg and narrow
 *    `required_algorithms` and the surviving Ed25519 signature no longer
 *    verifies, because the bytes changed. The verifier rebuilds the bytes from
 *    the REGISTERED set and the fields it recomputed, never from what the proof
 *    claims. This is a byte-level commitment, strictly stronger than
 *    EP-SIG-AGILITY-v1's `hybrid_all` policy alone.
 * 4. V1 COMPATIBILITY. v1 proofs keep verifying through the unchanged
 *    synchronous verifiers. v2 verification is ASYNC (ML-DSA verification is
 *    async), so it is a SEPARATE entry point rather than a signature change to
 *    the v1 function.
 * 5. NAMED REFUSALS. Every failure sets a named check false and pushes a
 *    readable reason; nothing throws on caller input. An absent ML-DSA backend
 *    is `pq_backend_unavailable` surfaced through the agility result, never a
 *    skipped check and never a pass on the classical leg.
 *
 * HOUSE SPLIT PRESERVED. The { verified, accepted } split is not collapsed:
 * `verified` = both signatures hold over the recomputed bytes; `accepted` =
 * verified AND both registry issuer halves were pinned out of band for the
 * proof's authority_id (and any head/epoch freshness pins are satisfied).
 *
 * HONEST BOUNDARIES. The ML-DSA backend is @noble/post-quantum's pure-JS
 * FIPS 204 implementation, which is not independently audited and is not a FIPS
 * validated module; verifying under this profile is not a certification claim.
 * v2 does NOT retroactively protect proofs already signed under v1.
 */
export declare const AUTHORITY_PROOF_V2_VERSION = "EP-AUTHORITY-PROOF-v2";
export declare const AUTHORITY_PROOF_V2_DOMAIN = "EP-AUTHORITY-PROOF-v2\0";
/** The registered required algorithm set, in canonical order. */
export declare const AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface AuthorityProofV2Signature {
    alg?: unknown;
    sig?: unknown;
    key_id?: unknown;
}
export interface AuthorityProofV2SignatureBlock {
    profile?: unknown;
    required_algorithms?: unknown;
    key_id?: unknown;
    /** Ed25519: base64url SPKI DER. */
    public_key?: unknown;
    pq_key_id?: unknown;
    /** ML-DSA-65: base64url of the raw public key bytes. */
    pq_public_key?: unknown;
    proof_digest?: unknown;
    signatures?: unknown;
    [key: string]: unknown;
}
export interface AuthorityProofV2 {
    '@type'?: unknown;
    authority_id?: unknown;
    registry_head?: unknown;
    registry_epoch?: unknown;
    signature?: AuthorityProofV2SignatureBlock | null;
    [key: string]: unknown;
}
/** A v2 registry issuer pin: BOTH public halves, pinned out of band. */
export interface PinnedRegistryKeyV2 {
    issuer_id: string;
    /** Ed25519 base64url SPKI DER. */
    public_key: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key: string;
    key_id?: string;
    pq_key_id?: string;
}
export interface AuthorityProofV2Options extends AgilityOptions {
    pinnedRegistryKeys?: PinnedRegistryKeyV2[];
    expectRegistryHead?: string;
    expectMinEpoch?: number;
}
/**
 * The bytes BOTH legs sign: the domain tag, the unsigned proof body, and the
 * registered `required_algorithms` set. Exported so the lib issuer produces
 * byte-identical material to what this verifier recomputes (the same discipline
 * revocation.ts uses via revocationV2SignedPayload). canonicalize() sorts keys.
 */
export declare function authorityProofV2SignedBytes(unsignedBody: Record<string, unknown>, requiredAlgorithms?: readonly string[]): Buffer;
/** Digest of the v2 signed body, excluding the signature envelope. */
export declare function authorityProofV2Digest(proof: AuthorityProofV2): string;
export interface VerifyAuthorityProofV2Result {
    verified: boolean;
    accepted: boolean;
    checks: Record<string, boolean>;
    reason?: string;
    key_id?: string;
    pq_key_id?: string;
    proof_digest?: string;
}
/**
 * verifyAuthorityProofV2 -- FAIL-CLOSED hybrid authority-proof check. Never
 * throws on caller input. `verified` requires both legs to verify over the
 * recomputed bytes under the pinned keys; `accepted` additionally requires the
 * issuer pin (both halves) to name the proof's authority_id.
 */
export declare function verifyAuthorityProofV2(proof: AuthorityProofV2 | null | undefined, opts?: AuthorityProofV2Options): Promise<VerifyAuthorityProofV2Result>;
//# sourceMappingURL=authority-proof.d.ts.map