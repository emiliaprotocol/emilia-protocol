import crypto from 'node:crypto';
import { type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
export type RiskRecord = Record<string, any>;
export type TrustedRiskKeys = Record<string, {
    issuer_id: string;
    public_key: string;
}>;
export declare const RISK_DIGEST: RegExp;
export declare const RISK_CAID: RegExp;
export declare const RISK_ID: RegExp;
export declare function riskRecord(value: unknown): value is RiskRecord;
export declare function riskExact(value: unknown, keys: readonly string[]): value is RiskRecord;
export declare function riskIdentifier(value: unknown): value is string;
export declare function riskInstant(value: unknown): number;
export declare function riskDigest(value: unknown): string;
export declare function riskClone<T>(value: T): T;
export declare function riskFreeze<T>(value: T): T;
export declare function signRiskBody(version: string, bodyInput: RiskRecord, signer: {
    issuer_id: string;
    key_id: string;
    private_key: crypto.KeyLike;
}): RiskRecord;
export declare function verifyRiskBody(artifact: unknown, version: string, trustedKeys: TrustedRiskKeys | undefined): {
    valid: boolean;
    reason: string | null;
    body: RiskRecord | null;
    artifact_digest: string | null;
};
/** Marker committed inside the hybrid signed bytes and carried in proof.profile. */
export declare const RISK_HYBRID_PROFILE = "EP-RISK-HYBRID-v2";
/** The registered required algorithm set for the hybrid proof, in canonical order. */
export declare const RISK_HYBRID_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/** v2 trusted-key pin: BOTH public halves for one issuer key id. */
export type TrustedRiskKeysV2 = Record<string, {
    issuer_id: string;
    /** Ed25519 base64url SPKI DER. */
    public_key: string;
    /** ML-DSA-65 base64url of the raw 1952-byte public key. */
    pq_public_key: string;
}>;
export interface RiskHybridSignature {
    alg: string;
    sig: string;
    key_id?: string;
}
export interface RiskHybridProof {
    profile: string;
    required_algorithms: string[];
    key_id: string;
    body_digest: string;
    signatures: RiskHybridSignature[];
}
export interface RiskHybridSigner {
    issuer_id: string;
    key_id: string;
    /** Ed25519 signing key. */
    private_key: crypto.KeyLike;
    /** ML-DSA-65 raw secret key (4032 bytes) as Uint8Array or base64url string. */
    pq_private_key: Uint8Array | string;
}
export type RiskV2Options = AgilityOptions;
/**
 * signRiskBodyV2 -- mint the hybrid, set-committed twin of signRiskBody.
 *
 * Reference: "PATTERN: the reference hybrid migration" (EP-REVOCATION-v2) in
 * docs/protocol/pq-hybrid-program.md. Five moves, applied here:
 *   1. VERSION BUMP, NOT A FIELD BUMP. The caller passes a distinct -v2 marker
 *      (e.g. EP-GATE-ALLOWANCE-v2); the v1 helper and its callers keep the flat
 *      `signature` proof. A deployed v1 verifier handed a v2 artifact refuses on
 *      its version/envelope check BEFORE inspecting any signature (never a leg
 *      pass, never a crash).
 *   2. SET SHAPE. `proof.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
 *      array ({ alg, sig, key_id? }), one entry per required algorithm.
 *   3. ANTI-STRIPPING BYTES. `required_algorithms` and the profile are inside
 *      the signed bytes (riskV2SigningBytes). Drop a leg and narrow the set and
 *      the surviving signature no longer verifies, because the bytes changed.
 *   4. V1 COMPATIBILITY. v1 stays synchronous and unchanged; v2 is a SEPARATE
 *      async entry point (ML-DSA verification is async).
 *   5. NAMED REFUSALS. Issuer-side misuse throws (a programming error);
 *      verifyRiskBodyV2 never throws on caller input and never passes on a
 *      missing ML-DSA backend.
 *
 * HONEST BOUNDARY: the ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, which is not independently audited and is not a FIPS
 * validated module; verifying under this profile is not a certification claim.
 * v2 does NOT retroactively protect artifacts already issued under v1.
 */
export declare function signRiskBodyV2(version: string, bodyInput: RiskRecord, signer: RiskHybridSigner, options?: RiskV2Options): Promise<RiskRecord>;
/**
 * verifyRiskBodyV2 -- FAIL-CLOSED hybrid verify, the set-committed twin of
 * verifyRiskBody. Same result shape ({ valid, reason, body, artifact_digest })
 * so a caller migrates by swapping the call and awaiting it. Both legs verify
 * over bytes rebuilt from the PRESENTED body and the REGISTERED algorithm set,
 * under the PINNED Ed25519 + ML-DSA-65 keys; a v2 artifact NEVER verifies on one
 * leg alone. See "PATTERN: the reference hybrid migration" in
 * docs/protocol/pq-hybrid-program.md.
 */
export declare function verifyRiskBodyV2(artifact: unknown, version: string, trustedKeys: TrustedRiskKeysV2 | undefined, options?: RiskV2Options): Promise<{
    valid: boolean;
    reason: string | null;
    body: RiskRecord | null;
    artifact_digest: string | null;
}>;
//# sourceMappingURL=reliance-risk-crypto.d.ts.map