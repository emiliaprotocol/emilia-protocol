import { type AgilityOptions } from './pq-signature-agility.js';
export declare const REVOCATION_VERSION = "EP-REVOCATION-v1";
export type RevocationTargetType = 'receipt' | 'commit' | 'delegation';
export interface RevocationTarget {
    target_type: RevocationTargetType;
    target_id: string;
    action_hash: string;
}
export interface RevocationProof {
    algorithm?: unknown;
    revoker_key_id?: unknown;
    signature_b64u?: unknown;
    public_key?: unknown;
    [key: string]: unknown;
}
export interface RevocationStatement {
    '@version'?: unknown;
    target_type?: unknown;
    target_id?: unknown;
    action_hash?: unknown;
    revoker_id?: unknown;
    revoked_at?: unknown;
    reason?: unknown;
    proof?: RevocationProof | null;
    [key: string]: unknown;
}
export interface RevocationOptions {
    revokerKeys?: Record<string, {
        public_key?: string;
        key_id?: string;
    }>;
    maxAgeSeconds?: number;
    now?: number | string | Date;
}
/**
 * @param {{target_type:string, target_id:string, action_hash:string}} target
 *   the authorization the relying party HOLDS and wants to know the status of.
 * @param {object} statement  the presented EP-REVOCATION-v1 statement.
 * @param {object} [opts]
 * @param {Object<string,{public_key:string}>} [opts.revokerKeys]  pinned keys by revoker_id.
 * @param {number} [opts.maxAgeSeconds]  DEPRECATED and ignored. Terminal
 *   revocations do not age out; freshness belongs to separate status evidence.
 * @param {number|string|Date} [opts.now]  decision time used to reject a
 *   revocation whose effective instant is still in the future.
 * @returns {{valid:boolean, checks:object, errors:string[]}}
 */
export declare function verifyRevocation(target: RevocationTarget | null | undefined, statement: RevocationStatement | null | undefined, opts?: RevocationOptions): {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
};
/**
 * Convenience: is `target` revoked by ANY of the presented statements? Fail-open
 * on an EMPTY list is the relying party's hazard (absence != not-revoked); this
 * only answers "do these statements revoke it?".
 *
 * v1 ONLY, and deliberately so: it is synchronous, and ML-DSA-65 verification
 * is asynchronous. An EP-REVOCATION-v2 statement in this bag is simply not
 * revoking (its `@version` fails the v1 check), which is fail-closed. Use
 * isRevokedAny() for a bag that may contain either version.
 */
export declare function isRevoked(target: RevocationTarget | null | undefined, statements: RevocationStatement[] | unknown, opts?: RevocationOptions): boolean;
/**
 * REFERENCE HYBRID MIGRATION. This is the smallest complete example of adding
 * a post-quantum leg to an existing EP artifact, and it is the template the
 * remaining single-Ed25519 surfaces copy. Five moving parts, in order:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    `proof`, which is a wire-format change, so the artifact takes a new
 *    `@version` (EP-REVOCATION-v1 -> EP-REVOCATION-v2) rather than growing an
 *    optional field on v1. The v1 verifier is left untouched: verifyRevocation()
 *    above still accepts exactly the statements it accepted before, and it
 *    refuses a v2 statement on the version marker BEFORE it inspects any
 *    signature (`unsupported version: EP-REVOCATION-v2`). A deployed v1
 *    verifier must never accept a hybrid statement on the strength of the one
 *    leg it happens to understand, and it must not crash; the version marker is
 *    what guarantees both. Never reuse the v1 marker for a hybrid artifact.
 *
 * 2. SET SHAPE. `proof` carries `required_algorithms` plus a `signatures`
 *    array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }), one entry per algorithm, in the registered order.
 *    Reuse that shape verbatim; do not invent a per-artifact signature schema.
 *    Ed25519 keeps its base64url SPKI DER public key; ML-DSA-65 carries raw
 *    base64url public key bytes, because it has no SPKI encoding EP consumes.
 *
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is inside the signed
 *    bytes (revocationV2SignedPayload below). Delete the ML-DSA leg and narrow
 *    `required_algorithms` to ["Ed25519"] and the surviving Ed25519 signature
 *    no longer verifies, because the bytes changed. Leave the set intact and
 *    the missing leg is a structural refusal. This is a byte-level commitment,
 *    strictly stronger than EP-SIG-AGILITY-v1's `hybrid_all` policy alone,
 *    which the agility module honestly documents as relying-party POLICY. The
 *    verifier rebuilds the bytes from the REGISTERED set and from the fields it
 *    independently recomputed; the presented statement never gets to choose
 *    what it is checked against.
 *
 * 4. V1 COMPATIBILITY. v1 statements keep verifying, unchanged, through the
 *    unchanged sync function. v2 verification is ASYNC because ML-DSA
 *    verification is async, so it is a SEPARATE entry point rather than a
 *    signature change to the v1 function; verifyRevocationStatement() routes on
 *    `@version` for callers holding a mixed bag. Do not make the v1 verifier
 *    async: every existing caller of a sync verifier is a breaking change you
 *    do not need.
 *
 * 5. NAMED REFUSALS. Every failure path sets a named check to false and pushes
 *    a human-readable error; nothing throws on caller input, and an
 *    INDETERMINATE result never authorizes. An absent ML-DSA backend is a
 *    refusal ('pq_backend_unavailable' surfaced through the agility result),
 *    never a skipped check and never a pass on the classical leg.
 *
 * HONEST BOUNDARIES. Everything the v1 header says about this profile still
 * holds: verification proves a PRESENTED statement is authentic and binds the
 * target, never that you hold the latest revocation state. The ML-DSA backend
 * is @noble/post-quantum's pure-JS FIPS 204 implementation, which is not
 * independently audited and is not a FIPS validated module; verifying under
 * this profile is not a certification claim. And v2 does NOT retroactively
 * protect statements already issued under v1.
 */
export declare const REVOCATION_V2_VERSION = "EP-REVOCATION-v2";
/** The registered required algorithm set, in canonical order. */
export declare const REVOCATION_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface RevocationV2Signature {
    alg?: unknown;
    sig?: unknown;
    key_id?: unknown;
}
export interface RevocationV2Proof {
    profile?: unknown;
    required_algorithms?: unknown;
    revoker_key_id?: unknown;
    /** Ed25519: base64url SPKI DER. */
    public_key?: unknown;
    pq_key_id?: unknown;
    /** ML-DSA-65: base64url of the raw 1952-byte public key. */
    pq_public_key?: unknown;
    signatures?: unknown;
    [key: string]: unknown;
}
export interface RevocationV2Statement extends Omit<RevocationStatement, 'proof'> {
    proof?: RevocationV2Proof | null;
}
/** A v2 revoker pin: BOTH public halves, pinned out of band. */
export interface RevokerV2KeyPin {
    /** Ed25519 base64url SPKI DER. */
    public_key?: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key?: string;
    key_id?: string;
    pq_key_id?: string;
}
export interface RevocationV2Options extends AgilityOptions {
    revokerKeys?: Record<string, RevokerV2KeyPin>;
    now?: number | string | Date;
}
export interface RevocationVerifyResult {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
}
/**
 * The bytes BOTH legs sign. Same fixed SIGNED_FIELDS set as v1, plus the
 * `required_algorithms` set and the v2 `@version` marker, so the algorithm set
 * and the profile are cryptographically committed. Recomputed independently by
 * the verifier from the PRESENTED fields and the REGISTERED set. canonicalize()
 * sorts keys, so field order here is irrelevant.
 */
export declare function revocationV2SignedPayload(stmt: RevocationV2Statement, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * verifyRevocationV2 -- FAIL-CLOSED hybrid revocation check. Never throws on
 * caller input. Every gating check must be true; any one false yields
 * valid:false, and a v2 statement NEVER verifies on one leg alone.
 */
export declare function verifyRevocationV2(target: RevocationTarget | null | undefined, statement: RevocationV2Statement | null | undefined, opts?: RevocationV2Options): Promise<RevocationVerifyResult>;
/**
 * Route a statement of EITHER version to its verifier. v1 statements keep the
 * exact v1 verdict; v2 statements get the hybrid check. A statement whose
 * `@version` is neither refuses on the version marker, through the v1 verifier,
 * which is the fail-closed answer.
 */
export declare function verifyRevocationStatement(target: RevocationTarget | null | undefined, statement: RevocationStatement | RevocationV2Statement | null | undefined, opts?: RevocationV2Options): Promise<RevocationVerifyResult>;
/**
 * Aggregate convenience over a bag that may mix v1 and v2 statements. Same
 * honest boundary as isRevoked(): `false` means "no VALID binding statement is
 * present IN THIS BAG", never "this target was never revoked anywhere".
 */
export declare function isRevokedAny(target: RevocationTarget | null | undefined, statements: unknown, opts?: RevocationV2Options): Promise<boolean>;
//# sourceMappingURL=revocation.d.ts.map