import { RELIANCE_PROFILE_VERSION } from './reliance.js';
import { type AgilityOptions } from './pq-signature-agility.js';
type Obj = Record<string, any>;
interface RegistryOptions {
    pinnedRegistryKeys?: Obj[];
    expectProfileId?: string;
    expectMinEpoch?: number;
}
export declare const PROFILE_REGISTRY_VERSION = "EP-RELIANCE-PROFILE-REGISTRY-v1";
export declare const PROFILE_REGISTRY_DOMAIN = "EP-RELIANCE-PROFILE-REGISTRY-v1\0";
/** Digest of the signed entry body, excluding the signature envelope. */
export declare function profileRegistryEntryDigest(entry: Obj): string;
/**
 * Sign a reliance profile into a registry entry. `privateKey` is a Node
 * Ed25519 KeyObject held by the REGISTRAR (never in this repo).
 * @returns {object} the signed EP-RELIANCE-PROFILE-REGISTRY-v1 entry
 */
export declare function signRelianceProfileEntry({ registry_id, profile_id, profile, registry_epoch, issued_at }: Obj, privateKey: any): Obj;
/**
 * Verify a registry entry against pinned registrar keys.
 * @param {object} entry
 * @param {object} [opts]
 * @param {Array<{registry_id:string,key_id?:string,public_key:string}>} [opts.pinnedRegistryKeys]
 * @param {string} [opts.expectProfileId]
 * @param {number} [opts.expectMinEpoch]
 * @returns {{verified:boolean, accepted:boolean, profile:(object|null), checks:object, reason?:string, entry_digest?:string, profile_hash?:string, key_id?:string, registry_id?:string, profile_id?:string, registry_epoch?:number}}
 *   `profile`, when present, is a deep frozen clone of the entry's profile and
 *   `profile_hash` is the digest of those exact bytes.
 */
export declare function verifyRelianceProfileEntry(entry: Obj, opts?: RegistryOptions): {
    verified: boolean;
    accepted: boolean;
    profile: null;
    checks: {
        [x: string]: boolean;
    };
    reason: string;
} | {
    verified: boolean;
    accepted: boolean;
    profile: null;
    checks: Record<string, boolean>;
    reason: string;
    entry_digest: string;
    profile_hash?: undefined;
    key_id?: undefined;
    registry_id?: undefined;
    profile_id?: undefined;
    registry_epoch?: undefined;
} | {
    verified: boolean;
    accepted: boolean;
    profile: Obj;
    checks: Record<string, boolean>;
    reason: string;
    entry_digest: string;
    profile_hash: string;
    key_id: string;
    registry_id: string;
    profile_id?: undefined;
    registry_epoch?: undefined;
} | {
    verified: boolean;
    accepted: boolean;
    profile: Obj;
    checks: Record<string, boolean>;
    key_id: string;
    registry_id: string;
    profile_id: any;
    registry_epoch: any;
    entry_digest: string;
    profile_hash: string;
    reason?: undefined;
};
/**
 * Re-check that a verification result's profile still hashes to the
 * `profile_hash` the result was issued with. Pure, offline, and independent of
 * the registry entry: a consumer holding only the result can prove the bytes it
 * is about to evaluate are the bytes the verdict was computed over.
 *
 * BINDING ONLY, never acceptance: `ok` says the profile matches its hash, and
 * says nothing about `verified` or `accepted` — read those fields separately.
 * Fail-closed with a reason; an expected mismatch returns, it never throws.
 *
 * @param {object} result a verifyRelianceProfileEntry() result
 * @returns {{ok:boolean, reason:(string|null), profile_hash:(string|null)}}
 */
export declare function assertRelianceProfileBound(result: Obj): {
    ok: boolean;
    reason: string | null;
    profile_hash: string | null;
};
export { RELIANCE_PROFILE_VERSION };
/**
 * Same five-move hybrid migration as packages/verify/src/revocation.ts's
 * EP-REVOCATION-v2 (read that file's header for the full write-up); applied
 * here to the registry entry.
 *
 * 1. VERSION BUMP. `@type: EP-RELIANCE-PROFILE-REGISTRY-v2`, not a field grown
 *    on v1. verifyRelianceProfileEntry() above is untouched: its first check
 *    is `entry['@type'] !== PROFILE_REGISTRY_VERSION -> fail('unsupported_version')`,
 *    an immediate return before any v2-only field is ever read, so a v2 entry
 *    handed to the v1 verifier refuses cleanly and never throws.
 *
 * 2. SET SHAPE + FIELD LAYOUT CHOICE. The single `signature: {algorithm,
 *    public_key, key_id, entry_digest, signature_b64u}` object v1 carries has
 *    no room for a second algorithm, so v2 replaces it with a `proof: {...}`
 *    sub-object carrying `entry_digest`, `required_algorithms`, the Ed25519
 *    `key_id`/`public_key`, the ML-DSA-65 `pq_key_id`/`pq_public_key`, and a
 *    `signatures` array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({alg, sig, key_id?}). CHOICE: nested `proof`, not flattened onto the
 *    entry, because that is this file's OWN v1 idiom -- v1 already keeps its
 *    envelope under a nested `signature` sub-object rather than flattening
 *    `public_key`/`entry_digest` onto the entry body, and `unsigned(entry)` /
 *    `entrySigningBytes()` already assume "the envelope is one sibling key to
 *    strip". `unsignedV2()` mirrors that exactly: it strips `proof`, not five
 *    separate top-level fields. `profile` and `profile_hash` stay top-level
 *    exactly as in v1, since they are the SIGNED BODY, not part of the
 *    signature envelope.
 *
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is inside the signed bytes
 *    (entrySigningBytesV2 below), under a v2-only domain separator distinct
 *    from PROFILE_REGISTRY_DOMAIN so a v1 and v2 signature over similar-looking
 *    fields can never collide. Narrowing the set after signing changes the
 *    bytes, so the surviving Ed25519 signature stops verifying even though it
 *    was never touched -- proved by a hostile test, not merely asserted.
 *
 * 4. V1 COMPATIBILITY. v1 stays synchronous, unchanged.
 *    verifyRelianceProfileEntryV2() is a separate async entry point (ML-DSA
 *    verification is async), and verifyRelianceProfileEntryStatement() routes
 *    a caller's mixed bag by `@type`, mirroring verifyRevocationStatement().
 *
 * 5. NAMED REFUSALS. Every gate is a named boolean in `checks` plus a
 *    `reason` string; nothing throws on entry/key content, and an absent
 *    ML-DSA backend is a refusal ('pq_backend_unavailable', surfaced through
 *    the agility result), never a skipped check or a pass on the Ed25519 leg
 *    alone. `verified` is computed under the entry's OWN presented key
 *    material (never the pin) so it is honest about what the bytes prove;
 *    `accepted` is a SEPARATE check that both presented key halves equal a
 *    pin for this exact registry_id -- the same two-step structure v1 already
 *    uses ("signature must verify regardless of pinning, so verified is
 *    honest").
 */
export declare const PROFILE_REGISTRY_V2_VERSION = "EP-RELIANCE-PROFILE-REGISTRY-v2";
export declare const PROFILE_REGISTRY_V2_DOMAIN = "EP-RELIANCE-PROFILE-REGISTRY-v2\0";
/** The registered required algorithm set, in canonical order. */
export declare const PROFILE_REGISTRY_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface ProfileRegistryV2Signature {
    alg?: unknown;
    sig?: unknown;
    key_id?: unknown;
}
export interface ProfileRegistryV2Proof {
    entry_digest?: unknown;
    required_algorithms?: unknown;
    /** Ed25519: base64url SPKI DER. */
    key_id?: unknown;
    public_key?: unknown;
    /** ML-DSA-65: base64url of the raw 1952-byte public key. */
    pq_key_id?: unknown;
    pq_public_key?: unknown;
    signatures?: unknown;
    [key: string]: unknown;
}
export interface RegistryV2KeyPin {
    registry_id?: string;
    /** Ed25519 base64url SPKI DER. */
    public_key?: string;
    key_id?: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key?: string;
    pq_key_id?: string;
}
export interface RegistryV2Options {
    pinnedRegistryKeys?: RegistryV2KeyPin[];
    expectProfileId?: string;
    expectMinEpoch?: number;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}
/**
 * The bytes BOTH legs sign: the v2 unsigned body plus the committed
 * `required_algorithms` set, under the v2-only domain separator. Throws if
 * `requiredAlgorithms` is not exactly the registered set -- mirrors
 * revocationV2SignedPayload's guard, so an issuer can never mint bytes over a
 * narrowed or widened set through this function. The verifier always calls
 * this with the REGISTERED default, never the presented `required_algorithms`.
 */
export declare function entrySigningBytesV2(unsignedEntryV2: Obj, requiredAlgorithms?: readonly string[]): Buffer;
/** Digest of the signed v2 entry body, excluding the `proof` envelope. */
export declare function profileRegistryEntryDigestV2(entry: Obj, requiredAlgorithms?: readonly string[]): string;
export interface RelianceProfileEntryV2Signer {
    /** Ed25519 private key, node crypto KeyObject. */
    privateKey: any;
    /** ML-DSA-65 secret key: 4032 raw bytes, or base64url of them. */
    pqSecretKey: Uint8Array | string;
    /** ML-DSA-65 public key: 1952 raw bytes, or base64url of them. */
    pqPublicKeyB64u: Uint8Array | string;
}
/**
 * Sign a reliance profile into a v2 (hybrid) registry entry, under BOTH
 * registered algorithms over one set of bytes that COMMIT to the required
 * algorithm set (see entrySigningBytesV2). Issuer-side reference tooling:
 * THROWS rather than emit a half-hybrid entry, the same fail-closed honesty
 * gate buildRevocationV2 uses in lib/revocation/revocation.ts -- issuer-side
 * misuse (missing profile fields, missing PQ key material, unavailable ML-DSA
 * backend) is a programming error, never a silently downgraded artifact.
 */
export declare function signRelianceProfileEntryV2({ registry_id, profile_id, profile, registry_epoch, issued_at }: Obj, signer: RelianceProfileEntryV2Signer): Promise<Obj>;
/**
 * Verify a v2 (hybrid) registry entry against pinned registrar keys. ASYNC,
 * unlike v1, because ML-DSA-65 verification is async. FAIL-CLOSED throughout:
 * nothing here throws on entry or key content, and a missing ML-DSA backend
 * is a named refusal, never a skipped check.
 *
 * VERIFIED (both signatures cryptographically hold under the registered
 * algorithm set, the recomputed entry_digest, and the recomputed profile_hash
 * -- checked under the entry's OWN presented key material) is kept strictly
 * separate from ACCEPTED (verified AND both presented key halves equal a pin
 * registered for this exact registry_id).
 */
export declare function verifyRelianceProfileEntryV2(entry: Obj, opts?: RegistryV2Options): Promise<{
    verified: boolean;
    accepted: boolean;
    profile: null;
    checks: {
        [x: string]: boolean;
    };
    reason: string;
} | {
    verified: boolean;
    accepted: boolean;
    profile: null;
    checks: Record<string, boolean>;
    reason: string;
    entry_digest: string;
    profile_hash?: undefined;
    key_id?: undefined;
    pq_key_id?: undefined;
    registry_id?: undefined;
    profile_id?: undefined;
    registry_epoch?: undefined;
} | {
    verified: boolean;
    accepted: boolean;
    profile: Obj;
    checks: Record<string, boolean>;
    reason: string;
    entry_digest: string;
    profile_hash: string;
    key_id: string;
    pq_key_id: string;
    registry_id: string;
    profile_id?: undefined;
    registry_epoch?: undefined;
} | {
    verified: boolean;
    accepted: boolean;
    profile: Obj;
    checks: Record<string, boolean>;
    key_id: string;
    pq_key_id: string;
    registry_id: string;
    profile_id: string;
    registry_epoch: any;
    entry_digest: string;
    profile_hash: string;
    reason?: undefined;
}>;
/**
 * Route an entry of EITHER version to its verifier. v1 entries get the exact
 * v1 verdict (sync, resolved as a Promise); v2 entries get the hybrid check.
 * An entry whose `@type` is neither refuses on the version marker, through
 * the v1 verifier, which is the fail-closed answer. Mirrors
 * verifyRevocationStatement() in revocation.ts.
 */
export declare function verifyRelianceProfileEntryStatement(entry: Obj, opts?: RegistryOptions & RegistryV2Options): Promise<{
    verified: boolean;
    accepted: boolean;
    profile: null;
    checks: {
        [x: string]: boolean;
    };
    reason: string;
} | {
    verified: boolean;
    accepted: boolean;
    profile: Obj;
    checks: Record<string, boolean>;
    reason: string;
    entry_digest: string;
    profile_hash: string;
    key_id: string;
    registry_id: string;
    profile_id?: undefined;
    registry_epoch?: undefined;
} | {
    verified: boolean;
    accepted: boolean;
    profile: Obj;
    checks: Record<string, boolean>;
    key_id: string;
    registry_id: string;
    profile_id: any;
    registry_epoch: any;
    entry_digest: string;
    profile_hash: string;
    reason?: undefined;
}>;
//# sourceMappingURL=reliance-profile-registry.d.ts.map