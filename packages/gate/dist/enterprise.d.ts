/**
 * EMILIA Gate — enterprise entitlement layer (EP-GATE-ENTITLEMENT-v1).
 *
 * The license key IS an EP-style artifact: a signed entitlement — Ed25519 over
 * canonical JSON (sorted keys, same idiom as receipts/evidence) of
 * { org, tier, features[], limits, not_before, expires_at, kid }. Verifiers pin
 * issuer keys by kid; nothing in the artifact is trusted until the signature
 * verifies against a pinned key.
 *
 * OPEN-CORE SEMANTICS — two different fail directions, by design:
 *   - The CORE gate is never bricked. No entitlement, an expired one, a
 *     tampered one, an unknown kid — all resolve to { valid:false,
 *     tier:'community' } with a machine-readable reason. Community tier always
 *     works; a licensing failure can never block the firewall itself.
 *   - Enterprise FEATURES fail closed. `requireFeature` returns true ONLY for
 *     a cryptographically valid, in-window entitlement that explicitly lists
 *     the feature. Everything else — including community fallback — is false.
 *
 * Pure functions: inputs in, verdict out. Time is injected (`now`), never read
 * from the wall clock implicitly, so verification is deterministic.
 */
import crypto from 'node:crypto';
import { type AgileSignature } from '@emilia-protocol/verify/pq-signature-agility';
export declare const ENTITLEMENT_VERSION = "EP-GATE-ENTITLEMENT-v1";
export declare const ENTITLEMENT_TIERS: string[];
/**
 * Mint a signed entitlement (test/ops helper — the licensing service, not the
 * verifier, holds the private key). Throws on invalid fields: a malformed
 * license must never be issued, only refused.
 * @param {crypto.KeyObject} privateKey Ed25519 private key
 * @param {object} fields { org, tier, features?, limits?, not_before, expires_at, kid }
 * @returns {{ '@version': string, payload: object, signature: { algorithm: 'Ed25519', value: string } }}
 */
type EntitlementFields = {
    org: string;
    tier: string;
    features?: string[];
    limits?: Record<string, any>;
    not_before: string | number;
    expires_at: string | number;
    kid: string;
};
export declare function mintEntitlement(privateKey: any, fields: EntitlementFields): {
    '@version': string;
    payload: Record<string, any>;
    signature: {
        algorithm: string;
        value: string;
    };
};
/**
 * Verify an entitlement. NEVER throws for a bad artifact — every failure
 * resolves to the community tier with a machine-readable reason, so a licensing
 * problem degrades gracefully instead of bricking the gate. Enterprise features
 * remain gated by `requireFeature`, which fails closed on any non-valid result.
 *
 * @param {object|string|null} entitlementJson the artifact (object or JSON string); absence -> community
 * @param {object} [o]
 * @param {object|Array<{kid:string,key:string}>} [o.issuerKeys] pinned kid -> base64url SPKI-DER public key
 * @param {number|string|function} [o.now=Date.now] injected clock (ms, ISO, or () => ms)
 * @returns {{ valid: boolean, tier: string, features: string[], limits: object|null, reason: string, org?: string, kid?: string, not_before?: any, expires_at?: any }}
 */
export declare function verifyEntitlement(entitlementJson: any, { issuerKeys, now, }?: {
    issuerKeys?: Record<string, string> | Array<{
        kid: string;
        key: string;
    }>;
    now?: number | string | (() => number);
}): {
    valid: boolean;
    tier: string;
    features: never[];
    limits: null;
    reason: any;
} | {
    valid: boolean;
    tier: any;
    features: any;
    limits: any;
    reason: string;
    org: any;
    kid: any;
    not_before: any;
    expires_at: any;
};
/**
 * Is `feature` licensed? FAIL CLOSED: true only for a valid entitlement that
 * explicitly lists the feature. Community fallback, invalid/expired/tampered
 * artifacts, and unlisted features are all false — no enterprise code path
 * runs without a live license naming it.
 * @param {object} verified the result of verifyEntitlement
 * @param {string} feature
 * @returns {boolean}
 */
export declare function requireFeature(verified: any, feature: any): any;
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the entitlement artifact.
 *
 * 1. VERSION BUMP. `signature: {algorithm,value}` becomes `proof:
 *    {required_algorithms, signatures}`, a shape change, so this is a new
 *    `@version` (-v1 -> -v2), never an optional field on v1. verifyEntitlement
 *    above is UNCHANGED and still refuses a v2 document at
 *    `unsupported_version` (checked before it ever inspects `signature`,
 *    which a v2 document does not even carry) -- it never crashes on one.
 * 2. SET SHAPE. `proof.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
 *    array, one entry per required algorithm, reused verbatim.
 * 3. ANTI-STRIPPING. `required_algorithms` is INSIDE the signed bytes
 *    (entitlementV2SignedBytes below), alongside the payload. Dropping the
 *    ML-DSA leg and narrowing `required_algorithms` to `["Ed25519"]` changes
 *    the signed bytes, so the surviving Ed25519 signature no longer verifies.
 * 4. V1 COMPATIBILITY. verifyEntitlement stays synchronous and untouched.
 *    verifyEntitlementV2 is a SEPARATE async entry point (ML-DSA verification
 *    is inherently async); verifyEntitlementStatement routes on `@version`.
 * 5. NAMED REFUSALS, COMMUNITY FALLBACK PRESERVED. verifyEntitlementV2 keeps
 *    the open-core contract exactly: it NEVER throws, and every failure --
 *    tampered, expired, unknown kid, missing PQ backend, one leg alone --
 *    resolves to `{valid:false, tier:'community', reason}`. An absent ML-DSA
 *    backend surfaces as `pq_backend_unavailable`, never a silent pass on the
 *    Ed25519 leg alone (that would be exactly the downgrade a hybrid pin
 *    exists to prevent).
 *
 * HONEST BOUNDARY. Same as every other hybrid profile in this repository:
 * the ML-DSA-65 backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, not independently audited and not a FIPS validated module.
 * Issuing or verifying under this profile is not a certification claim, and
 * this profile is opt-in -- nothing here is on by default.
 */
export declare const ENTITLEMENT_V2_VERSION = "EP-GATE-ENTITLEMENT-v2";
export declare const ENTITLEMENT_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/** A v2 issuer pin: BOTH public halves, pinned out of band by kid. */
export interface EntitlementV2IssuerKeyPin {
    /** Ed25519 base64url SPKI DER. */
    public_key: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key: string;
}
/**
 * The bytes BOTH legs sign: the entitlement payload plus the registered
 * algorithm set and the v2 version marker, so the algorithm set is
 * cryptographically committed alongside the payload it protects. Recomputed
 * independently by the verifier from the payload it holds and the REGISTERED
 * set -- never from anything the presented document could narrow.
 */
export declare function entitlementV2SignedBytes(payload: Record<string, unknown>, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * Mint a hybrid entitlement. Throws on invalid fields or an unavailable PQ
 * backend -- issuer-side misuse is a programming error, and a proof missing
 * the ML-DSA leg must never be emitted.
 */
export declare function mintEntitlementV2(keys: {
    ed: {
        privateKey: crypto.KeyObject;
    };
    pq: {
        secretKey: Uint8Array | string;
    };
}, fields: EntitlementFields): Promise<{
    '@version': string;
    payload: Record<string, any>;
    proof: {
        required_algorithms: ("Ed25519" | "ML-DSA-65")[];
        signatures: AgileSignature[];
    };
}>;
/**
 * Verify a hybrid entitlement. NEVER throws -- preserves the exact open-core
 * community-fallback contract of verifyEntitlement: absence, tampering,
 * expiry, an unknown/classical-only-pinned kid, a stripped or narrowed leg,
 * and an unavailable ML-DSA backend all resolve to
 * `{valid:false, tier:'community', reason}`. requireFeature() above already
 * fails closed on any non-valid result, so no separate v2 gate is needed.
 */
export declare function verifyEntitlementV2(entitlementJson: any, { issuerKeys, now, }?: {
    issuerKeys?: Record<string, EntitlementV2IssuerKeyPin> | Array<{
        kid: string;
    } & EntitlementV2IssuerKeyPin>;
    now?: number | string | (() => number);
}): Promise<{
    valid: boolean;
    tier: string;
    features: never[];
    limits: null;
    reason: any;
} | {
    valid: boolean;
    tier: any;
    features: any;
    limits: any;
    reason: string;
    org: any;
    kid: any;
    not_before: any;
    expires_at: any;
}>;
/**
 * Route an entitlement document of EITHER version to its verifier. A v1
 * document keeps the exact synchronous v1 verdict (wrapped in a resolved
 * Promise so callers holding a mixed bag get one uniform async surface); a
 * v2 document gets the hybrid check.
 */
export declare function verifyEntitlementStatement(entitlementJson: any, opts?: {
    issuerKeys?: Record<string, string> | Array<{
        kid: string;
        key: string;
    }> | Record<string, EntitlementV2IssuerKeyPin> | Array<{
        kid: string;
    } & EntitlementV2IssuerKeyPin>;
    now?: number | string | (() => number);
}): Promise<{
    valid: boolean;
    tier: string;
    features: never[];
    limits: null;
    reason: any;
} | {
    valid: boolean;
    tier: any;
    features: any;
    limits: any;
    reason: string;
    org: any;
    kid: any;
    not_before: any;
    expires_at: any;
}>;
declare const _default: {
    mintEntitlement: typeof mintEntitlement;
    verifyEntitlement: typeof verifyEntitlement;
    requireFeature: typeof requireFeature;
    ENTITLEMENT_VERSION: string;
    ENTITLEMENT_TIERS: string[];
    mintEntitlementV2: typeof mintEntitlementV2;
    verifyEntitlementV2: typeof verifyEntitlementV2;
    verifyEntitlementStatement: typeof verifyEntitlementStatement;
    ENTITLEMENT_V2_VERSION: string;
    ENTITLEMENT_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
};
export default _default;
//# sourceMappingURL=enterprise.d.ts.map