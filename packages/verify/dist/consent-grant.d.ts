/**
 * EP-CONSENT-GRANT-v1 — the scoped, revocable STANDING-CONSENT artifact.
 *
 * Fills binding 3 of Blake Morrison's Command Authority Envelope
 * (draft-morrison-ot-command-authority): a "consent grant" that is scoped,
 * revocable, and names {asset, control_verb, expiry}. This is DISTINCT from the
 * per-action receipt at the binding moment (CAE binding 4, which is what an EP
 * receipt IS). EP always HAD the pieces (policy scoping, directory scope,
 * pinning, revocation statements); until now it did not ship one first-class
 * object that is exactly a standing grant. This module is that object.
 *
 * THE TWO ARTIFACTS, kept distinct on purpose:
 *   - The GRANT (this file) is STANDING AUTHORITY: "principal P authorizes
 *     control_verb V on asset A until expiry E, subject to constraints C." It is
 *     issued once and holds over a window; it is revocable at any time.
 *   - The per-action RECEIPT (index.js verifyReceipt / verifyTrustReceipt) is
 *     the BINDING MOMENT: a named human's device-bound signature over the EXACT
 *     action, at the moment of consequence, before execution.
 *   A receipt "acts under" a grant by carrying the grant's grant_hash;
 *   verifyReceiptUnderGrant() is that composition.
 *
 * HONEST BOUNDARY (the same currency bound as everywhere else in this package):
 *   Neither the grant nor the receipt establishes BUSINESS correctness — that
 *   the authorized operation is the right thing to do. Offline verification of
 *   EITHER is AUTHENTICITY-AS-OF-COMMIT, never proof of CURRENT VALIDITY: a grant
 *   authentic today may have been revoked one second later, and absence of a
 *   revocation statement is NOT proof of not-revoked. Revocation currency needs a
 *   FRESH revocation snapshot pushed to the verifier, exactly like any other EP
 *   status (see docs/EP-REVOCATION-SPEC.md §7 and EP-CURRENCY-v1). This module
 *   checks a PRESENTED revocation statement and refuses when one binds the grant;
 *   it does not and cannot manufacture the absence of one.
 *
 * REUSE, NOT FORK: canonicalize() + the sha256 helper, the "sha256:<hex>"
 * convention, the Ed25519 (crypto.verify(null, digest, ...)) signing convention,
 * and the RFC-3339-with-offset window profile are all imported/mirrored from
 * index.js. Revocation is checked with verifyRevocation() from revocation.js
 * against a 'commit'-typed target keyed by grant_hash. No new canonicalization,
 * no new signature scheme, no new revocation machinery.
 *
 * FAIL-CLOSED: every check refuses on missing / malformed / expired / unpinned /
 * revoked input with a DISTINCT reason. A default is always the weakest outcome
 * (invalid / not covered).
 *
 * @license Apache-2.0
 */
import crypto from 'node:crypto';
import { type AgilityOptions } from './pq-signature-agility.js';
type Obj = Record<string, any>;
interface ConsentGrantOptions {
    now?: number | string | Date;
    revocation?: Obj;
    revokerKeys?: Record<string, Obj>;
    revocationMaxAgeSeconds?: number;
}
interface CompositionOptions extends ConsentGrantOptions {
    pinnedPrincipalKey?: string;
    grantHash?: string;
    assetCovers?: (receiptAsset: any, grantAsset: any) => boolean;
    verbCovers?: (receiptVerb: any, grantVerb: any) => boolean;
}
interface GrantResult {
    valid: boolean;
    checks: Record<string, boolean>;
    reason?: string;
}
export declare const CONSENT_GRANT_VERSION = "EP-CONSENT-GRANT-v1";
/**
 * Compute the grant_hash: "sha256:" + hex over the JCS/RFC-8785 canonical bytes
 * of the grant with grant_hash and signature excluded. Same canonicalize() +
 * SHA-256 EP uses everywhere.
 * @param {object} grant
 * @returns {string|null} "sha256:<hex>" or null if the grant is unusable.
 */
export declare function computeGrantHash(grant: Obj): string | null;
/**
 * True iff grant.grant_hash equals the recomputed hash over the grant body.
 * Fail-closed: a missing or malformed grant_hash returns false.
 * @param {object} grant
 * @returns {boolean}
 */
export declare function verifyGrantHash(grant: Obj): boolean;
/**
 * REFERENCE ISSUER (tests / examples): stamp grant_hash and sign the grant with
 * the principal's Ed25519 key. Not required to consume a grant — any issuer that
 * produces the same canonical body + signature convention interoperates.
 *
 * @param {object} spec  the grant fields WITHOUT grant_hash/signature:
 *   { grant_id, principal, asset, control_verb, constraints?, issued_at, expires_at }.
 *   profile is stamped if absent. Values MUST be canonicalizable (strings/safe
 *   integers/booleans/null/arrays/objects) — encode non-integer quantities
 *   (amount ceilings) as STRINGS, like every other EP signed field.
 * @param {crypto.KeyObject|{privateKey:crypto.KeyObject}} signer  the principal's
 *   Ed25519 private key (or an object carrying one as .privateKey).
 * @returns {object} the complete EP-CONSENT-GRANT-v1 grant with grant_hash and signature.
 */
export declare function buildConsentGrant(spec: Obj, signer: any): Obj;
/**
 * Verify an EP-CONSENT-GRANT-v1 standing consent grant, fully offline.
 *
 * Establishes, all fail-closed:
 *   (hash)          grant_hash binds the canonical grant body (tamper any field
 *                   — asset, control_verb, constraints, expiry — and this fails);
 *   (signature)     the principal's device-bound Ed25519 signature verifies over
 *                   the SAME canonical body, under the caller-PINNED principal key
 *                   (an unpinned / self-asserted key confers NOTHING);
 *   (within_window) `now` is within [issued_at, expires_at], both RFC-3339 with
 *                   an explicit offset; an expired (or not-yet-valid) grant refuses.
 * If a revocation statement binding this grant_hash is supplied AND valid under
 * its own pinned revoker key, the grant refuses ('grant_revoked').
 *
 * HONESTY: this proves the PRESENTED grant is authentic and in-window as of the
 * commit it was signed at. It does NOT prove the grant is still LIVE (absence of
 * a revocation statement is not proof of not-revoked) and says NOTHING about
 * business correctness. Currency needs a fresh revocation snapshot, same as any
 * EP status.
 *
 * @param {object} grant  the EP-CONSENT-GRANT-v1 object.
 * @param {string|undefined} pinnedPrincipalKey  the principal's Ed25519 public key,
 *   base64url SPKI DER. REQUIRED — absent => refuse (unpinned).
 * @param {object} [opts]
 * @param {number|string|Date} [opts.now]  reference time for the validity window;
 *   defaults to Date.now(). A string is parsed under the RFC-3339-with-offset profile.
 * @param {object} [opts.revocation]  a PRESENTED EP-REVOCATION-v1 statement to
 *   check against this grant_hash (target_type 'commit', target_id = grant_id).
 * @param {Object<string,{public_key:string}>} [opts.revokerKeys]  pinned revoker
 *   keys by revoker_id, passed through to verifyRevocation. If a revocation
 *   artifact is supplied but cannot be verified, the grant refuses with
 *   revocation_invalid; malformed negative evidence is never treated as absent.
 * @param {number} [opts.revocationMaxAgeSeconds]  DEPRECATED compatibility
 *   option; terminal revocation statements do not age out.
 * @returns {{ valid:boolean, checks:{hash:boolean, signature:boolean, within_window:boolean}, reason?:string }}
 */
export declare function verifyConsentGrant(grant: Obj, pinnedPrincipalKey: string | undefined, opts?: ConsentGrantOptions): GrantResult;
/**
 * Extract the grant_hash a receipt claims to act under. The per-action receipt
 * SHOULD carry grant_hash INSIDE its signed Action Object so the binding-moment
 * authorization is cryptographically tied to the standing grant it exercised.
 * The reference implementation now mints grant_hash natively into the canonical
 * Action Object (lib/guard-adapter.js), so it is covered by the action hash and
 * the human signature over the action.
 *
 * Precedence — the SIGNED reference is preferred over the caller override, so a
 * present, signed grant_hash always wins:
 *   1. receipt.action.grant_hash        (native, inside the signed Action Object) — STRONG
 *   2. receipt.action.consent_grant_hash (explicit signed alias)                  — STRONG
 *   3. receipt.grant_hash                (top-level; only signed if the receipt
 *                                         profile folds it under its signature)   — as strong as that profile
 *   4. overrideGrantHash                 (caller-supplied, out-of-band)           — ADVISORY
 *
 * STRENGTH BOUNDARY (honesty): a grant_hash read from the signed Action Object
 * (1 or 2) is a STRONG binding — tampering it breaks the action hash and thus the
 * receipt's own signature. A caller-supplied override (4) is ADVISORY: it is only
 * as trustworthy as the caller, since nothing in the receipt's cryptography
 * covers it. The signed reference therefore takes precedence and an override is
 * used ONLY when the receipt carries no native grant reference (the transitional
 * case for receipts minted before this field existed). Use
 * receiptGrantBindingStrength() to report which one applied.
 *
 * Returning the referenced hash is separate from checking it MATCHES the grant —
 * verifyReceiptUnderGrant does the comparison and refuses on mismatch.
 * @param {object} receipt
 * @param {string} [overrideGrantHash]  a grant_hash the caller supplies out-of-band
 *   when the receipt does not carry a native one (documented, transitional, ADVISORY).
 * @returns {string|null} the referenced grant_hash ("sha256:<hex>") or null.
 */
export declare function receiptReferencedGrantHash(receipt: Obj, overrideGrantHash?: string): string | null;
/**
 * Report WHERE the receipt's grant reference came from, so a relying party can
 * distinguish the strong (signed) binding from the advisory (caller-supplied)
 * one. Same precedence as receiptReferencedGrantHash().
 * @param {object} receipt
 * @param {string} [overrideGrantHash]
 * @returns {'signed_action' | 'top_level' | 'caller_override' | 'none'}
 *   - 'signed_action'   : from receipt.action.grant_hash / consent_grant_hash —
 *                         covered by the action hash + the receipt's signature (STRONG).
 *   - 'top_level'       : from receipt.grant_hash — strength depends on whether the
 *                         receipt profile signs that field.
 *   - 'caller_override' : from the out-of-band override — ADVISORY, as trustworthy
 *                         as the caller only.
 *   - 'none'            : the receipt references no grant and no override was given.
 */
export declare function receiptGrantBindingStrength(receipt: Obj, overrideGrantHash?: string): 'signed_action' | 'top_level' | 'caller_override' | 'none';
/**
 * COMPOSITION: verify that a per-action receipt legitimately "acts under" a
 * standing consent grant. This is the join between CAE binding 4 (the receipt,
 * the binding moment) and CAE binding 3 (this grant, standing authority).
 *
 * Verifies, all fail-closed with a DISTINCT reason:
 *   (a) grant           — verifyConsentGrant(grant, pinnedPrincipalKey): the grant
 *                         is authentic, in-window, and (if a statement is supplied)
 *                         not revoked. A bad hash/signature surfaces as
 *                         'grant_signature_invalid'; an out-of-window grant as
 *                         'grant_expired'; a revoked grant as 'grant_revoked'.
 *   (b) asset_covered   — the receipt's action asset is covered by the grant's
 *                         asset (exact match; extend with a scope predicate later).
 *   (c) verb_covered    — the receipt's action control verb is covered by the
 *                         grant's control_verb (exact match).
 *   (d) grant_binding   — the receipt REFERENCES grant_hash (per
 *                         receiptReferencedGrantHash — the SIGNED action.grant_hash
 *                         preferred over a caller override) and it equals the
 *                         grant's own grant_hash. The result also carries
 *                         `binding_strength` ('signed_action' | 'top_level' |
 *                         'caller_override' | 'none'): a signed reference is the
 *                         STRONG binding (covered by the receipt's signature), a
 *                         caller override is ADVISORY (as trustworthy as the caller).
 *
 * HONESTY: the grant is STANDING authority; the binding-moment receipt is the
 * PER-ACTION authorization. Both are required and they are DIFFERENT artifacts —
 * a valid grant does not authorize an action without a receipt bound to it, and a
 * receipt bound to a grant does not authorize an action the grant does not cover.
 * Neither establishes BUSINESS correctness. Offline verification of either is
 * authenticity-as-of-commit, NOT current validity: revocation currency needs a
 * fresh revocation snapshot supplied here, the same as any EP status. This
 * function does NOT re-verify the receipt's own cryptography end-to-end — call
 * verifyReceipt / verifyTrustReceipt for that; this checks the GRANT and the
 * SCOPE/BINDING join. It reads the receipt's asset/verb/grant_hash from the
 * signed Action Object, so those fields are covered by the receipt's own signature.
 *
 * Refusal reasons (distinct, fail-closed):
 *   'grant_signature_invalid' | 'grant_not_yet_valid' | 'grant_expired' | 'grant_revoked'
 *   | 'revocation_invalid' | 'asset_mismatch' | 'verb_mismatch' | 'grant_binding_mismatch'
 *   plus structural refusals ('missing_receipt', 'missing_action',
 *   'missing_grant_reference').
 *
 * @param {object} receipt  the per-action receipt.
 * @param {object} grant    the EP-CONSENT-GRANT-v1 standing grant.
 * @param {object} [opts]
 * @param {number|string|Date} [opts.now]  reference time (window + revocation freshness).
 * @param {string} [opts.pinnedPrincipalKey]  the grant principal's Ed25519 public key (base64url SPKI DER).
 * @param {object} [opts.revocation]  a presented EP-REVOCATION-v1 statement against the grant_hash.
 * @param {Object<string,{public_key:string}>} [opts.revokerKeys]  pinned revoker keys.
 * @param {number} [opts.revocationMaxAgeSeconds]  DEPRECATED compatibility
 *   option; terminal revocation statements do not age out.
 * @param {string} [opts.grantHash]  out-of-band grant_hash override when the receipt does not carry one.
 * @param {(receiptAsset:any, grantAsset:any)=>boolean} [opts.assetCovers]  optional
 *   scope predicate; default is strict equality. MUST fail closed (return false on doubt).
 * @param {(receiptVerb:any, grantVerb:any)=>boolean} [opts.verbCovers]  optional
 *   verb-coverage predicate; default is strict equality.
 * @returns {{ ok:boolean, checks:object, binding_strength?:string, reason?:string }}
 *   `binding_strength` (present from the grant-binding step onward) reports where
 *   the grant reference came from: 'signed_action' (strong) | 'top_level' |
 *   'caller_override' (advisory) | 'none'.
 */
export declare function verifyReceiptUnderGrant(receipt: Obj, grant: Obj, opts?: CompositionOptions): {
    ok: false;
    checks: Record<string, boolean>;
    reason: string;
} | {
    binding_strength: "none" | "signed_action" | "top_level" | "caller_override";
    ok: false;
    checks: Record<string, boolean>;
    reason: string;
} | {
    ok: boolean;
    checks: Record<string, boolean>;
    binding_strength: "none" | "signed_action" | "top_level" | "caller_override";
};
/**
 * Follows the reference hybrid migration written up in full in
 * packages/verify/src/revocation.ts (search for "EP-REVOCATION-v2" there for
 * the five-move pattern this copies). Short form as applied here:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. v1's `signature` string becomes v2's
 *    `signatures` array, which is a wire-format change, so the artifact takes
 *    a new `profile` (EP-CONSENT-GRANT-v1 -> EP-CONSENT-GRANT-v2) instead of
 *    growing an optional field on v1. verifyConsentGrant() above is untouched
 *    and still refuses a v2 grant on its very first content check
 *    (`grant.profile !== CONSENT_GRANT_VERSION`) before it ever looks at a
 *    v2-only field, so it cannot crash on one.
 *
 * 2. SET SHAPE. `signature` (string) becomes `signatures`: an array shaped
 *    exactly like EP-SIG-AGILITY-v1's AgileSignature ({ alg, sig, key_id? }),
 *    one entry per algorithm, in the registered order. The grant body also
 *    carries a `required_algorithms` field. Ed25519 keeps its base64url SPKI
 *    DER convention (via the caller's out-of-band pin); ML-DSA-65 carries raw
 *    base64url bytes, because it has no SPKI encoding EP consumes. Unlike
 *    EP-REVOCATION-v2, this artifact carries NO self-asserted key material at
 *    all -- verifyConsentGrant already required an out-of-band pinned key for
 *    v1, and v2 keeps that property, just widened to both algorithms.
 *
 * 3. ANTI-STRIPPING BYTES. grantSignedBodyV2() strips grant_hash and
 *    signatures (plural) but KEEPS required_algorithms in the body, and
 *    REFUSES to produce bytes at all unless the grant's own
 *    required_algorithms is exactly CONSENT_GRANT_V2_REQUIRED_ALGORITHMS.
 *    grant_hash and BOTH signatures are computed over those bytes. A narrowed
 *    or reordered required_algorithms therefore fails three ways at once: the
 *    algorithm_set check (direct comparison), and the hash + signature_set_valid
 *    checks (grantSignedBodyV2 refuses to even compute bytes to check against).
 *
 * 4. V1 COMPATIBILITY. verifyConsentGrant stays synchronous and unchanged.
 *    verifyConsentGrantV2 is a new, separate, ASYNC entry point (ML-DSA-65
 *    verification is async); verifyConsentGrantStatement() routes on
 *    `grant.profile` for a caller holding a mixed bag, mirroring
 *    verifyRevocationStatement().
 *
 * 5. NAMED REFUSALS. Every failure path sets a named boolean in `checks` and
 *    pushes a human-readable string to `errors`; nothing throws on grant
 *    contents, pinned keys, or signatures -- only canonicalize()/crypto calls
 *    wrapped in try/catch. An absent or failing ML-DSA backend surfaces
 *    through verifyAgileSignatureSet's own 'pq_backend_unavailable' reason as
 *    a refusal, never a pass on the Ed25519 leg alone.
 *
 * HONEST BOUNDARIES. Everything the v1 header says still holds: offline
 * verification proves the PRESENTED grant is authentic and in-window as of
 * the commit it was signed at, never that it is still LIVE. Revocation
 * currency and business correctness are exactly as out of scope as they are
 * for v1. v1 revocation statements remain valid evidence against a v2
 * grant's hash exactly as they do today for v1 grants -- there is no
 * v2-specific revocation path.
 */
export declare const CONSENT_GRANT_V2_VERSION = "EP-CONSENT-GRANT-v2";
/** The registered required algorithm set, in canonical order. */
export declare const CONSENT_GRANT_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface ConsentGrantV2Signature {
    alg?: unknown;
    sig?: unknown;
    key_id?: unknown;
}
/** A v2 principal pin: BOTH public halves, pinned out of band. Mirrors the
 * single pinnedPrincipalKey string v1 takes, widened to carry both algorithms. */
export interface PinnedPrincipalKeysV2 {
    /** Ed25519 base64url SPKI DER. */
    public_key?: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key?: string;
}
export interface ConsentGrantV2Options extends AgilityOptions {
    now?: number | string | Date;
    revocation?: Obj;
    revokerKeys?: Record<string, Obj>;
    revocationMaxAgeSeconds?: number;
}
export interface GrantV2Result {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
}
export interface ConsentGrantV2Signer {
    /** Ed25519 private key. */
    privateKey: crypto.KeyObject;
    /** ML-DSA-65 secret key: 4032 raw bytes, or base64url of them. */
    pqSecretKey: Uint8Array | string;
    /** ML-DSA-65 public key: 1952 raw bytes, or base64url of them. Validated
     *  for length only (catches a swapped secret/public pair at issuance) --
     *  never embedded in the grant; this artifact carries no self-asserted
     *  key material. */
    pqPublicKeyB64u: Uint8Array | string;
}
/**
 * Compute the v2 grant_hash: "sha256:" + hex over the canonical bytes of the
 * grant with grant_hash and signatures excluded (required_algorithms stays
 * in). Returns null (never throws) if the grant is unusable or its
 * required_algorithms is not the registered set.
 */
export declare function computeGrantHashV2(grant: Obj): string | null;
/**
 * REFERENCE ISSUER (tests / examples): mint an EP-CONSENT-GRANT-v2 hybrid
 * grant. Same spec/signer split as buildConsentGrant(), widened to a signer
 * carrying BOTH an Ed25519 private key and ML-DSA-65 secret+public key
 * material (mirrors lib/revocation/revocation.ts's RevocationV2Signer /
 * buildRevocationV2). THROWS rather than emit a half-hybrid grant --
 * issuer-side misuse is a programming error, and an unavailable ML-DSA
 * backend makes signAgileSet() throw, so a grant missing the PQ leg is never
 * produced.
 *
 * @param {object} spec  grant fields WITHOUT profile/required_algorithms/
 *   grant_hash/signatures: { grant_id, principal, asset, control_verb,
 *   constraints?, issued_at, expires_at }.
 * @param {object} signer  { privateKey: Ed25519 KeyObject, pqSecretKey,
 *   pqPublicKeyB64u }.
 * @returns {object} the complete EP-CONSENT-GRANT-v2 grant.
 */
export declare function buildConsentGrantV2(spec: Obj, signer: ConsentGrantV2Signer): Promise<Obj>;
/**
 * Verify an EP-CONSENT-GRANT-v2 hybrid standing consent grant, fully offline.
 * FAIL-CLOSED: every gating check must be true; any one false yields
 * valid:false, and a v2 grant NEVER verifies on one leg alone. Never throws
 * on caller-controlled input (grant contents, pinned keys, signatures).
 *
 * Establishes, all fail-closed (see the checks object for the full set):
 *   (version)              grant.profile === CONSENT_GRANT_V2_VERSION.
 *   (structure)             the same asset/control_verb sanity guard v1 uses.
 *   (algorithm_set)         grant.required_algorithms is EXACTLY the
 *                           registered set, order-sensitive.
 *   (legs_present)          grant.signatures carries one well-formed entry
 *                           per required algorithm, no duplicates, no extras.
 *   (key_pinned)            BOTH an Ed25519 and an ML-DSA-65 principal key
 *                           are pinned (identified-but-not-trusted).
 *   (within_window)         now is within [issued_at, expires_at].
 *   (hash)                  grant_hash binds the v2 body (including
 *                           required_algorithms).
 *   (signature_set_valid)   both signatures verify over the recomputed bytes
 *                           under the PINNED keys (never any self-asserted
 *                           key material -- this artifact carries none).
 *   (revocation)            if opts.revocation is supplied, the EXISTING v1
 *                           verifyRevocation() from revocation.js against a
 *                           {target_type:'commit', target_id: grant.grant_id,
 *                           action_hash: grant.grant_hash} target -- no
 *                           v2-specific revocation path.
 *
 * @param {object} grant  the EP-CONSENT-GRANT-v2 object.
 * @param {{public_key?:string, pq_public_key?:string}|undefined} pinnedPrincipalKeys
 *   the principal's Ed25519 (base64url SPKI DER) and ML-DSA-65 (base64url raw
 *   bytes) public keys. REQUIRED -- either half missing => refuse (unpinned).
 * @param {object} [opts]
 * @returns {Promise<{valid:boolean, checks:Record<string,boolean>, errors:string[]}>}
 */
export declare function verifyConsentGrantV2(grant: Obj, pinnedPrincipalKeys: PinnedPrincipalKeysV2 | undefined, opts?: ConsentGrantV2Options): Promise<GrantV2Result>;
/**
 * Route a grant of EITHER version to its verifier. v1 grants get the exact
 * v1 verdict (sync, wrapped as a resolved Promise); v2 grants get the async
 * hybrid check. A grant whose profile is neither refuses on the profile
 * marker, through the v1 verifier -- the fail-closed answer. Mirrors
 * verifyRevocationStatement() in revocation.ts.
 */
export declare function verifyConsentGrantStatement(grant: Obj, pinnedKeys: string | PinnedPrincipalKeysV2 | undefined, opts?: ConsentGrantOptions | ConsentGrantV2Options): Promise<GrantResult | GrantV2Result>;
export {};
//# sourceMappingURL=consent-grant.d.ts.map