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
export {};
//# sourceMappingURL=consent-grant.d.ts.map