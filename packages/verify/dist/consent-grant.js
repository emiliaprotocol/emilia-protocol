// SPDX-License-Identifier: Apache-2.0
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
import { canonicalize } from './index.js';
import { verifyRevocation } from './revocation.js';
import { signAgileSet, verifyAgileSignatureSet, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, } from './pq-signature-agility.js';
export const CONSENT_GRANT_VERSION = 'EP-CONSENT-GRANT-v1';
const HASH_PREFIX = /^sha256:/i;
function sha256Hex(input) {
    return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}
// Normalize a "sha256:<hex>" or bare hex string to a well-formed 64-char hex, or
// '' if malformed. '' can never equal a real digest, so comparisons fail closed.
// Mirrors revocation.js hexOf() exactly (cross-language consistent).
function hexOf(h) {
    const s = String(h ?? '').replace(HASH_PREFIX, '').toLowerCase();
    return /^[0-9a-f]{64}$/.test(s) ? s : '';
}
// Canonical EP timestamp profile: RFC 3339 with an EXPLICIT UTC offset ("Z" or
// ±hh:mm). No-timezone and date-only forms are REJECTED as ambiguous. Identical
// to parseInstant() in index.js — the one profile JS, Python, and Go all parse
// and reject identically (fail-closed). Returns epoch ms or NaN.
const RFC3339_OFFSET = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
function parseInstant(value) {
    if (typeof value !== 'string' || !RFC3339_OFFSET.test(value))
        return NaN;
    return Date.parse(value);
}
function normalizeNow(now) {
    if (now === undefined)
        return Date.now();
    if (typeof now === 'number')
        return Number.isFinite(now) ? now : NaN;
    if (now instanceof Date) {
        const ms = now.getTime();
        return Number.isFinite(ms) ? ms : NaN;
    }
    return parseInstant(now);
}
// The signed / hashed body: the grant with BOTH grant_hash and signature
// removed. grant_hash is computed over these bytes, and the principal signs the
// SAME bytes, so the hash and the signature cover an identical, self-consistent
// object (the hash cannot contain its own value; the signature cannot contain
// its own value). Deep-clone via spread so we never mutate the caller's object.
function grantSignedBody(grant) {
    if (!grant || typeof grant !== 'object' || Array.isArray(grant))
        return null;
    const body = { ...grant };
    delete body.grant_hash;
    delete body.signature;
    return body;
}
/**
 * Compute the grant_hash: "sha256:" + hex over the JCS/RFC-8785 canonical bytes
 * of the grant with grant_hash and signature excluded. Same canonicalize() +
 * SHA-256 EP uses everywhere.
 * @param {object} grant
 * @returns {string|null} "sha256:<hex>" or null if the grant is unusable.
 */
export function computeGrantHash(grant) {
    const body = grantSignedBody(grant);
    if (body === null)
        return null;
    return 'sha256:' + sha256Hex(canonicalize(body));
}
/**
 * True iff grant.grant_hash equals the recomputed hash over the grant body.
 * Fail-closed: a missing or malformed grant_hash returns false.
 * @param {object} grant
 * @returns {boolean}
 */
export function verifyGrantHash(grant) {
    const recomputed = computeGrantHash(grant);
    if (recomputed === null)
        return false;
    return hexOf(grant?.grant_hash) === hexOf(recomputed);
}
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
export function buildConsentGrant(spec, signer) {
    const s = /** @type {any} */ (signer);
    const privateKey = s && s.privateKey ? s.privateKey : s;
    const grant = {
        profile: CONSENT_GRANT_VERSION,
        ...spec,
    };
    delete grant.grant_hash;
    delete grant.signature;
    const body = grantSignedBody(grant);
    const bodyBytes = Buffer.from(canonicalize(body), 'utf8');
    const grantHash = 'sha256:' + sha256Hex(canonicalize(body));
    const signature = crypto.sign(null, bodyBytes, privateKey).toString('base64url');
    return { ...grant, grant_hash: grantHash, signature };
}
function refuseGrant(reason, checks) {
    return { valid: false, checks, reason };
}
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
export function verifyConsentGrant(grant, pinnedPrincipalKey, opts = {}) {
    const checks = { hash: false, signature: false, within_window: false };
    if (!grant || typeof grant !== 'object' || Array.isArray(grant)) {
        return refuseGrant('no grant presented (fail-closed)', checks);
    }
    if (grant.profile !== CONSENT_GRANT_VERSION) {
        return refuseGrant(`unsupported profile "${grant.profile}" (expected ${CONSENT_GRANT_VERSION})`, checks);
    }
    if (!grant.asset || !grant.control_verb) {
        return refuseGrant('grant is missing asset or control_verb', checks);
    }
    // (hash) grant_hash must bind the canonical grant body.
    const body = grantSignedBody(grant);
    if (body === null) {
        return refuseGrant('grant body could not be canonicalized', checks);
    }
    const bodyCanonical = canonicalize(body);
    const recomputedHash = 'sha256:' + sha256Hex(bodyCanonical);
    checks.hash = hexOf(grant.grant_hash) !== '' && hexOf(grant.grant_hash) === hexOf(recomputedHash);
    if (!checks.hash) {
        return refuseGrant('grant_hash does not bind the canonical grant body (tampered or malformed hash)', checks);
    }
    // (signature) the principal's Ed25519 signature over the SAME body, under the
    // PINNED principal key. Absent key => unpinned => refuse.
    if (typeof pinnedPrincipalKey !== 'string' || !pinnedPrincipalKey) {
        return refuseGrant('no pinned principal key (grant principal identified but not trusted)', checks);
    }
    if (typeof grant.signature !== 'string' || !grant.signature) {
        return refuseGrant('grant signature is missing', checks);
    }
    try {
        const keyObject = crypto.createPublicKey({
            key: Buffer.from(pinnedPrincipalKey, 'base64url'),
            format: 'der',
            type: 'spki',
        });
        checks.signature = crypto.verify(null, Buffer.from(bodyCanonical, 'utf8'), keyObject, Buffer.from(grant.signature, 'base64url'));
    }
    catch (e) {
        return refuseGrant(`grant signature verification failed: ${e instanceof Error ? e.message : String(e)}`, checks);
    }
    if (!checks.signature) {
        return refuseGrant('grant signature does not verify under the pinned principal key', checks);
    }
    // (within_window) now within [issued_at, expires_at], RFC-3339-with-offset.
    const issuedMs = parseInstant(grant.issued_at);
    const expiresMs = parseInstant(grant.expires_at);
    if (Number.isNaN(issuedMs) || Number.isNaN(expiresMs)) {
        return refuseGrant('grant issued_at or expires_at is not an RFC-3339 instant with an explicit offset', checks);
    }
    if (issuedMs > expiresMs) {
        return refuseGrant('grant issued_at is after expires_at (empty validity window)', checks);
    }
    const nowMs = normalizeNow(opts.now);
    if (!Number.isFinite(nowMs)) {
        return refuseGrant('opts.now is not a parseable instant', checks);
    }
    if (nowMs < issuedMs) {
        return refuseGrant('grant is not yet valid (now is before issued_at)', checks);
    }
    if (nowMs > expiresMs) {
        return refuseGrant('grant is expired (now is after expires_at)', checks);
    }
    checks.within_window = true;
    // Revocation (optional): once the caller supplies a statement, it becomes a
    // required security input. A valid binding statement refuses as revoked; an
    // invalid, unpinned, malformed, or wrong-target statement refuses as
    // revocation_invalid. Silently treating bad negative evidence as absence
    // would revive the grant.
    if (opts.revocation !== undefined) {
        const target = {
            target_type: 'commit',
            target_id: grant.grant_id,
            action_hash: grant.grant_hash,
        };
        const rev = verifyRevocation(target, opts.revocation, {
            revokerKeys: opts.revokerKeys || {},
            now: opts.now,
            ...(typeof opts.revocationMaxAgeSeconds === 'number'
                ? { maxAgeSeconds: opts.revocationMaxAgeSeconds }
                : {}),
        });
        if (rev.valid) {
            return refuseGrant('grant_revoked', checks);
        }
        return refuseGrant('revocation_invalid', checks);
    }
    return { valid: true, checks };
}
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
export function receiptReferencedGrantHash(receipt, overrideGrantHash) {
    if (receipt && typeof receipt === 'object') {
        const action = receipt.action;
        if (action && typeof action === 'object') {
            // Prefer the SIGNED action-object reference (strong binding) over any
            // caller override (advisory), so a native grant_hash always wins.
            if (action.grant_hash)
                return action.grant_hash;
            if (action.consent_grant_hash)
                return action.consent_grant_hash;
        }
        if (receipt.grant_hash)
            return receipt.grant_hash;
    }
    return overrideGrantHash || null;
}
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
export function receiptGrantBindingStrength(receipt, overrideGrantHash) {
    if (receipt && typeof receipt === 'object') {
        const action = receipt.action;
        if (action && typeof action === 'object' && (action.grant_hash || action.consent_grant_hash)) {
            return 'signed_action';
        }
        if (receipt.grant_hash)
            return 'top_level';
    }
    return overrideGrantHash ? 'caller_override' : 'none';
}
function refuseComposition(reason, checks) {
    return { ok: false, checks, reason };
}
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
export function verifyReceiptUnderGrant(receipt, grant, opts = {}) {
    const checks = {
        grant: false,
        asset_covered: false,
        verb_covered: false,
        grant_binding: false,
    };
    if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
        return refuseComposition('missing_receipt', checks);
    }
    const action = receipt.action;
    if (!action || typeof action !== 'object') {
        return refuseComposition('missing_action', checks);
    }
    // (a) the grant itself. Map its refusal onto a distinct composition reason.
    const grantResult = verifyConsentGrant(grant, opts.pinnedPrincipalKey, {
        now: opts.now,
        revocation: opts.revocation,
        revokerKeys: opts.revokerKeys,
        revocationMaxAgeSeconds: opts.revocationMaxAgeSeconds,
    });
    checks.grant = grantResult.valid;
    if (!grantResult.valid) {
        let reason = 'grant_signature_invalid';
        if (grantResult.reason === 'grant_revoked')
            reason = 'grant_revoked';
        else if (grantResult.reason === 'revocation_invalid')
            reason = 'revocation_invalid';
        else if (grantResult.checks.within_window === false && grantResult.checks.hash && grantResult.checks.signature) {
            reason = (grantResult.reason && grantResult.reason.includes('not yet valid'))
                ? 'grant_not_yet_valid'
                : 'grant_expired';
        }
        return refuseComposition(reason, checks);
    }
    // (b) asset coverage. Default is strict equality; a caller MAY supply a
    // fail-closed scope predicate for hierarchical assets.
    const assetCovers = typeof opts.assetCovers === 'function'
        ? opts.assetCovers
        : (a, b) => a === b;
    try {
        checks.asset_covered = assetCovers(action.asset, grant.asset) === true;
    }
    catch {
        // A caller-supplied predicate is policy code, not trusted verification
        // evidence. A buggy or hostile predicate must refuse rather than escape the
        // verifier's structured result contract or crash its enclosing service.
        checks.asset_covered = false;
    }
    if (!checks.asset_covered) {
        return refuseComposition('asset_mismatch', checks);
    }
    // (c) verb coverage. Default is strict equality.
    const verbCovers = typeof opts.verbCovers === 'function'
        ? opts.verbCovers
        : (a, b) => a === b;
    try {
        checks.verb_covered = verbCovers(action.control_verb, grant.control_verb) === true;
    }
    catch {
        checks.verb_covered = false;
    }
    if (!checks.verb_covered) {
        return refuseComposition('verb_mismatch', checks);
    }
    // (d) grant binding. The receipt MUST reference the grant's grant_hash (or the
    // caller supplies it out-of-band, transitional) and it MUST equal the grant's.
    // The SIGNED action.grant_hash is preferred over the caller override; a signed
    // reference is the STRONG binding (covered by the receipt's own signature),
    // while a caller override is ADVISORY (only as trustworthy as the caller).
    // binding_strength is surfaced as a top-level result field (NOT a `checks`
    // member, so the frozen four-member checks shape is unchanged) so a relying
    // party can distinguish a strong from an advisory binding and price it.
    const referenced = receiptReferencedGrantHash(receipt, opts.grantHash);
    const bindingStrength = receiptGrantBindingStrength(receipt, opts.grantHash);
    if (!referenced) {
        return { ...refuseComposition('missing_grant_reference', checks), binding_strength: bindingStrength };
    }
    checks.grant_binding = hexOf(referenced) !== '' && hexOf(referenced) === hexOf(grant.grant_hash);
    if (!checks.grant_binding) {
        return { ...refuseComposition('grant_binding_mismatch', checks), binding_strength: bindingStrength };
    }
    return { ok: true, checks, binding_strength: bindingStrength };
}
// ===========================================================================
// EP-CONSENT-GRANT-v2 -- the hybrid (Ed25519 + ML-DSA-65) standing-consent grant
// ===========================================================================
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
export const CONSENT_GRANT_V2_VERSION = 'EP-CONSENT-GRANT-v2';
/** The registered required algorithm set, in canonical order. */
export const CONSENT_GRANT_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
function algorithmSetMatchesRegisteredGrant(algorithms) {
    return Array.isArray(algorithms)
        && algorithms.length === CONSENT_GRANT_V2_REQUIRED_ALGORITHMS.length
        && algorithms.every((a, i) => a === CONSENT_GRANT_V2_REQUIRED_ALGORITHMS[i]);
}
function agilityPassthroughGrant(opts) {
    const out = {};
    if (opts.mldsaBackend !== undefined)
        out.mldsaBackend = opts.mldsaBackend;
    if (opts.mldsaBackendLoader !== undefined)
        out.mldsaBackendLoader = opts.mldsaBackendLoader;
    if (opts.deterministic !== undefined)
        out.deterministic = opts.deterministic;
    return out;
}
function toRawB64uGrant(value, expectedLength, label) {
    const bytes = value instanceof Uint8Array
        ? Buffer.from(value)
        : (/^[A-Za-z0-9_-]+$/.test(String(value)) ? Buffer.from(String(value), 'base64url') : Buffer.alloc(0));
    if (bytes.length !== expectedLength) {
        throw new Error(`buildConsentGrantV2: ${label} must be ${expectedLength} raw bytes (or base64url of them)`);
    }
    return bytes.toString('base64url');
}
/**
 * The v2 signed / hashed body: the grant with grant_hash and signatures
 * (plural) removed, KEEPING required_algorithms -- so the algorithm set is
 * itself part of what grant_hash binds and what both signatures cover.
 * Throws (never silently narrows) unless the grant's own required_algorithms
 * is EXACTLY the registered CONSENT_GRANT_V2_REQUIRED_ALGORITHMS set: a
 * narrowed, widened, or reordered set can never even be turned into signable
 * bytes here, so hashing, signing, and verifying all refuse together instead
 * of computing bytes over a set the presenter invented. Deep-clone via spread
 * so we never mutate the caller's object, exactly like grantSignedBody().
 */
function grantSignedBodyV2(grant) {
    if (!grant || typeof grant !== 'object' || Array.isArray(grant)) {
        throw new Error('grantSignedBodyV2: grant must be an object');
    }
    if (!algorithmSetMatchesRegisteredGrant(grant.required_algorithms)) {
        throw new Error('grantSignedBodyV2: grant.required_algorithms is not the registered EP-CONSENT-GRANT-v2 set');
    }
    const body = { ...grant };
    delete body.grant_hash;
    delete body.signatures;
    return body;
}
/**
 * Compute the v2 grant_hash: "sha256:" + hex over the canonical bytes of the
 * grant with grant_hash and signatures excluded (required_algorithms stays
 * in). Returns null (never throws) if the grant is unusable or its
 * required_algorithms is not the registered set.
 */
export function computeGrantHashV2(grant) {
    try {
        return 'sha256:' + sha256Hex(canonicalize(grantSignedBodyV2(grant)));
    }
    catch {
        return null;
    }
}
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
export async function buildConsentGrantV2(spec, signer) {
    if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
        throw new Error('buildConsentGrantV2: spec must be an object');
    }
    if (!spec.asset || !spec.control_verb) {
        throw new Error('buildConsentGrantV2: spec must include asset and control_verb (fail-closed honesty gate)');
    }
    const issuedMs = parseInstant(spec.issued_at);
    const expiresMs = parseInstant(spec.expires_at);
    if (!Number.isFinite(issuedMs) || !Number.isFinite(expiresMs)) {
        throw new Error('buildConsentGrantV2: issued_at and expires_at must be RFC-3339 instants with an explicit offset');
    }
    if (issuedMs > expiresMs) {
        throw new Error('buildConsentGrantV2: issued_at is after expires_at (empty validity window)');
    }
    if (!signer || typeof signer !== 'object') {
        throw new Error('buildConsentGrantV2 requires signer.{privateKey,pqSecretKey,pqPublicKeyB64u}');
    }
    const privateKey = signer.privateKey;
    if (!privateKey || typeof privateKey !== 'object' || privateKey.type !== 'private') {
        throw new Error('buildConsentGrantV2: signer.privateKey must be a node crypto Ed25519 private KeyObject');
    }
    if (privateKey.asymmetricKeyType !== 'ed25519') {
        throw new Error('buildConsentGrantV2: signer.privateKey must be Ed25519 (algorithm-key mismatch)');
    }
    if (!signer.pqSecretKey) {
        throw new Error('buildConsentGrantV2 requires signer.pqSecretKey');
    }
    if (!signer.pqPublicKeyB64u) {
        throw new Error('buildConsentGrantV2 requires signer.pqPublicKeyB64u');
    }
    const pqSecret = toRawB64uGrant(signer.pqSecretKey, ML_DSA_65_SECRET_KEY_BYTES, 'signer.pqSecretKey');
    toRawB64uGrant(signer.pqPublicKeyB64u, ML_DSA_65_PUBLIC_KEY_BYTES, 'signer.pqPublicKeyB64u');
    const grant = {
        profile: CONSENT_GRANT_V2_VERSION,
        ...spec,
        required_algorithms: [...CONSENT_GRANT_V2_REQUIRED_ALGORITHMS],
    };
    delete grant.grant_hash;
    delete grant.signatures;
    const body = grantSignedBodyV2(grant);
    const bodyCanonical = canonicalize(body);
    const bodyBytes = Buffer.from(bodyCanonical, 'utf8');
    const grantHash = 'sha256:' + sha256Hex(bodyCanonical);
    const signatures = await signAgileSet(new Uint8Array(bodyBytes), [
        { alg: 'Ed25519', private_key: privateKey },
        { alg: 'ML-DSA-65', private_key: pqSecret },
    ]);
    const byAlg = new Map(signatures.map((s) => [s.alg, s]));
    const ordered = CONSENT_GRANT_V2_REQUIRED_ALGORITHMS.map((alg) => {
        const s = byAlg.get(alg);
        if (!s)
            throw new Error(`buildConsentGrantV2: signing produced no ${alg} leg`);
        return s;
    });
    return { ...grant, grant_hash: grantHash, signatures: ordered };
}
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
export async function verifyConsentGrantV2(grant, pinnedPrincipalKeys, opts = {}) {
    opts = opts && typeof opts === 'object' ? opts : {};
    const checks = {
        version: true,
        structure: true,
        algorithm_set: true,
        legs_present: true,
        key_pinned: true,
        within_window: true,
        hash: true,
        signature_set_valid: true,
        revocation: true,
    };
    const errors = [];
    const fail = (key, msg) => { checks[key] = false; errors.push(msg); };
    const done = () => ({ valid: Object.values(checks).every(Boolean), checks, errors });
    if (!grant || typeof grant !== 'object' || Array.isArray(grant)) {
        fail('structure', 'no grant presented (fail-closed)');
        fail('hash', 'no grant presented (fail-closed)');
        fail('signature_set_valid', 'no grant presented (fail-closed)');
        return done();
    }
    // 1. version. A v1 grant handed here refuses cleanly, the mirror image of
    //    v1's verifyConsentGrant refusing a v2 grant on its own profile check.
    if (grant.profile !== CONSENT_GRANT_V2_VERSION) {
        fail('version', `unsupported profile "${grant.profile}" (expected ${CONSENT_GRANT_V2_VERSION})`);
    }
    // 2. structure: the same early guard v1 uses.
    if (!grant.asset || !grant.control_verb) {
        fail('structure', 'grant is missing asset or control_verb');
    }
    // 3. algorithm_set: exact, order-sensitive. A narrowed / widened / reordered
    //    set refuses here AND (independently) makes grantSignedBodyV2 refuse to
    //    even produce signable bytes below, so hash and signature_set_valid also
    //    fail together -- the presented set is never trusted for what to verify
    //    against.
    if (!algorithmSetMatchesRegisteredGrant(grant.required_algorithms)) {
        fail('algorithm_set', `grant.required_algorithms must be exactly ${JSON.stringify([...CONSENT_GRANT_V2_REQUIRED_ALGORITHMS])} (set narrowing / widening refused)`);
    }
    // 4. exactly one signature per required algorithm.
    const signatures = Array.isArray(grant.signatures) ? grant.signatures : null;
    if (!signatures || signatures.length === 0) {
        fail('legs_present', 'grant.signatures must carry one signature per required algorithm');
    }
    else {
        const presented = new Set();
        let malformed = false;
        for (const s of signatures) {
            if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
                fail('legs_present', 'each grant.signatures entry must be { alg, sig, key_id? }');
                malformed = true;
                break;
            }
            if (presented.has(s.alg)) {
                fail('legs_present', `duplicate signature for algorithm "${s.alg}"`);
                malformed = true;
                break;
            }
            presented.add(s.alg);
        }
        if (!malformed) {
            for (const alg of CONSENT_GRANT_V2_REQUIRED_ALGORITHMS) {
                if (!presented.has(alg))
                    fail('legs_present', `missing required ${alg} signature (leg stripped)`);
            }
            for (const alg of presented) {
                if (!CONSENT_GRANT_V2_REQUIRED_ALGORITHMS.includes(alg)) {
                    fail('legs_present', `unexpected algorithm "${alg}" outside the registered set`);
                }
            }
        }
    }
    // 5. principal keys: BOTH halves pinned. Identified-but-not-trusted -- a
    //    self-asserted key confers NOTHING, and this artifact carries no key
    //    material on the grant itself; the caller always pins out of band.
    const pins = pinnedPrincipalKeys && typeof pinnedPrincipalKeys === 'object' ? pinnedPrincipalKeys : {};
    const pinnedEd = typeof pins.public_key === 'string' && pins.public_key.length > 0 ? pins.public_key : null;
    const pinnedPq = typeof pins.pq_public_key === 'string' && pins.pq_public_key.length > 0 ? pins.pq_public_key : null;
    if (!pinnedEd || !pinnedPq) {
        fail('key_pinned', 'no pinned Ed25519 + ML-DSA-65 principal key pair (grant principal identified but not trusted)');
    }
    // 6. within_window: identical RFC-3339 window logic to v1.
    const issuedMs = parseInstant(grant.issued_at);
    const expiresMs = parseInstant(grant.expires_at);
    const nowMs = normalizeNow(opts.now);
    if (Number.isNaN(issuedMs) || Number.isNaN(expiresMs)) {
        fail('within_window', 'grant issued_at or expires_at is not an RFC-3339 instant with an explicit offset');
    }
    else if (issuedMs > expiresMs) {
        fail('within_window', 'grant issued_at is after expires_at (empty validity window)');
    }
    else if (!Number.isFinite(nowMs)) {
        fail('within_window', 'opts.now is not a parseable instant');
    }
    else if (nowMs < issuedMs) {
        fail('within_window', 'grant is not yet valid (now is before issued_at)');
    }
    else if (nowMs > expiresMs) {
        fail('within_window', 'grant is expired (now is after expires_at)');
    }
    // 7. hash: grant_hash binds the v2 body, which INCLUDES required_algorithms
    //    (see grantSignedBodyV2). A narrowed/widened/reordered set makes
    //    grantSignedBodyV2 refuse to even produce bytes, so hash and
    //    signature_set_valid fail together with algorithm_set above.
    let recomputedBytes = null;
    try {
        recomputedBytes = Buffer.from(canonicalize(grantSignedBodyV2(grant)), 'utf8');
    }
    catch {
        recomputedBytes = null;
    }
    if (!recomputedBytes) {
        fail('hash', 'grant body could not be canonicalized (missing, malformed, or non-registered required_algorithms)');
        fail('signature_set_valid', 'grant body could not be canonicalized (missing, malformed, or non-registered required_algorithms)');
        return done();
    }
    const bodyCanonical = recomputedBytes.toString('utf8');
    const recomputedHash = 'sha256:' + sha256Hex(bodyCanonical);
    if (hexOf(grant.grant_hash) === '' || hexOf(grant.grant_hash) !== hexOf(recomputedHash)) {
        fail('hash', 'grant_hash does not bind the canonical v2 grant body (tampered or malformed)');
    }
    // 8. signature set: BOTH legs, over the recomputed bytes, under the PINNED
    //    keys only -- never any self-asserted key material.
    if (!signatures) {
        fail('signature_set_valid', 'no signatures to verify (leg stripped)');
    }
    else if (!pinnedEd || !pinnedPq) {
        fail('signature_set_valid', 'no pinned Ed25519 + ML-DSA-65 principal key pair (grant principal identified but not trusted)');
    }
    else {
        const verificationKeys = [
            { alg: 'Ed25519', public_key: pinnedEd },
            { alg: 'ML-DSA-65', public_key: pinnedPq },
        ];
        let setResult;
        try {
            setResult = await verifyAgileSignatureSet(new Uint8Array(recomputedBytes), signatures, verificationKeys, {
                ...agilityPassthroughGrant(opts),
                policy: 'hybrid_all',
                requiredAlgorithms: [...CONSENT_GRANT_V2_REQUIRED_ALGORITHMS],
            });
        }
        catch {
            // verifyAgileSignatureSet documents that it never throws; an injected
            // backend that does is still a refusal here, never a pass.
            setResult = null;
        }
        if (setResult?.verified !== true) {
            const reason = String(setResult?.reason ?? 'signature_set_unverified');
            fail('signature_set_valid', `grant signature set does not verify under the pinned Ed25519 + ML-DSA-65 keys (${reason})`);
        }
    }
    // 9. revocation (optional): identical semantics to v1 -- once supplied it
    //    becomes a required security input; a valid binding statement refuses
    //    as revoked, an invalid/unpinned/malformed/wrong-target statement
    //    refuses as revocation_invalid. Reuses the EXISTING v1 verifyRevocation
    //    from revocation.js against the grant_hash; no v2-specific revocation
    //    path.
    if (opts.revocation !== undefined) {
        const target = {
            target_type: 'commit',
            target_id: grant.grant_id,
            action_hash: grant.grant_hash,
        };
        const rev = verifyRevocation(target, opts.revocation, {
            revokerKeys: opts.revokerKeys || {},
            now: opts.now,
            ...(typeof opts.revocationMaxAgeSeconds === 'number'
                ? { maxAgeSeconds: opts.revocationMaxAgeSeconds }
                : {}),
        });
        if (rev.valid) {
            fail('revocation', 'grant_revoked');
        }
        else {
            fail('revocation', 'revocation_invalid');
        }
    }
    return done();
}
/**
 * Route a grant of EITHER version to its verifier. v1 grants get the exact
 * v1 verdict (sync, wrapped as a resolved Promise); v2 grants get the async
 * hybrid check. A grant whose profile is neither refuses on the profile
 * marker, through the v1 verifier -- the fail-closed answer. Mirrors
 * verifyRevocationStatement() in revocation.ts.
 */
export async function verifyConsentGrantStatement(grant, pinnedKeys, opts = {}) {
    if (grant && typeof grant === 'object' && !Array.isArray(grant) && grant.profile === CONSENT_GRANT_V2_VERSION) {
        return verifyConsentGrantV2(grant, pinnedKeys, opts);
    }
    return verifyConsentGrant(grant, pinnedKeys, opts);
}
//# sourceMappingURL=consent-grant.js.map