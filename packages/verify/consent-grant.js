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
 *     the BINDING MOMENT: a named human's signature over the EXACT action, at
 *     the moment of consequence, before execution. Device binding is a property
 *     of the receipt's selected ceremony profile, not of this grant module.
 *   A receipt "acts under" a grant by carrying the grant's grant_hash;
 *   verifyReceiptUnderGrant() is that composition. When a grant carries
 *   non-empty `constraints`, composition also requires a relying-party supplied
 *   constraints evaluator. Signed constraints are never treated as decorative
 *   metadata.
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
const RFC3339_OFFSET = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/;
function parseInstant(value) {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_OFFSET);
  if (!match) return NaN;
  const [, year, month, day, hour, minute, second, , , offsetHour, offsetMinute] = match;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  if (calendar.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`) {
    return NaN;
  }
  if (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59)) {
    return NaN;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function normalizeNow(now) {
  if (now === undefined) return Date.now();
  if (typeof now === 'number') return now;
  const ms = parseInstant(now instanceof Date ? now.toISOString() : now);
  return ms;
}

// The signed / hashed body: the grant with BOTH grant_hash and signature
// removed. grant_hash is computed over these bytes, and the principal signs the
// SAME bytes, so the hash and the signature cover an identical, self-consistent
// object (the hash cannot contain its own value; the signature cannot contain
// its own value). Deep-clone via spread so we never mutate the caller's object.
function grantSignedBody(grant) {
  if (!grant || typeof grant !== 'object' || Array.isArray(grant)) return null;
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
  if (body === null) return null;
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
  if (recomputed === null) return false;
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
  const privateKey = signer && signer.privateKey ? signer.privateKey : signer;
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
 *   (signature)     the principal's Ed25519 signature verifies over the SAME
 *                   canonical body, under the caller-PINNED principal key. Key
 *                   custody or hardware binding is established outside this
 *                   verifier (an unpinned / self-asserted key confers NOTHING);
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
 * @param {string} pinnedPrincipalKey  the principal's Ed25519 public key,
 *   base64url SPKI DER. REQUIRED — absent => refuse (unpinned).
 * @param {object} [opts]
 * @param {number|string|Date} [opts.now]  reference time for the validity window;
 *   defaults to Date.now(). A string is parsed under the RFC-3339-with-offset profile.
 * @param {object} [opts.revocation]  a PRESENTED EP-REVOCATION-v1 statement to
 *   check against this grant_hash (target_type 'commit', target_id = grant_id).
 * @param {Object<string,{public_key:string}>} [opts.revokerKeys]  pinned revoker
 *   keys by revoker_id, passed through to verifyRevocation (a revocation under an
 *   unpinned revoker is ignored — it cannot revoke, fail-closed on the REVOKER).
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
  if (grant.constraints !== undefined
      && (!grant.constraints
        || typeof grant.constraints !== 'object'
        || Array.isArray(grant.constraints))) {
    return refuseGrant('grant constraints must be an object when supplied', checks);
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
    checks.signature = crypto.verify(
      null,
      Buffer.from(bodyCanonical, 'utf8'),
      keyObject,
      Buffer.from(grant.signature, 'base64url'),
    );
  } catch (e) {
    return refuseGrant(`grant signature verification failed: ${e.message}`, checks);
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
  if (Number.isNaN(nowMs)) {
    return refuseGrant('opts.now is not a parseable instant', checks);
  }
  if (nowMs < issuedMs) {
    return refuseGrant('grant is not yet valid (now is before issued_at)', checks);
  }
  if (nowMs > expiresMs) {
    return refuseGrant('grant is expired (now is after expires_at)', checks);
  }
  checks.within_window = true;

  // Revocation (optional): a presented statement that VALIDLY binds this
  // grant_hash under its OWN pinned revoker key refuses the grant. Reuses the
  // revocation.js verifier against a 'commit'-typed target keyed on grant_hash.
  if (opts.revocation !== undefined) {
    const target = {
      target_type: 'commit',
      target_id: grant.grant_id,
      action_hash: grant.grant_hash,
    };
    const rev = verifyRevocation(target, opts.revocation, {
      revokerKeys: opts.revokerKeys || {},
      ...(typeof opts.revocationMaxAgeSeconds === 'number'
        ? { maxAgeSeconds: opts.revocationMaxAgeSeconds, now: opts.now }
        : {}),
    });
    if (rev.valid) {
      return refuseGrant('grant_revoked', checks);
    }
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
      if (action.grant_hash) return action.grant_hash;
      if (action.consent_grant_hash) return action.consent_grant_hash;
    }
    if (receipt.grant_hash) return receipt.grant_hash;
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
    if (receipt.grant_hash) return 'top_level';
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
 *   (e) constraints     — when the signed grant carries one or more constraints,
 *                         the relying party MUST supply `constraintsCover`.
 *                         The evaluator receives the signed Action Object, the
 *                         signed constraints, and the verified grant, and MUST
 *                         return exactly true. Missing, throwing, or false
 *                         evaluators refuse.
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
 *   'grant_signature_invalid' | 'grant_constraints_invalid' | 'grant_not_yet_valid'
 *   | 'grant_expired' | 'grant_revoked' | 'asset_mismatch' | 'verb_mismatch'
 *   | 'grant_binding_mismatch' | 'constraint_evaluator_missing' | 'constraints_mismatch'
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
 * @param {(action:object, constraints:object, grant:object)=>boolean} [opts.constraintsCover]
 *   REQUIRED when `grant.constraints` is non-empty. It MUST return exactly true
 *   to authorize; false, a truthy non-boolean value, or an exception refuses.
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
    constraints_covered: false,
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
    if (grantResult.reason === 'grant_revoked') reason = 'grant_revoked';
    else if (grantResult.reason === 'grant constraints must be an object when supplied') {
      reason = 'grant_constraints_invalid';
    }
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
  } catch {
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
  } catch {
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
  // member) so a relying party can distinguish a strong from an advisory
  // binding and price it.
  const referenced = receiptReferencedGrantHash(receipt, opts.grantHash);
  const bindingStrength = receiptGrantBindingStrength(receipt, opts.grantHash);
  if (!referenced) {
    return { ...refuseComposition('missing_grant_reference', checks), binding_strength: bindingStrength };
  }
  checks.grant_binding = hexOf(referenced) !== '' && hexOf(referenced) === hexOf(grant.grant_hash);
  if (!checks.grant_binding) {
    return { ...refuseComposition('grant_binding_mismatch', checks), binding_strength: bindingStrength };
  }

  // (e) profile constraints. The generic verifier cannot safely guess the
  // semantics of fields such as amount ceilings, jurisdictions, purposes, or
  // media-use terms. A signed constraint therefore requires an explicit
  // profile evaluator instead of silently becoming unenforced metadata.
  const constraints = grant.constraints;
  const hasConstraints = constraints
    && typeof constraints === 'object'
    && !Array.isArray(constraints)
    && Object.keys(constraints).length > 0;
  if (hasConstraints) {
    if (typeof opts.constraintsCover !== 'function') {
      return {
        ...refuseComposition('constraint_evaluator_missing', checks),
        binding_strength: bindingStrength,
      };
    }
    try {
      checks.constraints_covered = opts.constraintsCover(action, constraints, grant) === true;
    } catch {
      checks.constraints_covered = false;
    }
    if (!checks.constraints_covered) {
      return {
        ...refuseComposition('constraints_mismatch', checks),
        binding_strength: bindingStrength,
      };
    }
  } else {
    checks.constraints_covered = true;
  }

  return { ok: true, checks, binding_strength: bindingStrength };
}
