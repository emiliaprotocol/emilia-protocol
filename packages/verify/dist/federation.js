/**
 * @emilia-protocol/verify — Federation (PIP-006)
 *
 * Operator-B cross-operator verification client.
 *
 * PIP-006 defines the minimal contract that lets an EP-RECEIPT-v1 issued by
 * Operator A be verified by an independent Operator B using only A's published
 * discovery surfaces — no shared database, no central authority, no trust in
 * A's policy decisions. This module is the relying-party (Operator B) side of
 * that contract.
 *
 * Cross-operator semantics (PIP-006 §"Cross-operator semantics"). Given a
 * receipt from Operator A, Operator B MUST:
 *   1. Resolve A's verification key from A's /.well-known/ep-keys.json
 *      (current key, or a historical key if the receipt predates a rotation).
 *   2. Verify the Ed25519 signature over the canonical receipt payload.
 *   3. Confirm the receipt is not in A's revocation set.
 *   4. Apply B's *local* trust policy to the verified receipt.
 *
 * This module performs steps 1–3 and returns the evidence, and it enforces the
 * decisive part of step 4: a receipt is only ever `accepted` when the relying
 * party has independently, out-of-band, pinned the issuing operator.
 *
 * TRUST ANCHOR — fail closed. `verified` and `accepted` are DIFFERENT verdicts:
 *   - `verified` = the signature checks out against a key the receipt's own
 *     discovery surface advertises. This proves the payload was signed by
 *     whoever controls `signature.signer`'s key — nothing more.
 *   - `accepted` = the relying party trusts that signer. This decision MUST be
 *     anchored in a caller-supplied, out-of-band trust source (a pinned issuer
 *     allowlist and/or an expectedSigner and/or a pinned key set). It is NEVER
 *     derived solely from fields the receipt carries.
 *
 * The receipt-carried `signature.signer` and `signature.key_discovery` are
 * ATTACKER-CONTROLLED. An attacker can mint a receipt with their own key, host
 * a matching ep-keys.json at a URL they control, and point key_discovery there.
 * Such a receipt will `verify` (its signature is internally consistent) but it
 * must NEVER `accept` unless the relying party has already pinned that issuer.
 *
 * PINNING THE ID IS NOT ENOUGH — PIN THE KEY SOURCE. A bare signer-id pin does
 * not authenticate WHERE the verifying key comes from. The receipt still names
 * the discovery URL, so an attacker who sets `signature.signer` to a pinned id
 * and points `key_discovery` at their own ep-keys.json (advertising THEIR key
 * under the pinned id) would otherwise verify-and-accept — laundering trust
 * through a pinned string. To close this, a pin MUST bind the key SOURCE for
 * that signer: an expected discovery origin/URL and/or a pinned public key. A
 * receipt-supplied key_discovery is honored ONLY when its origin matches what
 * the relying party pinned for that signer (online), and a matched key is
 * accepted ONLY when it is the pinned key, if one was pinned (online + offline).
 * A caller-supplied opts.keyDiscoveryUrl is the relying party's OWN choice and
 * needs no such origin match. A receipt-carried key_discovery URL is at most a
 * *hint*: it is only fetched when the signer is pinned AND its origin is bound,
 * and every such fetch is routed through an SSRF guard (see assertSafeFetchUrl).
 *
 * "Federation enables receipt portability. It does not enable trust
 * laundering." — PIP-006.
 *
 * Zero runtime dependencies. Works fully offline when the caller supplies the
 * discovery document and revocation set. Online verification requires a
 * caller-provided resolver + pinned transport boundary; a plain injected or
 * global fetch cannot prevent DNS rebinding and is never treated as safe.
 *
 * @license Apache-2.0
 */
import { verifyReceipt } from './index.js';
/** @typedef {import('./index.js').IssuerPin} IssuerPin */
// =============================================================================
// KEY RESOLUTION
// =============================================================================
/**
 * Resolve the candidate verification keys an operator advertises for a signer.
 *
 * An ep-keys.json discovery document advertises a `keys` map of currently-valid
 * signing keys and, for rotation safety (PIP-006 §"Security considerations" →
 * Key rotation), an optional `historical_keys` map of retired-but-still-
 * verifiable keys. A receipt signed before a rotation must remain verifiable,
 * so we return current keys first and historical keys after, in that order.
 *
 * @param {object} discoveryDoc - parsed /.well-known/ep-keys.json
 * @param {string} signerId - the issuing operator's entity_id (receipt.signature.signer)
 * @returns {Array<{ public_key: string, status: 'current'|'historical', algorithm: string, retired_at?: string }>}
 */
export function resolveOperatorKeys(discoveryDoc, signerId) {
    const candidates = [];
    if (!discoveryDoc || typeof discoveryDoc !== 'object' || !signerId)
        return candidates;
    const current = discoveryDoc.keys?.[signerId];
    if (current?.public_key) {
        candidates.push({
            public_key: current.public_key,
            status: 'current',
            algorithm: current.algorithm || 'Ed25519',
        });
    }
    // historical_keys[signerId] = [{ public_key, algorithm?, retired_at? }, ...]
    const historical = discoveryDoc.historical_keys?.[signerId];
    if (Array.isArray(historical)) {
        for (const h of historical) {
            if (h?.public_key) {
                candidates.push({
                    public_key: h.public_key,
                    status: 'historical',
                    algorithm: h.algorithm || 'Ed25519',
                    retired_at: h.retired_at,
                });
            }
        }
    }
    return candidates;
}
// Parse a strict RFC 3339 timestamp to nanoseconds so sub-millisecond issuance
// cannot slip past a retirement boundary through Date's millisecond truncation.
function parseBoundTimestamp(value) {
    if (typeof value !== 'string')
        return null;
    const match = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/);
    if (!match || match[8] === '-00:00')
        return null;
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const second = Number(match[6]);
    const offsetHour = match[10] ? Number(match[10]) : 0;
    const offsetMinute = match[11] ? Number(match[11]) : 0;
    const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (month < 1 || month > 12 ||
        day < 1 || day > daysInMonth[month - 1] ||
        hour > 23 ||
        minute > 59 ||
        second > 59 ||
        offsetHour > 23 ||
        offsetMinute > 59) {
        return null;
    }
    const utcMilliseconds = Date.parse(`${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}Z`);
    if (!Number.isFinite(utcMilliseconds))
        return null;
    const fractionalNanoseconds = BigInt((match[7] || '').padEnd(9, '0') || '0');
    const offsetNanoseconds = BigInt(offsetHour * 60 + offsetMinute) * 60n * 1000000000n;
    const signedOffset = match[9] === '+' ? -offsetNanoseconds :
        match[9] === '-' ? offsetNanoseconds :
            0n;
    return BigInt(utcMilliseconds) * 1000000n + fractionalNanoseconds + signedOffset;
}
// =============================================================================
// OFFLINE VERIFICATION
// =============================================================================
/**
 * Verify a federated receipt fully offline.
 *
 * The caller supplies the issuing operator's discovery document (its
 * ep-keys.json) and, optionally, that operator's revocation set. No network
 * access is performed. This is the deterministic core that the online path and
 * the conformance harness both build on.
 *
 * TRUST IS OUT-OF-BAND. `accepted` is only ever true when the caller has pinned
 * the issuing operator via `opts.trustedIssuers` and/or `opts.expectedSigner`.
 * With no pin supplied, a cryptographically-`verified` receipt is still
 * `accepted: false` — the receipt's own `signature.signer` can be anything an
 * attacker chooses, so it can never, by itself, establish trust.
 *
 * @param {object} receipt - EP-RECEIPT-v1 document. MUST carry
 *   `signature.signer` (issuing operator entity_id) per PIP-006.
 * @param {object} discoveryDoc - the issuing operator's parsed ep-keys.json
 * @param {object} [opts]
 * @param {Set<string>|string[]} [opts.revokedReceiptIds] - operator A's revocation set
 * @param {string} [opts.expectedSigner] - if set, the receipt's signer MUST equal this
 *   (this is itself a pin: matching it authorizes acceptance)
 * @param {Set<string>|string[]|Record<string,IssuerPin>} [opts.trustedIssuers] -
 *   out-of-band allowlist of federation issuer entity_ids the relying party
 *   trusts. Acceptance REQUIRES the signer to be in this set (or to equal
 *   expectedSigner). Entries may be bare id strings, or an object map from
 *   signer id → pin binding ({ key_discovery, keyDiscoveryOrigin, publicKey,
 *   publicKeys }). A pin binding pins the KEY SOURCE, not just the id: when a
 *   pinned public key is supplied here, the matched verifying key MUST be one
 *   of the pinned keys or acceptance fails closed.
 * @returns {{
 *   accepted: boolean,
 *   verified: boolean,
 *   revoked: boolean,
 *   trusted: boolean,
 *   signer: string|null,
 *   keyMatched: 'current'|'historical'|null,
 *   checks: object,
 *   error?: string,
 * }}
 */
export function verifyFederatedReceiptOffline(receipt, discoveryDoc, opts = {}) {
    const result = {
        accepted: false,
        verified: false,
        revoked: false,
        trusted: false,
        signer: null,
        keyMatched: null,
        checks: { version: false, signer_present: false, signature: false, not_revoked: false, issuer_pinned: false },
    };
    const signer = receipt?.signature?.signer;
    if (!signer || typeof signer !== 'string') {
        // PIP-006 §"Federation contract": a federated receipt MUST identify its
        // issuing operator. Without signer there is no operator to resolve a key
        // from — the receipt is not portable.
        return { ...result, error: 'Receipt is missing signature.signer (not a federated receipt)' };
    }
    result.signer = signer;
    result.checks.signer_present = true;
    if (opts.expectedSigner && signer !== opts.expectedSigner) {
        return { ...result, error: `Signer mismatch: receipt signed by ${signer}, expected ${opts.expectedSigner}` };
    }
    const candidates = resolveOperatorKeys(discoveryDoc, signer);
    if (candidates.length === 0) {
        return { ...result, error: `Operator ${signer} advertises no key for this receipt` };
    }
    // Try current key first, then historical keys (rotation safety). The first
    // key that produces a valid signature wins; a tampered payload or a wrong
    // operator's key matches none of them.
    let matched = null;
    let lastChecks = null;
    let historicalKeyError = null;
    for (const cand of candidates) {
        const v = verifyReceipt(receipt, cand.public_key);
        lastChecks = v.checks;
        if (v.valid) {
            // Only inspect issued_at after the signature verifies: payload.issued_at
            // is then cryptographically bound to this receipt. A historical key has
            // no authority after retirement, and an absent/malformed boundary on
            // either side is not evidence that issuance preceded retirement.
            if (cand.status === 'historical') {
                const issuedAt = parseBoundTimestamp(receipt?.payload?.issued_at);
                const retiredAt = parseBoundTimestamp(cand.retired_at);
                if (issuedAt === null) {
                    historicalKeyError =
                        'Historical key matched the signature, but payload.issued_at is missing or malformed; refusing verification';
                    continue;
                }
                if (retiredAt === null) {
                    historicalKeyError =
                        'Historical key matched the signature, but retired_at is missing or malformed; refusing verification';
                    continue;
                }
                if (issuedAt > retiredAt) {
                    historicalKeyError =
                        'Historical key matched the signature, but payload.issued_at is after retired_at; refusing verification';
                    continue;
                }
            }
            matched = cand;
            break;
        }
    }
    if (lastChecks) {
        result.checks.version = lastChecks.version === true;
    }
    if (!matched) {
        return {
            ...result,
            error: historicalKeyError || 'Signature does not verify against any key the operator advertises',
        };
    }
    result.verified = true;
    result.checks.signature = true;
    result.checks.historical_key_time_valid = true;
    result.keyMatched = matched.status;
    // KEY-SOURCE PIN — fail closed. If the relying party pinned a specific public
    // key (or set of keys) for this signer, the key that actually verified the
    // signature MUST be one of them. This binds trust to the KEY, not merely the
    // signer string: a discovery doc that advertises an attacker's key under a
    // pinned id verifies internally but is refused here. Bare-id pins (no pinned
    // key) skip this — the caller-supplied discovery doc is the trust source
    // offline.
    const pinnedKeys = pinnedPublicKeysFor(signer, opts);
    if (pinnedKeys && !pinnedKeys.has(matched.public_key)) {
        return {
            ...result,
            error: `Verified key for ${signer} does not match the relying party's pinned key(s); ` +
                `refusing to accept a key from an unpinned source (fail closed)`,
        };
    }
    // Revocation (PIP-006 §"Cross-operator semantics" step 3). A revocation that
    // arrives after the action executed is a dispute, not a verification failure
    // (§"Security considerations" → Revocation) — but for the purpose of *now*
    // accepting the receipt as live evidence, a revoked receipt is not accepted.
    const revokedSet = normalizeStringSet(opts.revokedReceiptIds);
    const receiptId = receipt.payload?.receipt_id || receipt.receipt_id;
    result.revoked = Boolean(receiptId && revokedSet.has(receiptId));
    result.checks.not_revoked = !result.revoked;
    // TRUST DECISION — fail closed. Acceptance requires an out-of-band pin
    // supplied by the RELYING PARTY: an allowlisted issuer or a matching
    // expectedSigner. The receipt's own signer is attacker-controlled and can
    // never, by itself, authorize acceptance. `verified` (above) stands on its
    // own; `accepted` layers this trust decision on top.
    result.trusted = isIssuerPinned(signer, opts);
    result.checks.issuer_pinned = result.trusted;
    result.accepted = result.verified && !result.revoked && result.trusted;
    if (result.verified && !result.trusted && !result.error) {
        result.error =
            `Signature verifies but signer ${signer} is not pinned by the relying party ` +
                `(supply opts.trustedIssuers or opts.expectedSigner); a receipt-supplied signer cannot establish trust`;
    }
    return result;
}
// A signer is pinned when the relying party has authorized it out-of-band:
// either it is on the trustedIssuers allowlist, or it equals expectedSigner.
// With neither supplied, no signer is pinned — acceptance fails closed.
function isIssuerPinned(signer, opts) {
    if (opts.expectedSigner && signer === opts.expectedSigner)
        return true;
    return pinnedSignerIds(opts.trustedIssuers).has(signer);
}
// The set of signer ids the relying party has pinned via trustedIssuers,
// regardless of whether each pin is a bare id or a bound-pin object entry.
function pinnedSignerIds(trustedIssuers) {
    if (trustedIssuers instanceof Set)
        return trustedIssuers;
    if (Array.isArray(trustedIssuers))
        return new Set(trustedIssuers);
    if (isPlainObject(trustedIssuers))
        return new Set(Object.keys(trustedIssuers));
    return new Set();
}
// Look up the pin binding for a signer from trustedIssuers, if trustedIssuers is
// the object-map form. Bare-string / array forms carry no binding (id-only), so
// return null. expectedSigner is an id-only pin and never carries a binding.
// Returns { key_discovery?, keyDiscoveryOrigin?, publicKey?, publicKeys? }|null.
function pinBindingFor(signer, opts) {
    const ti = opts.trustedIssuers;
    if (!isPlainObject(ti))
        return null;
    const entry = ti[signer];
    if (!isPlainObject(entry))
        return null;
    return entry;
}
// The set of public keys the relying party pinned for a signer, or null if none
// were pinned (id-only pin). A non-null empty set is impossible: a binding with
// no key material returns null so key-pinning is strictly opt-in.
function pinnedPublicKeysFor(signer, opts) {
    const binding = pinBindingFor(signer, opts);
    if (!binding)
        return null;
    const keys = new Set();
    if (typeof binding.publicKey === 'string' && binding.publicKey)
        keys.add(binding.publicKey);
    if (Array.isArray(binding.publicKeys)) {
        for (const k of binding.publicKeys)
            if (typeof k === 'string' && k)
                keys.add(k);
    }
    return keys.size ? keys : null;
}
// The expected discovery origin the relying party bound to a signer, or null if
// none was bound. Accepts either an explicit `keyDiscoveryOrigin` (origin string)
// or a full `key_discovery` URL (origin is derived from it). Fail closed: an
// unparseable pinned URL/origin yields null AND is reported via the boolean flag
// on the binding so callers can distinguish "no binding" from "invalid binding".
function pinnedDiscoveryOriginFor(signer, opts) {
    const binding = pinBindingFor(signer, opts);
    if (!binding)
        return { bound: false, origin: null };
    const raw = binding.keyDiscoveryOrigin || binding.key_discovery;
    if (typeof raw !== 'string' || !raw)
        return { bound: false, origin: null };
    const origin = originOf(raw);
    return { bound: true, origin };
}
function originOf(value) {
    try {
        const u = new URL(String(value));
        return `${u.protocol}//${u.host}`;
    }
    catch {
        return null;
    }
}
function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Set);
}
function normalizeStringSet(input) {
    if (input instanceof Set)
        return input;
    if (Array.isArray(input))
        return new Set(input.filter((value) => typeof value === 'string'));
    return new Set();
}
// =============================================================================
// ONLINE VERIFICATION
// =============================================================================
/**
 * Verify a federated receipt against a live operator, fetching its discovery
 * and revocation surfaces.
 *
 * The receipt's `signature.key_discovery` URL (PIP-006 §"Federation contract")
 * is the operator's ep-keys.json location. Revocation is checked against the
 * operator's verifier-of-record endpoint (`/api/verify/{receipt_id}`). Its JSON
 * response is untrusted input: HTTP success and `revoked: false` are not proof
 * of current status. Acceptance requires a relying-party configured
 * `statusVerifier` to authenticate the response and confirm exact target binding
 * plus freshness. Cryptographic verification and live acceptance are
 * deliberately separate: an unavailable or untrusted status result does not
 * erase a valid signature (`verified` may remain true), but it MUST prevent a
 * live acceptance decision (`accepted` remains false).
 *
 * FAIL CLOSED + SSRF-GUARDED. The receipt-supplied `key_discovery` URL is
 * attacker-controlled. It is fetched ONLY when the relying party has pinned the
 * signer AND bound that signer's key SOURCE (an expected discovery origin/URL,
 * via the object-map form of opts.trustedIssuers). A bare signer-id pin does
 * NOT authenticate the key source: an attacker could set signature.signer to a
 * pinned id and point key_discovery at their own ep-keys.json advertising their
 * key under that id — verifying, but laundering trust. So a receipt-supplied
 * key_discovery whose origin is not explicitly bound to the pinned signer is
 * refused (fail closed). The receipt URL's origin must match the pinned origin.
 * A caller-supplied opts.keyDiscoveryUrl override is the relying party's OWN
 * choice — it is the source of truth and is always honored (still SSRF-guarded),
 * needing no origin match. Every fetch of a URL that could be influenced by the
 * receipt (key discovery, discovery-advertised verify_url_template) is routed
 * through two gates: assertSafeFetchUrl performs https/credential/literal-host
 * checks, then opts.networkBoundary resolves every address, rejects the entire
 * answer set unless every address is public, and fetches through a transport
 * pinned to that approved set. Redirects are disabled (redirect:manual).
 *
 * @param {object} receipt - EP-RECEIPT-v1 with signature.signer + signature.key_discovery
 * @param {object} [opts]
 * @param {object} opts.networkBoundary - required online resolver + pinned
 *   transport. resolveAddresses(hostname) MUST return every A/AAAA address.
 *   fetchPinned(url, init, { hostname, approvedAddresses }) MUST connect directly
 *   to one approved address without re-resolving, preserve hostname-based TLS
 *   SNI/Host handling, and return { response, connectedAddress }.
 * @param {typeof fetch} [opts.fetchImpl] - deprecated and rejected as an online
 *   transport when no networkBoundary is supplied; plain fetch is DNS-rebindable
 * @param {number} [opts.timeoutMs=5000]
 * @param {string} [opts.keyDiscoveryUrl] - relying-party override of the key_discovery URL
 * @param {string} [opts.verifyUrlBase] - relying-party override base for the revocation check
 * @param {Set<string>|string[]|Record<string,IssuerPin>} [opts.trustedIssuers] - out-of-band
 *   issuer allowlist (required for acceptance). To honor a RECEIPT-supplied
 *   key_discovery, use the object-map form and bind the signer's key source:
 *   { [signerId]: { key_discovery|keyDiscoveryOrigin, publicKey?|publicKeys? } }.
 *   A bare-id pin authorizes acceptance only when the caller supplies its own
 *   opts.keyDiscoveryUrl; it will NOT fetch a receipt-supplied URL (fail closed).
 * @param {string} [opts.expectedSigner] - out-of-band single-issuer pin (id only;
 *   like a bare-id trustedIssuers entry, it does not bind the key source, so it
 *   does not by itself authorize fetching a receipt-supplied key_discovery)
 * @param {Function} [opts.statusVerifier] - relying-party configured verifier for
 *   the fetched status document. It receives `(status, { receiptId, signer,
 *   verifyUrl })` and MUST return explicit `authenticated: true`,
 *   `target_bound: true`, `fresh: true`, and boolean `revoked`. Absence,
 *   exceptions, malformed output, or any non-true trust check fails closed.
 * @returns {Promise<ReturnType<typeof verifyFederatedReceiptOffline> & { fetched: object, revocation_confirmed?: boolean, revocation_status?: string }>}
 */
export async function verifyFederatedReceipt(receipt, opts = {}) {
    const signer = receipt?.signature?.signer || null;
    const bail = (fetched, error) => ({
        accepted: false, verified: false, revoked: false, trusted: false, signer,
        keyMatched: null, checks: {}, fetched, error,
    });
    // A caller-supplied opts.keyDiscoveryUrl override is the relying party's OWN
    // choice and is always honored (still SSRF-guarded below). Otherwise we may
    // only use the RECEIPT-supplied key_discovery, and only under two conditions:
    //   1. the signer is pinned out-of-band, AND
    //   2. the relying party has BOUND that signer's key source — an expected
    //      discovery origin/URL — and the receipt's key_discovery origin matches.
    // Pinning the id alone is NOT enough: a bare-id pin does not authenticate
    // WHERE the key comes from, so an attacker could set signer to a pinned id and
    // point key_discovery at their own ep-keys.json. Fail closed on both.
    const callerOverride = Boolean(opts.keyDiscoveryUrl);
    if (!callerOverride) {
        if (!isIssuerPinned(signer, opts)) {
            return bail({}, `Refusing to fetch a receipt-supplied key_discovery URL for unpinned signer ${signer || '(none)'}: ` +
                `supply opts.trustedIssuers/opts.expectedSigner, or a caller-controlled opts.keyDiscoveryUrl`);
        }
        const pinnedOrigin = pinnedDiscoveryOriginFor(signer, opts);
        if (!pinnedOrigin.bound) {
            return bail({}, `Refusing a receipt-supplied key_discovery for pinned signer ${signer}: the pin does not bind a key ` +
                `source. Pinning the id alone cannot authenticate the key origin. Pin the signer's key_discovery ` +
                `origin via the object form of opts.trustedIssuers ({ [signer]: { key_discovery } }), or supply a ` +
                `caller-controlled opts.keyDiscoveryUrl (fail closed).`);
        }
        const receiptOrigin = originOf(receipt?.signature?.key_discovery);
        if (!pinnedOrigin.origin || !receiptOrigin || receiptOrigin !== pinnedOrigin.origin) {
            return bail({ keyDiscoveryUrl: receipt?.signature?.key_discovery || null }, `Receipt-supplied key_discovery origin ${receiptOrigin || '(none)'} does not match the origin pinned ` +
                `for signer ${signer} (${pinnedOrigin.origin || '(invalid pinned origin)'}); refusing to fetch a key ` +
                `from an unpinned source (fail closed).`);
        }
    }
    const keyDiscoveryUrl = opts.keyDiscoveryUrl || receipt?.signature?.key_discovery;
    if (!keyDiscoveryUrl) {
        return bail({}, 'Receipt is missing signature.key_discovery and no keyDiscoveryUrl override given');
    }
    // SSRF guard on the (potentially receipt-supplied) discovery URL.
    const discoverySafe = assertSafeFetchUrl(keyDiscoveryUrl, opts);
    if (!discoverySafe.ok) {
        return bail({ keyDiscoveryUrl, discovery: { ok: false, blocked: true } }, `Blocked unsafe key_discovery URL: ${discoverySafe.error}`);
    }
    const networkBoundary = opts.networkBoundary;
    if (!networkBoundary ||
        typeof networkBoundary.resolveAddresses !== 'function' ||
        typeof networkBoundary.fetchPinned !== 'function') {
        return bail({ keyDiscoveryUrl, discovery: { ok: false, blocked: true } }, 'Online federation verification requires an explicit resolver + pinned-fetch network boundary; ' +
            'an injected plain fetch or global fetch is not safe against DNS rebinding');
    }
    /** @type {{ keyDiscoveryUrl: string, discovery: { ok: boolean }|null, revocation: { ok: boolean, revoked?: boolean, blocked?: boolean }|null }} */
    const fetched = { keyDiscoveryUrl, discovery: null, revocation: null };
    let discoveryDoc;
    try {
        discoveryDoc = await fetchJson(networkBoundary, keyDiscoveryUrl, opts.timeoutMs);
        fetched.discovery = { ok: true };
    }
    catch (e) {
        return bail(fetched, `Failed to fetch operator key discovery: ${e instanceof Error ? e.message : String(e)}`);
    }
    // Resolve revocation from the operator's verifier-of-record, when reachable.
    // The fetched JSON is never itself a trust source. A relying-party supplied
    // statusVerifier must authenticate it and establish exact target binding plus
    // freshness before either revoked:false or revoked:true becomes current state.
    const revokedReceiptIds = new Set();
    const receiptIdValue = receipt.payload?.receipt_id || receipt.receipt_id;
    const receiptId = typeof receiptIdValue === 'string' && receiptIdValue ? receiptIdValue : null;
    let revocationConfirmed = false;
    let statusChecks = {
        authenticated: false,
        target_bound: false,
        fresh: false,
        revoked_explicit: false,
    };
    if (receiptId) {
        // Prefer the operator's advertised verify_url_template (PIP-006) — it lets
        // an operator host its verifier-of-record at any path, not just
        // {origin}/api/verify. Fall back to origin-derivation for operators that
        // don't advertise it.
        const verifyUrl = resolveVerifyUrl(discoveryDoc, opts.verifyUrlBase, keyDiscoveryUrl, receiptId);
        // The verify URL can come from a discovery doc we fetched over an
        // attacker-influenced hop, so it too must clear the SSRF guard.
        if (verifyUrl && assertSafeFetchUrl(verifyUrl, opts).ok) {
            try {
                const v = await fetchJson(networkBoundary, verifyUrl, opts.timeoutMs);
                let statusResult = null;
                if (typeof opts.statusVerifier === 'function') {
                    try {
                        const candidate = await opts.statusVerifier(v, { receiptId, signer, verifyUrl });
                        statusResult = isPlainObject(candidate) ? candidate : null;
                    }
                    catch {
                        statusResult = null;
                    }
                }
                const responseTargetBound = isPlainObject(v) && v.receipt_id === receiptId;
                const responseHasRevoked = isPlainObject(v) && typeof v.revoked === 'boolean';
                const resultHasRevoked = statusResult !== null && typeof statusResult.revoked === 'boolean';
                statusChecks = {
                    authenticated: statusResult?.authenticated === true,
                    target_bound: responseTargetBound && statusResult?.target_bound === true,
                    fresh: statusResult?.fresh === true,
                    revoked_explicit: responseHasRevoked && resultHasRevoked && statusResult?.revoked === v.revoked,
                };
                revocationConfirmed = Object.values(statusChecks).every(Boolean);
                fetched.revocation = {
                    ok: true,
                    verified: revocationConfirmed,
                    revoked: revocationConfirmed ? v.revoked : undefined,
                    ...statusChecks,
                };
                if (revocationConfirmed && v.revoked === true)
                    revokedReceiptIds.add(receiptId);
            }
            catch {
                // Preserve cryptographic verification, but never interpret unavailable
                // revocation state as affirmative evidence that the receipt is live.
                fetched.revocation = { ok: false };
            }
        }
        else if (verifyUrl) {
            fetched.revocation = { ok: false, blocked: true };
        }
    }
    const offline = verifyFederatedReceiptOffline(receipt, discoveryDoc, {
        revokedReceiptIds,
        expectedSigner: opts.expectedSigner,
        trustedIssuers: opts.trustedIssuers,
    });
    const revoked = offline.revoked === true;
    const revocationStatus = revoked
        ? 'revoked'
        : revocationConfirmed
            ? 'confirmed_not_revoked'
            : 'unavailable';
    if (!revocationConfirmed) {
        return {
            ...offline,
            accepted: false,
            checks: {
                ...offline.checks,
                not_revoked: false,
                revocation_confirmed: false,
                status_authenticated: statusChecks.authenticated,
                status_target_bound: statusChecks.target_bound,
                status_fresh: statusChecks.fresh,
                status_revoked_explicit: statusChecks.revoked_explicit,
            },
            fetched,
            revocation_confirmed: false,
            revocation_status: revocationStatus,
            error: offline.accepted
                ? 'Signature verifies and issuer is pinned, but revocation status is unavailable or untrusted; refusing live acceptance'
                : offline.error,
        };
    }
    return {
        ...offline,
        checks: {
            ...offline.checks,
            revocation_confirmed: true,
            status_authenticated: true,
            status_target_bound: true,
            status_fresh: true,
            status_revoked_explicit: true,
        },
        fetched,
        revocation_confirmed: true,
        revocation_status: revocationStatus,
    };
}
// Build the verifier-of-record URL for a receipt. Priority:
//   1. explicit opts.verifyUrlBase override ({base}/api/verify/{id})
//   2. the operator's advertised verify_url_template ({receipt_id} substituted)
//   3. origin of the key_discovery URL + /api/verify/{id}
function resolveVerifyUrl(discoveryDoc, verifyUrlBase, keyDiscoveryUrl, receiptId) {
    const id = encodeURIComponent(receiptId);
    if (verifyUrlBase)
        return `${verifyUrlBase.replace(/\/$/, '')}/api/verify/${id}`;
    const tmpl = discoveryDoc?.verify_url_template;
    if (typeof tmpl === 'string' && tmpl.includes('{receipt_id}')) {
        return tmpl.replace('{receipt_id}', id);
    }
    const base = deriveVerifyBase(keyDiscoveryUrl);
    return base ? `${base}/api/verify/${id}` : null;
}
async function fetchJson(networkBoundary, url, timeoutMs = 5000) {
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
    try {
        const parsed = new URL(url);
        const hostname = normalizeHost(parsed.hostname);
        const resolved = await networkBoundary.resolveAddresses(hostname, {
            signal: controller?.signal,
        });
        const approvedAddresses = Object.freeze(validateResolvedAddresses(resolved));
        if (controller?.signal.aborted)
            throw new Error('address resolution timed out');
        // redirect:'manual' — a 3xx to a private/link-local host would bypass the
        // pinned transport, so both the transport contract and this response check
        // refuse to follow redirects. Operator surfaces must be served directly.
        const init = { redirect: 'manual' };
        if (controller)
            init.signal = controller.signal;
        const pinnedResult = await networkBoundary.fetchPinned(url, init, {
            hostname,
            approvedAddresses,
        });
        if (!isPlainObject(pinnedResult) || !('response' in pinnedResult)) {
            throw new Error('pinned transport returned a malformed result');
        }
        const connectedAddress = normalizeIpAddress(pinnedResult.connectedAddress);
        if (!connectedAddress || !approvedAddresses.includes(connectedAddress)) {
            throw new Error(`pinned transport connected address ${connectedAddress || '(invalid)'} was not approved`);
        }
        const res = pinnedResult.response;
        if (res && (res.type === 'opaqueredirect' || res.redirected === true)) {
            throw new Error('refusing to follow redirect');
        }
        const status = res?.status;
        if (typeof status === 'number' && status >= 300 && status < 400) {
            throw new Error(`refusing to follow redirect (HTTP ${status})`);
        }
        if (!res.ok)
            throw new Error(`HTTP ${res.status}`);
        return await res.json();
    }
    finally {
        if (timer)
            clearTimeout(timer);
    }
}
// Derive the operator's origin from its key_discovery URL so we can locate its
// /api/verify/{id} revocation surface on the same origin.
function deriveVerifyBase(keyDiscoveryUrl) {
    try {
        const u = new URL(keyDiscoveryUrl);
        return `${u.protocol}//${u.host}`;
    }
    catch {
        return null;
    }
}
// =============================================================================
// SSRF GUARD
// =============================================================================
// Any server-side fetch of a URL that a receipt (or a receipt-reachable
// discovery document) can influence is an SSRF primitive. This guard is a
// first-pass, string-only check — zero dependencies, safe in browsers/edge —
// that rejects classic SSRF targets before address resolution:
//   - non-https schemes (http/file/gopher/data/…),
//   - embedded credentials (user:pass@host),
//   - loopback / private / link-local / unique-local / cloud-metadata hosts.
// It is deliberately conservative: literal IPs in private ranges and the
// well-known metadata hostnames are blocked outright.
//
// This check is intentionally not the online trust boundary: hostnames can
// resolve or rebind to non-public addresses. fetchJson therefore requires the
// caller's resolver + pinned transport and validates every answer before I/O.
export function assertSafeFetchUrl(value, _opts = {}) {
    let url;
    try {
        url = new URL(String(value || ''));
    }
    catch {
        return { ok: false, error: 'not a valid URL' };
    }
    if (url.protocol !== 'https:') {
        return { ok: false, error: `scheme ${url.protocol} is not https` };
    }
    if (url.username || url.password) {
        return { ok: false, error: 'URL must not embed credentials' };
    }
    const host = normalizeHost(url.hostname);
    if (!host)
        return { ok: false, error: 'URL has no hostname' };
    if (isBlockedHostname(host) || isPrivateOrReservedAddress(host)) {
        return { ok: false, error: `host ${host} is private, loopback, link-local, or metadata` };
    }
    return { ok: true };
}
const BLOCKED_HOSTNAMES = new Set([
    'localhost',
    'ip6-localhost',
    'ip6-loopback',
    'metadata.google.internal',
]);
function normalizeHost(hostname) {
    return String(hostname || '')
        .trim()
        .replace(/^\[(.*)\]$/, '$1') // strip IPv6 brackets
        .replace(/\.$/, '') // strip trailing dot (FQDN root)
        .toLowerCase();
}
function isBlockedHostname(host) {
    if (BLOCKED_HOSTNAMES.has(host))
        return true;
    return host === 'localhost' || host.endsWith('.localhost');
}
function normalizeIpAddress(value) {
    const raw = normalizeHost(value);
    if (isIPv4(raw)) {
        return raw.split('.').map((part) => String(Number(part))).join('.');
    }
    if (!raw.includes(':'))
        return null;
    try {
        const parsed = new URL(`https://[${raw}]/`);
        const normalized = normalizeHost(parsed.hostname);
        return normalized.includes(':') ? normalized : null;
    }
    catch {
        return null;
    }
}
function validateResolvedAddresses(resolved) {
    if (!Array.isArray(resolved) || resolved.length === 0) {
        throw new Error('address resolution returned no addresses');
    }
    const approved = [];
    for (const raw of resolved) {
        const address = normalizeIpAddress(raw);
        if (!address) {
            throw new Error(`address resolution returned a non-IP value: ${String(raw)}`);
        }
        if (isPrivateOrReservedAddress(address)) {
            throw new Error(`resolved address ${address} is not public`);
        }
        if (!approved.includes(address))
            approved.push(address);
    }
    return approved;
}
function isPrivateOrReservedAddress(host) {
    if (isIPv4(host))
        return isPrivateIPv4(host);
    if (normalizeIpAddress(host)?.includes(':'))
        return isPrivateIPv6(host);
    return false;
}
function isIPv4(host) {
    const parts = host.split('.');
    return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}
function isPrivateIPv4(host) {
    const [a, b, c] = host.split('.').map(Number);
    return (a === 0 || // "this" network
        a === 10 || // private
        a === 127 || // loopback
        (a === 169 && b === 254) || // link-local (incl. 169.254.169.254 metadata)
        (a === 172 && b >= 16 && b <= 31) || // private
        (a === 192 && b === 168) || // private
        (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT
        (a === 192 && b === 0) || // IETF protocol + documentation assignments
        (a === 192 && b === 88 && c === 99) || // deprecated 6to4 relay anycast
        (a === 198 && (b === 18 || b === 19)) || // benchmarking
        (a === 198 && b === 51 && c === 100) || // documentation
        (a === 203 && b === 0 && c === 113) || // documentation
        a >= 224 // multicast / reserved
    );
}
function isPrivateIPv6(host) {
    const h = normalizeIpAddress(host);
    if (!h || !h.includes(':'))
        return true;
    if (h === '::1' || h === '::')
        return true;
    // IPv4-mapped (::ffff:a.b.c.d, or normalized ::ffff:7f00:1) — unwrap the
    // trailing 32 bits and re-check as IPv4.
    const mappedDotted = h.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mappedDotted && isIPv4(mappedDotted[1]))
        return isPrivateIPv4(mappedDotted[1]);
    const mappedHex = h.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (mappedHex) {
        const hi = parseInt(mappedHex[1], 16);
        const lo = parseInt(mappedHex[2], 16);
        const dotted = `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
        return isPrivateIPv4(dotted);
    }
    const firstHextet = Number.parseInt(h.split(':', 1)[0] || '0', 16);
    if ((firstHextet & 0xe000) !== 0x2000)
        return true; // require global-unicast 2000::/3
    return (h === '2001::' ||
        h.startsWith('2001::') || // Teredo / special-purpose
        h.startsWith('2001:0:') ||
        h.startsWith('2001:2:') || // benchmarking
        h.startsWith('2001:10:') || // ORCHID
        h.startsWith('2001:20:') || // ORCHIDv2
        h === '2001:db8::' ||
        h.startsWith('2001:db8:') || // documentation
        h === '2002::' ||
        h.startsWith('2002:') || // 6to4 transition
        h.startsWith('3fff:') // documentation/special-purpose
    );
}
export const _internals = {
    assertSafeFetchUrl,
    isPrivateIPv4,
    isPrivateIPv6,
    isBlockedHostname,
    pinnedDiscoveryOriginFor,
    pinnedPublicKeysFor,
    originOf,
};
//# sourceMappingURL=federation.js.map