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
 * discovery document and revocation set; works online with an injectable
 * fetch implementation (defaults to global fetch on Node 18+ / browsers).
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
  /** @type {Array<{ public_key: string, status: 'current'|'historical', algorithm: string, retired_at?: string }>} */
  const candidates = [];
  if (!discoveryDoc || typeof discoveryDoc !== 'object' || !signerId) return candidates;

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
  /** @type {{
   *   accepted: boolean,
   *   verified: boolean,
   *   revoked: boolean,
   *   trusted: boolean,
   *   signer: string|null,
   *   keyMatched: 'current'|'historical'|null,
   *   checks: { version: boolean, signer_present: boolean, signature: boolean, not_revoked: boolean, issuer_pinned: boolean },
   *   error?: string,
   * }} */
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
  for (const cand of candidates) {
    const v = verifyReceipt(receipt, cand.public_key);
    lastChecks = v.checks;
    if (v.valid) {
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
      error: 'Signature does not verify against any key the operator advertises',
    };
  }

  result.verified = true;
  result.checks.signature = true;
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
      error:
        `Verified key for ${signer} does not match the relying party's pinned key(s); ` +
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
  if (opts.expectedSigner && signer === opts.expectedSigner) return true;
  return pinnedSignerIds(opts.trustedIssuers).has(signer);
}

// The set of signer ids the relying party has pinned via trustedIssuers,
// regardless of whether each pin is a bare id or a bound-pin object entry.
function pinnedSignerIds(trustedIssuers) {
  if (trustedIssuers instanceof Set) return trustedIssuers;
  if (Array.isArray(trustedIssuers)) return new Set(trustedIssuers);
  if (isPlainObject(trustedIssuers)) return new Set(Object.keys(trustedIssuers));
  return new Set();
}

// Look up the pin binding for a signer from trustedIssuers, if trustedIssuers is
// the object-map form. Bare-string / array forms carry no binding (id-only), so
// return null. expectedSigner is an id-only pin and never carries a binding.
// Returns { key_discovery?, keyDiscoveryOrigin?, publicKey?, publicKeys? }|null.
function pinBindingFor(signer, opts) {
  const ti = opts.trustedIssuers;
  if (!isPlainObject(ti)) return null;
  const entry = ti[signer];
  if (!isPlainObject(entry)) return null;
  return entry;
}

// The set of public keys the relying party pinned for a signer, or null if none
// were pinned (id-only pin). A non-null empty set is impossible: a binding with
// no key material returns null so key-pinning is strictly opt-in.
function pinnedPublicKeysFor(signer, opts) {
  const binding = pinBindingFor(signer, opts);
  if (!binding) return null;
  const keys = new Set();
  if (typeof binding.publicKey === 'string' && binding.publicKey) keys.add(binding.publicKey);
  if (Array.isArray(binding.publicKeys)) {
    for (const k of binding.publicKeys) if (typeof k === 'string' && k) keys.add(k);
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
  if (!binding) return { bound: false, origin: null };
  const raw = binding.keyDiscoveryOrigin || binding.key_discovery;
  if (typeof raw !== 'string' || !raw) return { bound: false, origin: null };
  const origin = originOf(raw);
  return { bound: true, origin };
}

function originOf(value) {
  try {
    const u = new URL(String(value));
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Set);
}

function normalizeStringSet(input) {
  if (input instanceof Set) return input;
  if (Array.isArray(input)) return new Set(input);
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
 * operator's verifier-of-record endpoint (`/api/verify/{receipt_id}`), which
 * reports a `revoked` field. Cryptographic verification and live acceptance are
 * deliberately separate: an unavailable revocation surface does not erase a
 * valid signature (`verified` may remain true), but it MUST prevent a live
 * acceptance decision (`accepted` remains false) until status is confirmed.
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
 * through assertSafeFetchUrl: https-only, no embedded credentials, and private /
 * loopback / link-local / cloud-metadata targets are blocked, with redirects
 * disabled (redirect:manual).
 *
 * @param {object} receipt - EP-RECEIPT-v1 with signature.signer + signature.key_discovery
 * @param {object} [opts]
 * @param {typeof fetch} [opts.fetchImpl] - injectable fetch (defaults to global fetch)
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
 * @param {boolean} [opts.allowInsecureFetch=false] - test-only escape hatch to skip the SSRF guard
 * @returns {Promise<ReturnType<typeof verifyFederatedReceiptOffline> & { fetched: object, revocation_confirmed?: boolean, revocation_status?: string }>}
 */
export async function verifyFederatedReceipt(receipt, opts = {}) {
  const signer = receipt?.signature?.signer || null;
  const bail = (fetched, error) => ({
    accepted: false, verified: false, revoked: false, trusted: false, signer,
    keyMatched: null, checks: {}, fetched, error,
  });

  const fetchImpl = opts.fetchImpl || (typeof fetch !== 'undefined' ? fetch : null);
  if (!fetchImpl) {
    return bail({}, 'No fetch implementation available; use verifyFederatedReceiptOffline instead');
  }

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
      return bail(
        {},
        `Refusing to fetch a receipt-supplied key_discovery URL for unpinned signer ${signer || '(none)'}: ` +
        `supply opts.trustedIssuers/opts.expectedSigner, or a caller-controlled opts.keyDiscoveryUrl`,
      );
    }
    const pinnedOrigin = pinnedDiscoveryOriginFor(signer, opts);
    if (!pinnedOrigin.bound) {
      return bail(
        {},
        `Refusing a receipt-supplied key_discovery for pinned signer ${signer}: the pin does not bind a key ` +
        `source. Pinning the id alone cannot authenticate the key origin. Pin the signer's key_discovery ` +
        `origin via the object form of opts.trustedIssuers ({ [signer]: { key_discovery } }), or supply a ` +
        `caller-controlled opts.keyDiscoveryUrl (fail closed).`,
      );
    }
    const receiptOrigin = originOf(receipt?.signature?.key_discovery);
    if (!pinnedOrigin.origin || !receiptOrigin || receiptOrigin !== pinnedOrigin.origin) {
      return bail(
        { keyDiscoveryUrl: receipt?.signature?.key_discovery || null },
        `Receipt-supplied key_discovery origin ${receiptOrigin || '(none)'} does not match the origin pinned ` +
        `for signer ${signer} (${pinnedOrigin.origin || '(invalid pinned origin)'}); refusing to fetch a key ` +
        `from an unpinned source (fail closed).`,
      );
    }
  }

  const keyDiscoveryUrl = opts.keyDiscoveryUrl || receipt?.signature?.key_discovery;
  if (!keyDiscoveryUrl) {
    return bail({}, 'Receipt is missing signature.key_discovery and no keyDiscoveryUrl override given');
  }

  // SSRF guard on the (potentially receipt-supplied) discovery URL.
  const discoverySafe = assertSafeFetchUrl(keyDiscoveryUrl, opts);
  if (!discoverySafe.ok) {
    return bail(
      { keyDiscoveryUrl, discovery: { ok: false, blocked: true } },
      `Blocked unsafe key_discovery URL: ${discoverySafe.error}`,
    );
  }

  /** @type {{ keyDiscoveryUrl: string, discovery: { ok: boolean }|null, revocation: { ok: boolean, revoked?: boolean, blocked?: boolean }|null }} */
  const fetched = { keyDiscoveryUrl, discovery: null, revocation: null };
  let discoveryDoc;
  try {
    discoveryDoc = await fetchJson(fetchImpl, keyDiscoveryUrl, opts.timeoutMs);
    fetched.discovery = { ok: true };
  } catch (e) {
    return bail(fetched, `Failed to fetch operator key discovery: ${e.message}`);
  }

  // Resolve revocation from the operator's verifier-of-record, when reachable.
  const revokedReceiptIds = new Set();
  const receiptId = receipt.payload?.receipt_id || receipt.receipt_id;
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
        const v = await fetchJson(fetchImpl, verifyUrl, opts.timeoutMs);
        fetched.revocation = { ok: true, revoked: v?.revoked === true };
        if (v?.revoked === true) revokedReceiptIds.add(receiptId);
      } catch {
        // Preserve cryptographic verification, but never interpret unavailable
        // revocation state as affirmative evidence that the receipt is live.
        fetched.revocation = { ok: false };
      }
    } else if (verifyUrl) {
      fetched.revocation = { ok: false, blocked: true };
    }
  }

  const offline = verifyFederatedReceiptOffline(receipt, discoveryDoc, {
    revokedReceiptIds,
    expectedSigner: opts.expectedSigner,
    trustedIssuers: opts.trustedIssuers,
  });
  const revocationConfirmed = fetched.revocation?.ok === true;
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
      checks: { ...offline.checks, not_revoked: false, revocation_confirmed: false },
      fetched,
      revocation_confirmed: false,
      revocation_status: revocationStatus,
      error: offline.accepted
        ? 'Signature verifies and issuer is pinned, but revocation status is unavailable; refusing live acceptance'
        : offline.error,
    };
  }

  return {
    ...offline,
    checks: { ...offline.checks, revocation_confirmed: true },
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
  if (verifyUrlBase) return `${verifyUrlBase.replace(/\/$/, '')}/api/verify/${id}`;
  const tmpl = discoveryDoc?.verify_url_template;
  if (typeof tmpl === 'string' && tmpl.includes('{receipt_id}')) {
    return tmpl.replace('{receipt_id}', id);
  }
  const base = deriveVerifyBase(keyDiscoveryUrl);
  return base ? `${base}/api/verify/${id}` : null;
}

async function fetchJson(fetchImpl, url, timeoutMs = 5000) {
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
  try {
    // redirect:'manual' — a 3xx to a private/link-local host would bypass the
    // pre-flight SSRF guard, so we refuse to follow redirects at all. An
    // operator's discovery surface is expected to be served directly.
    const init = { redirect: 'manual' };
    if (controller) init.signal = controller.signal;
    const res = await fetchImpl(url, init);
    if (res && res.type === 'opaqueredirect') throw new Error('refusing to follow redirect');
    const status = res?.status;
    if (typeof status === 'number' && status >= 300 && status < 400) {
      throw new Error(`refusing to follow redirect (HTTP ${status})`);
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// Derive the operator's origin from its key_discovery URL so we can locate its
// /api/verify/{id} revocation surface on the same origin.
function deriveVerifyBase(keyDiscoveryUrl) {
  try {
    const u = new URL(keyDiscoveryUrl);
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

// =============================================================================
// SSRF GUARD
// =============================================================================

// Any server-side fetch of a URL that a receipt (or a receipt-reachable
// discovery document) can influence is an SSRF primitive. This guard is a
// pre-flight, string-only check — zero dependencies, safe in browsers/edge —
// that rejects the classic SSRF targets before a request is ever issued:
//   - non-https schemes (http/file/gopher/data/…),
//   - embedded credentials (user:pass@host),
//   - loopback / private / link-local / unique-local / cloud-metadata hosts.
// It is deliberately conservative: literal IPs in private ranges and the
// well-known metadata hostnames are blocked outright. Callers that must reach a
// private host (tests) can pass opts.allowInsecureFetch to bypass it.
//
// Note: this is a name/literal check, not a resolve-and-pin. It cannot stop DNS
// rebinding to a private address on its own; redirect:'manual' in fetchJson
// closes the redirect-to-private vector, and deployments that need full
// resolve-time pinning should layer a resolving guard (e.g. lib/sso/url-policy)
// in front. Kept dependency-free so /web and offline builds stay portable.
export function assertSafeFetchUrl(value, opts = {}) {
  if (opts.allowInsecureFetch) return { ok: true };
  let url;
  try {
    url = new URL(String(value || ''));
  } catch {
    return { ok: false, error: 'not a valid URL' };
  }
  if (url.protocol !== 'https:') {
    return { ok: false, error: `scheme ${url.protocol} is not https` };
  }
  if (url.username || url.password) {
    return { ok: false, error: 'URL must not embed credentials' };
  }
  const host = normalizeHost(url.hostname);
  if (!host) return { ok: false, error: 'URL has no hostname' };
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
    .replace(/\.$/, '')          // strip trailing dot (FQDN root)
    .toLowerCase();
}

function isBlockedHostname(host) {
  if (BLOCKED_HOSTNAMES.has(host)) return true;
  return host === 'localhost' || host.endsWith('.localhost');
}

function isPrivateOrReservedAddress(host) {
  if (isIPv4(host)) return isPrivateIPv4(host);
  if (host.includes(':')) return isPrivateIPv6(host);
  return false;
}

function isIPv4(host) {
  const parts = host.split('.');
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function isPrivateIPv4(host) {
  const [a, b] = host.split('.').map(Number);
  return (
    a === 0 ||                       // "this" network
    a === 10 ||                      // private
    a === 127 ||                     // loopback
    (a === 169 && b === 254) ||      // link-local (incl. 169.254.169.254 metadata)
    (a === 172 && b >= 16 && b <= 31) || // private
    (a === 192 && b === 168) ||      // private
    (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT
    (a === 198 && (b === 18 || b === 19)) || // benchmarking
    a >= 224                         // multicast / reserved
  );
}

function isPrivateIPv6(host) {
  const h = host.toLowerCase();
  if (h === '::1' || h === '::') return true;
  // IPv4-mapped (::ffff:a.b.c.d, or normalized ::ffff:7f00:1) — unwrap the
  // trailing 32 bits and re-check as IPv4.
  const mappedDotted = h.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mappedDotted && isIPv4(mappedDotted[1])) return isPrivateIPv4(mappedDotted[1]);
  const mappedHex = h.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mappedHex) {
    const hi = parseInt(mappedHex[1], 16);
    const lo = parseInt(mappedHex[2], 16);
    const dotted = `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
    return isPrivateIPv4(dotted);
  }
  return (
    h.startsWith('fc') ||   // unique local
    h.startsWith('fd') ||   // unique local
    h.startsWith('fe80') || // link-local
    h.startsWith('ff')      // multicast
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
