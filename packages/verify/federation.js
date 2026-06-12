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
 * This module performs steps 1–3 and returns the evidence. Step 4 is the
 * caller's: `accepted` is the default verified-and-not-revoked verdict, but a
 * relying party is free to ignore it and apply stricter local policy.
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
 * @param {object} receipt - EP-RECEIPT-v1 document. MUST carry
 *   `signature.signer` (issuing operator entity_id) per PIP-006.
 * @param {object} discoveryDoc - the issuing operator's parsed ep-keys.json
 * @param {object} [opts]
 * @param {Set<string>|string[]} [opts.revokedReceiptIds] - operator A's revocation set
 * @param {string} [opts.expectedSigner] - if set, the receipt's signer MUST equal this
 * @returns {{
 *   accepted: boolean,
 *   verified: boolean,
 *   revoked: boolean,
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
    signer: null,
    keyMatched: null,
    checks: { version: false, signer_present: false, signature: false, not_revoked: false },
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

  // Revocation (PIP-006 §"Cross-operator semantics" step 3). A revocation that
  // arrives after the action executed is a dispute, not a verification failure
  // (§"Security considerations" → Revocation) — but for the purpose of *now*
  // accepting the receipt as live evidence, a revoked receipt is not accepted.
  const revokedSet = normalizeRevocationSet(opts.revokedReceiptIds);
  const receiptId = receipt.payload?.receipt_id || receipt.receipt_id;
  result.revoked = Boolean(receiptId && revokedSet.has(receiptId));
  result.checks.not_revoked = !result.revoked;

  result.accepted = result.verified && !result.revoked;
  return result;
}

function normalizeRevocationSet(input) {
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
 * reports a `revoked` field; absence of an affirmative revocation is treated as
 * not-revoked (fail-open on revocation is the documented behavior — a missing
 * revocation feed must not block verification of an otherwise-valid receipt;
 * the converse — a present `revoked: true` — is honored).
 *
 * @param {object} receipt - EP-RECEIPT-v1 with signature.signer + signature.key_discovery
 * @param {object} [opts]
 * @param {typeof fetch} [opts.fetchImpl] - injectable fetch (defaults to global fetch)
 * @param {number} [opts.timeoutMs=5000]
 * @param {string} [opts.keyDiscoveryUrl] - override the receipt's key_discovery URL
 * @param {string} [opts.verifyUrlBase] - override base for the revocation check
 * @returns {Promise<ReturnType<typeof verifyFederatedReceiptOffline> & { fetched: object }>}
 */
export async function verifyFederatedReceipt(receipt, opts = {}) {
  const fetchImpl = opts.fetchImpl || (typeof fetch !== 'undefined' ? fetch : null);
  if (!fetchImpl) {
    return {
      accepted: false, verified: false, revoked: false, signer: receipt?.signature?.signer || null,
      keyMatched: null, checks: {}, fetched: {},
      error: 'No fetch implementation available; use verifyFederatedReceiptOffline instead',
    };
  }

  const keyDiscoveryUrl = opts.keyDiscoveryUrl || receipt?.signature?.key_discovery;
  if (!keyDiscoveryUrl) {
    return {
      accepted: false, verified: false, revoked: false, signer: receipt?.signature?.signer || null,
      keyMatched: null, checks: {}, fetched: {},
      error: 'Receipt is missing signature.key_discovery and no keyDiscoveryUrl override given',
    };
  }

  const fetched = { keyDiscoveryUrl, discovery: null, revocation: null };
  let discoveryDoc;
  try {
    discoveryDoc = await fetchJson(fetchImpl, keyDiscoveryUrl, opts.timeoutMs);
    fetched.discovery = { ok: true };
  } catch (e) {
    return {
      accepted: false, verified: false, revoked: false, signer: receipt?.signature?.signer || null,
      keyMatched: null, checks: {}, fetched,
      error: `Failed to fetch operator key discovery: ${e.message}`,
    };
  }

  // Resolve revocation from the operator's verifier-of-record, when reachable.
  const revokedReceiptIds = new Set();
  const receiptId = receipt.payload?.receipt_id || receipt.receipt_id;
  if (receiptId) {
    const verifyBase = opts.verifyUrlBase || deriveVerifyBase(keyDiscoveryUrl);
    if (verifyBase) {
      try {
        const v = await fetchJson(fetchImpl, `${verifyBase}/api/verify/${encodeURIComponent(receiptId)}`, opts.timeoutMs);
        fetched.revocation = { ok: true, revoked: v?.revoked === true };
        if (v?.revoked === true) revokedReceiptIds.add(receiptId);
      } catch {
        // Fail-open on revocation lookup: an unreachable revocation feed must
        // not turn a cryptographically-valid receipt into a failure. The
        // verdict notes that revocation could not be confirmed.
        fetched.revocation = { ok: false };
      }
    }
  }

  const offline = verifyFederatedReceiptOffline(receipt, discoveryDoc, {
    revokedReceiptIds,
    expectedSigner: opts.expectedSigner,
  });
  return { ...offline, fetched, revocation_confirmed: fetched.revocation?.ok === true };
}

async function fetchJson(fetchImpl, url, timeoutMs = 5000) {
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
  try {
    const res = await fetchImpl(url, controller ? { signal: controller.signal } : {});
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
