// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — issuer key registry (production key custody for the VERIFIER).
 *
 * A flat `trustedKeys: string[]` cannot express the two things a production
 * deployment needs:
 *   1. ROTATION — an issuer key is valid only for a window; a new key overlaps
 *      the old one, then the old one retires, without rejecting receipts that
 *      were legitimately issued while it was current.
 *   2. REVOCATION — a COMPROMISED issuer key must be rejected immediately, for
 *      every receipt, regardless of the issuance time the (now-untrusted) key
 *      claims. Fail closed: once revoked, the key signs nothing the gate accepts.
 *
 * The registry resolves, for a given receipt issuance time, the set of public
 * keys the gate should verify against — excluding revoked keys entirely and
 * windowed keys whose [not_before, not_after] does not contain that time. The
 * gate passes that resolved set to the receipt verifier, so an excluded key's
 * signature simply does not verify and the action is refused.
 *
 * A key with no window and no revocation behaves exactly like a flat trustedKeys
 * entry (back-compatible).
 */

function toMs(t) {
  if (t == null) return null;
  const ms = typeof t === 'number' ? t : Date.parse(t);
  return Number.isFinite(ms) ? ms : null;
}

/**
 * @param {Array<object>} entries each: {
 *   kid?: string, key: string (base64url SPKI-DER public key),
 *   not_before?: string|number, not_after?: string|number, revoked_at?: string|number
 * }
 */
export function createKeyRegistry(entries = []) {
  const list = [];
  function normalize(e) {
    if (!e || !e.key || typeof e.key !== 'string') throw new Error('key registry entry requires a base64url SPKI key');
    return {
      kid: e.kid || e.key.slice(0, 16),
      key: e.key,
      not_before: toMs(e.not_before),
      not_after: toMs(e.not_after),
      revoked_at: toMs(e.revoked_at),
    };
  }
  for (const e of entries) list.push(normalize(e));

  /** Is this entry usable to verify a receipt issued at `atMs`? */
  function entryActiveAt(entry, atMs) {
    if (entry.revoked_at != null) return false; // HARD revocation: never trust a revoked key
    if (entry.not_before != null && atMs != null && atMs < entry.not_before) return false;
    if (entry.not_after != null && atMs != null && atMs > entry.not_after) return false;
    // A windowed key with an unknown issuance time cannot be safely placed in
    // its window — fail closed and exclude it. An unwindowed key still applies.
    if ((entry.not_before != null || entry.not_after != null) && atMs == null) return false;
    return true;
  }

  return {
    /** The base64url public keys to verify a receipt issued at `at` (ISO or ms). */
    keysValidAt(at) {
      const atMs = toMs(at);
      return list.filter((e) => entryActiveAt(e, atMs)).map((e) => e.key);
    },
    /** Mark a kid revoked as of `at` (default: now-as-supplied). Fail-closed thereafter. */
    revoke(kid, at) {
      let n = 0;
      for (const e of list) {
        if (e.kid === kid && e.revoked_at == null) { e.revoked_at = toMs(at) ?? 0; n += 1; }
      }
      if (n === 0) throw new Error(`key registry: no active key with kid "${kid}" to revoke`);
      return n;
    },
    /** Add/rotate in a new key. */
    add(entry) { list.push(normalize(entry)); return this; },
    /** Operational snapshot (no private material; keys are public). */
    status(at) {
      const atMs = toMs(at);
      return list.map((e) => ({
        kid: e.kid,
        revoked: e.revoked_at != null,
        active: entryActiveAt(e, atMs),
        not_before: e.not_before,
        not_after: e.not_after,
        revoked_at: e.revoked_at,
      }));
    },
    get size() { return list.length; },
  };
}

/** Coerce a flat trustedKeys[] OR a registry into a registry (back-compat). */
export function asKeyRegistry(trustedKeysOrRegistry) {
  if (trustedKeysOrRegistry && typeof trustedKeysOrRegistry.keysValidAt === 'function') {
    return trustedKeysOrRegistry;
  }
  const keys = Array.isArray(trustedKeysOrRegistry) ? trustedKeysOrRegistry : [];
  return createKeyRegistry(keys.map((key) => ({ key })));
}

export default { createKeyRegistry, asKeyRegistry };
