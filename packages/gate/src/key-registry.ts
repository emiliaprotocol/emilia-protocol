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

const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;

type RawKeyEntry = {
  kid?: string;
  key: string;
  not_before?: string;
  not_after?: string;
  revoked_at?: string;
};
type NormalizedKeyEntry = {
  kid: string;
  key: string;
  not_before: number | null;
  not_after: number | null;
  revoked_at: number | null;
};

function strictInstantMs(value) {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_INSTANT);
  if (!match) return NaN;
  const [, y, mo, d, h, mi, s, , oh, om] = match;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(y), Number(mo) - 1, Number(d));
  calendar.setUTCHours(Number(h), Number(mi), Number(s), 0);
  if (calendar.toISOString().slice(0, 19) !== `${y}-${mo}-${d}T${h}:${mi}:${s}`) return NaN;
  if (oh !== undefined && (Number(oh) > 23 || Number(om) > 59)) return NaN;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : NaN;
}

function optionalInstant(entry, field) {
  if (!Object.hasOwn(entry, field)) return null;
  const ms = strictInstantMs(entry[field]);
  if (!Number.isFinite(ms)) {
    throw new Error(`key registry: ${field} must be a valid RFC3339 instant when supplied`);
  }
  return ms;
}

/**
 * @param {Array<object>} entries each: {
 *   kid?: string, key: string (base64url SPKI-DER public key),
 *   not_before?: string, not_after?: string, revoked_at?: string (strict RFC3339)
 * }
 */
export function createKeyRegistry(entries: RawKeyEntry[] = []) {
  const list: NormalizedKeyEntry[] = [];
  function normalize(e) {
    if (!e || !e.key || typeof e.key !== 'string') throw new Error('key registry entry requires a base64url SPKI key');
    const normalized = {
      kid: e.kid || e.key.slice(0, 16),
      key: e.key,
      not_before: optionalInstant(e, 'not_before'),
      not_after: optionalInstant(e, 'not_after'),
      revoked_at: optionalInstant(e, 'revoked_at'),
    };
    if (normalized.not_before != null && normalized.not_after != null
        && normalized.not_after < normalized.not_before) {
      throw new Error('key registry: not_after must not precede not_before');
    }
    return normalized;
  }
  for (const e of entries) list.push(normalize(e));

  /** Is this entry usable to verify a receipt issued at `atMs`? */
  function entryActiveAt(entry, atMs) {
    if (entry.revoked_at != null) return false; // HARD revocation: never trust a revoked key
    if (!Number.isFinite(atMs)) return false;
    if (entry.not_before != null && atMs < entry.not_before) return false;
    if (entry.not_after != null && atMs > entry.not_after) return false;
    return true;
  }

  return {
    /** The base64url public keys to verify a receipt issued at strict RFC3339 `at`. */
    keysValidAt(at) {
      const atMs = strictInstantMs(at);
      return list.filter((e) => entryActiveAt(e, atMs)).map((e) => e.key);
    },
    /** Mark a kid revoked as of `at` (default: now-as-supplied). Fail-closed thereafter. */
    revoke(kid: string, at?: string) {
      let revokedAt = 0;
      if (arguments.length > 1) {
        revokedAt = strictInstantMs(at);
        if (!Number.isFinite(revokedAt)) {
          throw new Error('key registry: revoked_at must be a valid RFC3339 instant when supplied');
        }
      }
      let n = 0;
      for (const e of list) {
        if (e.kid === kid && e.revoked_at == null) { e.revoked_at = revokedAt; n += 1; }
      }
      if (n === 0) throw new Error(`key registry: no active key with kid "${kid}" to revoke`);
      return n;
    },
    /** Add/rotate in a new key. */
    add(entry) { list.push(normalize(entry)); return this; },
    /** Operational snapshot (no private material; keys are public). */
    status(at) {
      const supplied = arguments.length > 0;
      const atMs = supplied ? strictInstantMs(at) : NaN;
      return list.map((e) => ({
        kid: e.kid,
        revoked: e.revoked_at != null,
        active: supplied
          ? entryActiveAt(e, atMs)
          : e.revoked_at == null && e.not_before == null && e.not_after == null,
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
