// SPDX-License-Identifier: Apache-2.0
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
import { strictJsonGate } from './strict-json.js';
export const ENTITLEMENT_VERSION = 'EP-GATE-ENTITLEMENT-v1';
export const ENTITLEMENT_TIERS = ['community', 'team', 'business', 'enterprise', 'regulated'];
/** The tier every failure path resolves to — the gate keeps working on it. */
const COMMUNITY = 'community';
/** Canonical JSON (recursive sorted keys) — matches @emilia-protocol/verify. */
function canonical(v) {
    if (v === null || v === undefined)
        return JSON.stringify(v);
    if (Array.isArray(v))
        return `[${v.map(canonical).join(',')}]`;
    if (typeof v === 'object') {
        return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',')}}`;
    }
    return JSON.stringify(v);
}
function toMs(t) {
    if (t == null)
        return null;
    const ms = typeof t === 'number' ? t : Date.parse(t);
    return Number.isFinite(ms) ? ms : null;
}
/** Community fallback — every refusal shape is identical and machine-readable. */
function community(reason, extra = {}) {
    return { valid: false, tier: COMMUNITY, features: [], limits: null, reason, ...extra };
}
/**
 * Mint a signed entitlement (test/ops helper — the licensing service, not the
 * verifier, holds the private key). Throws on invalid fields: a malformed
 * license must never be issued, only refused.
 * @param {crypto.KeyObject} privateKey Ed25519 private key
 * @param {object} fields { org, tier, features?, limits?, not_before, expires_at, kid }
 * @returns {{ '@version': string, payload: object, signature: { algorithm: 'Ed25519', value: string } }}
 */
export function mintEntitlement(privateKey, { org, tier, features = [], limits = {}, not_before, expires_at, kid, }) {
    if (!org || typeof org !== 'string')
        throw new Error('entitlement: org is required');
    if (!ENTITLEMENT_TIERS.includes(tier)) {
        throw new Error(`entitlement: unknown tier "${tier}" (expected one of ${ENTITLEMENT_TIERS.join('|')})`);
    }
    if (!Array.isArray(features) || features.some((f) => typeof f !== 'string')) {
        throw new Error('entitlement: features must be an array of strings');
    }
    if (!limits || typeof limits !== 'object' || Array.isArray(limits)) {
        throw new Error('entitlement: limits must be an object');
    }
    if (toMs(not_before) == null)
        throw new Error('entitlement: not_before is required (ISO or ms)');
    if (toMs(expires_at) == null)
        throw new Error('entitlement: expires_at is required (ISO or ms)');
    if (!kid || typeof kid !== 'string')
        throw new Error('entitlement: kid is required');
    // Snapshot features/limits into the signed payload: embedding the caller's live
    // array/object would let a licensing service mutate them after minting and
    // diverge the entitlement from its signature.
    const payload = { org, tier, features: structuredClone(features), limits: structuredClone(limits), not_before, expires_at, kid };
    const value = crypto.sign(null, Buffer.from(canonical(payload), 'utf8'), privateKey).toString('base64url');
    return { '@version': ENTITLEMENT_VERSION, payload, signature: { algorithm: 'Ed25519', value } };
}
/** Resolve a base64url SPKI-DER key for `kid` from a map or an entry list. */
function issuerKeyFor(issuerKeys, kid) {
    if (!issuerKeys)
        return null;
    if (Array.isArray(issuerKeys)) {
        const e = issuerKeys.find((x) => x && x.kid === kid && typeof x.key === 'string');
        return e ? e.key : null;
    }
    const k = issuerKeys[kid];
    return typeof k === 'string' ? k : null;
}
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
export function verifyEntitlement(entitlementJson, { issuerKeys, now = Date.now, } = {}) {
    // Absence is NOT an error: the open-core floor. Community keeps working.
    if (entitlementJson == null || entitlementJson === '')
        return community('no_entitlement');
    let doc = entitlementJson;
    if (typeof doc === 'string') {
        try {
            if (Buffer.byteLength(doc, 'utf8') > 1024 * 1024 || !strictJsonGate(doc).ok)
                return community('entitlement_unparseable');
            doc = JSON.parse(doc);
        }
        catch {
            return community('entitlement_unparseable');
        }
    }
    if (!doc || typeof doc !== 'object' || Array.isArray(doc))
        return community('entitlement_malformed');
    if (doc['@version'] !== ENTITLEMENT_VERSION)
        return community('unsupported_version');
    const p = doc.payload;
    const sig = doc.signature;
    if (!p || typeof p !== 'object' || !sig || typeof sig !== 'object')
        return community('entitlement_malformed');
    if (sig.algorithm !== 'Ed25519' || typeof sig.value !== 'string')
        return community('unsupported_algorithm');
    if (!ENTITLEMENT_TIERS.includes(p.tier))
        return community('unknown_tier');
    if (!Array.isArray(p.features) || p.features.some((f) => typeof f !== 'string'))
        return community('entitlement_malformed');
    // Issuer pinning: the kid must resolve to a PINNED key. An entitlement can
    // never nominate its own key — unknown kid (or no pins at all) fails closed.
    const keyB64 = issuerKeyFor(issuerKeys, p.kid);
    if (!keyB64)
        return community('unknown_kid', { kid: p.kid ?? null });
    let ok = false;
    try {
        const pub = crypto.createPublicKey({ key: Buffer.from(keyB64, 'base64url'), format: 'der', type: 'spki' });
        ok = crypto.verify(null, Buffer.from(canonical(p), 'utf8'), pub, Buffer.from(sig.value, 'base64url'));
    }
    catch {
        ok = false;
    }
    // One reason covers both tampering and a wrong key: the signature does not
    // verify against the pinned key for this kid.
    if (!ok)
        return community('bad_signature', { kid: p.kid });
    // Validity window — checked only AFTER the signature, so the timestamps
    // themselves are authenticated. Both bounds are required; an unparseable
    // window fails closed.
    const nowMs = typeof now === 'function' ? now() : toMs(now);
    const nbf = toMs(p.not_before);
    const exp = toMs(p.expires_at);
    if (nbf == null || exp == null || nowMs == null)
        return community('invalid_validity_window', { kid: p.kid });
    if (nowMs < nbf)
        return community('not_yet_valid', { kid: p.kid, not_before: p.not_before });
    if (nowMs > exp)
        return community('expired', { kid: p.kid, expires_at: p.expires_at });
    return {
        valid: true,
        tier: p.tier,
        features: p.features.slice(),
        limits: (p.limits && typeof p.limits === 'object') ? { ...p.limits } : {},
        reason: 'entitlement_verified',
        org: p.org,
        kid: p.kid,
        not_before: p.not_before,
        expires_at: p.expires_at,
    };
}
/**
 * Is `feature` licensed? FAIL CLOSED: true only for a valid entitlement that
 * explicitly lists the feature. Community fallback, invalid/expired/tampered
 * artifacts, and unlisted features are all false — no enterprise code path
 * runs without a live license naming it.
 * @param {object} verified the result of verifyEntitlement
 * @param {string} feature
 * @returns {boolean}
 */
export function requireFeature(verified, feature) {
    if (!verified || verified.valid !== true)
        return false;
    if (typeof feature !== 'string' || feature.length === 0)
        return false;
    return Array.isArray(verified.features) && verified.features.includes(feature);
}
export default { mintEntitlement, verifyEntitlement, requireFeature, ENTITLEMENT_VERSION, ENTITLEMENT_TIERS };
//# sourceMappingURL=enterprise.js.map