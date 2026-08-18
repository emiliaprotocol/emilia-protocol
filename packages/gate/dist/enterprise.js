// @ts-nocheck
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
import { canonicalizeFiniteJson, strictJsonGate } from './strict-json.js';
import { signAgileSet, verifyAgileSignatureSet, } from '@emilia-protocol/verify/pq-signature-agility';
export const ENTITLEMENT_VERSION = 'EP-GATE-ENTITLEMENT-v1';
export const ENTITLEMENT_TIERS = ['community', 'team', 'business', 'enterprise', 'regulated'];
/** The tier every failure path resolves to — the gate keeps working on it. */
const COMMUNITY = 'community';
/** Canonical JSON (recursive sorted keys) — matches @emilia-protocol/verify. */
const canonical = canonicalizeFiniteJson;
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
 * Shared field validation + payload snapshot for BOTH mintEntitlement (v1) and
 * mintEntitlementV2. Throws on invalid fields -- a malformed entitlement must
 * never be issued, only refused -- and returns the canonical payload object
 * both mint paths sign, so v1 and v2 can never disagree on what a "valid"
 * entitlement payload looks like.
 */
function validateAndSnapshotEntitlementFields({ org, tier, features = [], limits = {}, not_before, expires_at, kid, }) {
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
    return JSON.parse(canonical({ org, tier, features, limits, not_before, expires_at, kid }));
}
export function mintEntitlement(privateKey, fields) {
    const payload = validateAndSnapshotEntitlementFields(fields);
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
    try {
        // Normalize only after a descriptor-based canonical-domain check. This
        // refuses accessors, symbols, non-plain objects, sparse arrays and cycles
        // instead of letting them disappear before signature verification.
        doc = JSON.parse(canonical(doc));
    }
    catch {
        return community('entitlement_malformed');
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
// ===========================================================================
// EP-GATE-ENTITLEMENT-v2 -- the hybrid (Ed25519 + ML-DSA-65) entitlement
// ===========================================================================
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the entitlement artifact.
 *
 * 1. VERSION BUMP. `signature: {algorithm,value}` becomes `proof:
 *    {required_algorithms, signatures}`, a shape change, so this is a new
 *    `@version` (-v1 -> -v2), never an optional field on v1. verifyEntitlement
 *    above is UNCHANGED and still refuses a v2 document at
 *    `unsupported_version` (checked before it ever inspects `signature`,
 *    which a v2 document does not even carry) -- it never crashes on one.
 * 2. SET SHAPE. `proof.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
 *    array, one entry per required algorithm, reused verbatim.
 * 3. ANTI-STRIPPING. `required_algorithms` is INSIDE the signed bytes
 *    (entitlementV2SignedBytes below), alongside the payload. Dropping the
 *    ML-DSA leg and narrowing `required_algorithms` to `["Ed25519"]` changes
 *    the signed bytes, so the surviving Ed25519 signature no longer verifies.
 * 4. V1 COMPATIBILITY. verifyEntitlement stays synchronous and untouched.
 *    verifyEntitlementV2 is a SEPARATE async entry point (ML-DSA verification
 *    is inherently async); verifyEntitlementStatement routes on `@version`.
 * 5. NAMED REFUSALS, COMMUNITY FALLBACK PRESERVED. verifyEntitlementV2 keeps
 *    the open-core contract exactly: it NEVER throws, and every failure --
 *    tampered, expired, unknown kid, missing PQ backend, one leg alone --
 *    resolves to `{valid:false, tier:'community', reason}`. An absent ML-DSA
 *    backend surfaces as `pq_backend_unavailable`, never a silent pass on the
 *    Ed25519 leg alone (that would be exactly the downgrade a hybrid pin
 *    exists to prevent).
 *
 * HONEST BOUNDARY. Same as every other hybrid profile in this repository:
 * the ML-DSA-65 backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, not independently audited and not a FIPS validated module.
 * Issuing or verifying under this profile is not a certification claim, and
 * this profile is opt-in -- nothing here is on by default.
 */
export const ENTITLEMENT_V2_VERSION = 'EP-GATE-ENTITLEMENT-v2';
export const ENTITLEMENT_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
function algorithmSetMatchesRegistered(algorithms) {
    return Array.isArray(algorithms)
        && algorithms.length === ENTITLEMENT_V2_REQUIRED_ALGORITHMS.length
        && algorithms.every((a, i) => a === ENTITLEMENT_V2_REQUIRED_ALGORITHMS[i]);
}
/**
 * The bytes BOTH legs sign: the entitlement payload plus the registered
 * algorithm set and the v2 version marker, so the algorithm set is
 * cryptographically committed alongside the payload it protects. Recomputed
 * independently by the verifier from the payload it holds and the REGISTERED
 * set -- never from anything the presented document could narrow.
 */
export function entitlementV2SignedBytes(payload, requiredAlgorithms = ENTITLEMENT_V2_REQUIRED_ALGORITHMS) {
    if (!algorithmSetMatchesRegistered(requiredAlgorithms)) {
        throw new Error('entitlementV2SignedBytes: algorithm set is not the registered EP-GATE-ENTITLEMENT-v2 set');
    }
    return Buffer.from(canonical({
        '@version': ENTITLEMENT_V2_VERSION,
        payload,
        required_algorithms: [...requiredAlgorithms],
    }), 'utf8');
}
/**
 * Mint a hybrid entitlement. Throws on invalid fields or an unavailable PQ
 * backend -- issuer-side misuse is a programming error, and a proof missing
 * the ML-DSA leg must never be emitted.
 */
export async function mintEntitlementV2(keys, fields) {
    if (!keys?.ed?.privateKey || !keys?.pq?.secretKey) {
        throw new Error('entitlement v2: keys.ed.privateKey and keys.pq.secretKey are both required');
    }
    const payload = validateAndSnapshotEntitlementFields(fields);
    const requiredAlgorithms = [...ENTITLEMENT_V2_REQUIRED_ALGORITHMS];
    const bytes = new Uint8Array(entitlementV2SignedBytes(payload, requiredAlgorithms));
    const signingKeys = [
        { alg: 'Ed25519', private_key: keys.ed.privateKey },
        { alg: 'ML-DSA-65', private_key: keys.pq.secretKey },
    ];
    const signatures = await signAgileSet(bytes, signingKeys);
    return {
        '@version': ENTITLEMENT_V2_VERSION,
        payload,
        proof: { required_algorithms: requiredAlgorithms, signatures },
    };
}
/** Resolve a v2 issuer key pin for `kid` from a map or an entry list. */
function issuerKeyForV2(issuerKeys, kid) {
    if (!issuerKeys || typeof kid !== 'string' || kid.length === 0)
        return null;
    if (Array.isArray(issuerKeys)) {
        const e = issuerKeys.find((x) => x && x.kid === kid
            && typeof x.public_key === 'string' && typeof x.pq_public_key === 'string');
        return e ? { public_key: e.public_key, pq_public_key: e.pq_public_key } : null;
    }
    const pin = issuerKeys[kid];
    return pin && typeof pin.public_key === 'string' && typeof pin.pq_public_key === 'string' ? pin : null;
}
/**
 * Verify a hybrid entitlement. NEVER throws -- preserves the exact open-core
 * community-fallback contract of verifyEntitlement: absence, tampering,
 * expiry, an unknown/classical-only-pinned kid, a stripped or narrowed leg,
 * and an unavailable ML-DSA backend all resolve to
 * `{valid:false, tier:'community', reason}`. requireFeature() above already
 * fails closed on any non-valid result, so no separate v2 gate is needed.
 */
export async function verifyEntitlementV2(entitlementJson, { issuerKeys, now = Date.now, } = {}) {
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
    try {
        doc = JSON.parse(canonical(doc));
    }
    catch {
        return community('entitlement_malformed');
    }
    if (!doc || typeof doc !== 'object' || Array.isArray(doc))
        return community('entitlement_malformed');
    if (doc['@version'] !== ENTITLEMENT_V2_VERSION)
        return community('unsupported_version');
    const p = doc.payload;
    const proof = doc.proof;
    if (!p || typeof p !== 'object' || !proof || typeof proof !== 'object')
        return community('entitlement_malformed');
    if (!algorithmSetMatchesRegistered(proof.required_algorithms)) {
        return community('unsupported_algorithm_set');
    }
    if (!ENTITLEMENT_TIERS.includes(p.tier))
        return community('unknown_tier');
    if (!Array.isArray(p.features) || p.features.some((f) => typeof f !== 'string'))
        return community('entitlement_malformed');
    // Issuer pinning: kid must resolve to a PINNED pair (BOTH halves). An
    // entitlement can never nominate its own key, and a kid pinned for v1 only
    // (classical public_key with no pq_public_key) does not satisfy a v2 pin --
    // identified but not trusted for the leg that was never pinned.
    const pin = issuerKeyForV2(issuerKeys, p.kid);
    if (!pin)
        return community('unknown_kid', { kid: p.kid ?? null });
    let bytes;
    try {
        bytes = new Uint8Array(entitlementV2SignedBytes(p, ENTITLEMENT_V2_REQUIRED_ALGORITHMS));
    }
    catch {
        return community('entitlement_malformed');
    }
    let setResult;
    try {
        setResult = await verifyAgileSignatureSet(bytes, Array.isArray(proof.signatures) ? proof.signatures : [], [
            { alg: 'Ed25519', public_key: pin.public_key },
            { alg: 'ML-DSA-65', public_key: pin.pq_public_key },
        ], { policy: 'hybrid_all', requiredAlgorithms: [...ENTITLEMENT_V2_REQUIRED_ALGORITHMS] });
    }
    catch {
        setResult = null;
    } // verifyAgileSignatureSet never throws; a thrown backend is still a refusal.
    if (setResult?.verified !== true) {
        const reason = String(setResult?.reason ?? 'signature_set_unverified');
        return community('bad_signature', { kid: p.kid, hybrid_reason: reason });
    }
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
 * Route an entitlement document of EITHER version to its verifier. A v1
 * document keeps the exact synchronous v1 verdict (wrapped in a resolved
 * Promise so callers holding a mixed bag get one uniform async surface); a
 * v2 document gets the hybrid check.
 */
export async function verifyEntitlementStatement(entitlementJson, opts = {}) {
    let doc = entitlementJson;
    if (typeof doc === 'string') {
        try {
            if (Buffer.byteLength(doc, 'utf8') <= 1024 * 1024 && strictJsonGate(doc).ok)
                doc = JSON.parse(doc);
        }
        catch { /* fall through; the version-specific verifier will refuse it */ }
    }
    if (doc && typeof doc === 'object' && !Array.isArray(doc) && doc['@version'] === ENTITLEMENT_V2_VERSION) {
        return verifyEntitlementV2(entitlementJson, opts);
    }
    return verifyEntitlement(entitlementJson, opts);
}
export default {
    mintEntitlement,
    verifyEntitlement,
    requireFeature,
    ENTITLEMENT_VERSION,
    ENTITLEMENT_TIERS,
    mintEntitlementV2,
    verifyEntitlementV2,
    verifyEntitlementStatement,
    ENTITLEMENT_V2_VERSION,
    ENTITLEMENT_V2_REQUIRED_ALGORITHMS,
};
//# sourceMappingURL=enterprise.js.map