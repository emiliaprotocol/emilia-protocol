// SPDX-License-Identifier: Apache-2.0
/**
 * EP-REVOCATION-v1 — portable, offline-verifiable revocation statement check.
 *
 * Offline-package port of the reference verifier (lib/revocation/revocation.js).
 * Spec: docs/EP-REVOCATION-SPEC.md. This belongs in the published verifier
 * because a revocation statement is a PORTABLE artifact a relying party is
 * handed — it must be checkable with the same offline package that checks the
 * receipt, no EP server required.
 *
 * A revocation statement is an ADDITIVE signed claim that a previously-valid
 * authorization is now revoked. verifyRevocation(target, statement, opts) is
 * FAIL-CLOSED: it accepts only a statement whose Ed25519 proof verifies under a
 * key PINNED for revoker_id (identified-but-not-trusted — a self-asserted,
 * unpinned key confers NOTHING), that BINDS the EXACT (target_type, target_id,
 * action_hash) the verifier holds (revoking A must never revoke B), with a
 * well-formed revoked_at that is effective at the verifier's decision time.
 * A terminal revocation never becomes acceptable merely because it is old.
 *
 * HONEST BOUNDARY: this proves a PRESENTED statement is authentic and binds the
 * target. It does NOT prove you hold the LATEST revocation state — absence of a
 * statement is not proof of not-revoked (that is a transparency/feed problem,
 * out of scope; see SPEC §7).
 */
import crypto from 'node:crypto';
import { canonicalize } from './index.js';
import { verifyAgileSignatureSet, ML_DSA_65_PUBLIC_KEY_BYTES, } from './pq-signature-agility.js';
export const REVOCATION_VERSION = 'EP-REVOCATION-v1';
const TARGET_TYPES = Object.freeze(['receipt', 'commit', 'delegation']);
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const STATEMENT_KEYS = new Set([
    '@version', 'target_type', 'target_id', 'action_hash', 'revoker_id',
    'revoked_at', 'reason', 'proof',
]);
const PROOF_KEYS = new Set([
    'algorithm', 'revoker_key_id', 'signature_b64u', 'public_key',
]);
const FULL_REVOKER_KEY_ID = /^ep:revoker-key:sha256:[0-9a-f]{64}$/;
const LEGACY_REVOKER_KEY_ID = /^(?!ep:revoker-key:sha256:)[A-Za-z0-9._:#-]{1,128}$/;
// Validate to a well-formed 64-char SHA-256; malformed -> '' so comparisons
// fail closed (never match a real digest) and stay cross-language consistent. (HI-2)
const hexOf = (h) => {
    const s = String(h ?? '').replace(/^sha256:/, '').toLowerCase();
    return /^[0-9a-f]{64}$/.test(s) ? s : '';
};
function instantMs(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = value.match(RFC3339_INSTANT);
    if (!match)
        return NaN;
    const [, y, mo, d, h, mi, s, , oh, om] = match;
    const calendar = new Date(0);
    calendar.setUTCFullYear(Number(y), Number(mo) - 1, Number(d));
    calendar.setUTCHours(Number(h), Number(mi), Number(s), 0);
    if (calendar.toISOString().slice(0, 19) !== `${y}-${mo}-${d}T${h}:${mi}:${s}`)
        return NaN;
    if (oh !== undefined && (Number(oh) > 23 || Number(om) > 59))
        return NaN;
    return Date.parse(value);
}
function decisionTimeMs(value) {
    if (value === undefined)
        return Date.now();
    if (value instanceof Date)
        return value.getTime();
    if (typeof value === 'number')
        return Number.isFinite(value) ? value : NaN;
    return instantMs(value);
}
// The fixed SIGNED_FIELDS set, independently recomputed by the verifier so a
// producer cannot present one set of fields while claiming a signature over
// another. Mirrors EP-REVOCATION-SPEC §3.3. canonicalize() sorts keys.
function revocationSignedPayload(stmt) {
    return Buffer.from(canonicalize({
        '@version': REVOCATION_VERSION,
        action_hash: stmt.action_hash ?? null,
        reason: stmt.reason ?? null,
        revoked_at: stmt.revoked_at ?? null,
        revoker_id: stmt.revoker_id ?? null,
        target_id: stmt.target_id ?? null,
        target_type: stmt.target_type ?? null,
    }), 'utf8');
}
function verifyEd25519(bytes, publicKeyB64u, signatureB64u) {
    try {
        if (!bytes || !publicKeyB64u || !signatureB64u)
            return false;
        const key = crypto.createPublicKey({
            key: Buffer.from(String(publicKeyB64u), 'base64url'),
            format: 'der',
            type: 'spki',
        });
        return crypto.verify(null, bytes, key, Buffer.from(String(signatureB64u), 'base64url'));
    }
    catch {
        return false;
    }
}
function isWellFormedSignature(sigB64u) {
    try {
        return Buffer.from(String(sigB64u ?? ''), 'base64url').length === 64;
    }
    catch {
        return false;
    }
}
function exactKeys(value, allowed) {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).length === allowed.size
        && Object.keys(value).every((key) => allowed.has(key));
}
function revokerKeyId(publicKeyB64u) {
    try {
        if (typeof publicKeyB64u !== 'string' || publicKeyB64u.length === 0)
            return '';
        const der = Buffer.from(publicKeyB64u, 'base64url');
        if (der.length === 0 || der.toString('base64url') !== publicKeyB64u)
            return '';
        const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
        if (key.asymmetricKeyType !== 'ed25519')
            return '';
        return `ep:revoker-key:sha256:${crypto.createHash('sha256')
            .update(der).digest('hex')}`;
    }
    catch {
        return '';
    }
}
function isLegacyRevokerKeyId(value) {
    return typeof value === 'string' && LEGACY_REVOKER_KEY_ID.test(value);
}
/**
 * @param {{target_type:string, target_id:string, action_hash:string}} target
 *   the authorization the relying party HOLDS and wants to know the status of.
 * @param {object} statement  the presented EP-REVOCATION-v1 statement.
 * @param {object} [opts]
 * @param {Object<string,{public_key:string}>} [opts.revokerKeys]  pinned keys by revoker_id.
 * @param {number} [opts.maxAgeSeconds]  DEPRECATED and ignored. Terminal
 *   revocations do not age out; freshness belongs to separate status evidence.
 * @param {number|string|Date} [opts.now]  decision time used to reject a
 *   revocation whose effective instant is still in the future.
 * @returns {{valid:boolean, checks:object, errors:string[]}}
 */
export function verifyRevocation(target, statement, opts = {}) {
    opts = opts && typeof opts === 'object' ? opts : {};
    const revokerKeys = opts.revokerKeys || {};
    const checks = {
        version: true,
        structure: true,
        target_bound: true,
        revoker_key_pinned: true,
        revoker_key_bound: true,
        revoked_at_present: true,
        effective_at_or_before_T: true,
        revoker_signature_valid: true,
        signature_binds_statement: true,
    };
    const errors = [];
    const fail = (key, msg) => { checks[key] = false; errors.push(msg); };
    if (!statement || typeof statement !== 'object' || Array.isArray(statement)) {
        fail('signature_binds_statement', 'no revocation statement presented (fail-closed)');
        fail('revoker_signature_valid', 'no revocation statement presented (fail-closed)');
        return { valid: false, checks, errors };
    }
    if (statement['@version'] !== REVOCATION_VERSION) {
        fail('version', `unsupported version: ${statement['@version']}`);
    }
    const proof = statement.proof || null;
    if (!exactKeys(statement, STATEMENT_KEYS) || !exactKeys(proof, PROOF_KEYS)) {
        fail('structure', 'revocation statement and proof must use the exact closed EP-REVOCATION-v1 schema');
    }
    if (!target || typeof target !== 'object' || Array.isArray(target)) {
        fail('target_bound', 'no target handed to the verifier (fail-closed)');
    }
    else {
        const heldHash = hexOf(target.action_hash);
        const statementHash = hexOf(statement.action_hash);
        if (!TARGET_TYPES.includes(target.target_type)
            || typeof target.target_id !== 'string' || target.target_id.length === 0
            || !heldHash) {
            fail('target_bound', 'handed target is incomplete or malformed');
        }
        if (!(typeof statement.target_type === 'string' && TARGET_TYPES.includes(statement.target_type))
            || typeof statement.target_id !== 'string' || statement.target_id.length === 0
            || !statementHash) {
            fail('target_bound', 'revocation statement target is incomplete or malformed');
        }
        else if (statement.target_type !== target.target_type) {
            fail('target_bound', `statement target_type "${statement.target_type}" != handed "${target.target_type}"`);
        }
        else if (statement.target_id !== target.target_id) {
            fail('target_bound', `statement target_id "${statement.target_id}" != handed "${target.target_id}"`);
        }
        else if (statementHash !== heldHash) {
            fail('target_bound', `statement action_hash ${hexOf(statement.action_hash)} != handed ${hexOf(target.action_hash)} `
                + '(revoke-A-presented-for-B)');
        }
    }
    const revokerId = statement.revoker_id;
    const revokerIdValid = typeof revokerId === 'string' && revokerId.length > 0;
    /** @type {{public_key?: string, key_id?: string}} */
    const pin = revokerIdValid && revokerKeys && typeof revokerKeys === 'object'
        ? revokerKeys[revokerId] || {}
        : {};
    const pinned = pin.public_key;
    const presentedKey = proof?.public_key ?? null;
    if (!revokerIdValid) {
        fail('revoker_key_pinned', 'revoker_id must be a non-empty string');
    }
    else if (!pinned) {
        fail('revoker_key_pinned', `no pinned key for revoker "${revokerId}" (identified but not trusted)`);
    }
    else if (typeof presentedKey !== 'string' || presentedKey.length === 0 || pinned !== presentedKey) {
        fail('revoker_key_pinned', `presented revoker key != pinned key for "${revokerId}" (key substitution)`);
    }
    const derivedKeyId = revokerKeyId(presentedKey);
    const proofKeyId = proof?.revoker_key_id;
    const fullProfile = FULL_REVOKER_KEY_ID.test(typeof proofKeyId === 'string' ? proofKeyId : '')
        && proofKeyId === derivedKeyId
        && (pin.key_id === undefined || pin.key_id === derivedKeyId);
    const legacyProfile = isLegacyRevokerKeyId(proofKeyId)
        && typeof presentedKey === 'string' && presentedKey.length > 0
        && pinned === presentedKey
        && (pin.key_id === undefined || pin.key_id === proofKeyId);
    if (!derivedKeyId || (!fullProfile && !legacyProfile)) {
        fail('revoker_key_bound', 'revoker_key_id must be the full SPKI digest, or a historical v1 label bound to the exact pinned SPKI');
    }
    if (proof?.algorithm !== 'Ed25519') {
        fail('revoker_signature_valid', 'revocation proof algorithm must be Ed25519');
    }
    if (statement.reason !== undefined && statement.reason !== null && typeof statement.reason !== 'string') {
        fail('signature_binds_statement', 'reason must be a string or null');
    }
    const revokedAtMs = instantMs(statement.revoked_at);
    if (!Number.isFinite(revokedAtMs)) {
        fail('revoked_at_present', 'revoked_at is absent or not a well-formed RFC 3339 instant');
    }
    const nowMs = decisionTimeMs(opts.now);
    if (!Number.isFinite(revokedAtMs) || !Number.isFinite(nowMs) || revokedAtMs > nowMs) {
        fail('effective_at_or_before_T', 'revoked_at must be a valid instant at or before the verifier decision time');
    }
    let recomputedBytes = null;
    try {
        recomputedBytes = revocationSignedPayload(statement);
    }
    catch {
        recomputedBytes = null;
    }
    const signatureB64u = proof?.signature_b64u ?? null;
    const sigBindsPinned = pinned && recomputedBytes && verifyEd25519(recomputedBytes, pinned, signatureB64u);
    if (!sigBindsPinned) {
        const verifyKey = pinned || presentedKey;
        const sigOverRecomputed = verifyKey && recomputedBytes && verifyEd25519(recomputedBytes, verifyKey, signatureB64u);
        if (!signatureB64u || !verifyKey) {
            fail('revoker_signature_valid', 'revocation proof signature or key missing');
        }
        else if (!sigOverRecomputed && isWellFormedSignature(signatureB64u)) {
            fail('signature_binds_statement', 'revoker signature does not bind the presented statement bytes (recomputed payload mismatch)');
            fail('revoker_signature_valid', 'revoker signature does not verify under the pinned revoker key over the recomputed bytes');
        }
        else if (!sigOverRecomputed) {
            fail('revoker_signature_valid', 'revoker signature does not verify under the pinned revoker key');
        }
    }
    // maxAgeSeconds is intentionally ignored. Revocation is a terminal negative
    // fact: once effective, passage of time can never turn it into acceptance.
    // Recency applies only to separately authenticated non-revocation/status
    // evidence (for example a Token Status List checkpoint).
    const valid = Object.values(checks).every(Boolean);
    return { valid, checks, errors };
}
/**
 * Convenience: is `target` revoked by ANY of the presented statements? Fail-open
 * on an EMPTY list is the relying party's hazard (absence != not-revoked); this
 * only answers "do these statements revoke it?".
 *
 * v1 ONLY, and deliberately so: it is synchronous, and ML-DSA-65 verification
 * is asynchronous. An EP-REVOCATION-v2 statement in this bag is simply not
 * revoking (its `@version` fails the v1 check), which is fail-closed. Use
 * isRevokedAny() for a bag that may contain either version.
 */
export function isRevoked(target, statements, opts = {}) {
    if (!Array.isArray(statements))
        return false;
    return statements.some((s) => verifyRevocation(target, s, opts).valid);
}
// ===========================================================================
// EP-REVOCATION-v2 -- the hybrid (Ed25519 + ML-DSA-65) revocation statement
// ===========================================================================
/**
 * REFERENCE HYBRID MIGRATION. This is the smallest complete example of adding
 * a post-quantum leg to an existing EP artifact, and it is the template the
 * remaining single-Ed25519 surfaces copy. Five moving parts, in order:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    `proof`, which is a wire-format change, so the artifact takes a new
 *    `@version` (EP-REVOCATION-v1 -> EP-REVOCATION-v2) rather than growing an
 *    optional field on v1. The v1 verifier is left untouched: verifyRevocation()
 *    above still accepts exactly the statements it accepted before, and it
 *    refuses a v2 statement on the version marker BEFORE it inspects any
 *    signature (`unsupported version: EP-REVOCATION-v2`). A deployed v1
 *    verifier must never accept a hybrid statement on the strength of the one
 *    leg it happens to understand, and it must not crash; the version marker is
 *    what guarantees both. Never reuse the v1 marker for a hybrid artifact.
 *
 * 2. SET SHAPE. `proof` carries `required_algorithms` plus a `signatures`
 *    array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }), one entry per algorithm, in the registered order.
 *    Reuse that shape verbatim; do not invent a per-artifact signature schema.
 *    Ed25519 keeps its base64url SPKI DER public key; ML-DSA-65 carries raw
 *    base64url public key bytes, because it has no SPKI encoding EP consumes.
 *
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is inside the signed
 *    bytes (revocationV2SignedPayload below). Delete the ML-DSA leg and narrow
 *    `required_algorithms` to ["Ed25519"] and the surviving Ed25519 signature
 *    no longer verifies, because the bytes changed. Leave the set intact and
 *    the missing leg is a structural refusal. This is a byte-level commitment,
 *    strictly stronger than EP-SIG-AGILITY-v1's `hybrid_all` policy alone,
 *    which the agility module honestly documents as relying-party POLICY. The
 *    verifier rebuilds the bytes from the REGISTERED set and from the fields it
 *    independently recomputed; the presented statement never gets to choose
 *    what it is checked against.
 *
 * 4. V1 COMPATIBILITY. v1 statements keep verifying, unchanged, through the
 *    unchanged sync function. v2 verification is ASYNC because ML-DSA
 *    verification is async, so it is a SEPARATE entry point rather than a
 *    signature change to the v1 function; verifyRevocationStatement() routes on
 *    `@version` for callers holding a mixed bag. Do not make the v1 verifier
 *    async: every existing caller of a sync verifier is a breaking change you
 *    do not need.
 *
 * 5. NAMED REFUSALS. Every failure path sets a named check to false and pushes
 *    a human-readable error; nothing throws on caller input, and an
 *    INDETERMINATE result never authorizes. An absent ML-DSA backend is a
 *    refusal ('pq_backend_unavailable' surfaced through the agility result),
 *    never a skipped check and never a pass on the classical leg.
 *
 * HONEST BOUNDARIES. Everything the v1 header says about this profile still
 * holds: verification proves a PRESENTED statement is authentic and binds the
 * target, never that you hold the latest revocation state. The ML-DSA backend
 * is @noble/post-quantum's pure-JS FIPS 204 implementation, which is not
 * independently audited and is not a FIPS validated module; verifying under
 * this profile is not a certification claim. And v2 does NOT retroactively
 * protect statements already issued under v1.
 */
export const REVOCATION_V2_VERSION = 'EP-REVOCATION-v2';
/** The registered required algorithm set, in canonical order. */
export const REVOCATION_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
const STATEMENT_V2_KEYS = new Set([
    '@version', 'target_type', 'target_id', 'action_hash', 'revoker_id',
    'revoked_at', 'reason', 'proof',
]);
const PROOF_V2_KEYS = new Set([
    'profile', 'required_algorithms', 'revoker_key_id', 'public_key',
    'pq_key_id', 'pq_public_key', 'signatures',
]);
function algorithmSetMatchesRegistered(algorithms) {
    return Array.isArray(algorithms)
        && algorithms.length === REVOCATION_V2_REQUIRED_ALGORITHMS.length
        && algorithms.every((a, i) => a === REVOCATION_V2_REQUIRED_ALGORITHMS[i]);
}
/**
 * The bytes BOTH legs sign. Same fixed SIGNED_FIELDS set as v1, plus the
 * `required_algorithms` set and the v2 `@version` marker, so the algorithm set
 * and the profile are cryptographically committed. Recomputed independently by
 * the verifier from the PRESENTED fields and the REGISTERED set. canonicalize()
 * sorts keys, so field order here is irrelevant.
 */
export function revocationV2SignedPayload(stmt, requiredAlgorithms = REVOCATION_V2_REQUIRED_ALGORITHMS) {
    if (!algorithmSetMatchesRegistered(requiredAlgorithms)) {
        throw new Error('revocationV2SignedPayload: algorithm set is not the registered EP-REVOCATION-v2 set');
    }
    return Buffer.from(canonicalize({
        '@version': REVOCATION_V2_VERSION,
        action_hash: stmt.action_hash ?? null,
        reason: stmt.reason ?? null,
        required_algorithms: [...requiredAlgorithms],
        revoked_at: stmt.revoked_at ?? null,
        revoker_id: stmt.revoker_id ?? null,
        target_id: stmt.target_id ?? null,
        target_type: stmt.target_type ?? null,
    }), 'utf8');
}
/**
 * verifyRevocationV2 -- FAIL-CLOSED hybrid revocation check. Never throws on
 * caller input. Every gating check must be true; any one false yields
 * valid:false, and a v2 statement NEVER verifies on one leg alone.
 */
export async function verifyRevocationV2(target, statement, opts = {}) {
    opts = opts && typeof opts === 'object' ? opts : {};
    const revokerKeys = opts.revokerKeys || {};
    const checks = {
        version: true,
        structure: true,
        target_bound: true,
        algorithm_set: true,
        legs_present: true,
        revoker_key_pinned: true,
        revoker_key_bound: true,
        revoked_at_present: true,
        effective_at_or_before_T: true,
        revoker_signature_valid: true,
        signature_binds_statement: true,
    };
    const errors = [];
    const fail = (key, msg) => { checks[key] = false; errors.push(msg); };
    const done = () => ({ valid: Object.values(checks).every(Boolean), checks, errors });
    if (!statement || typeof statement !== 'object' || Array.isArray(statement)) {
        fail('signature_binds_statement', 'no revocation statement presented (fail-closed)');
        fail('revoker_signature_valid', 'no revocation statement presented (fail-closed)');
        return done();
    }
    // 1. Version marker. A v1 statement handed to the v2 verifier refuses here,
    //    the mirror image of the v1 verifier refusing a v2 statement.
    if (statement['@version'] !== REVOCATION_V2_VERSION) {
        fail('version', `unsupported version: ${statement['@version']}`);
    }
    const proof = (statement.proof || null);
    if (!exactKeys(statement, STATEMENT_V2_KEYS) || !exactKeys(proof, PROOF_V2_KEYS)) {
        fail('structure', 'revocation statement and proof must use the exact closed EP-REVOCATION-v2 schema');
    }
    if (proof?.profile !== REVOCATION_V2_VERSION) {
        fail('structure', `revocation proof profile must be ${REVOCATION_V2_VERSION}`);
    }
    // 2. Target binding: identical to v1. Revoking A must never revoke B.
    if (!target || typeof target !== 'object' || Array.isArray(target)) {
        fail('target_bound', 'no target handed to the verifier (fail-closed)');
    }
    else {
        const heldHash = hexOf(target.action_hash);
        const statementHash = hexOf(statement.action_hash);
        if (!TARGET_TYPES.includes(target.target_type)
            || typeof target.target_id !== 'string' || target.target_id.length === 0
            || !heldHash) {
            fail('target_bound', 'handed target is incomplete or malformed');
        }
        if (!(typeof statement.target_type === 'string' && TARGET_TYPES.includes(statement.target_type))
            || typeof statement.target_id !== 'string' || statement.target_id.length === 0
            || !statementHash) {
            fail('target_bound', 'revocation statement target is incomplete or malformed');
        }
        else if (statement.target_type !== target.target_type) {
            fail('target_bound', `statement target_type "${statement.target_type}" != handed "${target.target_type}"`);
        }
        else if (statement.target_id !== target.target_id) {
            fail('target_bound', `statement target_id "${statement.target_id}" != handed "${target.target_id}"`);
        }
        else if (statementHash !== heldHash) {
            fail('target_bound', `statement action_hash ${hexOf(statement.action_hash)} != handed ${hexOf(target.action_hash)} `
                + '(revoke-A-presented-for-B)');
        }
    }
    // 3. Committed algorithm set: exact and order-sensitive. A narrowed set is
    //    the stripping attack's cover story, refused structurally here and
    //    (independently) by the signature check, which rebuilds the bytes from
    //    the REGISTERED set regardless of what the statement claims.
    if (!algorithmSetMatchesRegistered(proof?.required_algorithms)) {
        fail('algorithm_set', `proof.required_algorithms must be exactly ${JSON.stringify([...REVOCATION_V2_REQUIRED_ALGORITHMS])} (set narrowing / widening refused)`);
    }
    // 4. Exactly one signature per required algorithm.
    const signatures = Array.isArray(proof?.signatures) ? proof.signatures : null;
    if (!signatures || signatures.length === 0) {
        fail('legs_present', 'proof.signatures must carry one signature per required algorithm');
    }
    else {
        const presented = new Set();
        let malformed = false;
        for (const s of signatures) {
            if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
                fail('legs_present', 'each proof.signatures entry must be { alg, sig, key_id? }');
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
            for (const alg of REVOCATION_V2_REQUIRED_ALGORITHMS) {
                if (!presented.has(alg))
                    fail('legs_present', `missing required ${alg} signature (leg stripped)`);
            }
            for (const alg of presented) {
                if (!REVOCATION_V2_REQUIRED_ALGORITHMS.includes(alg)) {
                    fail('legs_present', `unexpected algorithm "${alg}" outside the registered set`);
                }
            }
        }
    }
    // 5. Revoker keys: BOTH halves pinned, and the presented halves must equal
    //    the pinned ones. Identified-but-not-trusted, per leg. A self-asserted,
    //    unpinned key confers NOTHING.
    const revokerId = statement.revoker_id;
    const revokerIdValid = typeof revokerId === 'string' && revokerId.length > 0;
    const pin = revokerIdValid && revokerKeys && typeof revokerKeys === 'object'
        ? revokerKeys[revokerId] || {}
        : {};
    const presentedEdKey = proof?.public_key ?? null;
    const presentedPqKey = proof?.pq_public_key ?? null;
    if (!revokerIdValid) {
        fail('revoker_key_pinned', 'revoker_id must be a non-empty string');
    }
    else if (!pin.public_key || !pin.pq_public_key) {
        fail('revoker_key_pinned', `no pinned Ed25519 + ML-DSA-65 key pair for revoker "${revokerId}" (identified but not trusted)`);
    }
    else {
        if (typeof presentedEdKey !== 'string' || presentedEdKey.length === 0 || pin.public_key !== presentedEdKey) {
            fail('revoker_key_pinned', `presented Ed25519 revoker key != pinned key for "${revokerId}" (key substitution)`);
        }
        if (typeof presentedPqKey !== 'string' || presentedPqKey.length === 0 || pin.pq_public_key !== presentedPqKey) {
            fail('revoker_key_pinned', `presented ML-DSA-65 revoker key != pinned key for "${revokerId}" (key substitution)`);
        }
    }
    // 6. Key identifiers. v2 has no historical emitters, so the digest-derived
    //    full identifier is the ONLY accepted profile; the v1 legacy label
    //    allowance is deliberately not carried forward. revokerKeyId() curve-pins
    //    the Ed25519 key, so an Ed448 (or any non-Ed25519) SPKI masquerading as
    //    the Ed25519 half fails here as well as in the signature check.
    const derivedKeyId = revokerKeyId(presentedEdKey);
    if (!derivedKeyId || proof?.revoker_key_id !== derivedKeyId
        || !FULL_REVOKER_KEY_ID.test(typeof proof?.revoker_key_id === 'string' ? proof.revoker_key_id : '')
        || (pin.key_id !== undefined && pin.key_id !== derivedKeyId)) {
        fail('revoker_key_bound', 'revoker_key_id must be the full SPKI digest of the presented Ed25519 revoker key');
    }
    const derivedPqKeyId = pqRevokerKeyId(presentedPqKey);
    if (!derivedPqKeyId || proof?.pq_key_id !== derivedPqKeyId
        || (pin.pq_key_id !== undefined && pin.pq_key_id !== derivedPqKeyId)) {
        fail('revoker_key_bound', 'pq_key_id must be the full digest of the presented ML-DSA-65 revoker key');
    }
    if (statement.reason !== undefined && statement.reason !== null && typeof statement.reason !== 'string') {
        fail('signature_binds_statement', 'reason must be a string or null');
    }
    // 7. Effective-time anchor: identical to v1. A terminal revocation never
    //    ages out; only a future effective instant is refused.
    const revokedAtMs = instantMs(statement.revoked_at);
    if (!Number.isFinite(revokedAtMs)) {
        fail('revoked_at_present', 'revoked_at is absent or not a well-formed RFC 3339 instant');
    }
    const nowMs = decisionTimeMs(opts.now);
    if (!Number.isFinite(revokedAtMs) || !Number.isFinite(nowMs) || revokedAtMs > nowMs) {
        fail('effective_at_or_before_T', 'revoked_at must be a valid instant at or before the verifier decision time');
    }
    // 8. Signature set: both legs, over bytes rebuilt from the PRESENTED fields
    //    and the REGISTERED algorithm set, under the PINNED keys. Policy
    //    'hybrid_all' with requiredAlgorithms pinned to the full set, so a
    //    missing leg is 'missing_required_algorithm' and never a pass.
    let recomputedBytes = null;
    try {
        recomputedBytes = revocationV2SignedPayload(statement, REVOCATION_V2_REQUIRED_ALGORITHMS);
    }
    catch {
        recomputedBytes = null;
    }
    if (!recomputedBytes) {
        fail('signature_binds_statement', 'revocation statement fields are not canonicalizable');
        fail('revoker_signature_valid', 'revocation statement fields are not canonicalizable');
        return done();
    }
    // Verify under the PINNED keys only. Never fall back to the proof's own
    // self-asserted key material: that is the whole point of the pin.
    const verificationKeys = [
        { alg: 'Ed25519', public_key: pin.public_key ?? '', key_id: derivedKeyId || undefined },
        { alg: 'ML-DSA-65', public_key: pin.pq_public_key ?? '', key_id: derivedPqKeyId || undefined },
    ];
    let setResult;
    try {
        setResult = await verifyAgileSignatureSet(new Uint8Array(recomputedBytes), signatures ?? [], verificationKeys, {
            ...agilityPassthrough(opts),
            policy: 'hybrid_all',
            requiredAlgorithms: [...REVOCATION_V2_REQUIRED_ALGORITHMS],
        });
    }
    catch {
        // verifyAgileSignatureSet documents that it never throws; an injected
        // backend that does is still a refusal here, never a pass.
        setResult = null;
    }
    if (setResult?.verified !== true) {
        const reason = String(setResult?.reason ?? 'signature_set_unverified');
        const failedLeg = Array.isArray(setResult?.results)
            ? setResult.results.find((r) => r?.verified !== true) ?? null
            : null;
        fail('revoker_signature_valid', `revoker signature set does not verify under the pinned Ed25519 + ML-DSA-65 keys (${reason})`);
        // A well-formed set that fails over the recomputed bytes is either forged
        // or valid over OTHER (tampered) bytes. Without the original bytes we
        // cannot tell which, so both the math and the binding are flagged, exactly
        // as v1 does.
        if (failedLeg?.reason === 'signature_invalid') {
            fail('signature_binds_statement', 'revoker signature set does not bind the presented statement bytes (recomputed payload mismatch)');
        }
    }
    return done();
}
/** ML-DSA-65 public-key identifier: the SHA-256 of the raw public key bytes. */
function pqRevokerKeyId(publicKeyRawB64u) {
    try {
        if (typeof publicKeyRawB64u !== 'string' || publicKeyRawB64u.length === 0)
            return '';
        const raw = Buffer.from(publicKeyRawB64u, 'base64url');
        if (raw.length !== ML_DSA_65_PUBLIC_KEY_BYTES || raw.toString('base64url') !== publicKeyRawB64u)
            return '';
        return `ep:revoker-key:ml-dsa-65:sha256:${crypto.createHash('sha256').update(raw).digest('hex')}`;
    }
    catch {
        return '';
    }
}
function agilityPassthrough(opts) {
    const out = {};
    if (opts.mldsaBackend !== undefined)
        out.mldsaBackend = opts.mldsaBackend;
    if (opts.mldsaBackendLoader !== undefined)
        out.mldsaBackendLoader = opts.mldsaBackendLoader;
    return out;
}
/**
 * Route a statement of EITHER version to its verifier. v1 statements keep the
 * exact v1 verdict; v2 statements get the hybrid check. A statement whose
 * `@version` is neither refuses on the version marker, through the v1 verifier,
 * which is the fail-closed answer.
 */
export async function verifyRevocationStatement(target, statement, opts = {}) {
    if (statement && typeof statement === 'object' && !Array.isArray(statement)
        && statement['@version'] === REVOCATION_V2_VERSION) {
        return verifyRevocationV2(target, statement, opts);
    }
    return verifyRevocation(target, statement, opts);
}
/**
 * Aggregate convenience over a bag that may mix v1 and v2 statements. Same
 * honest boundary as isRevoked(): `false` means "no VALID binding statement is
 * present IN THIS BAG", never "this target was never revoked anywhere".
 */
export async function isRevokedAny(target, statements, opts = {}) {
    if (!Array.isArray(statements))
        return false;
    for (const s of statements) {
        if ((await verifyRevocationStatement(target, s, opts)).valid)
            return true;
    }
    return false;
}
//# sourceMappingURL=revocation.js.map