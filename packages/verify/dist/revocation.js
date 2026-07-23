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
 */
export function isRevoked(target, statements, opts = {}) {
    if (!Array.isArray(statements))
        return false;
    return statements.some((s) => verifyRevocation(target, s, opts).valid);
}
//# sourceMappingURL=revocation.js.map