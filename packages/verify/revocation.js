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
 * well-formed revoked_at, optionally within a freshness window.
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

// Validate to a well-formed 64-char SHA-256; malformed -> '' so comparisons
// fail closed (never match a real digest) and stay cross-language consistent. (HI-2)
const hexOf = (h) => {
  const s = String(h ?? '').replace(/^sha256:/, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(s) ? s : '';
};

function instantMs(s) {
  if (typeof s !== 'string' || s.length === 0) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

// The fixed SIGNED_FIELDS set, independently recomputed by the verifier so a
// producer cannot present one set of fields while claiming a signature over
// another. Mirrors EP-REVOCATION-SPEC §3.3. canonicalize() sorts keys.
function revocationSignedPayload(stmt) {
  return Buffer.from(
    canonicalize({
      '@version': REVOCATION_VERSION,
      action_hash: stmt.action_hash ?? null,
      reason: stmt.reason ?? null,
      revoked_at: stmt.revoked_at ?? null,
      revoker_id: stmt.revoker_id ?? null,
      target_id: stmt.target_id ?? null,
      target_type: stmt.target_type ?? null,
    }),
    'utf8',
  );
}

function verifyEd25519(bytes, publicKeyB64u, signatureB64u) {
  try {
    if (!bytes || !publicKeyB64u || !signatureB64u) return false;
    const key = crypto.createPublicKey({
      key: Buffer.from(publicKeyB64u, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, bytes, key, Buffer.from(signatureB64u, 'base64url'));
  } catch {
    return false;
  }
}

function isWellFormedSignature(sigB64u) {
  try { return Buffer.from(String(sigB64u ?? ''), 'base64url').length === 64; }
  catch { return false; }
}

/**
 * @param {{target_type:string, target_id:string, action_hash:string}} target
 *   the authorization the relying party HOLDS and wants to know the status of.
 * @param {object} statement  the presented EP-REVOCATION-v1 statement.
 * @param {object} [opts]
 * @param {Object<string,{public_key:string}>} [opts.revokerKeys]  pinned keys by revoker_id.
 * @param {number} [opts.maxAgeSeconds]  freshness bound on the PRESENTED statement.
 * @param {number|string|Date} [opts.now]  reference time for freshness.
 * @returns {{valid:boolean, checks:object, errors:string[]}}
 */
export function verifyRevocation(target, statement, opts = {}) {
  const revokerKeys = opts.revokerKeys || {};
  const checks = {
    version: true,
    target_bound: true,
    revoker_key_pinned: true,
    revoked_at_present: true,
    revoker_signature_valid: true,
    signature_binds_statement: true,
    freshness: true,
  };
  const errors = [];
  const fail = (key, msg) => { checks[key] = false; errors.push(msg); };

  if (!statement || typeof statement !== 'object') {
    fail('signature_binds_statement', 'no revocation statement presented (fail-closed)');
    fail('revoker_signature_valid', 'no revocation statement presented (fail-closed)');
    return { valid: false, checks, errors };
  }

  if (statement['@version'] !== REVOCATION_VERSION) {
    fail('version', `unsupported version: ${statement['@version']}`);
  }

  if (!target || typeof target !== 'object') {
    fail('target_bound', 'no target handed to the verifier (fail-closed)');
  } else {
    if (target.target_type && !TARGET_TYPES.includes(target.target_type)) {
      fail('target_bound', `unknown target_type "${target.target_type}"`);
    }
    if (statement.target_type !== target.target_type) {
      fail('target_bound',
        `statement target_type "${statement.target_type}" != handed "${target.target_type}"`);
    }
    if (statement.target_id !== target.target_id) {
      fail('target_bound',
        `statement target_id "${statement.target_id}" != handed "${target.target_id}"`);
    } else if (hexOf(statement.action_hash) !== hexOf(target.action_hash)) {
      fail('target_bound',
        `statement action_hash ${hexOf(statement.action_hash)} != handed ${hexOf(target.action_hash)} `
        + '(revoke-A-presented-for-B)');
    }
  }

  const proof = statement.proof || null;
  const revokerId = statement.revoker_id;
  const pinned = revokerKeys[revokerId]?.public_key;
  const presentedKey = proof?.public_key ?? null;
  if (!pinned) {
    fail('revoker_key_pinned', `no pinned key for revoker "${revokerId}" (identified but not trusted)`);
  } else if (presentedKey && pinned !== presentedKey) {
    fail('revoker_key_pinned', `presented revoker key != pinned key for "${revokerId}" (key substitution)`);
  }

  const revokedAtMs = instantMs(statement.revoked_at);
  if (revokedAtMs === null) {
    fail('revoked_at_present', 'revoked_at is absent or not a well-formed RFC 3339 instant');
  }

  let recomputedBytes = null;
  try { recomputedBytes = revocationSignedPayload(statement); } catch { recomputedBytes = null; }
  const signatureB64u = proof?.signature_b64u ?? null;
  const sigBindsPinned = pinned && recomputedBytes && verifyEd25519(recomputedBytes, pinned, signatureB64u);
  if (!sigBindsPinned) {
    const verifyKey = pinned || presentedKey;
    const sigOverRecomputed = verifyKey && recomputedBytes && verifyEd25519(recomputedBytes, verifyKey, signatureB64u);
    if (!signatureB64u || !verifyKey) {
      fail('revoker_signature_valid', 'revocation proof signature or key missing');
    } else if (!sigOverRecomputed && isWellFormedSignature(signatureB64u)) {
      fail('signature_binds_statement',
        'revoker signature does not bind the presented statement bytes (recomputed payload mismatch)');
      fail('revoker_signature_valid',
        'revoker signature does not verify under the pinned revoker key over the recomputed bytes');
    } else if (!sigOverRecomputed) {
      fail('revoker_signature_valid', 'revoker signature does not verify under the pinned revoker key');
    }
  }

  if (typeof opts.maxAgeSeconds === 'number' && revokedAtMs !== null) {
    const nowMs = opts.now === undefined ? Date.now() : new Date(opts.now).getTime();
    if (!Number.isNaN(nowMs)) {
      const ageSeconds = (nowMs - revokedAtMs) / 1000;
      if (ageSeconds > opts.maxAgeSeconds) {
        fail('freshness',
          `revoked_at is ${Math.round(ageSeconds)}s old, beyond the ${opts.maxAgeSeconds}s window `
          + '(bounds a PRESENTED statement only; does not close the absence-of-statement gap)');
      }
    }
  }

  const valid = Object.values(checks).every(Boolean);
  return { valid, checks, errors };
}

/**
 * Convenience: is `target` revoked by ANY of the presented statements? Fail-open
 * on an EMPTY list is the relying party's hazard (absence != not-revoked); this
 * only answers "do these statements revoke it?".
 */
export function isRevoked(target, statements, opts = {}) {
  if (!Array.isArray(statements)) return false;
  return statements.some((s) => verifyRevocation(target, s, opts).valid);
}
