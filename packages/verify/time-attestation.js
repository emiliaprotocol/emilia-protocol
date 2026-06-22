// SPDX-License-Identifier: Apache-2.0
/**
 * EP-TIME-ATTESTATION-v1 — independent, offline-verifiable proof of WHEN.
 *
 * An EP signoff's `issued_at` is asserted by whoever stamped it. For the
 * absolute time of a signoff or receipt to be trustworthy to a third party, an
 * INDEPENDENT timestamping authority (TSA) — a party EP identifies but does not
 * trust — signs over (the hash of) the artifact plus the time. This is the
 * trusted-time analogue of everything else in EP: ASYMMETRIC, key-PINNED,
 * fail-closed. It composes with the strong ordered chain (which already proves
 * relative ORDER cryptographically): the chain proves sequence, a time
 * attestation bounds the absolute instant.
 *
 *   { "@version": "EP-TIME-ATTESTATION-v1",
 *     ts_authority_id: "ep:tsa:...",
 *     hashed: "sha256:<hex>",          // the artifact this attestation timestamps
 *     time:   "<RFC 3339>",            // the attested instant
 *     proof:  { algorithm:"Ed25519", ts_key_id, signature_b64u, public_key } }
 *
 * verifyTimeAttestation(att, opts) is FAIL-CLOSED: it accepts only when the
 * version matches, the TSA is PINNED (opts.tsaKeys[ts_authority_id], and the
 * proof key equals the pinned key), the Ed25519 proof verifies over the
 * verifier-recomputed canonical bytes, the time is a well-formed instant, and
 * (when supplied) the attested `hashed` equals opts.expectedHash and the time
 * falls within [opts.notBefore, opts.notAfter].
 *
 * HONEST BOUNDARY: this proves an independent authority attested this exact
 * content existed at time T. It does not prove the TSA's clock was correct, nor
 * that no EARLIER attestation exists. It bounds, it does not divine.
 */
import crypto from 'node:crypto';
import { canonicalize } from './index.js';

export const TIME_ATTESTATION_VERSION = 'EP-TIME-ATTESTATION-v1';

const hexOf = (h) => String(h ?? '').replace(/^sha256:/, '').toLowerCase();

function instantMs(s) {
  if (typeof s !== 'string' || s.length === 0) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

// The fixed bytes the TSA signature is bound to, recomputed independently.
function timeSignedPayload(att) {
  return Buffer.from(
    canonicalize({
      '@version': TIME_ATTESTATION_VERSION,
      hashed: att.hashed ?? null,
      time: att.time ?? null,
      ts_authority_id: att.ts_authority_id ?? null,
    }),
    'utf8',
  );
}

function verifyEd25519(bytes, publicKeyB64u, signatureB64u) {
  try {
    if (!bytes || !publicKeyB64u || !signatureB64u) return false;
    const key = crypto.createPublicKey({ key: Buffer.from(publicKeyB64u, 'base64url'), format: 'der', type: 'spki' });
    return crypto.verify(null, bytes, key, Buffer.from(signatureB64u, 'base64url'));
  } catch {
    return false;
  }
}

/**
 * @param {object} att  the EP-TIME-ATTESTATION-v1 statement.
 * @param {object} [opts]
 * @param {Object<string,{public_key:string}>} [opts.tsaKeys]  pinned TSA keys by ts_authority_id.
 * @param {string} [opts.expectedHash]  the artifact hash this attestation MUST cover.
 * @param {string|number|Date} [opts.notBefore]  attested time must be >= this.
 * @param {string|number|Date} [opts.notAfter]   attested time must be <= this.
 * @returns {{valid:boolean, checks:object, errors:string[]}}
 */
export function verifyTimeAttestation(att, opts = {}) {
  const tsaKeys = opts.tsaKeys || {};
  const checks = {
    version: true,
    tsa_key_pinned: true,
    time_present: true,
    signature_valid: true,
    hash_bound: true,   // vacuous unless opts.expectedHash supplied
    within_bounds: true, // vacuous unless opts.notBefore/notAfter supplied
  };
  const errors = [];
  const fail = (k, m) => { checks[k] = false; errors.push(m); };

  if (!att || typeof att !== 'object') {
    fail('signature_valid', 'no time attestation presented (fail-closed)');
    return { valid: false, checks, errors };
  }
  if (att['@version'] !== TIME_ATTESTATION_VERSION) fail('version', `unsupported version: ${att['@version']}`);

  const proof = att.proof || null;
  const pinned = tsaKeys[att.ts_authority_id]?.public_key;
  const presentedKey = proof?.public_key ?? null;
  if (!pinned) fail('tsa_key_pinned', `no pinned key for ts_authority "${att.ts_authority_id}" (identified but not trusted)`);
  else if (presentedKey && pinned !== presentedKey) fail('tsa_key_pinned', `presented TSA key != pinned key for "${att.ts_authority_id}"`);

  const ms = instantMs(att.time);
  if (ms === null) fail('time_present', 'time is absent or not a well-formed RFC 3339 instant');

  const sigOk = pinned && verifyEd25519(timeSignedPayload(att), pinned, proof?.signature_b64u);
  if (!sigOk) fail('signature_valid', 'TSA signature does not verify under the pinned key over the recomputed bytes');

  if (typeof opts.expectedHash === 'string') {
    if (hexOf(att.hashed) !== hexOf(opts.expectedHash)) {
      fail('hash_bound', `attestation hashed ${hexOf(att.hashed)} != expected ${hexOf(opts.expectedHash)}`);
    }
  }

  if (ms !== null) {
    const nb = opts.notBefore === undefined ? null : new Date(opts.notBefore).getTime();
    const na = opts.notAfter === undefined ? null : new Date(opts.notAfter).getTime();
    if (nb !== null && !Number.isNaN(nb) && ms < nb) fail('within_bounds', 'attested time is before notBefore');
    if (na !== null && !Number.isNaN(na) && ms > na) fail('within_bounds', 'attested time is after notAfter');
  }

  const valid = Object.values(checks).every(Boolean);
  return { valid, checks, errors };
}
