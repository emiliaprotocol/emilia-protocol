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
import { canonicalize } from '../index.js';

export const TIME_ATTESTATION_VERSION = 'EP-TIME-ATTESTATION-v1';

export interface TimeAttestation {
  '@version'?: unknown;
  ts_authority_id?: unknown;
  hashed?: unknown;
  time?: unknown;
  proof?: {
    public_key?: unknown;
    signature_b64u?: unknown;
    [key: string]: unknown;
  } | null;
  [key: string]: unknown;
}

export interface TimeAttestationOptions {
  tsaKeys?: Record<string, { public_key: string }>;
  expectedHash?: string;
  notBefore?: string | number | Date;
  notAfter?: string | number | Date;
  [key: string]: unknown;
}

export interface TimeAttestationResult {
  valid: boolean;
  checks: Record<string, boolean>;
  errors: string[];
}

// Validate to a well-formed 64-char SHA-256; malformed -> '' so comparisons
// fail closed (never match a real digest) and stay cross-language consistent. (HI-2)
const hexOf = (h: unknown): string => {
  const s = String(h ?? '').replace(/^sha256:/, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(s) ? s : '';
};

function instantMs(s: unknown): number | null {
  if (typeof s !== 'string' || s.length === 0) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

// The fixed bytes the TSA signature is bound to, recomputed independently.
function timeSignedPayload(att: TimeAttestation): Buffer {
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

function verifyEd25519(bytes: Buffer, publicKeyB64u: unknown, signatureB64u: unknown): boolean {
  try {
    if (!bytes || !publicKeyB64u || !signatureB64u) return false;
    const key = crypto.createPublicKey({ key: Buffer.from(String(publicKeyB64u), 'base64url'), format: 'der', type: 'spki' });
    return crypto.verify(null, bytes, key, Buffer.from(String(signatureB64u), 'base64url'));
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
export function verifyTimeAttestation(att: TimeAttestation | null | undefined, opts: TimeAttestationOptions = {}): TimeAttestationResult {
  opts = opts && typeof opts === 'object' ? opts : {};
  const tsaKeys = opts.tsaKeys || {};
  const checks: Record<string, boolean> = {
    version: true,
    tsa_key_pinned: true,
    time_present: true,
    signature_valid: true,
    hash_bound: true,   // vacuous unless opts.expectedHash supplied
    within_bounds: true, // vacuous unless opts.notBefore/notAfter supplied
  };
  const errors: string[] = [];
  const fail = (k: string, m: string) => { checks[k] = false; errors.push(m); };

  if (!att || typeof att !== 'object') {
    fail('signature_valid', 'no time attestation presented (fail-closed)');
    return { valid: false, checks, errors };
  }
  if (att['@version'] !== TIME_ATTESTATION_VERSION) fail('version', `unsupported version: ${att['@version']}`);

  const proof = att.proof || null;
  const authorityId = typeof att.ts_authority_id === 'string' ? att.ts_authority_id : '';
  const pinned = tsaKeys[authorityId]?.public_key;
  const presentedKey = proof?.public_key ?? null;
  if (!pinned) fail('tsa_key_pinned', `no pinned key for ts_authority "${authorityId}" (identified but not trusted)`);
  else if (presentedKey && pinned !== presentedKey) fail('tsa_key_pinned', `presented TSA key != pinned key for "${authorityId}"`);

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
