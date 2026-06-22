// SPDX-License-Identifier: Apache-2.0
/**
 * EP-EVIDENCE-RECORD-v1 — long-term, crypto-agile preservation of an EP artifact.
 *
 * EP receipts must "verify years — even decades — later," and government
 * retention is 10-25+ years (see the GAGAS / Uniform Guidance mapping). But any
 * fixed algorithm (Ed25519, SHA-256) weakens over that horizon. Following the
 * approach of RFC 4998 (Evidence Record Syntax), an evidence record preserves a
 * protected artifact's non-repudiation across algorithm aging by a CHAIN of
 * renewals: each renewal re-timestamps the *previous* attestation under a fresh
 * (possibly stronger) hash, BEFORE the older algorithm is broken. Verifying the
 * chain proves the artifact has been continuously, independently time-anchored
 * from its first attestation to the latest renewal.
 *
 * Each renewal is an EP-TIME-ATTESTATION-v1 (already offline, asymmetric,
 * pinned-TSA, tri-language). This composes that verifier and adds the
 * hash-linkage between renewals.
 *
 *   { "@version": "EP-EVIDENCE-RECORD-v1",
 *     protected_hash: "sha256:<hex>",        // hash of the protected artifact (e.g. a receipt)
 *     archive_timestamps: [
 *       { time_attestation: <EP-TIME-ATTESTATION-v1> },   // [0] covers protected_hash
 *       { time_attestation: <EP-TIME-ATTESTATION-v1> },   // [i] covers hash(prior attestation), agile alg
 *       ...
 *     ] }
 *
 * FAIL-CLOSED. HONEST BOUNDARY: this proves the artifact was continuously
 * time-anchored by pinned authorities; it does not prove the artifact was
 * *correct*, nor that a renewal happened before a given algorithm actually broke
 * (that is an operational discipline the chain records, not one it can divine).
 */
import crypto from 'node:crypto';
import { canonicalize, verifyTimeAttestation } from './index.js';

export const EVIDENCE_RECORD_VERSION = 'EP-EVIDENCE-RECORD-v1';
const SUPPORTED_HASH = new Set(['sha256', 'sha384', 'sha512']);

// Parse "sha384:<hex>" (or bare hex, defaulting to sha256) -> { alg, hex }.
function algOf(hashed) {
  const s = String(hashed ?? '');
  const i = s.indexOf(':');
  if (i < 0) return { alg: 'sha256', hex: s.toLowerCase() };
  return { alg: s.slice(0, i).toLowerCase(), hex: s.slice(i + 1).toLowerCase() };
}

function hashHexWith(alg, bytes) {
  return crypto.createHash(alg).update(bytes).digest('hex');
}

/**
 * @param {object} record  the EP-EVIDENCE-RECORD-v1 document.
 * @param {object} [opts]
 * @param {Object<string,{public_key:string}>} [opts.tsaKeys]  pinned TSA keys by ts_authority_id.
 * @param {string} [opts.protectedHash]  the hash of the artifact the relying party HOLDS; binds the record to it.
 * @returns {{valid:boolean, checks:object, errors:string[], protected_since?:string, last_renewed?:string}}
 */
export function verifyEvidenceRecord(record, opts = {}) {
  const tsaKeys = opts.tsaKeys || {};
  const checks = {
    version: false,
    protected_bound: true,      // record.protected_hash == opts.protectedHash (vacuous if not supplied)
    chain_nonempty: false,
    all_timestamps_valid: true, // every renewal's TSA attestation verifies
    chain_linked: true,         // ts[0] covers protected_hash; ts[i] covers hash(prior attestation)
    monotonic_time: true,       // renewal times strictly increase
  };
  const errors = [];
  const fail = (k, m) => { checks[k] = false; errors.push(m); };

  try {
    if (record?.['@version'] !== EVIDENCE_RECORD_VERSION) {
      errors.push(`unsupported version: ${record?.['@version']}`);
      return { valid: false, checks, errors };
    }
    checks.version = true;

    const ats = Array.isArray(record.archive_timestamps) ? record.archive_timestamps : [];
    checks.chain_nonempty = ats.length > 0;
    if (!checks.chain_nonempty) {
      errors.push('no archive timestamps');
      return { valid: false, checks, errors };
    }

    if (typeof opts.protectedHash === 'string') {
      if (algOf(record.protected_hash).hex !== algOf(opts.protectedHash).hex) {
        fail('protected_bound', 'record protected_hash does not match the supplied artifact hash');
      }
    }

    let prevTime = null;
    let firstTime = null;
    for (let i = 0; i < ats.length; i++) {
      const ta = ats[i]?.time_attestation;
      const r = verifyTimeAttestation(ta, { tsaKeys });
      if (!r.valid) fail('all_timestamps_valid', `archive timestamp ${i} TSA attestation does not verify`);

      const cur = algOf(ta?.hashed);
      if (i === 0) {
        if (cur.hex !== algOf(record.protected_hash).hex) {
          fail('chain_linked', 'first archive timestamp does not cover protected_hash');
        }
      } else if (!SUPPORTED_HASH.has(cur.alg)) {
        fail('chain_linked', `renewal ${i} uses an unsupported hash algorithm "${cur.alg}"`);
      } else {
        const expected = hashHexWith(cur.alg, Buffer.from(canonicalize(ats[i - 1].time_attestation), 'utf8'));
        if (cur.hex !== expected) fail('chain_linked', `renewal ${i} does not cover the previous attestation`);
      }

      const t = Date.parse(ta?.time ?? '');
      if (Number.isNaN(t)) {
        fail('monotonic_time', `archive timestamp ${i} has no parseable time`);
      } else {
        if (prevTime !== null && !(t > prevTime)) fail('monotonic_time', `renewal ${i} time is not after the previous`);
        if (firstTime === null) firstTime = ta?.time;
        prevTime = t;
      }
    }

    const valid = Object.values(checks).every(Boolean);
    const last = ats[ats.length - 1]?.time_attestation?.time;
    return { valid, checks, errors, protected_since: firstTime, last_renewed: last };
  } catch {
    return { valid: false, checks, errors };
  }
}
