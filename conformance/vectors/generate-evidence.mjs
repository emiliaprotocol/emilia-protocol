// SPDX-License-Identifier: Apache-2.0
// Generator for executable EP-EVIDENCE-RECORD-v1 conformance vectors. Builds REAL
// renewal chains: each archive timestamp is an Ed25519-signed EP-TIME-ATTESTATION-v1,
// and renewals re-timestamp the prior attestation under a STRONGER hash (sha256 ->
// sha384) — the crypto-agility property. JS, Python, Go verify identically.
// Run: node generate-evidence.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';

const canon = (v) => v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v);
const hashHex = (alg, s) => crypto.createHash(alg).update(s, 'utf8').digest('hex');

const TV = 'EP-TIME-ATTESTATION-v1';
const EV = 'EP-EVIDENCE-RECORD-v1';
const TSA = 'ep:tsa:roughtime-1';

function newSigner() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
// A TSA-signed time attestation over `hashed` at `time`.
function timeAtt(signer, hashed, time) {
  const signed = { '@version': TV, hashed, time, ts_authority_id: TSA };
  return {
    '@version': TV, ts_authority_id: TSA, hashed, time,
    proof: { algorithm: 'Ed25519', ts_key_id: 'tk1', public_key: signer.pub, signature_b64u: crypto.sign(null, Buffer.from(canon(signed), 'utf8'), signer.privateKey).toString('base64url') },
  };
}
const pin = (s) => ({ [TSA]: { public_key: s.pub } });
const t = (m) => `2026-06-2${m}T12:00:00.000Z`; // distinct increasing days

// Build a 2-link record: ts0 covers protected_hash (sha256); ts1 re-timestamps
// ts0 under sha384. Optionally bend one thing for a negative.
/**
 * @param {{ privateKey: crypto.KeyObject, pub: string }} signer
 * @param {{ renewalHashed?: string|null, t0?: string, t1?: string }} [options]
 */
function record(signer, { renewalHashed = null, t0 = t(0), t1 = t(1) } = {}) {
  const PROTECTED = 'sha256:' + 'ab'.repeat(32);
  const ts0 = timeAtt(signer, PROTECTED, t0);
  const renew = renewalHashed !== null ? renewalHashed : 'sha384:' + hashHex('sha384', canon(ts0));
  const ts1 = timeAtt(signer, renew, t1);
  return { rec: { '@version': EV, protected_hash: PROTECTED, archive_timestamps: [{ time_attestation: ts0 }, { time_attestation: ts1 }] }, PROTECTED };
}

const V = [];
const add = (id, expectValid, vec) => V.push({ id, expect: { valid: expectValid }, ...vec });

{ const s = newSigner(); const { rec, PROTECTED } = record(s); add('accept_two_link_sha256_then_sha384', true, { evidence_record: rec, tsa_keys: pin(s), protected_hash: PROTECTED }); }
{ const s = newSigner(); const { rec, PROTECTED } = record(s, { renewalHashed: 'sha384:' + '0'.repeat(96) }); add('reject_broken_renewal', false, { evidence_record: rec, tsa_keys: pin(s), protected_hash: PROTECTED }); }
{ const s = newSigner(); const { rec, PROTECTED } = record(s); add('reject_unpinned_tsa', false, { evidence_record: rec, tsa_keys: {}, protected_hash: PROTECTED }); }
{ const s = newSigner(); const { rec } = record(s); add('reject_protected_mismatch', false, { evidence_record: rec, tsa_keys: pin(s), protected_hash: 'sha256:' + 'cd'.repeat(32) }); }
{ const s = newSigner(); const { rec, PROTECTED } = record(s, { t0: t(3), t1: t(1) }); add('reject_non_monotonic_time', false, { evidence_record: rec, tsa_keys: pin(s), protected_hash: PROTECTED }); }

const suite = {
  suite: 'EP-EVIDENCE-RECORD-v1',
  profile: 'Executable long-term evidence-record vectors (RFC 4998-style renewal chain; real Ed25519 TSA attestations; sha256 then sha384). verifyEvidenceRecord(record, {tsaKeys, protectedHash}) must return expect.valid.',
  vectors_version: '1.0.0',
  count: V.length,
  vectors: V,
};
writeFileSync(new URL('./evidence-record.v1.json', import.meta.url), JSON.stringify(suite, null, 2) + '\n');
console.log(`wrote evidence-record.v1.json — ${V.length} vectors`);
