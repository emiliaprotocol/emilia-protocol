// SPDX-License-Identifier: Apache-2.0
//
// EP-TIME-ATTESTATION-v1 verifier test. Builds a REAL Ed25519-signed time
// attestation and asserts the fail-closed predicate: accept the authentic,
// pinned, hash- and bounds-matching attestation; reject an unpinned TSA, a key
// substitution, a tampered time, a wrong covered hash, and an out-of-bounds time.
import { test } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { canonicalize } from './index.js';
import { verifyTimeAttestation, TIME_ATTESTATION_VERSION } from './time-attestation.js';

const HASH = 'sha256:' + 'c'.repeat(64);
const TSA = 'ep:tsa:roughtime-1';
const TIME = '2026-06-20T12:00:00.000Z';

function newSigner() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, publicKeyB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
function build({ time = TIME, hashed = HASH, signer }) {
  const payload = canonicalize({ '@version': TIME_ATTESTATION_VERSION, hashed, time, ts_authority_id: TSA });
  return {
    '@version': TIME_ATTESTATION_VERSION, ts_authority_id: TSA, hashed, time,
    proof: { algorithm: 'Ed25519', ts_key_id: 'tk1', public_key: signer.publicKeyB64u, signature_b64u: crypto.sign(null, Buffer.from(payload, 'utf8'), signer.privateKey).toString('base64url') },
  };
}
const pin = (s) => ({ tsaKeys: { [TSA]: { public_key: s.publicKeyB64u } } });

test('accepts authentic, pinned, hash- and bounds-matching attestation', () => {
  const s = newSigner();
  const r = verifyTimeAttestation(build({ signer: s }), { ...pin(s), expectedHash: HASH, notBefore: '2026-06-01T00:00:00Z', notAfter: '2026-07-01T00:00:00Z' });
  assert.strictEqual(r.valid, true, JSON.stringify(r.errors));
});

test('rejects an unpinned TSA', () => {
  const s = newSigner();
  const r = verifyTimeAttestation(build({ signer: s }), {});
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.tsa_key_pinned, false);
});

test('rejects key substitution', () => {
  const s = newSigner(); const other = newSigner();
  const r = verifyTimeAttestation(build({ signer: s }), { tsaKeys: { [TSA]: { public_key: other.publicKeyB64u } } });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.tsa_key_pinned, false);
});

test('rejects a tampered time (signature no longer binds)', () => {
  const s = newSigner();
  const att = build({ signer: s });
  att.time = '2030-01-01T00:00:00.000Z';
  const r = verifyTimeAttestation(att, pin(s));
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.signature_valid, false);
});

test('rejects when the covered hash is not the expected artifact', () => {
  const s = newSigner();
  const r = verifyTimeAttestation(build({ signer: s }), { ...pin(s), expectedHash: 'sha256:' + 'd'.repeat(64) });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.hash_bound, false);
});

test('rejects an out-of-bounds time', () => {
  const s = newSigner();
  const r = verifyTimeAttestation(build({ signer: s }), { ...pin(s), notAfter: '2026-06-01T00:00:00Z' });
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.checks.within_bounds, false);
});
