// SPDX-License-Identifier: Apache-2.0
/**
 * Tests for src/pq-signature-agility.ts (EP-SIG-AGILITY-v1).
 *
 * Exercises REAL ML-DSA-65 via @noble/post-quantum (devDependency at the repo
 * root). The suite FAILS LOUDLY if the backend is missing rather than
 * silently skipping, so a green run means the PQ leg actually ran.
 *
 * Run: npx tsx --test packages/verify/pq-signature-agility.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  AGILE_SIGNATURE_ALGORITHMS,
  AGILITY_REASONS,
  ML_DSA_65_SIGNATURE_BYTES,
  loadDefaultAgilityMldsaBackend,
  signAgile,
  signAgileSet,
  verifyAgileSignature,
  verifyAgileSignatureSet,
} from './dist/pq-signature-agility.js';
import { canonicalize } from './dist/index.js';

// --- fixtures ---------------------------------------------------------------

const backend = await loadDefaultAgilityMldsaBackend();
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const edPair = crypto.generateKeyPairSync('ed25519');
const edPubB64u = edPair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pqPair = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pqPair.publicKey).toString('base64url');

// The SAME canonical receipt bytes the existing EP-RECEIPT-v1 path signs.
const PAYLOAD = {
  action: { parameters: { amount: '100.00' }, type: 'wire.transfer.1' },
  issued_at: '2026-08-16T00:00:00Z',
  nonce: 'abc123',
};
const MESSAGE = Buffer.from(canonicalize(PAYLOAD), 'utf8');

const ED_KEY = { alg: 'Ed25519', public_key: edPubB64u, key_id: 'k-ed' };
const PQ_KEY = { alg: 'ML-DSA-65', public_key: pqPubB64u, key_id: 'k-pq' };

function flipBitB64u(b64u: string, byteIndex = 0): string {
  const buf = Buffer.from(b64u, 'base64url');
  buf[byteIndex] ^= 0x01;
  return buf.toString('base64url');
}

async function edSig() {
  return signAgile(MESSAGE, { alg: 'Ed25519', private_key: edPair.privateKey, key_id: 'k-ed' });
}
async function pqSig() {
  return signAgile(MESSAGE, { alg: 'ML-DSA-65', private_key: pqPair.secretKey, key_id: 'k-pq' });
}

const noBackendLoader = async () => null;

// --- backend presence (honesty gate: never silently skip) --------------------

test('real ML-DSA backend is available for this suite', () => {
  assert.ok(backend, 'expected @noble/post-quantum ml_dsa65 to be resolvable; PQ tests must run for real');
});

// --- happy paths -------------------------------------------------------------

test('Ed25519 signature over canonical receipt bytes verifies', async () => {
  const sig = await edSig();
  assert.equal(sig.alg, 'Ed25519');
  const r = await verifyAgileSignature(MESSAGE, sig, ED_KEY);
  assert.equal(r.verified, true);
  assert.equal(r.reason, null);
  assert.equal(r.alg, 'Ed25519');
  assert.deepEqual(r.checks, {
    algorithm_known: true, key_wellformed: true, signature_wellformed: true, signature_valid: true,
  });
});

test('ML-DSA-65 signature over the SAME canonical receipt bytes verifies', async () => {
  const sig = await pqSig();
  assert.equal(sig.alg, 'ML-DSA-65');
  assert.equal(Buffer.from(sig.sig, 'base64url').length, ML_DSA_65_SIGNATURE_BYTES);
  const r = await verifyAgileSignature(MESSAGE, sig, PQ_KEY);
  assert.equal(r.verified, true);
  assert.equal(r.checks.signature_valid, true);
});

test('deterministic ML-DSA-65 signing is reproducible', async () => {
  const a = await signAgile(MESSAGE, { alg: 'ML-DSA-65', private_key: pqPair.secretKey }, { deterministic: true });
  const b = await signAgile(MESSAGE, { alg: 'ML-DSA-65', private_key: pqPair.secretKey }, { deterministic: true });
  assert.equal(a.sig, b.sig);
  const r = await verifyAgileSignature(MESSAGE, a, PQ_KEY);
  assert.equal(r.verified, true);
});

// --- refusals: unknown algorithm never authorizes ----------------------------

test('unknown algorithm refuses with unknown_algorithm (INDETERMINATE never authorizes)', async () => {
  const sig = await edSig();
  const r = await verifyAgileSignature(MESSAGE, { ...sig, alg: 'Ed448' }, ED_KEY);
  assert.equal(r.verified, false);
  assert.equal(r.reason, AGILITY_REASONS.UNKNOWN_ALGORITHM);
  assert.equal(r.checks.algorithm_known, false);
  assert.equal(r.checks.signature_valid, null); // never even attempted
});

test('signAgile refuses to sign under an unknown algorithm', async () => {
  await assert.rejects(
    () => signAgile(MESSAGE, { alg: 'RSA-PSS', private_key: edPair.privateKey } as never),
    /unknown_algorithm/,
  );
});

// --- refusals: tampered / malformed inputs (fail-closed, no throws) ----------

test('tampered Ed25519 signature refuses with signature_invalid', async () => {
  const sig = await edSig();
  const r = await verifyAgileSignature(MESSAGE, { ...sig, sig: flipBitB64u(sig.sig) }, ED_KEY);
  assert.equal(r.verified, false);
  assert.equal(r.reason, AGILITY_REASONS.SIGNATURE_INVALID);
});

test('tampered ML-DSA-65 signature refuses with signature_invalid', async () => {
  const sig = await pqSig();
  const r = await verifyAgileSignature(MESSAGE, { ...sig, sig: flipBitB64u(sig.sig) }, PQ_KEY);
  assert.equal(r.verified, false);
  assert.equal(r.reason, AGILITY_REASONS.SIGNATURE_INVALID);
});

test('tampered message bytes refuse under BOTH algorithms', async () => {
  const tampered = Buffer.from(canonicalize({ ...PAYLOAD, nonce: 'abc124' }), 'utf8');
  const rEd = await verifyAgileSignature(tampered, await edSig(), ED_KEY);
  const rPq = await verifyAgileSignature(tampered, await pqSig(), PQ_KEY);
  assert.equal(rEd.verified, false);
  assert.equal(rPq.verified, false);
});

test('malformed signature material refuses with malformed_signature', async () => {
  for (const bad of ['', 'not base64url!!', 'AAAA' /* wrong length */]) {
    const r = await verifyAgileSignature(MESSAGE, { alg: 'Ed25519', sig: bad }, ED_KEY);
    assert.equal(r.verified, false);
    assert.equal(r.reason, AGILITY_REASONS.MALFORMED_SIGNATURE, `sig=${JSON.stringify(bad)}`);
  }
});

test('malformed key material refuses with malformed_key', async () => {
  const sig = await edSig();
  const r = await verifyAgileSignature(MESSAGE, sig, { alg: 'Ed25519', public_key: 'AAAA' });
  assert.equal(r.verified, false);
  assert.equal(r.reason, AGILITY_REASONS.MALFORMED_KEY);

  const pq = await pqSig();
  const r2 = await verifyAgileSignature(MESSAGE, pq, { alg: 'ML-DSA-65', public_key: new Uint8Array(10) });
  assert.equal(r2.verified, false);
  assert.equal(r2.reason, AGILITY_REASONS.MALFORMED_KEY);
});

test('a non-Ed25519 SPKI key pinned for Ed25519 refuses (curve pin)', async () => {
  const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const ecSpki = ec.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const r = await verifyAgileSignature(MESSAGE, await edSig(), { alg: 'Ed25519', public_key: ecSpki });
  assert.equal(r.verified, false);
  assert.equal(r.reason, AGILITY_REASONS.MALFORMED_KEY);
});

test('algorithm/key mismatch refuses without verifying anything', async () => {
  const sig = await edSig();
  const r = await verifyAgileSignature(MESSAGE, sig, PQ_KEY);
  assert.equal(r.verified, false);
  assert.equal(r.reason, AGILITY_REASONS.ALGORITHM_KEY_MISMATCH);
  assert.equal(r.checks.signature_valid, null);
});

test('missing ML-DSA backend is a refusal, never a pass or a skip', async () => {
  const sig = await pqSig();
  const r = await verifyAgileSignature(MESSAGE, sig, PQ_KEY, { mldsaBackendLoader: noBackendLoader });
  assert.equal(r.verified, false);
  assert.equal(r.reason, AGILITY_REASONS.PQ_BACKEND_UNAVAILABLE);
});

// --- hybrid set --------------------------------------------------------------

test('hybrid_all: both algorithms over the same bytes verify', async () => {
  const sigs = await signAgileSet(MESSAGE, [
    { alg: 'Ed25519', private_key: edPair.privateKey, key_id: 'k-ed' },
    { alg: 'ML-DSA-65', private_key: pqPair.secretKey, key_id: 'k-pq' },
  ]);
  const r = await verifyAgileSignatureSet(MESSAGE, sigs, [ED_KEY, PQ_KEY], { policy: 'hybrid_all' });
  assert.equal(r.verified, true);
  assert.equal(r.results.length, 2);
  assert.ok(r.results.every((x) => x.verified === true));
});

test('hybrid_all: stripping the PQ leg refuses (required set defaults to full registry)', async () => {
  const r = await verifyAgileSignatureSet(MESSAGE, [await edSig()], [ED_KEY, PQ_KEY], { policy: 'hybrid_all' });
  assert.equal(r.verified, false);
  assert.equal(r.reason, AGILITY_REASONS.MISSING_REQUIRED_ALGORITHM);
});

test('hybrid_all: one tampered leg fails the whole set, reason names the algorithm', async () => {
  const ed = await edSig();
  const pq = await pqSig();
  const r = await verifyAgileSignatureSet(
    MESSAGE, [ed, { ...pq, sig: flipBitB64u(pq.sig) }], [ED_KEY, PQ_KEY], { policy: 'hybrid_all' },
  );
  assert.equal(r.verified, false);
  assert.equal(r.reason, `ML-DSA-65:${AGILITY_REASONS.SIGNATURE_INVALID}`);
  // per-algorithm results are still reported, never collapsed
  assert.equal(r.results.find((x) => x.alg === 'Ed25519')?.verified, true);
  assert.equal(r.results.find((x) => x.alg === 'ML-DSA-65')?.verified, false);
});

test('per_algorithm: top-level verdict is null and per-alg verdicts stay separate', async () => {
  const pq = await pqSig();
  const r = await verifyAgileSignatureSet(
    MESSAGE, [await edSig(), { ...pq, sig: flipBitB64u(pq.sig) }], [ED_KEY, PQ_KEY], { policy: 'per_algorithm' },
  );
  assert.equal(r.verified, null); // null never authorizes
  assert.equal(r.results.find((x) => x.alg === 'Ed25519')?.verified, true);
  assert.equal(r.results.find((x) => x.alg === 'ML-DSA-65')?.verified, false);
});

test('duplicate presented algorithm refuses', async () => {
  const s = await edSig();
  const r = await verifyAgileSignatureSet(MESSAGE, [s, s], [ED_KEY, PQ_KEY]);
  assert.equal(r.verified, false);
  assert.equal(r.reason, AGILITY_REASONS.DUPLICATE_ALGORITHM);
});

test('empty signature set and unknown policy refuse', async () => {
  const r1 = await verifyAgileSignatureSet(MESSAGE, [], [ED_KEY]);
  assert.equal(r1.reason, AGILITY_REASONS.EMPTY_SIGNATURE_SET);
  const r2 = await verifyAgileSignatureSet(MESSAGE, [await edSig()], [ED_KEY], { policy: 'any_of' as never });
  assert.equal(r2.verified, false);
  assert.equal(r2.reason, AGILITY_REASONS.UNKNOWN_POLICY);
});

// --- conformance vectors (executed, not described) ---------------------------

test('conformance/pq-agility/vectors.json verifies exactly as recorded', async () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const vectorsPath = path.join(here, '..', '..', 'conformance', 'pq-agility', 'vectors.json');
  const doc = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));
  assert.equal(doc['@version'], 'EP-SIG-AGILITY-VECTORS-v1');

  // The recorded canonical bytes are exactly what canonicalize() yields today,
  // and both algorithms sign those SAME bytes.
  const canonical = canonicalize(doc.payload);
  assert.equal(canonical, doc.canonical_payload);
  const message = Buffer.from(canonical, 'utf8');
  assert.equal(
    crypto.createHash('sha256').update(message).digest('hex'),
    doc.canonical_payload_sha256,
  );

  const keys = [doc.keys.ed25519, doc.keys.ml_dsa_65];
  for (const v of doc.vectors) {
    if (v.kind === 'single') {
      const key = keys.find((k) => k.alg === v.signature.alg) ?? doc.keys.ed25519;
      const r = await verifyAgileSignature(message, v.signature, key);
      assert.equal(r.verified, v.expect.verified, `vector ${v.id}`);
      if (v.expect.reason !== undefined) assert.equal(r.reason, v.expect.reason, `vector ${v.id}`);
    } else {
      const r = await verifyAgileSignatureSet(message, v.signatures, keys, { policy: v.policy });
      assert.equal(r.verified, v.expect.verified, `vector ${v.id}`);
      if (v.expect.reason !== undefined && v.expect.reason !== null) {
        assert.equal(r.reason, v.expect.reason, `vector ${v.id}`);
      }
      if (v.expect.per_algorithm) {
        for (const [alg, want] of Object.entries(v.expect.per_algorithm)) {
          assert.equal(r.results.find((x) => x.alg === alg)?.verified, want, `vector ${v.id} ${alg}`);
        }
      }
    }
  }
});

test('registry is closed: exactly Ed25519 and ML-DSA-65', () => {
  assert.deepEqual([...AGILE_SIGNATURE_ALGORITHMS], ['Ed25519', 'ML-DSA-65']);
});
