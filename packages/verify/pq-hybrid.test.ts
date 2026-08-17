/**
 * Tests for pq-hybrid.js (EP-HYBRID-v1).
 *
 * These tests exercise REAL ML-DSA-65 via @noble/post-quantum (devDependency
 * at the repo root; resolved by Node module lookup, not a dependency of this
 * package). The suite FAILS LOUDLY if the backend is missing rather than
 * silently skipping, so a green run means the PQ leg actually ran.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import {
  HYBRID_ALG,
  HYBRID_SIGNATURE_ALGOS,
  HYBRID_REASONS,
  ML_DSA_65_SIGNATURE_BYTES,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  hybridSigningInput,
  loadDefaultMldsaBackend,
  signHybrid,
  verifyHybrid,
} from './pq-hybrid.js';

// --- fixtures ---------------------------------------------------------------

const backend = await loadDefaultMldsaBackend();
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const edPair = crypto.generateKeyPairSync('ed25519');
const edPubB64u = edPair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pqPair = ml_dsa65.keygen(crypto.randomBytes(32));

const MESSAGE = Buffer.from('checkpoint:{"tree_size":42,"root_hash":"sha256:ab"}', 'utf8');
const KEYS = { ed25519PublicKey: edPubB64u, mldsaPublicKey: pqPair.publicKey };

function flipBitB64u(b64u, byteIndex = 0) {
  const buf = Buffer.from(b64u, 'base64url');
  buf[byteIndex] ^= 0x01;
  return buf.toString('base64url');
}

async function makeEnvelope() {
  return signHybrid(MESSAGE, {
    ed25519PrivateKey: edPair.privateKey,
    mldsaSecretKey: pqPair.secretKey,
  });
}

const noBackendLoader = async () => null;

// --- backend presence (honesty gate: never silently skip) --------------------

test('real ML-DSA backend is available for this suite', () => {
  assert.ok(backend, 'expected @noble/post-quantum ml_dsa65 to be resolvable; PQ tests must run for real');
});

// --- happy path ---------------------------------------------------------------

test('valid hybrid envelope verifies (both legs real)', async () => {
  const env = await makeEnvelope();
  assert.equal(env.alg, HYBRID_ALG);
  assert.deepEqual(env.signature_algos, [...HYBRID_SIGNATURE_ALGOS]);
  const res = await verifyHybrid(MESSAGE, env, KEYS);
  assert.deepEqual(res, {
    verified: true,
    reason: null,
    checks: { envelope: true, algo_set: true, classical_signature: true, pq_signature: true },
  });
});

// --- anti-stripping ------------------------------------------------------------

test('stripping the PQ signature (sig removed, algo set intact) refuses: missing_signature', async () => {
  const env = await makeEnvelope();
  delete env.sigs['ML-DSA-65'];
  const res = await verifyHybrid(MESSAGE, env, KEYS);
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.MISSING_SIGNATURE);
});

test('stripping the PQ algo from signature_algos (classical-only presentation) refuses: algo_set_mismatch', async () => {
  const env = await makeEnvelope();
  env.signature_algos = ['Ed25519'];
  delete env.sigs['ML-DSA-65'];
  const res = await verifyHybrid(MESSAGE, env, KEYS);
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.ALGO_SET_MISMATCH);
});

test('the Ed25519 sig cryptographically commits to the algo set (core anti-stripping property)', async () => {
  const env = await makeEnvelope();
  const edSig = Buffer.from(env.sigs['Ed25519'], 'base64url');
  // The hybrid Ed25519 signature does NOT verify over the bare message...
  assert.equal(crypto.verify(null, MESSAGE, edPair.publicKey, edSig), false);
  // ...nor over a signing input committing to a REDUCED algo set...
  assert.equal(
    crypto.verify(null, hybridSigningInput(MESSAGE, ['Ed25519']), edPair.publicKey, edSig),
    false,
  );
  // ...only over the input committing to the FULL set.
  assert.equal(
    crypto.verify(null, hybridSigningInput(MESSAGE, [...HYBRID_SIGNATURE_ALGOS]), edPair.publicKey, edSig),
    true,
  );
});

test('tampered signature_algos (reorder) refuses: algo_set_mismatch', async () => {
  const env = await makeEnvelope();
  env.signature_algos = ['ML-DSA-65', 'Ed25519'];
  const res = await verifyHybrid(MESSAGE, env, KEYS);
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.ALGO_SET_MISMATCH);
});

test('tampered signature_algos (substituted algo) refuses: algo_set_mismatch', async () => {
  const env = await makeEnvelope();
  env.signature_algos = ['Ed25519', 'ML-DSA-44'];
  const res = await verifyHybrid(MESSAGE, env, KEYS);
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.ALGO_SET_MISMATCH);
});

test('extra signature entry beyond the committed set refuses: invalid_envelope', async () => {
  const env = await makeEnvelope();
  env.sigs['RSA'] = env.sigs['Ed25519'];
  const res = await verifyHybrid(MESSAGE, env, KEYS);
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.INVALID_ENVELOPE);
});

// --- bit flips ------------------------------------------------------------------

test('one flipped bit in the Ed25519 sig refuses: classical_signature_invalid', async () => {
  const env = await makeEnvelope();
  env.sigs['Ed25519'] = flipBitB64u(env.sigs['Ed25519']);
  const res = await verifyHybrid(MESSAGE, env, KEYS);
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.CLASSICAL_INVALID);
});

test('one flipped bit in the ML-DSA-65 sig refuses: pq_signature_invalid', async () => {
  const env = await makeEnvelope();
  env.sigs['ML-DSA-65'] = flipBitB64u(env.sigs['ML-DSA-65']);
  const res = await verifyHybrid(MESSAGE, env, KEYS);
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.PQ_INVALID);
});

test('tampered message refuses (classical leg fails first)', async () => {
  const env = await makeEnvelope();
  const res = await verifyHybrid(Buffer.from('other message'), env, KEYS);
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.CLASSICAL_INVALID);
});

// --- fail-closed on missing backend / missing input -------------------------------

test('no PQ backend => REFUSES with pq_backend_unavailable (never passes classical-only)', async () => {
  const env = await makeEnvelope();
  const res = await verifyHybrid(MESSAGE, env, KEYS, { mldsaBackendLoader: noBackendLoader });
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.PQ_BACKEND_UNAVAILABLE);
  assert.equal(res.checks.classical_signature, true); // classical leg was real and valid
  assert.equal(res.checks.pq_signature, null); // PQ leg was NOT evaluated, hence refusal
});

test('signHybrid with no PQ backend throws (never emits a classical-only envelope)', async () => {
  await assert.rejects(
    signHybrid(MESSAGE, { ed25519PrivateKey: edPair.privateKey, mldsaSecretKey: pqPair.secretKey },
      { mldsaBackendLoader: noBackendLoader }),
    /pq_backend_unavailable/,
  );
});

test('a mock PQ backend that always returns true still requires the classical leg', async () => {
  const env = await makeEnvelope();
  env.sigs['Ed25519'] = flipBitB64u(env.sigs['Ed25519']);
  const res = await verifyHybrid(MESSAGE, env, KEYS, { mldsaBackend: { verify: () => true } });
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.CLASSICAL_INVALID);
});

test('a mock PQ backend that always returns true still requires the algo-set match', async () => {
  const env = await makeEnvelope();
  env.signature_algos = ['Ed25519'];
  const res = await verifyHybrid(MESSAGE, env, KEYS, { mldsaBackend: { verify: () => true } });
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.ALGO_SET_MISMATCH);
});

test('missing envelope refuses: invalid_envelope', async () => {
  for (const bad of [undefined, null, 'str', [], { alg: 'EP-HYBRID-v2' }, { alg: HYBRID_ALG }]) {
    const res = await verifyHybrid(MESSAGE, bad, KEYS);
    assert.equal(res.verified, false);
    assert.equal(res.reason, HYBRID_REASONS.INVALID_ENVELOPE, `envelope=${JSON.stringify(bad)}`);
  }
});

test('missing message refuses: invalid_input', async () => {
  const env = await makeEnvelope();
  const res = await verifyHybrid(undefined, env, KEYS);
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.INVALID_INPUT);
});

test('missing key material refuses: missing_key', async () => {
  const env = await makeEnvelope();
  for (const badKeys of [undefined, {}, { ed25519PublicKey: edPubB64u }, { mldsaPublicKey: pqPair.publicKey },
    { ed25519PublicKey: 'not-a-key!!', mldsaPublicKey: pqPair.publicKey }]) {
    const res = await verifyHybrid(MESSAGE, env, badKeys);
    assert.equal(res.verified, false);
    assert.equal(res.reason, HYBRID_REASONS.MISSING_KEY);
  }
});

test('wrong ML-DSA public key refuses: pq_signature_invalid', async () => {
  const env = await makeEnvelope();
  const otherPq = ml_dsa65.keygen(crypto.randomBytes(32));
  const res = await verifyHybrid(MESSAGE, env, { ed25519PublicKey: edPubB64u, mldsaPublicKey: otherPq.publicKey });
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.PQ_INVALID);
});

// --- FINDING 1: classical leg must be pinned to Ed25519 (curve + length) -----
// Sol's exploit: forge the classical leg under a DIFFERENT EdDSA curve (Ed448),
// relabel it 'Ed25519', supply the matching Ed448 public key, and ride a valid
// ML-DSA-65 leg to verified:true. Pre-fix this returned verified:true.

test('Ed448 masquerade on the classical leg refuses: algorithm_key_mismatch (Sol exploit)', async () => {
  const env = await makeEnvelope(); // real, valid ML-DSA-65 leg
  const ed448 = crypto.generateKeyPairSync('ed448');
  const signingInput = hybridSigningInput(MESSAGE, [...HYBRID_SIGNATURE_ALGOS]);
  // A genuine Ed448 signature over the exact committed signing input.
  env.sigs['Ed25519'] = Buffer.from(crypto.sign(null, signingInput, ed448.privateKey)).toString('base64url');
  const ed448PubB64u = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const res = await verifyHybrid(MESSAGE, env, { ed25519PublicKey: ed448PubB64u, mldsaPublicKey: pqPair.publicKey });
  assert.equal(res.verified, false, 'MUST NOT verify an Ed448 leg relabeled Ed25519');
  // The curve pin fires first (114-byte sig also fails the length pin below).
  assert.equal(res.reason, HYBRID_REASONS.ALGORITHM_KEY_MISMATCH);
  assert.equal(res.checks.classical_signature, null);
});

test('an Ed448 sig padded/kept at its real 114-byte length under an Ed25519 key refuses: signature_length_invalid', async () => {
  const env = await makeEnvelope();
  const ed448 = crypto.generateKeyPairSync('ed448');
  const signingInput = hybridSigningInput(MESSAGE, [...HYBRID_SIGNATURE_ALGOS]);
  env.sigs['Ed25519'] = Buffer.from(crypto.sign(null, signingInput, ed448.privateKey)).toString('base64url');
  // Correct Ed25519 public key this time, but the 114-byte Ed448 signature
  // cannot pass the 64-byte length pin.
  const res = await verifyHybrid(MESSAGE, env, KEYS);
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.SIGNATURE_LENGTH_INVALID);
});

test('a truncated (63-byte) Ed25519 signature refuses: signature_length_invalid', async () => {
  const env = await makeEnvelope();
  const good = Buffer.from(env.sigs['Ed25519'], 'base64url');
  env.sigs['Ed25519'] = good.subarray(0, 63).toString('base64url');
  const res = await verifyHybrid(MESSAGE, env, KEYS);
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.SIGNATURE_LENGTH_INVALID);
});

test('a padded (65-byte) Ed25519 signature refuses: signature_length_invalid', async () => {
  const env = await makeEnvelope();
  const good = Buffer.from(env.sigs['Ed25519'], 'base64url');
  env.sigs['Ed25519'] = Buffer.concat([good, Buffer.from([0x00])]).toString('base64url');
  const res = await verifyHybrid(MESSAGE, env, KEYS);
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.SIGNATURE_LENGTH_INVALID);
});

test('an RSA public key pinned for the classical leg refuses: algorithm_key_mismatch', async () => {
  const env = await makeEnvelope();
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const rsaPubB64u = rsa.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const res = await verifyHybrid(MESSAGE, env, { ed25519PublicKey: rsaPubB64u, mldsaPublicKey: pqPair.publicKey });
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.ALGORITHM_KEY_MISMATCH);
});

test('a wrong-length ML-DSA-65 public key refuses: public_key_length_invalid', async () => {
  const env = await makeEnvelope();
  const short = pqPair.publicKey.subarray(0, ML_DSA_65_PUBLIC_KEY_BYTES - 1);
  const res = await verifyHybrid(MESSAGE, env, { ed25519PublicKey: edPubB64u, mldsaPublicKey: short });
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.PUBLIC_KEY_LENGTH_INVALID);
});

test('a truncated ML-DSA-65 signature refuses: signature_length_invalid', async () => {
  const env = await makeEnvelope();
  const good = Buffer.from(env.sigs['ML-DSA-65'], 'base64url');
  assert.equal(good.length, ML_DSA_65_SIGNATURE_BYTES);
  env.sigs['ML-DSA-65'] = good.subarray(0, ML_DSA_65_SIGNATURE_BYTES - 1).toString('base64url');
  const res = await verifyHybrid(MESSAGE, env, KEYS);
  assert.equal(res.verified, false);
  assert.equal(res.reason, HYBRID_REASONS.SIGNATURE_LENGTH_INVALID);
});

test('signHybrid refuses an Ed448 classical private key (never mints a mislabeled leg)', async () => {
  const ed448 = crypto.generateKeyPairSync('ed448');
  await assert.rejects(
    signHybrid(MESSAGE, { ed25519PrivateKey: ed448.privateKey, mldsaSecretKey: pqPair.secretKey }),
    /algorithm_key_mismatch/,
  );
});
