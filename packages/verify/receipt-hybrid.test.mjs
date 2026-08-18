// SPDX-License-Identifier: Apache-2.0
//
// EP-RECEIPT-HYBRID-v1 / EP-LOG-CHECKPOINT-HYBRID-v1 verifier tests.
//
// Real Ed25519 + real ML-DSA-65 signatures throughout. The hostile half is the
// point: leg stripping, set narrowing, wrong-length signatures, an Ed448 key
// masquerading as the Ed25519 half, algorithm relabelling, payload tampering,
// smuggled unsigned members, a missing PQ backend, and a v1 verifier handed a
// hybrid receipt.
//
// The PQ leg runs for real. This suite FAILS LOUDLY if @noble/post-quantum is
// missing rather than silently skipping, so a green run means ML-DSA-65
// actually verified.
//
// It is written as .test.mjs deliberately: it needs no generated Node-20
// companion, so it adds nothing to the checked-in generated-twin set.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

import {
  HYBRID_RECEIPT_PROFILE,
  HYBRID_RECEIPT_REQUIRED_ALGORITHMS,
  HYBRID_RECEIPT_REASONS,
  hybridReceiptSignedBytes,
  verifyHybridReceipt,
  verifyReceiptOfAnyProfile,
  LOG_CHECKPOINT_HYBRID_PROFILE,
  LOG_CHECKPOINT_HYBRID_REQUIRED_ALGORITHMS,
  LOG_CHECKPOINT_HYBRID_REASONS,
  logCheckpointHybridSignedBytes,
  logCheckpointSignedFields,
  verifyLogCheckpointHybridProof,
} from './receipt-hybrid.js';
import { verifyReceipt, canonicalize } from './index.js';
import { signAgileSet, verifyAgileSignature } from './pq-signature-agility.js';
// The ISSUING package's own byte builder. Importing it here is the whole point
// of the cross-package test below: if these two ever disagree, a receipt this
// repository issues stops verifying with the verifier this repository
// publishes, and no amount of per-package green would show it.
import { hybridSignedBytes, createHybridReceipt } from '../issue/hybrid-issuance.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const KEYS = {
  ed25519PublicKey: edPubB64u,
  ed25519KeyId: 'ep:key:hybrid-issuer-ed25519#1',
  mldsaPublicKey: pqPubB64u,
  mldsaKeyId: 'ep:key:hybrid-issuer-ml-dsa-65#1',
};

const PAYLOAD = {
  receipt_id: 'ep:receipt:hybrid-test-1',
  action_hash: `sha256:${'a'.repeat(64)}`,
  claim: { action_type: 'payment.send', outcome: 'authorized' },
  issued_at: '2026-08-17T12:00:00Z',
};

const clone = (v) => JSON.parse(JSON.stringify(v));

/** Mint a REAL hybrid receipt; overrides let a test tamper AFTER signing. */
async function buildReceipt({ payload = PAYLOAD, requiredAlgorithms = [...HYBRID_RECEIPT_REQUIRED_ALGORITHMS] } = {}) {
  const messageBytes = hybridReceiptSignedBytes(payload, requiredAlgorithms);
  const signatures = await signAgileSet(new Uint8Array(messageBytes), [
    { alg: 'Ed25519', private_key: ed.privateKey, key_id: KEYS.ed25519KeyId },
    { alg: 'ML-DSA-65', private_key: pq.secretKey, key_id: KEYS.mldsaKeyId },
  ]);
  return {
    '@version': HYBRID_RECEIPT_PROFILE,
    profile: { id: HYBRID_RECEIPT_PROFILE, required_algorithms: [...requiredAlgorithms] },
    payload,
    signatures,
  };
}

// ===========================================================================
// Cross-package byte compatibility -- the contract this module lives or dies by
// ===========================================================================

test('the verifier rebuilds byte-identical signed material to the ISSUER package', () => {
  const mine = hybridReceiptSignedBytes(PAYLOAD);
  const theirs = hybridSignedBytes(PAYLOAD);
  assert.ok(mine.equals(theirs),
    'packages/verify hybridReceiptSignedBytes must equal packages/issue hybridSignedBytes');
  // Assert the SHAPE too, not just equality, so a future change that breaks
  // both together still trips a test.
  assert.equal(mine.toString('utf8'), canonicalize({
    '@version': HYBRID_RECEIPT_PROFILE,
    payload: PAYLOAD,
    required_algorithms: ['Ed25519', 'ML-DSA-65'],
  }));
});

test('the two packages agree on the registered algorithm set', () => {
  assert.deepEqual([...HYBRID_RECEIPT_REQUIRED_ALGORITHMS], ['Ed25519', 'ML-DSA-65']);
  assert.deepEqual([...LOG_CHECKPOINT_HYBRID_REQUIRED_ALGORITHMS], ['Ed25519', 'ML-DSA-65']);
});

test('a receipt minted by the ISSUER verifies under the published verifier', async () => {
  const bundleSeed = new Uint8Array(crypto.createHash('sha256').update('receipt-hybrid.test/seed').digest());
  const issuerPq = ml_dsa65.keygen(bundleSeed);
  const issuerEd = crypto.generateKeyPairSync('ed25519');
  const doc = await createHybridReceipt({
    payload: PAYLOAD,
    keys: {
      ed25519PrivateKey: issuerEd.privateKey,
      ed25519KeyId: 'ep:key:issuer-ed#1',
      mldsaSecretKey: Buffer.from(issuerPq.secretKey).toString('base64url'),
      mldsaKeyId: 'ep:key:issuer-pq#1',
    },
  });
  const result = await verifyHybridReceipt(doc, {
    ed25519PublicKey: issuerEd.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
    mldsaPublicKey: Buffer.from(issuerPq.publicKey).toString('base64url'),
  });
  assert.equal(result.verified, true, `expected verified, got ${result.reason}`);
});

// The frozen public vectors carry an EXPECTED {verified, reason,
// failed_algorithm} per case, captured from the issuing package's verifier.
// Running the published verifier against every one of them is the strongest
// available statement that the two agree: not just on the accepting case, but
// on WHY each hostile case is refused.
const VECTORS = JSON.parse(readFileSync(
  new URL('../../conformance/hybrid-receipts/vectors.json', import.meta.url), 'utf8',
));

test('the published verifier rebuilds the frozen vectors\' exact signed bytes', () => {
  const bytes = hybridReceiptSignedBytes(VECTORS.payload, VECTORS.required_algorithms);
  assert.equal(
    crypto.createHash('sha256').update(bytes).digest('hex'),
    VECTORS.signed_bytes_sha256,
  );
  assert.deepEqual(JSON.parse(bytes.toString('utf8')), VECTORS.signed_material);
});

test('every frozen conformance vector gets the SAME verdict and the SAME reason', async () => {
  const keys = {
    ed25519PublicKey: VECTORS.keys.Ed25519.public_key,
    ed25519KeyId: VECTORS.keys.Ed25519.key_id,
    mldsaPublicKey: VECTORS.keys['ML-DSA-65'].public_key,
    mldsaKeyId: VECTORS.keys['ML-DSA-65'].key_id,
  };
  assert.ok(VECTORS.vectors.length >= 10, 'the frozen corpus must not have shrunk');
  let accepted = 0;
  for (const c of VECTORS.vectors) {
    const result = await verifyHybridReceipt(c.receipt, keys);
    assert.deepEqual(
      { verified: result.verified, reason: result.reason, failed_algorithm: result.failed_algorithm },
      c.expect,
      `vector "${c.id}" (${c.description})`,
    );
    if (c.expect.verified) accepted++;
  }
  assert.ok(accepted >= 1, 'the corpus must contain at least one accepting case, or nothing was proven');
});

test('the frozen v1-verifier behaviour still reproduces exactly', () => {
  const captured = VECTORS.v1_verifier_behaviour['hybrid-receipt-under-v1-verifier'];
  const hybridCase = VECTORS.vectors.find((c) => c.id === 'hybrid-valid');
  const result = verifyReceipt(hybridCase.receipt, VECTORS.keys.Ed25519.public_key);
  assert.deepEqual(result, captured.result,
    'a deployed v1 verifier must keep refusing a hybrid receipt on the version marker, with the same recorded reason');
});

// ===========================================================================
// Valid roundtrip
// ===========================================================================

test('a well-formed hybrid receipt verifies under both pinned keys', async () => {
  const doc = await buildReceipt();
  const result = await verifyHybridReceipt(doc, KEYS);
  assert.equal(result.verified, true, `expected verified, got ${result.reason}`);
  assert.equal(result.reason, null);
  assert.deepEqual(result.checks, {
    profile: true, algorithm_set: true, legs_present: true, signatures_valid: true,
  });
  // Both legs actually ran; a green verdict on one leg would be the bug.
  assert.deepEqual(result.set_result.results.map((r) => [r.alg, r.verified]),
    [['Ed25519', true], ['ML-DSA-65', true]]);
});

test('unsigned metadata does not change the verdict and is not signed material', async () => {
  const doc = await buildReceipt();
  doc.metadata = { operator: 'ep_operator_emilia_primary' };
  assert.equal((await verifyHybridReceipt(doc, KEYS)).verified, true);
  doc.metadata.operator = 'attacker';
  assert.equal((await verifyHybridReceipt(doc, KEYS)).verified, true,
    'metadata is deliberately OUTSIDE the signed bytes; nothing may be authorized on it');
});

// ===========================================================================
// Hostile matrix
// ===========================================================================

test('STRIPPED LEG: dropping the ML-DSA signature but leaving the set is refused', async () => {
  const doc = await buildReceipt();
  doc.signatures = doc.signatures.filter((s) => s.alg === 'Ed25519');
  const result = await verifyHybridReceipt(doc, KEYS);
  assert.equal(result.verified, false);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.HYBRID_LEG_MISSING);
  assert.equal(result.failed_algorithm, 'ML-DSA-65');
  assert.equal(result.checks.legs_present, false);
});

test('NARROWED SET: dropping the leg AND narrowing required_algorithms is refused', async () => {
  const doc = await buildReceipt();
  doc.signatures = doc.signatures.filter((s) => s.alg === 'Ed25519');
  doc.profile.required_algorithms = ['Ed25519'];
  const result = await verifyHybridReceipt(doc, KEYS);
  assert.equal(result.verified, false);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.ALGORITHM_SET_MISMATCH);
  assert.equal(result.checks.algorithm_set, false);
});

test('ANTI-STRIPPING IS CRYPTOGRAPHIC, not just structural: the surviving Ed25519 leg does not verify over the narrowed bytes', async () => {
  const doc = await buildReceipt();
  const edLeg = doc.signatures.find((s) => s.alg === 'Ed25519');

  // The bytes an attacker WISHES the verifier would rebuild, after narrowing.
  const narrowedBytes = Buffer.from(canonicalize({
    '@version': HYBRID_RECEIPT_PROFILE,
    payload: PAYLOAD,
    required_algorithms: ['Ed25519'],
  }), 'utf8');

  // Go under the profile verifier and ask the signature math directly, so this
  // asserts the BYTE-LEVEL commitment rather than the structural refusal that
  // the previous test already covers.
  const overNarrowed = await verifyAgileSignature(
    new Uint8Array(narrowedBytes), edLeg, { alg: 'Ed25519', public_key: edPubB64u },
  );
  assert.equal(overNarrowed.verified, false,
    'narrowing the set must break the surviving signature: the set is INSIDE the signed bytes');
  assert.equal(overNarrowed.reason, 'signature_invalid');

  // Same signature over the FULL set still verifies, so the failure above is
  // attributable to the narrowing and to nothing else.
  const overFull = await verifyAgileSignature(
    new Uint8Array(hybridReceiptSignedBytes(PAYLOAD)), edLeg, { alg: 'Ed25519', public_key: edPubB64u },
  );
  assert.equal(overFull.verified, true);
});

test('WIDENED SET: adding an algorithm to the declared set is refused', async () => {
  const doc = await buildReceipt();
  doc.profile.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
  const result = await verifyHybridReceipt(doc, KEYS);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.ALGORITHM_SET_MISMATCH);
});

test('REORDERED SET: the registered order is part of the commitment', async () => {
  const doc = await buildReceipt();
  doc.profile.required_algorithms = ['ML-DSA-65', 'Ed25519'];
  const result = await verifyHybridReceipt(doc, KEYS);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.ALGORITHM_SET_MISMATCH);
});

test('WRONG-LENGTH SIGNATURE: a truncated ML-DSA leg is refused, never skipped', async () => {
  const doc = await buildReceipt();
  const pqLeg = doc.signatures.find((s) => s.alg === 'ML-DSA-65');
  pqLeg.sig = Buffer.from(pqLeg.sig, 'base64url').subarray(0, 3308).toString('base64url');
  const result = await verifyHybridReceipt(doc, KEYS);
  assert.equal(result.verified, false);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.SIGNATURE_INVALID);
  assert.equal(result.failed_algorithm, 'ML-DSA-65');
  assert.equal(result.set_result.results.find((r) => r.alg === 'ML-DSA-65').reason, 'malformed_signature');
});

test('WRONG-LENGTH SIGNATURE: a 63-byte Ed25519 leg is refused', async () => {
  const doc = await buildReceipt();
  const edLeg = doc.signatures.find((s) => s.alg === 'Ed25519');
  edLeg.sig = Buffer.from(edLeg.sig, 'base64url').subarray(0, 63).toString('base64url');
  const result = await verifyHybridReceipt(doc, KEYS);
  assert.equal(result.verified, false);
  assert.equal(result.set_result.results.find((r) => r.alg === 'Ed25519').reason, 'malformed_signature');
});

test('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half is refused, not verified under the wrong curve', async () => {
  const ed448 = crypto.generateKeyPairSync('ed448');
  const ed448Spki = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
  const doc = await buildReceipt();
  const result = await verifyHybridReceipt(doc, { ...KEYS, ed25519PublicKey: ed448Spki });
  assert.equal(result.verified, false);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.MISSING_KEY);
  assert.equal(result.failed_algorithm, 'Ed25519');
  assert.equal(result.set_result.results.find((r) => r.alg === 'Ed25519').reason, 'malformed_key');
});

test('ALGORITHM RELABELLING: an Ed25519 signature relabelled ML-DSA-65 is refused', async () => {
  const doc = await buildReceipt();
  const edLeg = doc.signatures.find((s) => s.alg === 'Ed25519');
  doc.signatures = [
    { alg: 'Ed25519', sig: edLeg.sig },
    { alg: 'ML-DSA-65', sig: edLeg.sig },
  ];
  const result = await verifyHybridReceipt(doc, KEYS);
  assert.equal(result.verified, false);
  // 64 bytes is not an ML-DSA-65 signature length; the length pin catches it
  // before any backend is consulted.
  assert.equal(result.set_result.results.find((r) => r.alg === 'ML-DSA-65').reason, 'malformed_signature');
});

test('KEY SUBSTITUTION: a different Ed25519 key does not verify the receipt', async () => {
  const other = crypto.generateKeyPairSync('ed25519');
  const doc = await buildReceipt();
  const result = await verifyHybridReceipt(doc, {
    ...KEYS,
    ed25519PublicKey: other.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
  });
  assert.equal(result.verified, false);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.SIGNATURE_INVALID);
});

test('TAMPERED PAYLOAD: a changed payload field breaks both legs', async () => {
  const doc = await buildReceipt();
  doc.payload = { ...clone(PAYLOAD), claim: { action_type: 'payment.send', outcome: 'authorized', amount: '1000000' } };
  const result = await verifyHybridReceipt(doc, KEYS);
  assert.equal(result.verified, false);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.SIGNATURE_INVALID);
  for (const r of result.set_result.results) assert.equal(r.verified, false);
});

test('DUPLICATE ALGORITHM: two Ed25519 legs are refused', async () => {
  const doc = await buildReceipt();
  const edLeg = doc.signatures.find((s) => s.alg === 'Ed25519');
  doc.signatures = [edLeg, { ...edLeg }, doc.signatures.find((s) => s.alg === 'ML-DSA-65')];
  const result = await verifyHybridReceipt(doc, KEYS);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.DUPLICATE_ALGORITHM);
});

test('UNEXPECTED ALGORITHM: an extra leg outside the registry is refused', async () => {
  const doc = await buildReceipt();
  doc.signatures = [...doc.signatures, { alg: 'Ed448', sig: 'AAAA' }];
  const result = await verifyHybridReceipt(doc, KEYS);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.UNEXPECTED_ALGORITHM);
  assert.equal(result.failed_algorithm, 'Ed448');
});

test('SMUGGLED MEMBER: an unknown top-level member is refused, not ignored', async () => {
  const doc = await buildReceipt();
  doc.authorized_amount = '1000000';
  const result = await verifyHybridReceipt(doc, KEYS);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.MALFORMED_RECEIPT);
});

test('ANCHOR: a Merkle anchor on a hybrid receipt is refused by name, not half-checked', async () => {
  const doc = await buildReceipt();
  doc.anchor = { alg: 'EP-MERKLE-v2', leaf_hash: 'a'.repeat(64), merkle_proof: [], merkle_root: 'a'.repeat(64) };
  const result = await verifyHybridReceipt(doc, KEYS);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.UNSUPPORTED_ANCHOR);
});

test('MISSING KEY: no pinned material is a refusal, not a structural pass', async () => {
  const doc = await buildReceipt();
  for (const keys of [null, undefined, {}, { ed25519PublicKey: edPubB64u }, { mldsaPublicKey: pqPubB64u }]) {
    const result = await verifyHybridReceipt(doc, keys);
    assert.equal(result.verified, false);
    assert.equal(result.reason, HYBRID_RECEIPT_REASONS.MISSING_KEY);
  }
});

test('NO PQ BACKEND: an absent ML-DSA backend refuses; it never passes on the classical leg', async () => {
  const doc = await buildReceipt();
  const result = await verifyHybridReceipt(doc, KEYS, { mldsaBackendLoader: () => null });
  assert.equal(result.verified, false);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.PQ_BACKEND_UNAVAILABLE);
  assert.equal(result.failed_algorithm, 'ML-DSA-65');
  // The Ed25519 leg genuinely verified. That is exactly why an unavailable
  // backend must be a refusal rather than a skipped check.
  assert.equal(result.set_result.results.find((r) => r.alg === 'Ed25519').verified, true);
});

test('a THROWING injected backend is a refusal, never a pass', async () => {
  const doc = await buildReceipt();
  const result = await verifyHybridReceipt(doc, KEYS, {
    mldsaBackend: { verify: () => { throw new Error('boom'); } },
  });
  assert.equal(result.verified, false);
});

test('NOTHING THROWS on hostile caller input', async () => {
  const hostile = [
    null, undefined, 0, '', 'EP-RECEIPT-HYBRID-v1', [], [1, 2], { '@version': 1 },
    { '@version': HYBRID_RECEIPT_PROFILE },
    { '@version': HYBRID_RECEIPT_PROFILE, profile: null, payload: {}, signatures: [] },
    { '@version': HYBRID_RECEIPT_PROFILE, profile: { id: HYBRID_RECEIPT_PROFILE, required_algorithms: ['Ed25519', 'ML-DSA-65'] }, payload: { n: 1.5 }, signatures: [{ alg: 'Ed25519', sig: 'AAAA' }] },
    { '@version': HYBRID_RECEIPT_PROFILE, profile: { id: HYBRID_RECEIPT_PROFILE, required_algorithms: 'Ed25519' }, payload: {}, signatures: [] },
  ];
  for (const doc of hostile) {
    const result = await verifyHybridReceipt(doc, KEYS);
    assert.equal(result.verified, false);
    assert.equal(typeof result.reason, 'string');
  }
});

// ===========================================================================
// v1 refuses v2 -- the compatibility property the version marker exists for
// ===========================================================================

test('V1 REFUSES HYBRID: the unchanged synchronous verifyReceipt refuses on the version marker and does not throw', async () => {
  const doc = await buildReceipt();
  const result = verifyReceipt(doc, edPubB64u);
  assert.equal(result.valid, false);
  assert.equal(result.error, `Unsupported version: ${HYBRID_RECEIPT_PROFILE}`);
  // Refused BEFORE any signature was inspected: that is the required outcome.
  assert.equal(result.checks.version, false);
  assert.equal(result.checks.signature, false);
});

test('LEG LIFTING: a hybrid receipt\'s Ed25519 leg does not verify inside an EP-RECEIPT-v1 envelope', async () => {
  const doc = await buildReceipt();
  const edLeg = doc.signatures.find((s) => s.alg === 'Ed25519');
  const lifted = {
    '@version': 'EP-RECEIPT-v1',
    payload: PAYLOAD,
    signature: { algorithm: 'Ed25519', value: edLeg.sig },
  };
  const result = verifyReceipt(lifted, edPubB64u);
  assert.equal(result.valid, false,
    'the profile id is inside the signed bytes, so the leg cannot be lifted between envelopes');
  assert.equal(result.checks.version, true);
  assert.equal(result.checks.signature, false);
});

test('HYBRID REFUSES V1: a v1 receipt handed to the hybrid verifier refuses on the version marker', async () => {
  const payloadBytes = Buffer.from(canonicalize(PAYLOAD), 'utf8');
  const v1 = {
    '@version': 'EP-RECEIPT-v1',
    payload: PAYLOAD,
    signature: { algorithm: 'Ed25519', value: crypto.sign(null, payloadBytes, ed.privateKey).toString('base64url') },
  };
  assert.equal(verifyReceipt(v1, edPubB64u).valid, true, 'control: the v1 receipt is genuinely valid');
  const result = await verifyHybridReceipt(v1, KEYS);
  assert.equal(result.verified, false);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.UNKNOWN_PROFILE);
});

test('the ROUTER gives each profile its own verifier\'s verdict', async () => {
  const hybrid = await buildReceipt();
  const payloadBytes = Buffer.from(canonicalize(PAYLOAD), 'utf8');
  const v1 = {
    '@version': 'EP-RECEIPT-v1',
    payload: PAYLOAD,
    signature: { algorithm: 'Ed25519', value: crypto.sign(null, payloadBytes, ed.privateKey).toString('base64url') },
  };

  const hybridRoute = await verifyReceiptOfAnyProfile(hybrid, KEYS);
  assert.equal(hybridRoute.profile, HYBRID_RECEIPT_PROFILE);
  assert.equal(hybridRoute.valid, true);

  const v1Route = await verifyReceiptOfAnyProfile(v1, KEYS);
  assert.equal(v1Route.profile, 'EP-RECEIPT-v1');
  assert.equal(v1Route.valid, true);

  // A caller holding only the classical half is handed a hybrid receipt.
  const halfPinned = await verifyReceiptOfAnyProfile(hybrid, { ed25519PublicKey: edPubB64u });
  assert.equal(halfPinned.valid, false);
  assert.equal(halfPinned.reason, HYBRID_RECEIPT_REASONS.MISSING_KEY);

  const unknown = await verifyReceiptOfAnyProfile({ '@version': 'EP-RECEIPT-v9' }, KEYS);
  assert.equal(unknown.valid, false);
});

// ===========================================================================
// EP-LOG-CHECKPOINT-HYBRID-v1
// ===========================================================================

const CHECKPOINT = Object.freeze({
  tree_size: 42,
  root_hash: `sha256:${'d'.repeat(64)}`,
  log_key_id: 'ep:log:acme#1',
  merkle_alg: 'EP-MERKLE-v2',
});

async function buildCheckpointProof({ checkpoint = CHECKPOINT, requiredAlgorithms = [...LOG_CHECKPOINT_HYBRID_REQUIRED_ALGORITHMS] } = {}) {
  const bytes = logCheckpointHybridSignedBytes(checkpoint, requiredAlgorithms);
  const signatures = await signAgileSet(new Uint8Array(bytes), [
    { alg: 'Ed25519', private_key: ed.privateKey, key_id: 'ep:log:acme#1' },
    { alg: 'ML-DSA-65', private_key: pq.secretKey, key_id: 'ep:log:acme-pq#1' },
  ]);
  return {
    '@version': LOG_CHECKPOINT_HYBRID_PROFILE,
    profile: { id: LOG_CHECKPOINT_HYBRID_PROFILE, required_algorithms: [...requiredAlgorithms] },
    checkpoint: logCheckpointSignedFields(checkpoint),
    signatures,
  };
}

test('a well-formed checkpoint proof verifies against the held checkpoint', async () => {
  const proof = await buildCheckpointProof();
  const result = await verifyLogCheckpointHybridProof(CHECKPOINT, proof, KEYS);
  assert.equal(result.verified, true, `expected verified, got ${result.reason}`);
  assert.deepEqual(result.checks, {
    profile: true, algorithm_set: true, checkpoint_bound: true, legs_present: true, signatures_valid: true,
  });
});

test('a held checkpoint carrying log_signature is accepted; the signature is not signed material', async () => {
  const proof = await buildCheckpointProof();
  const held = { ...CHECKPOINT, log_signature: 'AAAA' };
  assert.equal((await verifyLogCheckpointHybridProof(held, proof, KEYS)).verified, true);
});

test('CHECKPOINT SUBSTITUTION: a proof for a different root does not speak for this one', async () => {
  const proof = await buildCheckpointProof();
  const otherRoot = { ...CHECKPOINT, root_hash: `sha256:${'e'.repeat(64)}` };
  const result = await verifyLogCheckpointHybridProof(otherRoot, proof, KEYS);
  assert.equal(result.verified, false);
  assert.equal(result.reason, LOG_CHECKPOINT_HYBRID_REASONS.CHECKPOINT_MISMATCH);
  assert.equal(result.checks.checkpoint_bound, false);
});

test('CHECKPOINT SUBSTITUTION: a different tree_size is refused', async () => {
  const proof = await buildCheckpointProof();
  const result = await verifyLogCheckpointHybridProof({ ...CHECKPOINT, tree_size: 43 }, proof, KEYS);
  assert.equal(result.reason, LOG_CHECKPOINT_HYBRID_REASONS.CHECKPOINT_MISMATCH);
});

test('LEGACY LOG: an EP-MERKLE-v1 checkpoint cannot enter this profile', async () => {
  const proof = await buildCheckpointProof();
  const legacy = { tree_size: 42, root_hash: CHECKPOINT.root_hash, log_key_id: 'ep:log:acme#1' };
  const result = await verifyLogCheckpointHybridProof(legacy, proof, KEYS);
  assert.equal(result.verified, false);
  // No merkle_alg at all: the closed member set refuses it before the alg check.
  assert.equal(result.reason, LOG_CHECKPOINT_HYBRID_REASONS.MALFORMED_CHECKPOINT);
  const wrongAlg = { ...CHECKPOINT, merkle_alg: 'EP-MERKLE-v1' };
  assert.equal((await verifyLogCheckpointHybridProof(wrongAlg, proof, KEYS)).reason,
    LOG_CHECKPOINT_HYBRID_REASONS.UNSUPPORTED_MERKLE_ALG);
});

test('STRIPPED LEG: a checkpoint proof missing its ML-DSA leg is refused', async () => {
  const proof = await buildCheckpointProof();
  proof.signatures = proof.signatures.filter((s) => s.alg === 'Ed25519');
  const result = await verifyLogCheckpointHybridProof(CHECKPOINT, proof, KEYS);
  assert.equal(result.reason, LOG_CHECKPOINT_HYBRID_REASONS.HYBRID_LEG_MISSING);
});

test('NARROWED SET: a checkpoint proof narrowing required_algorithms is refused', async () => {
  const proof = await buildCheckpointProof();
  proof.signatures = proof.signatures.filter((s) => s.alg === 'Ed25519');
  proof.profile.required_algorithms = ['Ed25519'];
  const result = await verifyLogCheckpointHybridProof(CHECKPOINT, proof, KEYS);
  assert.equal(result.reason, LOG_CHECKPOINT_HYBRID_REASONS.ALGORITHM_SET_MISMATCH);
});

test('NO PQ BACKEND: a checkpoint proof refuses rather than pass on the Ed25519 leg', async () => {
  const proof = await buildCheckpointProof();
  const result = await verifyLogCheckpointHybridProof(CHECKPOINT, proof, KEYS, { mldsaBackendLoader: () => null });
  assert.equal(result.verified, false);
  assert.equal(result.reason, LOG_CHECKPOINT_HYBRID_REASONS.PQ_BACKEND_UNAVAILABLE);
});

test('SMUGGLED MEMBER: an unknown member on the checkpoint or the proof is refused', async () => {
  const proof = await buildCheckpointProof();
  const smuggled = { ...proof, note: 'trust me' };
  assert.equal((await verifyLogCheckpointHybridProof(CHECKPOINT, smuggled, KEYS)).reason,
    LOG_CHECKPOINT_HYBRID_REASONS.MALFORMED_PROOF);
  assert.equal((await verifyLogCheckpointHybridProof({ ...CHECKPOINT, note: 'x' }, proof, KEYS)).reason,
    LOG_CHECKPOINT_HYBRID_REASONS.MALFORMED_CHECKPOINT);
});

test('checkpoint verification NEVER THROWS on hostile caller input', async () => {
  const proof = await buildCheckpointProof();
  for (const bad of [null, undefined, 0, '', [], { '@version': 1 }, { tree_size: -1 }, { ...CHECKPOINT, tree_size: 1.5 }]) {
    const a = await verifyLogCheckpointHybridProof(bad, proof, KEYS);
    assert.equal(a.verified, false);
    assert.equal(typeof a.reason, 'string');
    const b = await verifyLogCheckpointHybridProof(CHECKPOINT, bad, KEYS);
    assert.equal(b.verified, false);
    assert.equal(typeof b.reason, 'string');
  }
});
