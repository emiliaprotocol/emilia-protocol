#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Generates conformance/hybrid-receipts/vectors.json: deterministic
// EP-RECEIPT-HYBRID-v1 receipts and the exact refusals a conforming verifier
// must produce for each attack on them.
//
// Every byte is reproducible from fixed public seed labels (TEST KEYS ONLY --
// see README.md). Run with --check to prove the checked-in file still matches
// what this generator produces; that is what the test suite calls.
//
//   node conformance/hybrid-receipts/generate.mjs           # rewrite
//   node conformance/hybrid-receipts/generate.mjs --check   # verify

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  HYBRID_RECEIPT_PROFILE,
  HYBRID_RECEIPT_REQUIRED_ALGORITHMS,
  createHybridReceipt,
  hybridSignedBytes,
} from '../../packages/issue/dist/hybrid-issuance.js';
import { verifyReceipt } from '../../packages/verify/index.js';

const HERE: string = path.dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH: string = path.join(HERE, 'vectors.json');

// --- deterministic test key material ----------------------------------------
// Same construction as conformance/pq-agility, with this profile's own labels
// so the two vector sets never share key material.

const ED25519_SEED_LABEL = 'EP-RECEIPT-HYBRID-v1/vectors/ed25519/1';
const MLDSA_SEED_LABEL = 'EP-RECEIPT-HYBRID-v1/vectors/ml-dsa-65/1';
// RFC 8410 PKCS#8 prefix for a raw 32-byte Ed25519 seed.
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

const seedOf = (label: string): Buffer => crypto.createHash('sha256').update(label, 'utf8').digest();

function ed25519KeyPairFromSeed(label: string) {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seedOf(label)]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = crypto.createPublicKey(privateKey);
  return {
    privateKey,
    publicKeyB64u: publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
  };
}

async function mldsaKeyPairFromSeed(label: string) {
  const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
  const pair = ml_dsa65.keygen(new Uint8Array(seedOf(label)));
  return {
    secretKeyB64u: Buffer.from(pair.secretKey).toString('base64url'),
    publicKeyB64u: Buffer.from(pair.publicKey).toString('base64url'),
  };
}

// --- the payload under test -------------------------------------------------

const PAYLOAD = {
  action: {
    parameters: { amount: '1250.00', currency: 'USD', destination: 'acct:vendor-88' },
    type: 'wire.transfer.1',
  },
  issued_at: '2026-08-16T00:00:00Z',
  issuer: 'ep:issuer:hybrid-conformance',
  nonce: 'ZmpTPmqOm5nQ1x7Ym0nQ2A',
};

const OTHER_PAYLOAD = { ...PAYLOAD, nonce: 'different-nonce-same-issuer' };

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** The one leg for `alg`, or a hard failure: a generator must never emit a guess. */
function legOf(doc: Record<string, any>, alg: string): Record<string, any> {
  const leg = (doc.signatures as Array<Record<string, any>>).find((s) => s.alg === alg);
  if (!leg) throw new Error(`generate: receipt is missing its ${alg} leg`);
  return leg;
}

// --- vector construction ----------------------------------------------------

async function build(): Promise<Record<string, any>> {
  const ed = ed25519KeyPairFromSeed(ED25519_SEED_LABEL);
  const pq = await mldsaKeyPairFromSeed(MLDSA_SEED_LABEL);

  const keys = {
    ed25519PrivateKey: ed.privateKey,
    ed25519KeyId: 'ep:key:hybrid-conformance-ed25519#1',
    mldsaSecretKey: pq.secretKeyB64u,
    mldsaKeyId: 'ep:key:hybrid-conformance-ml-dsa-65#1',
  };
  // deterministic: FIPS 204 signing with rnd fixed, so the 3309-byte ML-DSA
  // signature is pinned by seed + message and this file is reproducible.
  const options = { deterministic: true };

  const receipt = await createHybridReceipt({ payload: PAYLOAD, keys, ...options });
  const other = await createHybridReceipt({ payload: OTHER_PAYLOAD, keys, ...options });

  const signedBytes = hybridSignedBytes(PAYLOAD);

  const vectors: Array<Record<string, any>> = [];
  const add = (
    id: string,
    description: string,
    doc: Record<string, any>,
    expect: Record<string, any>,
  ): void => { vectors.push({ id, description, receipt: doc, expect }); };

  add(
    'hybrid-valid',
    'Both legs over the same canonical bytes, committed algorithm set intact.',
    receipt,
    { verified: true, reason: null, failed_algorithm: null },
  );

  const strippedEd = clone(receipt);
  strippedEd.signatures = strippedEd.signatures.filter((s: any) => s.alg !== 'Ed25519');
  add(
    'ed25519-leg-stripped',
    'The classical leg is removed. The committed set still requires it.',
    strippedEd,
    { verified: false, reason: 'hybrid_leg_missing', failed_algorithm: 'Ed25519' },
  );

  const strippedPq = clone(receipt);
  strippedPq.signatures = strippedPq.signatures.filter((s: any) => s.alg !== 'ML-DSA-65');
  add(
    'ml-dsa-leg-stripped',
    'The post-quantum leg is removed. This is the downgrade attack the profile exists to stop.',
    strippedPq,
    { verified: false, reason: 'hybrid_leg_missing', failed_algorithm: 'ML-DSA-65' },
  );

  const narrowed = clone(strippedPq);
  narrowed.profile.required_algorithms = ['Ed25519'];
  add(
    'ml-dsa-leg-stripped-and-set-narrowed',
    'The stripped receipt also claims it only ever required Ed25519. Refused structurally; the surviving signature would not verify over the narrowed bytes either, because the required set is inside the signed material.',
    narrowed,
    { verified: false, reason: 'algorithm_set_mismatch', failed_algorithm: null },
  );

  const differentBytes = clone(receipt);
  differentBytes.signatures = differentBytes.signatures.map((s: any) => (
    s.alg === 'ML-DSA-65' ? clone(legOf(other, 'ML-DSA-65')) : s
  ));
  add(
    'legs-over-different-bytes',
    'A valid ML-DSA-65 leg from a receipt over a DIFFERENT payload is spliced in. Both legs must cover identical bytes.',
    differentBytes,
    { verified: false, reason: 'signature_invalid', failed_algorithm: 'ML-DSA-65' },
  );

  const differentBytesEd = clone(receipt);
  differentBytesEd.signatures = differentBytesEd.signatures.map((s: any) => (
    s.alg === 'Ed25519' ? clone(legOf(other, 'Ed25519')) : s
  ));
  add(
    'classical-leg-over-different-bytes',
    'The same splice in the other direction: a valid Ed25519 leg from another payload.',
    differentBytesEd,
    { verified: false, reason: 'signature_invalid', failed_algorithm: 'Ed25519' },
  );

  const tampered = clone(receipt);
  tampered.payload.action.parameters.amount = '9999999.00';
  add(
    'payload-tampered',
    'The signed amount is changed. Both legs fail; neither can be repaired independently.',
    tampered,
    { verified: false, reason: 'signature_invalid', failed_algorithm: 'Ed25519' },
  );

  const duplicated = clone(receipt);
  duplicated.signatures = [duplicated.signatures[0], duplicated.signatures[0], duplicated.signatures[1]];
  add(
    'duplicate-classical-leg',
    'One algorithm presented twice. One verdict per algorithm, so a repeat is refused rather than counted.',
    duplicated,
    { verified: false, reason: 'duplicate_algorithm', failed_algorithm: 'Ed25519' },
  );

  const extra = clone(receipt);
  extra.signatures = [...extra.signatures, { alg: 'RSA-PSS', sig: 'AAAA' }];
  add(
    'algorithm-outside-committed-set',
    'A leg for an algorithm the receipt never committed to. Refused, not ignored.',
    extra,
    { verified: false, reason: 'unexpected_algorithm', failed_algorithm: 'RSA-PSS' },
  );

  const relabelled = clone(receipt);
  relabelled['@version'] = 'EP-RECEIPT-v1';
  add(
    'hybrid-relabelled-as-classical',
    'The hybrid document wearing the classical version marker. The hybrid verifier refuses an unknown profile; it never guesses at another format.',
    relabelled,
    { verified: false, reason: 'unknown_profile', failed_algorithm: null },
  );

  // --- what an EP-RECEIPT-v1 verifier does with all this --------------------
  // Captured by RUNNING packages/verify's verifyReceipt, not predicted.

  const v1OnHybrid = verifyReceipt(receipt, ed.publicKeyB64u);
  const repackaged = {
    '@version': 'EP-RECEIPT-v1',
    payload: PAYLOAD,
    signature: {
      algorithm: 'Ed25519',
      value: legOf(receipt, 'Ed25519').sig,
      key_id: keys.ed25519KeyId,
    },
  };
  const v1OnRepackagedLeg = verifyReceipt(repackaged, ed.publicKeyB64u);

  return {
    '@version': 'EP-RECEIPT-HYBRID-CONFORMANCE-v1',
    profile: HYBRID_RECEIPT_PROFILE,
    generated_by: 'conformance/hybrid-receipts/generate.mts',
    required_algorithms: [...HYBRID_RECEIPT_REQUIRED_ALGORITHMS],
    keys: {
      'Ed25519': {
        seed_label: ED25519_SEED_LABEL,
        key_id: keys.ed25519KeyId,
        public_key: ed.publicKeyB64u,
      },
      'ML-DSA-65': {
        seed_label: MLDSA_SEED_LABEL,
        key_id: keys.mldsaKeyId,
        public_key: pq.publicKeyB64u,
      },
    },
    payload: PAYLOAD,
    signed_material: {
      '@version': HYBRID_RECEIPT_PROFILE,
      payload: PAYLOAD,
      required_algorithms: [...HYBRID_RECEIPT_REQUIRED_ALGORITHMS],
    },
    signed_bytes_sha256: crypto.createHash('sha256').update(signedBytes).digest('hex'),
    vectors,
    v1_verifier_behaviour: {
      note: 'Captured by running verifyReceipt() from packages/verify against these exact documents.',
      'hybrid-receipt-under-v1-verifier': {
        description: 'An EP-RECEIPT-v1 verifier handed the hybrid receipt unchanged.',
        result: v1OnHybrid,
      },
      'classical-leg-repackaged-as-v1': {
        description: 'The hybrid receipt\'s Ed25519 leg lifted into an EP-RECEIPT-v1 envelope over the same payload. The version check now passes and the signature check fails, because the hybrid leg signed bytes that name the profile and the full algorithm set.',
        result: v1OnRepackagedLeg,
      },
    },
  };
}

// --- emit / check -----------------------------------------------------------

const serialize = (value: unknown): string => `${JSON.stringify(value, null, 2)}\n`;

const built = await build();
const text = serialize(built);

if (process.argv.includes('--check')) {
  const existing = fs.readFileSync(VECTORS_PATH, 'utf8');
  if (existing !== text) {
    console.error('conformance/hybrid-receipts/vectors.json is stale; run: node conformance/hybrid-receipts/generate.mjs');
    process.exit(1);
  }
  console.log(`vectors.json is reproducible (${built.vectors.length} vectors)`);
} else {
  fs.writeFileSync(VECTORS_PATH, text);
  console.log(`wrote ${VECTORS_PATH} (${built.vectors.length} vectors)`);
}
