// SPDX-License-Identifier: Apache-2.0
/**
 * Tests for src/hybrid-issuance.ts (EP-RECEIPT-HYBRID-v1 issuance).
 *
 * Exercises REAL ML-DSA-65 through @noble/post-quantum (a devDependency at the
 * repository root) by way of EP-SIG-AGILITY-v1. The suite FAILS LOUDLY if the
 * PQ backend or the agility module is missing rather than skipping, so a green
 * run means both legs were actually produced and actually checked.
 *
 * Run: node --test packages/issue/hybrid-issuance.test.js
 *  or: npx tsx --test packages/issue/hybrid-issuance.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  HYBRID_RECEIPT_PROFILE,
  HYBRID_RECEIPT_REASONS,
  HYBRID_RECEIPT_REQUIRED_ALGORITHMS,
  createHybridReceipt,
  generateHybridIssuerKeyBundle,
  hybridSignedBytes,
  loadAgilityModule,
  signingKeysFromHybridBundle,
  verificationKeysFromHybridBundle,
  verifyHybridReceipt,
} from './dist/hybrid-issuance.js';
import { canonicalize } from './dist/index.js';
import { verifyReceipt } from '../verify/index.js';

// --- fixtures ---------------------------------------------------------------

const agility = await loadAgilityModule();
assert.ok(agility, 'EP-SIG-AGILITY-v1 module must resolve; a skipped hybrid suite proves nothing');

const bundle = await generateHybridIssuerKeyBundle({
  ed25519KeyId: 'ep:key:test-hybrid-ed25519#1',
  mldsaKeyId: 'ep:key:test-hybrid-ml-dsa-65#1',
});
const signingKeys = signingKeysFromHybridBundle(bundle);
const verificationKeys = verificationKeysFromHybridBundle(bundle);

const PAYLOAD = {
  action: { parameters: { amount: '100.00' }, type: 'wire.transfer.1' },
  issued_at: '2026-08-16T00:00:00Z',
  issuer: 'ep:issuer:test',
  nonce: 'abc123',
};

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

async function issue(payload: Record<string, any> = PAYLOAD, metadata?: Record<string, any>) {
  return createHybridReceipt({ payload, keys: signingKeys, ...(metadata ? { metadata } : {}) });
}

// --- issuance ---------------------------------------------------------------

test('createHybridReceipt mints both legs over one set of canonical bytes', async () => {
  const doc = await issue(PAYLOAD, { operator: 'ep_operator_test' });

  assert.equal(doc['@version'], HYBRID_RECEIPT_PROFILE);
  assert.equal(doc.profile.id, HYBRID_RECEIPT_PROFILE);
  assert.deepEqual(doc.profile.required_algorithms, [...HYBRID_RECEIPT_REQUIRED_ALGORITHMS]);
  assert.deepEqual(doc.signatures.map((s) => s.alg), [...HYBRID_RECEIPT_REQUIRED_ALGORITHMS]);
  assert.deepEqual(doc.payload, PAYLOAD);
  assert.deepEqual(doc.metadata, { operator: 'ep_operator_test' });

  // Ed25519 is 64 bytes, ML-DSA-65 is 3309 (FIPS 204).
  assert.equal(Buffer.from(doc.signatures[0].sig, 'base64url').length, 64);
  assert.equal(Buffer.from(doc.signatures[1].sig, 'base64url').length, 3309);
  assert.equal(doc.signatures[0].key_id, 'ep:key:test-hybrid-ed25519#1');
  assert.equal(doc.signatures[1].key_id, 'ep:key:test-hybrid-ml-dsa-65#1');

  // Both legs verify over the SAME bytes, checked directly against the
  // agility module rather than only through this module's own wrapper.
  const message = new Uint8Array(hybridSignedBytes(PAYLOAD));
  const direct = await agility!.verifyAgileSignatureSet(
    message,
    doc.signatures,
    [
      { alg: 'Ed25519', public_key: verificationKeys.ed25519PublicKey },
      { alg: 'ML-DSA-65', public_key: verificationKeys.mldsaPublicKey },
    ],
    { policy: 'hybrid_all', requiredAlgorithms: [...HYBRID_RECEIPT_REQUIRED_ALGORITHMS] },
  );
  assert.equal(direct.verified, true, direct.reason ?? '');
});

test('the signed bytes commit to the profile and the full algorithm set', () => {
  const bytes = hybridSignedBytes(PAYLOAD).toString('utf8');
  assert.equal(bytes, canonicalize({
    '@version': HYBRID_RECEIPT_PROFILE,
    payload: PAYLOAD,
    required_algorithms: [...HYBRID_RECEIPT_REQUIRED_ALGORITHMS],
  }));
  // Not the bare EP-RECEIPT-v1 signing input: that is the whole point.
  assert.notEqual(bytes, canonicalize(PAYLOAD));
});

test('createHybridReceipt refuses issuer-side misuse rather than downgrading', async () => {
  await assert.rejects(
    () => createHybridReceipt({ payload: PAYLOAD, keys: { ...signingKeys, mldsaSecretKey: 'AAAA' } as any }),
    /mldsaSecretKey must be 4032 raw bytes/,
  );
  await assert.rejects(
    () => createHybridReceipt({
      payload: PAYLOAD,
      keys: { ...signingKeys, ed25519PrivateKey: crypto.generateKeyPairSync('ed448').privateKey },
    }),
    /not Ed25519/,
  );
  // A payload outside the canonicalization profile never becomes a receipt.
  await assert.rejects(
    () => createHybridReceipt({ payload: { amount: 1.5 } as any, keys: signingKeys }),
    /canonicalization profile/,
  );
  // No agility module means no receipt, never a single-signature one.
  await assert.rejects(
    () => createHybridReceipt({ payload: PAYLOAD, keys: signingKeys, agility: {} as any }),
    new RegExp(HYBRID_RECEIPT_REASONS.AGILITY_MODULE_UNAVAILABLE),
  );
});

// --- verification -----------------------------------------------------------

test('verifyHybridReceipt accepts a well-formed hybrid receipt', async () => {
  const result = await verifyHybridReceipt(await issue(), verificationKeys);
  assert.equal(result.verified, true, result.reason ?? '');
  assert.equal(result.reason, null);
  assert.deepEqual(result.checks, {
    profile: true,
    algorithm_set: true,
    legs_present: true,
    signatures_valid: true,
  });
  assert.equal(result.set_result?.policy, 'hybrid_all');
});

test('stripping either leg refuses with hybrid_leg_missing', async () => {
  const doc = await issue();
  for (const removed of HYBRID_RECEIPT_REQUIRED_ALGORITHMS) {
    const stripped = clone(doc);
    stripped.signatures = stripped.signatures.filter((s) => s.alg !== removed);
    const result = await verifyHybridReceipt(stripped, verificationKeys);
    assert.equal(result.verified, false);
    assert.equal(result.reason, HYBRID_RECEIPT_REASONS.HYBRID_LEG_MISSING);
    assert.equal(result.failed_algorithm, removed);
    assert.equal(result.checks.legs_present, false);
  }
});

test('narrowing the committed algorithm set refuses with algorithm_set_mismatch', async () => {
  const doc = await issue();
  // The attacker's cover story for a stripped leg: claim the receipt only ever
  // required one algorithm. Refused structurally, and the surviving signature
  // would not verify over the narrowed bytes either (next test).
  for (const narrowed of [['Ed25519'], ['ML-DSA-65'], ['ML-DSA-65', 'Ed25519'], []]) {
    const tampered = clone(doc);
    tampered.profile.required_algorithms = narrowed;
    const result = await verifyHybridReceipt(tampered, verificationKeys);
    assert.equal(result.verified, false);
    assert.equal(result.reason, HYBRID_RECEIPT_REASONS.ALGORITHM_SET_MISMATCH);
    assert.equal(result.checks.algorithm_set, false);
  }
});

test('the surviving leg does not verify over a narrowed algorithm set', async () => {
  // The cryptographic half of the anti-stripping control, independent of the
  // structural refusal above: the set lives INSIDE the signed bytes.
  const doc = await issue();
  const narrowedBytes = new Uint8Array(Buffer.from(canonicalize({
    '@version': HYBRID_RECEIPT_PROFILE,
    payload: PAYLOAD,
    required_algorithms: ['Ed25519'],
  }), 'utf8'));
  const result = await agility!.verifyAgileSignatureSet(
    narrowedBytes,
    [doc.signatures[0]],
    [{ alg: 'Ed25519', public_key: verificationKeys.ed25519PublicKey }],
    { policy: 'hybrid_all', requiredAlgorithms: ['Ed25519'] },
  );
  assert.equal(result.verified, false);
  assert.equal(result.results[0].reason, 'signature_invalid');
});

test('legs over different bytes refuse with signature_invalid', async () => {
  const doc = await issue();
  const other = await issue({ ...PAYLOAD, nonce: 'different-nonce' });
  // Splice the ML-DSA leg from a receipt over a DIFFERENT payload onto this one.
  const spliced = clone(doc);
  spliced.signatures[1] = clone(other.signatures[1]);
  const result = await verifyHybridReceipt(spliced, verificationKeys);
  assert.equal(result.verified, false);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.SIGNATURE_INVALID);
  assert.equal(result.failed_algorithm, 'ML-DSA-65');
  assert.equal(result.checks.signatures_valid, false);

  // Same in the other direction: the classical leg over other bytes.
  const splicedEd = clone(doc);
  splicedEd.signatures[0] = clone(other.signatures[0]);
  const edResult = await verifyHybridReceipt(splicedEd, verificationKeys);
  assert.equal(edResult.verified, false);
  assert.equal(edResult.reason, HYBRID_RECEIPT_REASONS.SIGNATURE_INVALID);
  assert.equal(edResult.failed_algorithm, 'Ed25519');
});

test('a tampered payload refuses on both legs', async () => {
  const doc = await issue();
  const tampered = clone(doc);
  tampered.payload.action.parameters.amount = '1000000.00';
  const result = await verifyHybridReceipt(tampered, verificationKeys);
  assert.equal(result.verified, false);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.SIGNATURE_INVALID);
  assert.ok(result.set_result?.results.every((r) => r.verified === false));
});

test('structural refusals are named and nothing throws on hostile input', async () => {
  const doc = await issue();
  const cases: Array<[unknown, string]> = [
    [null, HYBRID_RECEIPT_REASONS.MALFORMED_RECEIPT],
    [[], HYBRID_RECEIPT_REASONS.MALFORMED_RECEIPT],
    ['EP-RECEIPT-HYBRID-v1', HYBRID_RECEIPT_REASONS.MALFORMED_RECEIPT],
    [{ ...clone(doc), '@version': 'EP-RECEIPT-v1' }, HYBRID_RECEIPT_REASONS.UNKNOWN_PROFILE],
    [{ ...clone(doc), '@version': 'EP-RECEIPT-HYBRID-v2' }, HYBRID_RECEIPT_REASONS.UNKNOWN_PROFILE],
    [{ ...clone(doc), profile: undefined }, HYBRID_RECEIPT_REASONS.MALFORMED_RECEIPT],
    [{ ...clone(doc), profile: { id: 'other', required_algorithms: [] } }, HYBRID_RECEIPT_REASONS.UNKNOWN_PROFILE],
    [{ ...clone(doc), signatures: [] }, HYBRID_RECEIPT_REASONS.HYBRID_LEG_MISSING],
    [{ ...clone(doc), signatures: 'not-an-array' }, HYBRID_RECEIPT_REASONS.HYBRID_LEG_MISSING],
    [{ ...clone(doc), signatures: [{ alg: 'Ed25519' }] }, HYBRID_RECEIPT_REASONS.MALFORMED_RECEIPT],
  ];
  for (const [input, expected] of cases) {
    const result = await verifyHybridReceipt(input, verificationKeys);
    assert.equal(result.verified, false);
    assert.equal(result.reason, expected, `input ${JSON.stringify(input)?.slice(0, 60)}`);
  }

  // A duplicated leg is one algorithm presented twice: refused, never counted twice.
  const duplicated = clone(doc);
  duplicated.signatures = [duplicated.signatures[0], duplicated.signatures[0], duplicated.signatures[1]];
  const dupResult = await verifyHybridReceipt(duplicated, verificationKeys);
  assert.equal(dupResult.reason, HYBRID_RECEIPT_REASONS.DUPLICATE_ALGORITHM);

  // An extra algorithm outside the committed set is refused, not ignored.
  const extra = clone(doc);
  extra.signatures = [...extra.signatures, { alg: 'RSA-PSS', sig: 'AAAA' }];
  const extraResult = await verifyHybridReceipt(extra, verificationKeys);
  assert.equal(extraResult.reason, HYBRID_RECEIPT_REASONS.UNEXPECTED_ALGORITHM);
  assert.equal(extraResult.failed_algorithm, 'RSA-PSS');

  // Missing key material refuses before any signature work.
  const noKeys = await verifyHybridReceipt(doc, null);
  assert.equal(noKeys.reason, HYBRID_RECEIPT_REASONS.MISSING_KEY);
  const halfKeys = await verifyHybridReceipt(doc, { ed25519PublicKey: verificationKeys.ed25519PublicKey } as any);
  assert.equal(halfKeys.reason, HYBRID_RECEIPT_REASONS.MISSING_KEY);
});

test('an absent PQ backend refuses instead of passing on the classical leg', async () => {
  const doc = await issue();
  const result = await verifyHybridReceipt(doc, verificationKeys, {
    mldsaBackendLoader: () => null,
  });
  assert.equal(result.verified, false);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.PQ_BACKEND_UNAVAILABLE);
  assert.equal(result.failed_algorithm, 'ML-DSA-65');
  // The classical leg did verify; the receipt still does not.
  assert.equal(result.set_result?.results[0].verified, true);
});

// --- interaction with EP-RECEIPT-v1 verifiers -------------------------------

test('an EP-RECEIPT-v1 verifier refuses a hybrid receipt cleanly', async () => {
  const doc = await issue();
  const result = verifyReceipt(doc, verificationKeys.ed25519PublicKey as string);
  assert.equal(result.valid, false);
  assert.equal(result.checks.version, false);
  assert.equal(result.checks.signature, false);
  assert.equal(result.error, `Unsupported version: ${HYBRID_RECEIPT_PROFILE}`);
});

test('a hybrid Ed25519 leg repackaged as EP-RECEIPT-v1 fails the signature check', async () => {
  const doc = await issue();
  const repackaged = {
    '@version': 'EP-RECEIPT-v1',
    payload: PAYLOAD,
    signature: { algorithm: 'Ed25519', value: doc.signatures[0].sig, key_id: doc.signatures[0].key_id },
  };
  const result = verifyReceipt(repackaged, verificationKeys.ed25519PublicKey as string);
  assert.equal(result.valid, false);
  assert.equal(result.checks.version, true);
  assert.equal(result.checks.signature, false);
});

// --- key bundle -------------------------------------------------------------

test('EP-HYBRID-ISSUER-KEYS-v1 bundles carry both key pairs at their pinned sizes', async () => {
  assert.equal(bundle['@version'], 'EP-HYBRID-ISSUER-KEYS-v1');
  assert.equal(bundle.profile, HYBRID_RECEIPT_PROFILE);
  assert.equal(Buffer.from(bundle['ml-dsa-65'].private_key, 'base64url').length, 4032);
  assert.equal(Buffer.from(bundle['ml-dsa-65'].public_key, 'base64url').length, 1952);
  assert.equal(signingKeys.ed25519PrivateKey.asymmetricKeyType, 'ed25519');

  // A fixed seed reproduces the same ML-DSA key pair, which is what the
  // conformance vectors rely on.
  const seed = new Uint8Array(crypto.createHash('sha256').update('EP-RECEIPT-HYBRID-v1/test/seed').digest());
  const a = await generateHybridIssuerKeyBundle({ seed });
  const b = await generateHybridIssuerKeyBundle({ seed });
  assert.equal(a['ml-dsa-65'].public_key, b['ml-dsa-65'].public_key);
  assert.equal(a['ml-dsa-65'].private_key, b['ml-dsa-65'].private_key);
});
