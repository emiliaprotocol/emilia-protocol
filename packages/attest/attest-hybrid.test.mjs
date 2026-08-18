// SPDX-License-Identifier: Apache-2.0
//
// EP-ATTEST-HYBRID-v1 tests, plus the byte-identity regression for the
// unchanged EP-ATTEST-v2 path.
//
// The regression independently recomputes the canonical payload bytes and the
// Ed25519 signature with code written here, so a refactor that quietly changed
// what signWorkReceipt() signs cannot pass by reusing the module's own
// canonicalize().
//
// The PQ leg runs for real. This suite FAILS LOUDLY if @noble/post-quantum is
// missing rather than silently skipping.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  ATTEST_VERSION,
  ATTEST_HYBRID_VERSION,
  ATTEST_HYBRID_ENVELOPE,
  sha256Hex,
  signWorkReceipt,
  signWorkReceiptHybrid,
  verifyIdentity,
} from './index.js';
import { generateHybridIssuerKeyBundle } from '../issue/hybrid-issuance.js';
import { verifyReceipt } from '../verify/index.js';
import { verifyHybridReceipt, HYBRID_RECEIPT_REASONS } from '../verify/receipt-hybrid.js';

await import('@noble/post-quantum/ml-dsa.js');

/** INDEPENDENT canonicalizer -- deliberately not the package's own. */
function independentCanonicalize(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return `[${value.map(independentCanonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort()
      .map((k) => `${JSON.stringify(k)}:${independentCanonicalize(value[k])}`)
      .join(',')}}`;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('outside the EP canonicalization profile');
    return String(value);
  }
  return JSON.stringify(value);
}

const IDENTITY = Buffer.from('agent-identity-file-bytes');
const WORK = Buffer.from('the work product bytes');
const KNOWN_GOOD = sha256Hex(IDENTITY);
const SUBJECT = 'ep:approver:cfo';
const ISSUED_AT = '2026-08-17T12:00:00Z';
const RECEIPT_ID = 'att_fixed_for_determinism';

const BASE_ARGS = {
  identity: IDENTITY,
  knownGoodHash: KNOWN_GOOD,
  knownGoodSubject: SUBJECT,
  work: WORK,
  subject: SUBJECT,
  issuedAt: ISSUED_AT,
  receiptId: RECEIPT_ID,
};

const ed = crypto.generateKeyPairSync('ed25519');
const bundle = await generateHybridIssuerKeyBundle({
  seed: new Uint8Array(crypto.createHash('sha256').update('attest-hybrid.test/seed').digest()),
});

/** The payload the test expects, built here rather than read from the module. */
function expectedPayload(profile) {
  return {
    attest_profile: profile,
    receipt_id: RECEIPT_ID,
    subject: SUBJECT,
    identity: { algorithm: 'SHA-256', hash: KNOWN_GOOD, matched_known_good: true },
    work: { algorithm: 'SHA-256', hash: sha256Hex(WORK) },
    claim: { action_type: 'work.signed', outcome: 'attested' },
    issued_at: ISSUED_AT,
  };
}

// ===========================================================================
// REGRESSION: EP-ATTEST-v2 / EP-RECEIPT-v1 issuance is byte-identical
// ===========================================================================

test('REGRESSION: signWorkReceipt still signs exactly the bytes it signed before', () => {
  const { document, public_key } = signWorkReceipt({ ...BASE_ARGS, signerPrivateKey: ed.privateKey });

  assert.equal(document['@version'], 'EP-RECEIPT-v1');
  assert.equal(document.payload.attest_profile, ATTEST_VERSION);
  assert.deepEqual(document.payload, expectedPayload(ATTEST_VERSION));
  assert.deepEqual(Object.keys(document).sort(), ['@version', 'payload', 'signature']);
  assert.deepEqual(document.signature, { algorithm: 'Ed25519', value: document.signature.value });

  // The signature verifies over INDEPENDENTLY recomputed canonical bytes.
  const bytes = Buffer.from(independentCanonicalize(document.payload), 'utf8');
  assert.equal(
    crypto.verify(null, bytes, ed.publicKey, Buffer.from(document.signature.value, 'base64url')),
    true,
  );
  // And under the published offline verifier, which is what a relying party runs.
  assert.equal(verifyReceipt(document, public_key).valid, true);
});

test('REGRESSION: every refusal on the classical path still fires', () => {
  const cases = [
    [{ ...BASE_ARGS, knownGoodHash: 'f'.repeat(64) }, /identity does not match/],
    [{ ...BASE_ARGS, subject: 'ep:approver:other' }, /does not match the relying-party identity pin/],
    [{ ...BASE_ARGS, knownGoodSubject: undefined }, /knownGoodSubject is required/],
    [{ ...BASE_ARGS, subject: undefined }, /subject \(identity id\) is required/],
    [{ ...BASE_ARGS, issuedAt: 'yesterday' }, /issuedAt must be a valid UTC RFC3339 timestamp/],
    [{ ...BASE_ARGS, receiptId: '' }, /receiptId must be a non-empty string/],
    [{ ...BASE_ARGS, workName: 42 }, /workName must be null or a non-empty string/],
  ];
  for (const [args, pattern] of cases) {
    assert.throws(() => signWorkReceipt({ ...args, signerPrivateKey: ed.privateKey }), pattern);
  }
  assert.throws(
    () => signWorkReceipt({ ...BASE_ARGS, signerPrivateKey: crypto.generateKeyPairSync('ed448').privateKey }),
    /must be Ed25519/,
  );
});

test('REGRESSION: an anchored classical receipt still self-checks its EP-MERKLE-v2 leaf', () => {
  const { document, public_key } = signWorkReceipt({
    ...BASE_ARGS, signerPrivateKey: ed.privateKey, anchor: true,
  });
  assert.equal(document.anchor.alg, 'EP-MERKLE-v2');
  const result = verifyReceipt(document, public_key);
  assert.equal(result.valid, true);
  assert.equal(result.checks.anchor, true);
});

// ===========================================================================
// EP-ATTEST-HYBRID-v1
// ===========================================================================

test('a hybrid attestation verifies under the published hybrid verifier', async () => {
  const { document, verification_keys } = await signWorkReceiptHybrid({ ...BASE_ARGS, keyBundle: bundle });

  assert.equal(document['@version'], ATTEST_HYBRID_ENVELOPE);
  assert.equal(ATTEST_HYBRID_ENVELOPE, 'EP-RECEIPT-HYBRID-v1');
  assert.equal(document.payload.attest_profile, ATTEST_HYBRID_VERSION);
  assert.equal(ATTEST_HYBRID_VERSION, 'EP-ATTEST-HYBRID-v1');
  assert.deepEqual(document.signatures.map((s) => s.alg), ['Ed25519', 'ML-DSA-65']);

  const result = await verifyHybridReceipt(document, verification_keys);
  assert.equal(result.verified, true, `expected verified, got ${result.reason}`);
  assert.deepEqual(result.set_result.results.map((r) => [r.alg, r.verified]),
    [['Ed25519', true], ['ML-DSA-65', true]]);
});

test('the hybrid payload binds the SAME facts as the classical one, under a different profile marker', async () => {
  const { document } = await signWorkReceiptHybrid({ ...BASE_ARGS, keyBundle: bundle });
  assert.deepEqual(document.payload, expectedPayload(ATTEST_HYBRID_VERSION));
  // Same identity and work bytes, different signed material: a leg cannot be
  // lifted between the two profiles.
  const classical = signWorkReceipt({ ...BASE_ARGS, signerPrivateKey: ed.privateKey });
  assert.notEqual(
    independentCanonicalize(document.payload),
    independentCanonicalize(classical.document.payload),
  );
});

test('V1 REFUSES HYBRID: the unchanged verifyReceipt refuses a hybrid attestation on the version marker', async () => {
  const { document, verification_keys } = await signWorkReceiptHybrid({ ...BASE_ARGS, keyBundle: bundle });
  const result = verifyReceipt(document, verification_keys.ed25519PublicKey);
  assert.equal(result.valid, false);
  assert.equal(result.error, 'Unsupported version: EP-RECEIPT-HYBRID-v1');
  assert.equal(result.checks.signature, false, 'refused BEFORE any signature was inspected');
});

test('the hybrid path applies the SAME identity and subject refusals as the classical path', async () => {
  const cases = [
    [{ ...BASE_ARGS, knownGoodHash: 'f'.repeat(64) }, /identity does not match/],
    [{ ...BASE_ARGS, subject: 'ep:approver:other' }, /does not match the relying-party identity pin/],
    [{ ...BASE_ARGS, issuedAt: 'yesterday' }, /issuedAt must be a valid UTC RFC3339 timestamp/],
  ];
  for (const [args, pattern] of cases) {
    await assert.rejects(() => signWorkReceiptHybrid({ ...args, keyBundle: bundle }), pattern);
  }
  await assert.rejects(() => signWorkReceiptHybrid({ ...BASE_ARGS }), /keyBundle is required/);
  await assert.rejects(
    () => signWorkReceiptHybrid({ ...BASE_ARGS, keyBundle: { ed25519: bundle.ed25519 } }),
    /both private keys/,
  );
});

test('NO PQ BACKEND: hybrid issuance REFUSES rather than emit a classical-only attestation', async () => {
  await assert.rejects(
    () => signWorkReceiptHybrid({
      ...BASE_ARGS,
      keyBundle: bundle,
      mldsaBackendLoader: () => null,
    }),
    /pq_backend_unavailable/,
  );
});

test('a tampered hybrid attestation does not verify', async () => {
  const { document, verification_keys } = await signWorkReceiptHybrid({ ...BASE_ARGS, keyBundle: bundle });
  const tampered = JSON.parse(JSON.stringify(document));
  tampered.payload.subject = 'ep:approver:attacker';
  const result = await verifyHybridReceipt(tampered, verification_keys);
  assert.equal(result.verified, false);
  assert.equal(result.reason, HYBRID_RECEIPT_REASONS.SIGNATURE_INVALID);
});

test('verifyIdentity is unchanged and still fail-closed', () => {
  assert.equal(verifyIdentity({ identity: IDENTITY, knownGoodHash: KNOWN_GOOD }).verified, true);
  assert.equal(verifyIdentity({ identity: IDENTITY, knownGoodHash: 'f'.repeat(64) }).verified, false);
  assert.equal(verifyIdentity({ identity: IDENTITY, knownGoodHash: KNOWN_GOOD.toUpperCase() }).verified, true);
  assert.equal(verifyIdentity({}).verified, false);
});
