/**
 * PIP-006 Federation — two-operator cross-redemption conformance harness.
 *
 * This is the executable form of PIP-006 acceptance gate #1: a second,
 * independent operator (Operator B) verifies a receipt issued by Operator A
 * using ONLY A's published discovery surfaces — no shared key material, no
 * shared database, no trust in A's policy.
 *
 * Operator A and Operator B are independent Ed25519 identities generated here.
 * A issues a genuine EP-RECEIPT-v1 (real signature over the canonical payload);
 * B resolves A's key from A's ep-keys.json and verifies. The negative cases
 * prove the contract is sound: tampering, wrong-operator keys, and revocation
 * are all rejected, while a pre-rotation receipt still verifies against A's
 * advertised historical key.
 *
 * Run: node --test federation.test.js   (or: npm test, from packages/verify/)
 *
 * @license Apache-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  resolveOperatorKeys,
  verifyFederatedReceiptOffline,
  verifyFederatedReceipt,
} from './federation.js';

// ── Canonicalization (must match packages/verify/index.js canonicalize) ──────
// Operator A signs canonical bytes; the verifier re-derives them identically.
function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

// ── Operator helpers ─────────────────────────────────────────────────────────

/** Create an independent EP operator identity (an Ed25519 signing key). */
function makeOperator(operatorId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  return { operatorId, publicKey, privateKey, publicKeyB64u };
}

const KEY_DISCOVERY = (op) => `https://${op.operatorId}.example/.well-known/ep-keys.json`;

/** Operator issues a genuine EP-RECEIPT-v1 over `payload`, signed with `signingKey`. */
function issueReceipt(op, payload, { signingKey } = {}) {
  const priv = signingKey || op.privateKey;
  const sig = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), priv);
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      signer: op.operatorId,
      key_discovery: KEY_DISCOVERY(op),
      algorithm: 'Ed25519',
      value: sig.toString('base64url'),
    },
  };
}

/** Build an operator's ep-keys.json discovery document. */
function discoveryDoc(op, { historical = [] } = {}) {
  const doc = {
    version: '1.0',
    operator_id: op.operatorId,
    keys: { [op.operatorId]: { public_key: op.publicKeyB64u, algorithm: 'Ed25519' } },
  };
  if (historical.length) {
    doc.historical_keys = {
      [op.operatorId]: historical.map((h) => ({
        public_key: h.publicKeyB64u,
        algorithm: 'Ed25519',
        retired_at: h.retired_at || '2026-01-01T00:00:00Z',
      })),
    };
  }
  return doc;
}

const samplePayload = (receiptId) => ({
  receipt_id: receiptId,
  '@version': 'EP-RECEIPT-v1',
  entity_id: 'ep_entity_acme_agent',
  action: { type: 'fin/payment-release', amount: 82000, currency: 'USD' },
  context: { risk_signals: ['large_amount'], change: { after_bank_hash: 'abc123' } },
  issued_at: '2026-06-11T12:00:00Z',
});

// ── 1. Happy path: cross-operator redemption ─────────────────────────────────

test('Operator B accepts a valid receipt issued by Operator A', () => {
  const A = makeOperator('ep_operator_a');
  const B = makeOperator('ep_operator_b'); // B is independent; never sees A's private key
  void B;

  const receipt = issueReceipt(A, samplePayload('ep_receipt_001'));
  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(A));

  assert.equal(result.accepted, true, 'a valid cross-operator receipt must be accepted');
  assert.equal(result.verified, true);
  assert.equal(result.revoked, false);
  assert.equal(result.signer, 'ep_operator_a');
  assert.equal(result.keyMatched, 'current');
  assert.equal(result.checks.signature, true);
  assert.equal(result.checks.not_revoked, true);
});

// ── 2. Tamper rejection ──────────────────────────────────────────────────────

test('a tampered payload does not verify (no trust laundering)', () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_002'));

  // Relying party flips the amount after issuance.
  receipt.payload.action.amount = 1; // was 82000

  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(A));
  assert.equal(result.verified, false);
  assert.equal(result.accepted, false);
  assert.match(result.error || '', /does not verify/);
});

// ── 3. Wrong-operator key rejection ──────────────────────────────────────────

test('a receipt does not verify against a different operator\'s key', () => {
  const A = makeOperator('ep_operator_a');
  const Imposter = makeOperator('ep_operator_a'); // same id, different key

  const receipt = issueReceipt(A, samplePayload('ep_receipt_003'));
  // B is handed the imposter's discovery doc (same operator_id, wrong key).
  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(Imposter));

  assert.equal(result.verified, false);
  assert.equal(result.accepted, false);
});

test('expectedSigner mismatch is rejected before key resolution', () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_003b'));
  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(A), {
    expectedSigner: 'ep_operator_somebody_else',
  });
  assert.equal(result.verified, false);
  assert.match(result.error || '', /Signer mismatch/);
});

// ── 4. Key rotation: historical key still verifies an old receipt ─────────────

test('a pre-rotation receipt verifies against an advertised historical key', () => {
  // A signs with an OLD key, then rotates. A's discovery doc advertises the new
  // key as current and the old key as historical. The old receipt must remain
  // verifiable (PIP-006 §Security considerations → Key rotation).
  const oldKeyPair = crypto.generateKeyPairSync('ed25519');
  const oldOp = {
    operatorId: 'ep_operator_a',
    privateKey: oldKeyPair.privateKey,
    publicKeyB64u: oldKeyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
  const A = makeOperator('ep_operator_a'); // new (current) key

  const oldReceipt = issueReceipt(oldOp, samplePayload('ep_receipt_004'), { signingKey: oldKeyPair.privateKey });
  const doc = discoveryDoc(A, { historical: [oldOp] });

  const result = verifyFederatedReceiptOffline(oldReceipt, doc);
  assert.equal(result.verified, true, 'pre-rotation receipt must verify against historical key');
  assert.equal(result.accepted, true);
  assert.equal(result.keyMatched, 'historical');
});

test('resolveOperatorKeys returns current before historical', () => {
  const oldKeyPair = crypto.generateKeyPairSync('ed25519');
  const oldOp = {
    operatorId: 'ep_operator_a',
    publicKeyB64u: oldKeyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
  const A = makeOperator('ep_operator_a');
  const keys = resolveOperatorKeys(discoveryDoc(A, { historical: [oldOp] }), 'ep_operator_a');
  assert.equal(keys.length, 2);
  assert.equal(keys[0].status, 'current');
  assert.equal(keys[1].status, 'historical');
});

// ── 5. Revocation ────────────────────────────────────────────────────────────

test('a revoked receipt verifies cryptographically but is not accepted', () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_005'));

  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(A), {
    revokedReceiptIds: new Set(['ep_receipt_005']),
  });

  // The signature is still valid — revocation is a policy/dispute signal, not a
  // forgery. But the receipt must not be accepted as live evidence.
  assert.equal(result.verified, true);
  assert.equal(result.revoked, true);
  assert.equal(result.accepted, false);
  assert.equal(result.checks.not_revoked, false);
});

// ── 6. Malformed / non-federated receipts ────────────────────────────────────

test('a receipt without signature.signer is not a federated receipt', () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_006'));
  delete receipt.signature.signer;

  const result = verifyFederatedReceiptOffline(receipt, discoveryDoc(A));
  assert.equal(result.verified, false);
  assert.match(result.error || '', /missing signature\.signer/);
});

test('an operator that advertises no key for the signer is rejected', () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_007'));
  const emptyDoc = { version: '1.0', operator_id: 'ep_operator_a', keys: {} };
  const result = verifyFederatedReceiptOffline(receipt, emptyDoc);
  assert.equal(result.verified, false);
  assert.match(result.error || '', /advertises no key/);
});

// ── 7. Online path with injected fetch (no real network) ─────────────────────

test('online verifyFederatedReceipt resolves keys + revocation via injected fetch', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_008'));
  const doc = discoveryDoc(A);

  // A fake transport that serves A's discovery doc and a not-revoked verdict.
  const fetchImpl = async (url) => {
    if (url.endsWith('/ep-keys.json')) {
      return { ok: true, status: 200, json: async () => doc };
    }
    if (url.includes('/api/verify/')) {
      return { ok: true, status: 200, json: async () => ({ receipt_id: 'ep_receipt_008', revoked: false }) };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };

  const result = await verifyFederatedReceipt(receipt, { fetchImpl });
  assert.equal(result.verified, true);
  assert.equal(result.accepted, true);
  assert.equal(result.revocation_confirmed, true);
  assert.equal(result.fetched.keyDiscoveryUrl, KEY_DISCOVERY(A));
});

test('online path honors an operator revocation verdict', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_009'));
  const doc = discoveryDoc(A);

  const fetchImpl = async (url) => {
    if (url.endsWith('/ep-keys.json')) return { ok: true, status: 200, json: async () => doc };
    if (url.includes('/api/verify/')) {
      return { ok: true, status: 200, json: async () => ({ receipt_id: 'ep_receipt_009', revoked: true }) };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };

  const result = await verifyFederatedReceipt(receipt, { fetchImpl });
  assert.equal(result.verified, true);
  assert.equal(result.revoked, true);
  assert.equal(result.accepted, false);
});

test('online path fails closed when key discovery is unreachable', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_010'));
  const fetchImpl = async () => { throw new Error('network down'); };
  const result = await verifyFederatedReceipt(receipt, { fetchImpl });
  assert.equal(result.verified, false);
  assert.equal(result.accepted, false);
  assert.match(result.error || '', /Failed to fetch operator key discovery/);
});

test('online path fails open on revocation lookup but still verifies signature', async () => {
  const A = makeOperator('ep_operator_a');
  const receipt = issueReceipt(A, samplePayload('ep_receipt_011'));
  const doc = discoveryDoc(A);
  // Discovery succeeds; revocation endpoint is down.
  const fetchImpl = async (url) => {
    if (url.endsWith('/ep-keys.json')) return { ok: true, status: 200, json: async () => doc };
    throw new Error('revocation feed down');
  };
  const result = await verifyFederatedReceipt(receipt, { fetchImpl });
  assert.equal(result.verified, true);
  assert.equal(result.accepted, true, 'an unreachable revocation feed must not fail a valid receipt');
  assert.equal(result.revocation_confirmed, false);
});
