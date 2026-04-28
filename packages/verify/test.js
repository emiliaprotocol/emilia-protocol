// SPDX-License-Identifier: Apache-2.0
//
// @emilia-protocol/verify — bundled tests.
//
// Run via:
//   npm test
//
// Goal: catch the v1.0.0 shallow-canonicalization regression and prove
// 1.0.1 round-trips deeply-nested signed payloads. Pure Node test (no
// vitest, no jest) so the package stays zero-runtime-dep.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  verifyReceipt,
  verifyMerkleAnchor,
  verifyCommitmentProof,
} from './index.js';

// ─── Helpers ──────────────────────────────────────────────────────────────

// Same recursive canonicalize the verifier uses internally — exposing a
// matching signer here proves byte-identical determinism.
function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function signWithRecursiveCanonical(payload, privateKey) {
  const canonical = canonicalize(payload);
  return crypto.sign(null, Buffer.from(canonical, 'utf8'), privateKey).toString('base64url');
}

function makeKeypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKey,
    publicKeyBase64url: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

// ─── Round-trip on flat payloads (sanity) ─────────────────────────────────

test('verifyReceipt: round-trips flat payload', () => {
  const { privateKey, publicKeyBase64url } = makeKeypair();
  const payload = { receipt_id: 'tr_flat', issuer: 'demo', created_at: '2026-04-15T00:00:00Z' };
  const doc = {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: signWithRecursiveCanonical(payload, privateKey) },
  };
  const result = verifyReceipt(doc, publicKeyBase64url);
  assert.equal(result.valid, true);
  assert.equal(result.checks.signature, true);
});

// ─── Round-trip on DEEPLY-NESTED payloads (the v1.0.0 regression) ──────────

test('verifyReceipt: round-trips DEEPLY-NESTED payload (v1.0.0 regression)', () => {
  const { privateKey, publicKeyBase64url } = makeKeypair();
  // The exact /r/example shape — claim.context.change.after_bank_hash
  // is at depth 4, claim.context.risk_signals is an array, and there
  // are alphabetic-out-of-order keys at multiple levels (issuer before
  // receipt_id, vendor_name after vendor_id, etc.).
  const payload = {
    receipt_id: 'tr_example',
    issuer: 'ep_demo_treasury_v1',
    subject: 'vendor:VEND-9821',
    claim: {
      action_type: 'vendor_bank_account_change',
      outcome: 'allow_with_signoff',
      context: {
        organization: 'demo_treasury',
        vendor_id: 'VEND-9821',
        vendor_name: 'Acme Industrial LLC',
        change: {
          before_bank_hash: 'sha256:abc',
          after_bank_hash: 'sha256:def',
        },
        risk_signals: [
          'NEW_DESTINATION',
          'AFTER_HOURS_SUBMISSION',
          'NO_PRIOR_CHANGE_30D',
          'UNUSUAL_SUBMITTER_ASN',
        ],
        outbound_payments_pending_usd: 248750,
      },
    },
    created_at: '2026-04-15T22:14:08Z',
    protocol_version: 'EP-CORE-v1.0',
  };
  const doc = {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: signWithRecursiveCanonical(payload, privateKey) },
  };
  const result = verifyReceipt(doc, publicKeyBase64url);
  assert.equal(result.valid, true, 'recursive canonicalize must round-trip nested payloads');
  assert.equal(result.checks.signature, true);
});

// ─── Tamper detection at depth (the failure mode v1.0.0 enabled) ─────────

test('verifyReceipt: rejects tampering of a deeply-nested field', () => {
  const { privateKey, publicKeyBase64url } = makeKeypair();
  const payload = {
    receipt_id: 'tr_x',
    claim: { context: { change: { after_bank_hash: 'sha256:GOOD' } } },
  };
  const doc = {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: signWithRecursiveCanonical(payload, privateKey) },
  };

  // Honest verify — passes.
  assert.equal(verifyReceipt(doc, publicKeyBase64url).valid, true);

  // Now tamper the deeply-nested bank hash. Nothing else changes.
  const tamperedDoc = JSON.parse(JSON.stringify(doc));
  tamperedDoc.payload.claim.context.change.after_bank_hash = 'sha256:EVIL';

  const result = verifyReceipt(tamperedDoc, publicKeyBase64url);
  assert.equal(result.valid, false, 'tampered nested field MUST fail verification');
  assert.equal(result.checks.signature, false);
});

// ─── Key-order independence (sorted-canonical determinism) ────────────────

test('verifyReceipt: signature is invariant under top-level key reorder', () => {
  const { privateKey, publicKeyBase64url } = makeKeypair();

  const payloadA = { receipt_id: 'tr_a', issuer: 'demo', subject: 's' };
  const payloadB = { subject: 's', issuer: 'demo', receipt_id: 'tr_a' };

  // Sign payloadA, attach signature, then place under payloadB's key
  // ordering. Recursive canonicalize means both reorderings produce the
  // same canonical bytes, so signature must verify against either form.
  const sig = signWithRecursiveCanonical(payloadA, privateKey);

  const docB = {
    '@version': 'EP-RECEIPT-v1',
    payload: payloadB,
    signature: { algorithm: 'Ed25519', value: sig },
  };
  assert.equal(verifyReceipt(docB, publicKeyBase64url).valid, true);
});

test('verifyReceipt: signature invariant under nested-key reorder', () => {
  const { privateKey, publicKeyBase64url } = makeKeypair();
  const payloadA = {
    receipt_id: 'tr_n',
    claim: { z_last: 1, a_first: 2, m_mid: { y: 1, x: 2 } },
  };
  const payloadB = {
    claim: { a_first: 2, m_mid: { x: 2, y: 1 }, z_last: 1 },
    receipt_id: 'tr_n',
  };
  const sig = signWithRecursiveCanonical(payloadA, privateKey);
  const docB = {
    '@version': 'EP-RECEIPT-v1',
    payload: payloadB,
    signature: { algorithm: 'Ed25519', value: sig },
  };
  assert.equal(verifyReceipt(docB, publicKeyBase64url).valid, true);
});

// ─── Surface contract ─────────────────────────────────────────────────────

test('verifyReceipt: rejects unsupported version', () => {
  const r = verifyReceipt({ '@version': 'BOGUS', payload: {}, signature: { value: 'x', algorithm: 'Ed25519' } }, 'fake');
  assert.equal(r.valid, false);
});

test('verifyReceipt: rejects missing payload or signature', () => {
  assert.equal(verifyReceipt({ '@version': 'EP-RECEIPT-v1' }, 'fake').valid, false);
  assert.equal(verifyReceipt({ '@version': 'EP-RECEIPT-v1', payload: {} }, 'fake').valid, false);
});

// ─── Merkle anchor ─────────────────────────────────────────────────────────

test('verifyMerkleAnchor: trivial single-leaf proof', () => {
  // root == leaf when proof is empty.
  const leaf = crypto.createHash('sha256').update('leaf', 'utf8').digest('hex');
  assert.equal(verifyMerkleAnchor(leaf, [], leaf), true);
});

test('verifyMerkleAnchor: rejects oversize proofs', () => {
  const leaf = 'aaaa';
  const tooLong = Array.from({ length: 21 }, () => ({ hash: 'bb', position: 'left' }));
  assert.equal(verifyMerkleAnchor(leaf, tooLong, 'cc'), false);
});

// ─── Commitment proof ─────────────────────────────────────────────────────

test('verifyCommitmentProof: accepts well-formed unexpired claim', () => {
  const r = verifyCommitmentProof({
    '@version': 'EP-PROOF-v1',
    claim: { domain: 'demo' },
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  });
  assert.equal(r.valid, true);
});

test('verifyCommitmentProof: rejects expired claim', () => {
  const r = verifyCommitmentProof({
    '@version': 'EP-PROOF-v1',
    claim: { domain: 'demo' },
    expires_at: '2020-01-01T00:00:00Z',
  });
  assert.equal(r.valid, false);
});
