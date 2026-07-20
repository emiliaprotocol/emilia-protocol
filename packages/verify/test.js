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
  canonicalize as canonicalizeFromVerifier,
  isCanonicalizable,
  verifyReceipt,
  verifyMerkleAnchor,
  verifyCommitmentProof,
  verifyWebAuthnSignoff,
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

test('canonicalize: consensus-split edge vector is pinned to JS/JCS bytes', () => {
  const payload = {
    '@version': 'EP-RECEIPT-v1',
    action: { action_type: 'payment.release', amount_usd: 1.0, risk_score: -0.0 },
    context: { '\uFFFD': 'replacement_char', '🙂': 'slight_smile' },
    entity_id: 'ep_entity_poc_test',
    signoffs: [],
  };
  const canonical = canonicalizeFromVerifier(payload);
  assert.equal(canonical, '{"@version":"EP-RECEIPT-v1","action":{"action_type":"payment.release","amount_usd":1,"risk_score":0},"context":{"🙂":"slight_smile","�":"replacement_char"},"entity_id":"ep_entity_poc_test","signoffs":[]}');
  assert.equal(crypto.createHash('sha256').update(canonical, 'utf8').digest('hex'), '49c642930186d4ed0324c6099f077c38a16cac19e327c2f58bb76f19a33351b2');
  assert.equal(isCanonicalizable(payload), true);
  assert.equal(isCanonicalizable({ unsafe: 1e20 }), false);
  assert.equal(isCanonicalizable({ fractional: 1.25 }), false);
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
  const tooLong = Array.from({ length: 21 }, () => ({ hash: 'bb', position: /** @type {'left'} */ ('left') }));
  assert.equal(verifyMerkleAnchor(leaf, tooLong, 'cc'), false);
});

// ─── Commitment proof ─────────────────────────────────────────────────────

test('verifyCommitmentProof: rejects unsigned proof by default', () => {
  const r = verifyCommitmentProof({
    '@version': 'EP-PROOF-v1',
    claim: { domain: 'demo' },
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'Signature and public key are required');
});

test('verifyCommitmentProof: accepts unsigned proof only when explicitly allowed', () => {
  const r = verifyCommitmentProof({
    '@version': 'EP-PROOF-v1',
    claim: { domain: 'demo' },
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  }, null, { allowUnsigned: true });
  assert.equal(r.valid, true);
});

test('verifyCommitmentProof: accepts signed commitment with pinned public key', () => {
  const { privateKey, publicKeyBase64url } = makeKeypair();
  const commitment = {
    domain: 'demo',
    subject: 'vendor:VEND-9821',
    claim_hash: 'a'.repeat(64),
  };
  const r = verifyCommitmentProof({
    '@version': 'EP-PROOF-v1',
    claim: { domain: 'demo' },
    commitment,
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    signature: {
      algorithm: 'Ed25519',
      value: signWithRecursiveCanonical(commitment, privateKey),
    },
  }, publicKeyBase64url);
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

// ─── Class A WebAuthn signoff (offline) ─────────────────────────────────────

// Build a real assertion over a context with a local P-256 key — same shape
// a platform authenticator produces.
/**
 * @param {{
 *   tamperContext?: Record<string, string> | null,
 *   flags?: number,
 *   type?: string,
 *   rpId?: string,
 * }} [opts]
 */
function makeSignoff({ tamperContext = null, flags = 0x05, type = 'webauthn.get', rpId = 'emiliaprotocol.ai' } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const context = {
    ep_version: '1.0', context_type: 'ep.signoff.v1',
    action_hash: 'a'.repeat(64), nonce: 'sig_' + 'c'.repeat(32),
    approver: 'ep:approver:jchen', initiator: 'ent_agent_7',
    issued_at: '2026-06-09T17:21:05.000Z', expires_at: '2026-06-09T17:26:05.000Z',
  };
  const canon = (v) => {
    if (v === null || v === undefined) return JSON.stringify(v);
    if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
    if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`;
    return JSON.stringify(v);
  };
  const challenge = crypto.createHash('sha256').update(canon(context), 'utf8').digest().toString('base64url');
  const clientData = Buffer.from(JSON.stringify({ type, challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
  const authData = Buffer.concat([
    crypto.createHash('sha256').update(rpId, 'utf8').digest(),
    Buffer.from([flags]),
    Buffer.from([0, 0, 0, 9]),
  ]);
  const signed = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
  const signature = crypto.sign('sha256', signed, privateKey);
  return {
    signoff: {
      context: tamperContext ? { ...context, ...tamperContext } : context,
      webauthn: {
        authenticator_data: authData.toString('base64url'),
        client_data_json: clientData.toString('base64url'),
        signature: signature.toString('base64url'),
      },
    },
    spki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

test('verifyWebAuthnSignoff: accepts a valid device-key assertion', () => {
  const { signoff, spki } = makeSignoff();
  const r = verifyWebAuthnSignoff(signoff, spki, { rpId: 'emiliaprotocol.ai' });
  assert.equal(r.valid, true);
  assert.equal(r.checks.challenge_binding, true);
  assert.equal(r.checks.user_verified, true);
  assert.equal(r.checks.signature, true);
});

test('verifyWebAuthnSignoff: rejects a tampered action (challenge no longer binds)', () => {
  const { signoff, spki } = makeSignoff({ tamperContext: { action_hash: 'f'.repeat(64) } });
  const r = verifyWebAuthnSignoff(signoff, spki);
  assert.equal(r.checks.challenge_binding, false);
  assert.equal(r.valid, false);
});

test('verifyWebAuthnSignoff: rejects when user verification is unset', () => {
  const { signoff, spki } = makeSignoff({ flags: 0x01 });
  assert.equal(verifyWebAuthnSignoff(signoff, spki).valid, false);
});

test('verifyWebAuthnSignoff: rejects the wrong relying party', () => {
  const { signoff, spki } = makeSignoff({ rpId: 'evil.example' });
  const r = verifyWebAuthnSignoff(signoff, spki, { rpId: 'emiliaprotocol.ai' });
  assert.equal(r.checks.rp_id_hash, false);
  assert.equal(r.valid, false);
});
