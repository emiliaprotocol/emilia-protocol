/**
 * Equivalence + correctness tests for web.js (Web Crypto port).
 *
 * The browser verifier is only trustworthy if it agrees with the audited Node
 * verifier byte-for-byte. Every test below runs BOTH index.js (Node crypto)
 * and web.js (Web Crypto, available as globalThis.crypto in Node 18+) against
 * the SAME fixtures and asserts identical { valid, checks }. If the two ever
 * diverge, that's a bug in the port — caught here, before a buyer trusts a
 * green checkmark in their browser.
 *
 * Run: node --test packages/verify/web.test.js
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import * as nodeV from './index.js';
import * as webV from './web.js';

// Same recursive canonicalization the verifiers use, for building signed fixtures.
function canon(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`;
  }
  return JSON.stringify(v);
}

function makeReceipt(payload) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const sig = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey);
  return {
    doc: {
      '@version': 'EP-RECEIPT-v1',
      payload,
      signature: { algorithm: 'Ed25519', value: sig.toString('base64url') },
    },
    spki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

function makeCommitmentProof() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const commitment = {
    domain: 'demo',
    subject: 'vendor:VEND-9821',
    claim_hash: 'a'.repeat(64),
  };
  const sig = crypto.sign(null, Buffer.from(canon(commitment), 'utf8'), privateKey);
  return {
    proof: {
      '@version': 'EP-PROOF-v1',
      claim: { domain: 'demo' },
      commitment,
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      signature: { algorithm: 'Ed25519', value: sig.toString('base64url') },
    },
    spki: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

// Mirrors test.js makeSignoff — a real P-256 assertion over an EP context.
function makeSignoff({ tamperContext = null, flags = 0x05, type = 'webauthn.get', rpId = 'emiliaprotocol.ai' } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const context = {
    ep_version: '1.0', context_type: 'ep.signoff.v1',
    action_hash: 'a'.repeat(64), nonce: 'sig_' + 'c'.repeat(32),
    approver: 'ep:approver:jchen', initiator: 'ent_agent_7',
    issued_at: '2026-06-09T17:21:05.000Z', expires_at: '2026-06-09T17:26:05.000Z',
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

// Assert the two implementations agree, and (optionally) on a specific validity.
async function assertEquivalentReceipt(doc, spki, expectValid) {
  const a = nodeV.verifyReceipt(doc, spki);
  const b = await webV.verifyReceipt(doc, spki);
  assert.deepEqual(b.checks, a.checks, 'receipt checks must match Node');
  assert.equal(b.valid, a.valid, 'receipt validity must match Node');
  if (expectValid !== undefined) assert.equal(b.valid, expectValid);
}

async function assertEquivalentSignoff(signoff, spki, opts, expectValid) {
  const a = nodeV.verifyWebAuthnSignoff(signoff, spki, opts);
  const b = await webV.verifyWebAuthnSignoff(signoff, spki, opts);
  assert.deepEqual(b.checks, a.checks, 'signoff checks must match Node');
  assert.equal(b.valid, a.valid, 'signoff validity must match Node');
  if (expectValid !== undefined) assert.equal(b.valid, expectValid);
}

async function assertEquivalentProof(proof, spki, opts, expectValid) {
  const a = nodeV.verifyCommitmentProof(proof, spki, opts);
  const b = await webV.verifyCommitmentProof(proof, spki, opts);
  assert.deepEqual(b, a, 'proof result must match Node');
  if (expectValid !== undefined) assert.equal(b.valid, expectValid);
}

// ─── runtime guard ───────────────────────────────────────────────────────────

test('web port reports Web Crypto support in this runtime', () => {
  assert.equal(webV.isSupported(), true);
});

// ─── receipts (Ed25519) ────────────────────────────────────────────────────

test('receipt: valid — both verifiers accept, identically', async () => {
  const { doc, spki } = makeReceipt({ receipt_id: 'tr_web', issuer: 'demo', created_at: '2026-06-10T00:00:00Z' });
  await assertEquivalentReceipt(doc, spki, true);
});

test('receipt: nested payload — both accept (recursive canonicalization parity)', async () => {
  const { doc, spki } = makeReceipt({
    receipt_id: 'tr_nested',
    context: { amount: 82000, change: { after_bank_hash: 'x'.repeat(64) }, risk_signals: ['new_destination', 'after_hours'] },
    issuer: 'demo',
  });
  await assertEquivalentReceipt(doc, spki, true);
});

test('receipt: key-order-independent — reordered payload still verifies in both', async () => {
  const { doc, spki } = makeReceipt({ a: 1, z: 2, m: { y: 9, b: 8 } });
  // Re-serialize the payload object with shuffled key order; canonical bytes are identical.
  const shuffled = { z: doc.payload.z, m: { b: doc.payload.m.b, y: doc.payload.m.y }, a: doc.payload.a };
  await assertEquivalentReceipt({ ...doc, payload: shuffled }, spki, true);
});

test('receipt: tampered payload — both reject, identically', async () => {
  const { doc, spki } = makeReceipt({ receipt_id: 'tr_t', issuer: 'demo' });
  const tampered = { ...doc, payload: { ...doc.payload, receipt_id: 'tr_HACKED' } };
  await assertEquivalentReceipt(tampered, spki, false);
});

test('receipt: wrong key — both reject', async () => {
  const { doc } = makeReceipt({ receipt_id: 'tr_k', issuer: 'demo' });
  const { spki: otherKey } = makeReceipt({ receipt_id: 'other', issuer: 'demo' });
  await assertEquivalentReceipt(doc, otherKey, false);
});

test('receipt: bad version — both reject with same error path', async () => {
  const a = nodeV.verifyReceipt({ '@version': 'NOPE', payload: {}, signature: { value: 'x', algorithm: 'Ed25519' } }, 'AA');
  const b = await webV.verifyReceipt({ '@version': 'NOPE', payload: {}, signature: { value: 'x', algorithm: 'Ed25519' } }, 'AA');
  assert.equal(a.valid, false);
  assert.equal(b.valid, false);
  assert.deepEqual(b.checks, a.checks);
});

// ─── Merkle anchor ────────────────────────────────────────────────────────────

test('merkle anchor: valid inclusion proof — both reconstruct the root', async () => {
  const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
  const hashPair = (x, y) => { const s = [x, y].sort(); return sha(s[0] + s[1]); };
  const leaf = sha('leaf-receipt');
  const sib1 = sha('sibling-1');
  const lvl1 = hashPair(leaf, sib1);
  const sib2 = sha('sibling-2');
  const root = hashPair(lvl1, sib2);
  const proof = [{ hash: sib1, position: 'right' }, { hash: sib2, position: 'right' }];

  assert.equal(nodeV.verifyMerkleAnchor(leaf, proof, root), true);
  assert.equal(await webV.verifyMerkleAnchor(leaf, proof, root), true);
  // tampered sibling → both false
  const badProof = [{ hash: sha('evil'), position: 'right' }, { hash: sib2, position: 'right' }];
  assert.equal(nodeV.verifyMerkleAnchor(leaf, badProof, root), false);
  assert.equal(await webV.verifyMerkleAnchor(leaf, badProof, root), false);
});

// ─── commitment proofs (Ed25519) ───────────────────────────────────────────────

test('commitment proof: signed proof — both accept', async () => {
  const { proof, spki } = makeCommitmentProof();
  await assertEquivalentProof(proof, spki, undefined, true);
});

test('commitment proof: unsigned proof — both reject by default', async () => {
  const proof = {
    '@version': 'EP-PROOF-v1',
    claim: { domain: 'demo' },
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  };
  await assertEquivalentProof(proof, undefined, undefined, false);
});

test('commitment proof: unsigned proof — explicit structure-only mode matches', async () => {
  const proof = {
    '@version': 'EP-PROOF-v1',
    claim: { domain: 'demo' },
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  };
  await assertEquivalentProof(proof, undefined, { allowUnsigned: true }, true);
});

// ─── Class A WebAuthn signoff (ECDSA P-256, DER→raw conversion) ──────────────

test('signoff: valid device assertion — both verifiers accept, identically', async () => {
  const { signoff, spki } = makeSignoff();
  await assertEquivalentSignoff(signoff, spki, { rpId: 'emiliaprotocol.ai' }, true);
});

test('signoff: tampered action — both reject (challenge no longer binds)', async () => {
  const { signoff, spki } = makeSignoff({ tamperContext: { action_hash: 'f'.repeat(64) } });
  await assertEquivalentSignoff(signoff, spki, {}, false);
});

test('signoff: no user verification — both reject', async () => {
  const { signoff, spki } = makeSignoff({ flags: 0x01 });
  await assertEquivalentSignoff(signoff, spki, {}, false);
});

test('signoff: wrong relying party — both reject', async () => {
  const { signoff, spki } = makeSignoff({ rpId: 'evil.example' });
  await assertEquivalentSignoff(signoff, spki, { rpId: 'emiliaprotocol.ai' }, false);
});

test('signoff: run 12 random key pairs — DER→raw conversion never diverges', async () => {
  // The DER→raw P-256 conversion is the only place the browser path differs from
  // Node. Exercise it across many signatures (variable r/s lengths, leading
  // zero bytes) to be confident the conversion is exact.
  for (let i = 0; i < 12; i++) {
    const { signoff, spki } = makeSignoff();
    await assertEquivalentSignoff(signoff, spki, { rpId: 'emiliaprotocol.ai' }, true);
  }
});
