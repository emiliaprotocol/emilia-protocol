// SPDX-License-Identifier: Apache-2.0
//
// EP × x402 demand-side rail. Proves: the 402 challenge is x402-shaped; a valid
// EP-ENVELOPE proof (registry-verified) and a valid bare EP-RECEIPT-v1 both
// release; and missing / malformed / wrong-action / unpinned proofs fail closed.

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { x402ReceiptChallenge, decodeX402Payment, verifyX402Proof, X402_VERSION, EP_X402_SCHEME } from '../lib/require-receipt/x402.js';
import { migrate } from '../lib/envelope/index.js';
import { buildRevocation } from '../lib/revocation/revocation.js';

function ed25519() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, publicKeyB64u: publicKey.export({ format: 'der', type: 'spki' }).toString('base64url') };
}
// Mirror @emilia-protocol/require-receipt's canonicalizer for minting test receipts.
function canon(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`;
  return JSON.stringify(v);
}
function mintReceipt(action, outcome, kp) {
  const payload = { receipt_id: 'r_test', subject: 'agent:demo', created_at: new Date().toISOString(), claim: { action_type: action, outcome } };
  const sig = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), kp.privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { value: sig }, public_key: kp.publicKeyB64u };
}
const b64 = (o) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64');

describe('EP × x402 — challenge', () => {
  it('is x402-shaped and names the accepted proofs', () => {
    const c = x402ReceiptChallenge({ action: 'demo.delete', resource: '/x' });
    expect(c.x402Version).toBe(X402_VERSION);
    expect(c.accepts[0].scheme).toBe(EP_X402_SCHEME);
    expect(c.accepts[0].extra.accepted_proofs).toEqual(['EP-ENVELOPE-v1', 'EP-RECEIPT-v1']);
    expect(c.accepts[0].extra.action_type).toBe('demo.delete');
    expect(c.accepts[0].extra.registry).toBe('/.well-known/ep-profiles.json');
  });
  it('decodeX402Payment returns null on garbage', () => {
    expect(decodeX402Payment('!!!not-base64-json')).toBeNull();
    expect(decodeX402Payment('')).toBeNull();
  });
});

describe('EP × x402 — verify proof (fail closed)', () => {
  it('releases on a valid EP-ENVELOPE proof (registry-verified)', () => {
    const rk = ed25519();
    const REVOKER = 'ep:org:t';
    const TARGET = { target_type: 'receipt', target_id: 'x', action_hash: 'sha256:' + '1'.repeat(64) };
    const stmt = buildRevocation({ target: TARGET, revoker_id: REVOKER, reason: 'r', signer: { privateKey: rk.privateKey, publicKeyB64u: rk.publicKeyB64u } });
    const env = migrate(stmt, 'urn:ep:profile:revocation:v1');
    const r = verifyX402Proof(b64(env), { target: TARGET, revokerKeys: { [REVOKER]: { public_key: rk.publicKeyB64u } } });
    expect(r.ok).toBe(true);
    expect(r.profile).toBe('urn:ep:profile:revocation:v1');
    expect(r.settlement.success).toBe(true);
  });
  it('fails closed on an EP-ENVELOPE with an unpinned key', () => {
    const rk = ed25519();
    const REVOKER = 'ep:org:t';
    const TARGET = { target_type: 'receipt', target_id: 'x', action_hash: 'sha256:' + '1'.repeat(64) };
    const stmt = buildRevocation({ target: TARGET, revoker_id: REVOKER, reason: 'r', signer: { privateKey: rk.privateKey, publicKeyB64u: rk.publicKeyB64u } });
    const env = migrate(stmt, 'urn:ep:profile:revocation:v1');
    expect(verifyX402Proof(b64(env), { target: TARGET, revokerKeys: {} }).valid).toBe(false);
  });

  it('releases on a valid, action-bound bare EP-RECEIPT-v1', () => {
    const kp = ed25519();
    const doc = mintReceipt('demo.delete_production_database', 'allow_with_signoff', kp);
    const r = verifyX402Proof(b64(doc), { allowInlineKey: true, action: 'demo.delete_production_database', allowedOutcomes: ['allow', 'allow_with_signoff'] });
    expect(r.ok).toBe(true);
    expect(r.profile).toBe('urn:ep:profile:receipt:v1');
  });
  it('rejects a bare receipt bound to the WRONG action', () => {
    const kp = ed25519();
    const doc = mintReceipt('other.action', 'allow', kp);
    const r = verifyX402Proof(b64(doc), { allowInlineKey: true, action: 'demo.delete_production_database' });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('action_mismatch');
  });
  it('rejects missing / malformed / unrecognized proofs', () => {
    expect(verifyX402Proof(null).valid).toBe(false);
    expect(verifyX402Proof('!!!').valid).toBe(false);
    expect(verifyX402Proof(b64({ hello: 'world' })).reason).toBe('unrecognized_proof');
  });
});
