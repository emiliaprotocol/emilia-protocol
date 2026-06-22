// SPDX-License-Identifier: Apache-2.0
// Generator for executable EP §6.2 Trust Receipt conformance vectors. Mints REAL
// receipts via packages/issue (Class-A WebAuthn signoff + Ed25519 log checkpoint +
// Merkle inclusion), so JS, Python, and Go verify the SAME bytes identically.
// Run: node generate-trustreceipt.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import {
  buildContexts, collectSignoffs, assembleAuthorizationReceipt,
  policyHash as computePolicyHash, generateEd25519KeyPair,
} from '../../packages/issue/index.js';

const ISSUED_AT = '2026-06-13T11:00:00.000Z';
const EXPIRES_AT = '2026-06-13T18:00:00.000Z';
const COMMITTED_AT = '2026-06-13T11:30:00.000Z';
const FLAG_UP = 0x01; const FLAG_UV = 0x04;

function newP256() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, publicKeyB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
function classASigner({ approverKeyId, privateKey, signedAt }) {
  return {
    approverKeyId, keyClass: 'A', signedAt,
    signWebAuthn: (digest) => {
      const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: Buffer.from(digest).toString('base64url'), origin: 'https://test.emilia', crossOrigin: false }), 'utf8');
      const ad = Buffer.concat([crypto.createHash('sha256').update('rp').digest(), Buffer.from([FLAG_UP | FLAG_UV]), Buffer.from([0, 0, 0, 1])]);
      const signed = Buffer.concat([ad, crypto.createHash('sha256').update(cd).digest()]);
      return { authenticator_data: ad.toString('base64url'), client_data_json: cd.toString('base64url'), signature: crypto.sign('sha256', signed, privateKey).toString('base64url') };
    },
  };
}

async function mint(actionParams) {
  const action = { action_type: 'payment.release', policy_id: 'pol:test', initiator: 'ep:agent:1', params: actionParams };
  const kp = newP256(); const logKp = generateEd25519KeyPair();
  const contexts = buildContexts({ action, policyHash: computePolicyHash({ policy_id: action.policy_id }), approvers: ['ep:approver:dir'], requiredApprovals: 1, issuedAt: ISSUED_AT, expiresAt: EXPIRES_AT });
  const signoffs = await collectSignoffs(contexts, [classASigner({ approverKeyId: 'ep:key:dir#1', signedAt: ISSUED_AT, privateKey: kp.privateKey })]);
  const receipt = assembleAuthorizationReceipt({ receiptId: `ep:receipt:${crypto.randomBytes(8).toString('base64url')}`, action, contexts, signoffs, committedAt: COMMITTED_AT, log: { privateKey: logKp.privateKey, logKeyId: 'ep:log:test#1' } });
  const verification = { approver_keys: { 'ep:key:dir#1': { public_key: kp.publicKeyB64u, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2036-01-01T00:00:00Z' } }, log_public_key: logKp.publicKeyB64u };
  return { receipt, verification };
}

const V = [];
const add = (id, expectValid, trust_receipt, verification) => V.push({ id, expect: { valid: expectValid }, trust_receipt, verification });

const valid = await mint({ amount: 82000, currency: 'USD' });
add('accept_valid_receipt', true, valid.receipt, valid.verification);

{ // tamper an action parameter after signing → recomputed action_hash mismatch
  const m = await mint({ amount: 82000, currency: 'USD' });
  m.receipt.action = { ...m.receipt.action, params: { amount: 820000, currency: 'USD' } };
  add('reject_tampered_action', false, m.receipt, m.verification);
}
{ // verifier pins a DIFFERENT log key → checkpoint signature fails
  const m = await mint({ amount: 82000, currency: 'USD' });
  m.verification.log_public_key = generateEd25519KeyPair().publicKeyB64u;
  add('reject_wrong_log_key', false, m.receipt, m.verification);
}
{ // tamper the Merkle inclusion path → inclusion proof fails
  const m = await mint({ amount: 82000, currency: 'USD' });
  if (m.receipt.log_proof?.inclusion_path?.[0]) {
    m.receipt.log_proof.inclusion_path[0].hash = crypto.createHash('sha256').update('evil').digest('hex');
  } else {
    m.receipt.log_proof = { ...m.receipt.log_proof, inclusion_path: [{ hash: crypto.createHash('sha256').update('evil').digest('hex'), position: 'right' }] };
  }
  add('reject_broken_inclusion', false, m.receipt, m.verification);
}

const suite = {
  suite: 'EP-TRUST-RECEIPT-v1 (§6.2)',
  profile: 'Executable §6.2 Trust Receipt vectors (real Class-A WebAuthn + Ed25519 log checkpoint + Merkle inclusion). verifyTrustReceipt(receipt, {approverKeys, logPublicKey}) must return expect.valid.',
  vectors_version: '1.0.0',
  count: V.length,
  vectors: V,
};
writeFileSync(new URL('./trust-receipt.exec.v1.json', import.meta.url), JSON.stringify(suite, null, 2) + '\n');
console.log(`wrote trust-receipt.exec.v1.json — ${V.length} vectors`);
