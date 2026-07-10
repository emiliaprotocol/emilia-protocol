// SPDX-License-Identifier: Apache-2.0
// Generator for executable EP §6.2 Trust Receipt conformance vectors. Mints REAL
// receipts via packages/issue (Class-A WebAuthn signoff + Ed25519 log checkpoint +
// Merkle inclusion), so JS, Python, and Go verify the SAME bytes identically.
// Run: node generate-trustreceipt.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import {
  buildContexts, collectSignoffs, assembleAuthorizationReceipt,
  assembleAuthorizationReceiptLegacyV1,
  policyHash as computePolicyHash, generateEd25519KeyPair,
  softwareSignerFromPrivateKey,
} from '../../packages/issue/index.js';
import { canonicalize } from '../../packages/verify/index.js';

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

async function mint(actionParams, { legacy = false, downgradeClassA = false } = {}) {
  const action = { action_type: 'payment.release', policy_id: 'pol:test', initiator: 'ep:agent:1', params: actionParams };
  const logKp = generateEd25519KeyPair();
  const contexts = buildContexts({ action, policyHash: computePolicyHash({ policy_id: action.policy_id }), approvers: ['ep:approver:dir'], requiredApprovals: 1, issuedAt: ISSUED_AT, expiresAt: EXPIRES_AT });

  // Downgrade-attack construction: the signoff is a bare Ed25519 Class-B software
  // signature (NO WebAuthn), but the verifier PINS the same key as Class-A. A
  // verifier that lets the attacker-declared signoff key_class win would take the
  // Class-B path and accept the bare signature; the correct rule is that the
  // PINNED key class is authoritative, forcing the Class-A WebAuthn path, which
  // finds no assertion and rejects. See index.js verifyTrustReceipt.
  let signoffs; let approverPublicKeyB64u; let pinnedKeyClass;
  if (downgradeClassA) {
    const edKp = generateEd25519KeyPair();
    signoffs = await collectSignoffs(contexts, [softwareSignerFromPrivateKey({
      privateKey: edKp.privateKey, approverKeyId: 'ep:key:dir#1', signedAt: ISSUED_AT, keyClass: 'B',
    })]);
    approverPublicKeyB64u = edKp.publicKeyB64u;
    pinnedKeyClass = 'A'; // pinned Class-A; the signoff declares 'B' with a bare signature
  } else {
    const kp = newP256();
    signoffs = await collectSignoffs(contexts, [classASigner({ approverKeyId: 'ep:key:dir#1', signedAt: ISSUED_AT, privateKey: kp.privateKey })]);
    approverPublicKeyB64u = kp.publicKeyB64u;
    pinnedKeyClass = 'A';
  }
  const assemble = legacy ? assembleAuthorizationReceiptLegacyV1 : assembleAuthorizationReceipt;
  const receipt = assemble({ receiptId: `ep:receipt:${crypto.randomBytes(8).toString('base64url')}`, action, contexts, signoffs, committedAt: COMMITTED_AT, log: { privateKey: logKp.privateKey, logKeyId: 'ep:log:test#1' } });
  const verification = { approver_keys: { 'ep:key:dir#1': { approver_id: 'ep:approver:dir', public_key: approverPublicKeyB64u, key_class: pinnedKeyClass, valid_from: '2026-01-01T00:00:00Z', valid_to: '2036-01-01T00:00:00Z' } }, log_public_key: logKp.publicKeyB64u };
  return { receipt, verification, logPrivateKey: logKp.privateKey };
}

const V = [];
const add = (id, expectValid, trust_receipt, verification, verify_opts) =>
  V.push({ id, expect: { valid: expectValid }, trust_receipt, verification, ...(verify_opts ? { verify_opts } : {}) });

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
{ // §6.2 migration: a v2 receipt is accepted (alg == EP-MERKLE-v2 by default)
  const m = await mint({ amount: 500, currency: 'USD' });
  if (m.receipt.log_proof.alg !== 'EP-MERKLE-v2') throw new Error('expected v2 anchor from default issuance');
  add('accept_v2_inclusion', true, m.receipt, m.verification);
}
{ // legacy v1 anchor is REFUSED by default (no allowLegacyMerkle) — the core fix
  const m = await mint({ amount: 500, currency: 'USD' }, { legacy: true });
  if (m.receipt.log_proof.alg) throw new Error('legacy v1 must not carry a v2 alg marker');
  add('reject_legacy_v1_by_default', false, m.receipt, m.verification);
}
{ // same legacy v1 anchor VERIFIES when the caller explicitly opts in
  const m = await mint({ amount: 500, currency: 'USD' }, { legacy: true });
  add('accept_legacy_v1_when_opted_in', true, m.receipt, m.verification, { allowLegacyMerkle: true });
}
{ // I-JSON gate: a non-representable number in signed material is rejected fail-closed
  const m = await mint({ amount: 82000, currency: 'USD' });
  m.receipt.action.params.rate = 1e-7; // outside the EP canonicalization profile
  m.receipt.action_hash = `sha256:${crypto.createHash('sha256').update('x').digest('hex')}`;
  add('reject_non_canonicalizable_number', false, m.receipt, m.verification);
}
{ // empty-path degenerate: an empty inclusion_path folds to leaf == root, which is
  // only a true inclusion statement for a SINGLE-LEAF tree. The checkpoint here is
  // RE-SIGNED with the real log key after forging tree_size, so the ONLY refusing
  // check is the empty-path rule: a verifier WITHOUT the rule would accept this
  // receipt as "included" in a claimed 4-leaf tree whose root merely repeats the
  // leaf hash. Must refuse: "empty inclusion_path requires checkpoint tree_size 1".
  const m = await mint({ amount: 82000, currency: 'USD' });
  if (m.receipt.log_proof.inclusion_path.length !== 0) throw new Error('expected single-leaf receipt (empty inclusion_path)');
  const cp = { ...m.receipt.log_proof.checkpoint };
  delete cp.log_signature;
  cp.tree_size = 4;
  const log_signature = crypto.sign(null, crypto.createHash('sha256').update(canonicalize(cp), 'utf8').digest(), m.logPrivateKey).toString('base64url');
  m.receipt.log_proof.checkpoint = { ...cp, log_signature };
  add('reject_empty_path_tree_size_not_1', false, m.receipt, m.verification);
}
{ // empty-path degenerate: a single-leaf tree has exactly one index, 0. leaf_index
  // sits OUTSIDE the signed checkpoint, so this mutation leaves every signature
  // valid — only the empty-path rule refuses. Must refuse:
  // "empty inclusion_path requires leaf_index 0 in a single-leaf tree".
  const m = await mint({ amount: 82000, currency: 'USD' });
  if (m.receipt.log_proof.inclusion_path.length !== 0) throw new Error('expected single-leaf receipt (empty inclusion_path)');
  m.receipt.log_proof.leaf_index = 1;
  add('reject_empty_path_nonzero_leaf_index', false, m.receipt, m.verification);
}
{ // Class-A downgrade: the pinned key entry is Class-A, but the signoff declares
  // key_class:'B' and carries only a bare Ed25519 signature (no WebAuthn). The
  // PINNED class is authoritative, so the verifier MUST take the Class-A WebAuthn
  // path, find no assertion, and reject. A verifier that let the attacker-declared
  // signoff key_class win would accept the bare signature — the downgrade this
  // vector locks out. Every OTHER check (action_hash, commitments, inclusion,
  // checkpoint, windows) is intact; the ONLY refusing check is signoff_signatures.
  const m = await mint({ amount: 82000, currency: 'USD' }, { downgradeClassA: true });
  if (m.receipt.signoffs[0].key_class !== 'B') throw new Error('expected signoff to declare key_class B');
  if (m.receipt.signoffs[0].webauthn) throw new Error('expected a bare (non-WebAuthn) Class-B signoff');
  if (m.verification.approver_keys['ep:key:dir#1'].key_class !== 'A') throw new Error('expected the pinned key to be Class-A');
  add('reject_pinned_class_a_bare_signature_downgrade', false, m.receipt, m.verification);
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
