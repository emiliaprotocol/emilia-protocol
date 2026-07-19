// SPDX-License-Identifier: Apache-2.0
//
// EP-RELIANCE-KERNEL-v1 — a $50,000 bank wire release.
//
//   node examples/reliance/bank-wire.mjs
//
// A bank will not move money on "a receipt exists." It relies only when the WHOLE
// evidence packet is admissible under ITS OWN pinned rule:
//   identity + a device-bound Class-A ceremony + scoped CFO authority
//   + policy match + a fresh revocation check + an unconsumed one-time gate.
// This runs the composition offline, no account, no database, and shows the wire
// REFUSED (a distinct closed verdict) until every leg composes to `rely`.
import crypto from 'node:crypto';
import { evaluateReliance } from '../../packages/verify/reliance.js';
import { signAuthorityProof } from '../../lib/authority/proof.js';

// ── canonicalization + hashing (byte-identical to the verifier) ──────────────
const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));
const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const leafV2 = (p) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(p, 'utf8')])).digest('hex');
const pairV2 = (l, r) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([1]), Buffer.from(l, 'utf8'), Buffer.from(r, 'utf8')])).digest('hex');
const ed = () => { const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519'); return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') }; };
const p256 = () => { const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') }; };

const logKey = ed();
const controller = ed();
const cfo = p256();               // Class-A device (WebAuthn)
const registryKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from('c1'.repeat(32), 'hex')]), format: 'der', type: 'pkcs8' });
const registryPub = crypto.createPublicKey(registryKey).export({ type: 'spki', format: 'der' }).toString('base64url');

function signA(digestHex) {
  const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
  const authData = Buffer.concat([crypto.createHash('sha256').update('www.emiliaprotocol.ai').digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]);
  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
  const signature = crypto.sign('sha256', signedData, cfo.privateKey);
  return { authenticator_data: authData.toString('base64url'), client_data_json: clientDataJSON.toString('base64url'), signature: signature.toString('base64url') };
}

function buildReceipt() {
  const action = { ep_version: '1.0', action_type: 'wire.release', organization_id: 'acme', target: { system: 'treasury', resource: 'wire/8841' }, parameters: { amount: '50000.00', currency: 'USD' }, initiator: 'ep:entity:agent-treasury-7', policy_id: 'ep:policy:wires-over-100k@v12', requested_at: '2026-06-09T17:21:04Z' };
  const action_hash = `sha256:${sha(canon(action))}`;
  const base = { ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash, policy_id: 'ep:policy:wires-over-100k@v12', policy_hash: 'sha256:77ab1234', initiator: action.initiator, required_approvals: 2, issued_at: '2026-06-09T17:21:05Z', expires_at: '2026-06-09T17:36:05Z' };
  const ctx1 = { ...base, approver: 'ep:approver:jchen-controller', approver_index: 1, nonce: 'n-1' };
  const ctx2 = { ...base, approver: 'ep:approver:mrios-cfo', approver_index: 2, nonce: 'n-2' };
  const d1 = sha(canon(ctx1)); const d2 = sha(canon(ctx2));
  const signoffs = [
    { context_hash: `sha256:${d1}`, signature: crypto.sign(null, Buffer.from(d1, 'hex'), controller.privateKey).toString('base64url'), key_class: 'B', approver_key_id: 'ep:key:controller#1', signed_at: '2026-06-09T17:24:40Z' },
    { context_hash: `sha256:${d2}`, signature: 'unused', key_class: 'A', approver_key_id: 'ep:key:cfo#1', signed_at: '2026-06-09T17:25:01Z', webauthn: signA(d2) },
  ];
  const receipt = { receipt_id: 'ep:receipt:wire-8841', action, action_hash, contexts: [ctx1, ctx2], signoffs, consumption: { nonce: 'n-consume', state: 'COMMITTED', committed_at: '2026-06-09T17:25:02Z' } };
  const leaf = leafV2(canon(receipt));
  const root = pairV2(pairV2(leaf, sha('s1')), sha('s2'));
  const checkpoint = { tree_size: 4, root_hash: `sha256:${root}`, log_key_id: 'ep:log:1', merkle_alg: 'EP-MERKLE-v2' };
  const log_signature = crypto.sign(null, crypto.createHash('sha256').update(canon(checkpoint), 'utf8').digest(), logKey.privateKey).toString('base64url');
  receipt.log_proof = { alg: 'EP-MERKLE-v2', leaf_hash: `sha256:${leaf}`, leaf_index: 0, inclusion_path: [{ hash: sha('s1'), position: 'right' }, { hash: sha('s2'), position: 'right' }], checkpoint: { ...checkpoint, log_signature } };
  return receipt;
}

const receipt = buildReceipt();
const NOW = Date.parse('2026-07-07T00:00:00.000Z');
const KEYS = {
  'ep:key:controller#1': { approver_id: 'ep:approver:jchen-controller', public_key: controller.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
  'ep:key:cfo#1': { approver_id: 'ep:approver:mrios-cfo', public_key: cfo.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
};
const opts = { approverKeys: KEYS, logPublicKey: logKey.pub, rpId: 'www.emiliaprotocol.ai', isConsumed: () => false };

// The BANK's pinned reliance rule for releasing a wire.
const bankProfile = {
  '@type': 'EP-RELIANCE-PROFILE-v1',
  required_assurance: 'class_a',
  required_authority: true,
  max_revocation_staleness_sec: 300,
  accepted_registry_keys: [{ issuer_id: 'auth_cfo', organization_id: 'acme', public_key: registryPub, min_epoch: 17, registry_head: 'sha256:' + '11'.repeat(32) }],
  accepted_issuer_keys: [logKey.pub],
  accepted_policy_hashes: ['sha256:77ab1234'],
  required_evidence: ['receipt', 'class_a_or_quorum', 'authority_proof', 'revocation_freshness', 'consumption_proof'],
};

const action = { action_type: 'wire.release', amount: 50000, currency: 'USD', organization_id: 'acme', policy_hash: 'sha256:77ab1234', action_hash: receipt.action_hash };
const cfoAuthorityProof = signAuthorityProof({
  authority_id: 'auth_cfo', subject: 'ep:approver:mrios-cfo', organization_id: 'acme', role: 'cfo',
  scope: ['wire.release'], limits: { max_amount_usd: 50000, currency: 'USD' },
  validity: { from: '2026-01-01T00:00:00.000Z', to: '2027-01-01T00:00:00.000Z' },
  revocation: { status: 'not_revoked', checked_at: '2026-07-06T23:59:00.000Z' },
  registry_head: 'sha256:' + '11'.repeat(32), registry_epoch: 17, policy_hash: 'sha256:77ab1234', issued_at: '2026-07-06T23:59:00.000Z',
}, registryKey);
const underScopedCfoAuthorityProof = signAuthorityProof({
  authority_id: 'auth_cfo', subject: 'ep:approver:mrios-cfo', organization_id: 'acme', role: 'cfo',
  scope: ['wire.release'], limits: { max_amount_usd: 40000, currency: 'USD' },
  validity: { from: '2026-01-01T00:00:00.000Z', to: '2027-01-01T00:00:00.000Z' },
  revocation: { status: 'not_revoked', checked_at: '2026-07-06T23:59:00.000Z' },
  registry_head: 'sha256:' + '11'.repeat(32), registry_epoch: 17, policy_hash: 'sha256:77ab1234', issued_at: '2026-07-06T23:59:00.000Z',
}, registryKey);
const staleCfoAuthorityProof = signAuthorityProof({
  authority_id: 'auth_cfo', subject: 'ep:approver:mrios-cfo', organization_id: 'acme', role: 'cfo',
  scope: ['wire.release'], limits: { max_amount_usd: 50000, currency: 'USD' },
  validity: { from: '2026-01-01T00:00:00.000Z', to: '2027-01-01T00:00:00.000Z' },
  revocation: { status: 'not_revoked', checked_at: '2026-01-01T00:00:00.000Z' },
  registry_head: 'sha256:' + '11'.repeat(32), registry_epoch: 17, policy_hash: 'sha256:77ab1234', issued_at: '2026-07-06T23:59:00.000Z',
}, registryKey);

function rely(input) { return evaluateReliance({ ...input, relying_party_profile: bankProfile, now: NOW }, opts); }
const line = (label, verdict) => console.log(`${(verdict === 'rely' ? 'RELEASE ' : 'REFUSE  ')} ${label.padEnd(46)} → ${verdict}`);

console.log('\n$50,000 wire release — the bank relies only when the whole packet composes.\n');

// Each attempt is the same wire, missing exactly one leg the bank pinned.
const attempts = [
  ['receipt only, no scoped authority', { action, receipt, revocation_state: { checked_at: '2026-07-06T23:58:00.000Z' }, consumption: { consumed: false } }],
  ['signed amount exceeds authority ceiling', { action, receipt, authority_proof: underScopedCfoAuthorityProof, revocation_state: { checked_at: '2026-07-06T23:58:00.000Z' }, consumption: { consumed: false } }],
  ['authority ok but revocation check is stale', { action, receipt, authority_proof: staleCfoAuthorityProof, consumption: { consumed: false } }],
  ['everything ok but already consumed', { action, receipt, authority_proof: cfoAuthorityProof, revocation_state: { checked_at: '2026-07-06T23:58:00.000Z' }, consumption: { consumed: true } }],
  ['ALL legs compose', { action, receipt, authority_proof: cfoAuthorityProof, revocation_state: { checked_at: '2026-07-06T23:58:00.000Z' }, consumption: { consumed: false } }],
];

const results = attempts.map(([label, input]) => { const v = rely(input).verdict; line(label, v); return v; });

const expected = ['do_not_rely_authority_missing', 'do_not_rely_amount_exceeded', 'do_not_rely_stale_revocation', 'do_not_rely_already_consumed', 'rely'];
const ok = results.every((v, i) => v === expected[i]);
console.log(`\n${ok ? 'OK — the wire releases ONLY when identity + Class-A + scoped authority + policy + fresh revocation + unconsumed gate all compose to `rely`.' : 'FAILED — reliance composition is wrong.'}`);
process.exit(ok ? 0 : 1);
