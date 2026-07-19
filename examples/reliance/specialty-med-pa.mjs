// SPDX-License-Identifier: Apache-2.0
//
// EP-RELIANCE-KERNEL-v1 — specialty medication prior authorization.
//
//   node examples/reliance/specialty-med-pa.mjs
//
// The healthcare wedge, run offline. A specialty-drug PA determination is not
// something a pharmacy, PBM, or hub should dispense on because "an approval
// exists." It relies only when the WHOLE evidence packet is admissible under the
// relying party's OWN pinned rule:
//   identity + a device-bound reviewer ceremony + scoped payer/prescriber
//   authority for THIS drug + the pinned benefit policy + a fresh eligibility
//   (revocation) check + a one-time, unconsumed authorization.
//
// PUBLIC-SAFE: fully synthetic. No PHI, no real member/prescriber identifiers,
// no real drug/plan. This rides BESIDE an NCPDP transaction (its digest is bound
// into the action), it does not replace one.
import crypto from 'node:crypto';
import { evaluateReliance } from '../../packages/verify/reliance.js';
import { signAuthorityProof } from '../../lib/authority/proof.js';

const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));
const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const leafV2 = (p) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(p, 'utf8')])).digest('hex');
const pairV2 = (l, r) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([1]), Buffer.from(l, 'utf8'), Buffer.from(r, 'utf8')])).digest('hex');
const ed = () => { const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519'); return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') }; };
const p256 = () => { const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') }; };

const logKey = ed();                 // the hub / EHR transparency-log key
const intake = ed();                 // Class-B intake software (the agent that filed the PA)
const reviewer = p256();             // Class-A device: the payer medical reviewer
const registryKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from('a7'.repeat(32), 'hex')]), format: 'der', type: 'pkcs8' });
const registryPub = crypto.createPublicKey(/** @type {any} */ (registryKey)).export({ type: 'spki', format: 'der' }).toString('base64url');

// A synthetic NCPDP transaction the PA determination rides beside. Only its
// digest is bound into the action — no transaction contents leave the rail.
const NCPDP_TXN_DIGEST = 'sha256:' + sha('ncpdp:script:synthetic-pa-request:2026-07-07');
const BENEFIT_POLICY_HASH = 'sha256:' + sha('payer:benefit-policy:specialty-tier4:planX@v7');

function signA(digestHex) {
  const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
  const authData = Buffer.concat([crypto.createHash('sha256').update('www.emiliaprotocol.ai').digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]);
  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
  const signature = crypto.sign('sha256', signedData, reviewer.privateKey);
  return { authenticator_data: authData.toString('base64url'), client_data_json: clientDataJSON.toString('base64url'), signature: signature.toString('base64url') };
}

function buildPaReceipt() {
  const action = {
    ep_version: '1.0', action_type: 'rx.prior_auth.approve',
    organization_id: 'planX',
    target: { system: 'pbm.adjudication', resource: 'pa/specialty/synthetic-001' },
    parameters: { drug: 'SYNTHETIC-SPECIALTY-DRUG', ncpdp_txn: NCPDP_TXN_DIGEST },
    initiator: 'ep:entity:pa-intake-agent', policy_id: 'ep:policy:specialty-tier4-planX@v7',
    requested_at: '2026-07-07T14:00:00Z',
  };
  const action_hash = `sha256:${sha(canon(action))}`;
  const base = { ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash, policy_id: 'ep:policy:specialty-tier4-planX@v7', policy_hash: BENEFIT_POLICY_HASH, initiator: action.initiator, required_approvals: 2, issued_at: '2026-07-07T14:00:05Z', expires_at: '2026-07-07T14:15:05Z' };
  const ctx1 = { ...base, approver: 'ep:approver:intake-agent', approver_index: 1, nonce: 'n-1' };
  const ctx2 = { ...base, approver: 'ep:approver:payer-reviewer', approver_index: 2, nonce: 'n-2' };
  const d1 = sha(canon(ctx1)); const d2 = sha(canon(ctx2));
  const signoffs = [
    { context_hash: `sha256:${d1}`, signature: crypto.sign(null, Buffer.from(d1, 'hex'), intake.privateKey).toString('base64url'), key_class: 'B', approver_key_id: 'ep:key:intake#1', signed_at: '2026-07-07T14:03:40Z' },
    { context_hash: `sha256:${d2}`, signature: 'unused', key_class: 'A', approver_key_id: 'ep:key:reviewer#1', signed_at: '2026-07-07T14:04:01Z', webauthn: signA(d2) },
  ];
  const receipt = { receipt_id: 'ep:receipt:pa-specialty-001', action, action_hash, contexts: [ctx1, ctx2], signoffs, consumption: { nonce: 'n-pa-consume', state: 'COMMITTED', committed_at: '2026-07-07T14:04:02Z' } };
  const leaf = leafV2(canon(receipt));
  const root = pairV2(pairV2(leaf, sha('s1')), sha('s2'));
  const checkpoint = { tree_size: 4, root_hash: `sha256:${root}`, log_key_id: 'ep:log:hub#1', merkle_alg: 'EP-MERKLE-v2' };
  const log_signature = crypto.sign(null, crypto.createHash('sha256').update(canon(checkpoint), 'utf8').digest(), logKey.privateKey).toString('base64url');
  receipt.log_proof = { alg: 'EP-MERKLE-v2', leaf_hash: `sha256:${leaf}`, leaf_index: 0, inclusion_path: [{ hash: sha('s1'), position: 'right' }, { hash: sha('s2'), position: 'right' }], checkpoint: { ...checkpoint, log_signature } };
  return receipt;
}

const receipt = buildPaReceipt();
const NOW = Date.parse('2026-07-07T14:05:00.000Z');
const KEYS = {
  'ep:key:intake#1': { approver_id: 'ep:approver:intake-agent', public_key: intake.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
  'ep:key:reviewer#1': { approver_id: 'ep:approver:payer-reviewer', public_key: reviewer.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
};
const opts = { approverKeys: KEYS, logPublicKey: logKey.pub, rpId: 'www.emiliaprotocol.ai', isConsumed: () => false };

// The PHARMACY's / hub's pinned rule for relying on a PA determination before dispensing.
const pharmacyProfile = {
  '@type': 'EP-RELIANCE-PROFILE-v1',
  required_assurance: 'class_a',            // a device-bound reviewer signoff, not a bare token
  required_authority: true,                 // scoped payer/prescriber authority for THIS drug
  max_revocation_staleness_sec: 3600,       // eligibility checked within the last hour
  accepted_registry_keys: [{ issuer_id: 'auth_payer_reviewer', organization_id: 'planX', public_key: registryPub, min_epoch: 9, registry_head: 'sha256:' + '22'.repeat(32) }],
  accepted_issuer_keys: [logKey.pub],
  accepted_policy_hashes: [BENEFIT_POLICY_HASH],
  required_evidence: ['receipt', 'class_a_or_quorum', 'authority_proof', 'revocation_freshness', 'consumption_proof'],
};

const action = { action_type: 'rx.prior_auth.approve', organization_id: 'planX', policy_hash: BENEFIT_POLICY_HASH, action_hash: receipt.action_hash };

// The payer reviewer's scoped authority: may approve specialty PA for this drug family, under this benefit policy.
const reviewerAuthority = (overrides = {}) => signAuthorityProof({
  authority_id: 'auth_payer_reviewer', subject: 'ep:approver:payer-reviewer', organization_id: 'planX', role: 'payer_medical_reviewer',
  scope: ['rx.prior_auth.approve'], limits: {},
  validity: { from: '2026-01-01T00:00:00.000Z', to: '2027-01-01T00:00:00.000Z' },
  revocation: { status: 'not_revoked', checked_at: '2026-07-07T13:59:00.000Z' },
  registry_head: 'sha256:' + '22'.repeat(32), registry_epoch: 9, policy_hash: BENEFIT_POLICY_HASH, issued_at: '2026-07-07T13:59:00.000Z',
  ...overrides,
}, registryKey);

function rely(input) { return evaluateReliance({ ...input, relying_party_profile: pharmacyProfile, now: NOW }, opts); }
const line = (label, verdict) => console.log(`${(verdict === 'rely' ? 'DISPENSE' : 'HOLD    ')} ${label.padEnd(52)} → ${verdict}`);

console.log('\nSpecialty-med prior auth — the pharmacy dispenses only when the whole PA packet composes.');
console.log('(synthetic, no PHI; rides beside NCPDP txn ' + NCPDP_TXN_DIGEST.slice(0, 22) + '…)\n');

const fresh = { checked_at: '2026-07-07T14:00:00.000Z' };
const attempts = [
  ['determination receipt only, no scoped authority', { action, receipt, revocation_state: fresh, consumption: { consumed: false } }],
  ['reviewer authority is for a different action', { action, receipt, authority_proof: reviewerAuthority({ scope: ['rx.refill.approve'] }), revocation_state: fresh, consumption: { consumed: false } }],
  ['reviewer authority cites the wrong benefit policy', { action, receipt, authority_proof: reviewerAuthority({ policy_hash: 'sha256:' + sha('wrong-policy') }), revocation_state: fresh, consumption: { consumed: false } }],
  ['member eligibility check is stale', { action, receipt, authority_proof: reviewerAuthority({ revocation: { status: 'not_revoked', checked_at: '2026-07-01T00:00:00.000Z' } }), consumption: { consumed: false } }],
  ['authorization already filled once', { action, receipt, authority_proof: reviewerAuthority(), revocation_state: fresh, consumption: { consumed: true } }],
  ['ALL legs compose', { action, receipt, authority_proof: reviewerAuthority(), revocation_state: fresh, consumption: { consumed: false } }],
];

const results = attempts.map(([label, input]) => { const v = rely(input).verdict; line(label, v); return v; });
const expected = ['do_not_rely_authority_missing', 'do_not_rely_scope_mismatch', 'do_not_rely_policy_mismatch', 'do_not_rely_stale_revocation', 'do_not_rely_already_consumed', 'rely'];
const ok = results.every((v, i) => v === expected[i]);
console.log(`\n${ok ? 'OK — the PA dispenses ONLY when a device-bound reviewer with scoped authority for THIS drug, under the pinned benefit policy, with a fresh eligibility check and an unconsumed one-time authorization, all compose to `rely`. Every refusal is a distinct, signed, appeal-ready reason.' : 'FAILED — PA reliance composition is wrong.'}`);
process.exit(ok ? 0 : 1);
