// SPDX-License-Identifier: Apache-2.0
//
// Regenerates the reliance-gap example fixtures: one fully synthetic,
// de-identified specialty prior-auth action packet plus five relying-party
// profiles with genuinely different requirements.
//
//   node examples/reliance-gap/generate-fixtures.mjs
//
// PUBLIC-SAFE: everything is synthetic. Fake identifiers, digests of synthetic
// strings, no PHI shapes. The Ed25519 log and registry keys are derived from
// fixed seeds so the profiles are stable across regenerations; the Class-A
// reviewer key (P-256) is generated fresh and carried inside the packet's
// context, so the packet stays self-consistent.
//
// The committed JSON outputs are what the README, tests, and CLI runs use;
// this script only exists to reproduce them.
import crypto from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { signAuthorityProof } from '../../lib/authority/proof.js';

const HERE = dirname(fileURLToPath(import.meta.url));

const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));
const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const leafV2 = (p) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(p, 'utf8')])).digest('hex');
const pairV2 = (l, r) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([1]), Buffer.from(l, 'utf8'), Buffer.from(r, 'utf8')])).digest('hex');

// Deterministic Ed25519 keys from fixed 32-byte seeds (pkcs8 DER prefix trick,
// same as examples/reliance/specialty-med-pa.mjs) so profile pins stay stable.
const edFromSeed = (seedByte) => {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedByte.repeat(32), 'hex')]),
    format: 'der', type: 'pkcs8',
  });
  return { privateKey, pub: crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url') };
};
const p256 = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
};

const logKey = edFromSeed('a1');   // hub transparency-log key (pinned by profiles)
const intake = edFromSeed('b2');   // Class-B intake software key
const registry = edFromSeed('c3'); // authority-registry key (pinned by profiles)
const reviewer = p256();           // Class-A device: the payer medical reviewer

// Synthetic NCPDP transaction and benefit policy: only digests of synthetic
// strings ride in the action, never transaction contents.
const NCPDP_TXN_DIGEST = 'sha256:' + sha('demo:ncpdp:script:synthetic-pa-request:PA-DEMO-0001');
const BENEFIT_POLICY_HASH = 'sha256:' + sha('demo:payer:benefit-policy:specialty-tier4:plan-demo@v1');
const HUB_CONTRACT_POLICY_HASH = 'sha256:' + sha('demo:hub:contracted-policy:specialty-dispense@v3');

const RP_ID = 'www.emiliaprotocol.ai';

function signClassA(digestHex) {
  const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: `https://${RP_ID}` }), 'utf8');
  const authData = Buffer.concat([crypto.createHash('sha256').update(RP_ID).digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]);
  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
  const signature = crypto.sign('sha256', signedData, reviewer.privateKey);
  return { authenticator_data: authData.toString('base64url'), client_data_json: clientDataJSON.toString('base64url'), signature: signature.toString('base64url') };
}

// The action: a synthetic specialty prior-auth approval, bound to the NCPDP
// transaction by digest. action_hash is over the inner action object.
const innerAction = {
  ep_version: '1.0',
  action_type: 'rx.prior_auth.approve',
  target: { system: 'pbm.adjudication', resource: 'pa/specialty/PA-DEMO-0001' },
  parameters: { drug: 'DEMODRUG 40MG SYRINGE (synthetic)', ncpdp_txn: NCPDP_TXN_DIGEST, pa_case: 'PA-DEMO-0001' },
  initiator: 'ep:entity:demo-intake-agent',
  policy_id: 'ep:policy:demo-specialty-tier4@v1',
  requested_at: '2026-07-08T14:00:00Z',
};
const ACTION_HASH = `sha256:${sha(canon(innerAction))}`;

function buildReceipt() {
  const base = {
    ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash: ACTION_HASH,
    policy_id: 'ep:policy:demo-specialty-tier4@v1', policy_hash: BENEFIT_POLICY_HASH,
    initiator: innerAction.initiator, required_approvals: 2,
    issued_at: '2026-07-08T14:00:05Z', expires_at: '2026-07-08T14:30:05Z',
  };
  const ctx1 = { ...base, approver: 'ep:approver:demo-intake-agent', approver_index: 1, nonce: 'demo-n-1' };
  const ctx2 = { ...base, approver: 'ep:approver:demo-payer-reviewer', approver_index: 2, nonce: 'demo-n-2' };
  const d1 = sha(canon(ctx1)); const d2 = sha(canon(ctx2));
  const signoffs = [
    { context_hash: `sha256:${d1}`, signature: crypto.sign(null, Buffer.from(d1, 'hex'), intake.privateKey).toString('base64url'), key_class: 'B', approver_key_id: 'ep:key:demo-intake#1', signed_at: '2026-07-08T14:03:40Z' },
    { context_hash: `sha256:${d2}`, signature: 'unused', key_class: 'A', approver_key_id: 'ep:key:demo-reviewer#1', signed_at: '2026-07-08T14:04:01Z', webauthn: signClassA(d2) },
  ];
  const receipt = {
    receipt_id: 'ep:receipt:demo-pa-specialty-0001', action: innerAction, action_hash: ACTION_HASH,
    contexts: [ctx1, ctx2], signoffs,
    consumption: { nonce: 'demo-n-pa-consume', state: 'COMMITTED', committed_at: '2026-07-08T14:04:02Z' },
  };
  const leaf = leafV2(canon(receipt));
  const root = pairV2(pairV2(leaf, sha('demo-sibling-1')), sha('demo-sibling-2'));
  const checkpoint = { tree_size: 4, root_hash: `sha256:${root}`, log_key_id: 'ep:log:demo-hub#1', merkle_alg: 'EP-MERKLE-v2' };
  const log_signature = crypto.sign(null, crypto.createHash('sha256').update(canon(checkpoint), 'utf8').digest(), logKey.privateKey).toString('base64url');
  receipt.log_proof = {
    alg: 'EP-MERKLE-v2', leaf_hash: `sha256:${leaf}`, leaf_index: 0,
    inclusion_path: [{ hash: sha('demo-sibling-1'), position: 'right' }, { hash: sha('demo-sibling-2'), position: 'right' }],
    checkpoint: { ...checkpoint, log_signature },
  };
  return receipt;
}

// The payer reviewer's scoped authority: approve specialty PA under the demo
// benefit policy, valid through 2027, revocation checked at issuance.
const authorityProof = signAuthorityProof({
  authority_id: 'auth_demo_payer_reviewer',
  subject: 'ep:approver:demo-payer-reviewer',
  organization_id: 'plan-demo',
  role: 'payer_medical_reviewer',
  scope: ['rx.prior_auth.approve'],
  limits: {},
  validity: { from: '2026-01-01T00:00:00.000Z', to: '2027-01-01T00:00:00.000Z' },
  revocation: { status: 'not_revoked', checked_at: '2026-07-08T13:59:00.000Z' },
  registry_head: 'sha256:' + 'd4'.repeat(32),
  registry_epoch: 3,
  policy_hash: BENEFIT_POLICY_HASH,
  issued_at: '2026-07-08T13:59:00.000Z',
}, registry.privateKey);

const packet = {
  note: 'Fully synthetic specialty prior-auth demo packet. All identifiers are fake, all digests are of synthetic strings, and no PHI shapes are present.',
  evaluated_at: '2026-07-08T15:00:00Z',
  action: { ...innerAction, action_hash: ACTION_HASH, policy_hash: BENEFIT_POLICY_HASH },
  evidence: [
    { type: 'receipt', artifact: buildReceipt() },
    { type: 'authority_proof', artifact: authorityProof },
    { type: 'revocation_state', artifact: { checked_at: '2026-07-08T14:30:00Z' } },
    { type: 'consumption', artifact: { consumed: false } },
    {
      '@type': 'x-demo-fax-confirmation',
      pages: 3,
      sent_at: '2026-07-08T13:45:00Z',
      note: 'legacy artifact with no registered verifier; the report records it as unverifiable presence and never counts it as evidence',
    },
  ],
  context: {
    approver_keys: {
      'ep:key:demo-intake#1': { public_key: intake.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
      'ep:key:demo-reviewer#1': { public_key: reviewer.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
    },
    log_public_key: logKey.pub,
    rp_id: RP_ID,
  },
};

// Five relying parties, five pinned profiles, genuinely different requirements.
const REGISTRY_PIN = [{ issuer_id: 'auth_demo_payer_reviewer', public_key: registry.pub }];
const profiles = {
  'pharmacy.json': {
    '@type': 'EP-RELIANCE-PROFILE-v1',
    profile_id: 'ep:profile:demo:dispensing-pharmacy@v1',
    party: 'dispensing pharmacy',
    description: 'Dispenses only on a device-bound reviewer signoff, scoped payer authority, an eligibility check within the last hour, the pinned benefit policy, and a one-time unconsumed authorization.',
    required_assurance: 'class_a',
    required_authority: true,
    max_revocation_staleness_sec: 3600,
    accepted_registry_keys: REGISTRY_PIN,
    accepted_issuer_keys: [logKey.pub],
    accepted_policy_hashes: [BENEFIT_POLICY_HASH],
    required_evidence: ['receipt', 'authority_proof', 'revocation_freshness', 'consumption_proof'],
  },
  'payer-pbm.json': {
    '@type': 'EP-RELIANCE-PROFILE-v1',
    profile_id: 'ep:profile:demo:payer-pbm@v1',
    party: 'payer / PBM adjudication',
    description: 'Accepts any pinned-key signature (its own reviewer already sits in the loop), requires scoped authority and the pinned benefit policy, tolerates a day-old eligibility check.',
    required_assurance: 'signed',
    required_authority: true,
    max_revocation_staleness_sec: 86400,
    accepted_registry_keys: REGISTRY_PIN,
    accepted_issuer_keys: [logKey.pub],
    accepted_policy_hashes: [BENEFIT_POLICY_HASH],
    required_evidence: ['receipt', 'authority_proof', 'revocation_freshness'],
  },
  'prescriber-ehr.json': {
    '@type': 'EP-RELIANCE-PROFILE-v1',
    profile_id: 'ep:profile:demo:prescriber-ehr@v1',
    party: 'prescriber EHR',
    description: 'Surfaces the determination to the prescriber only when a two-person quorum (reviewer plus pharmacist) is bound to the exact transaction.',
    required_assurance: 'quorum',
    required_authority: false,
    accepted_registry_keys: [],
    accepted_issuer_keys: [logKey.pub],
    accepted_policy_hashes: [],
    required_evidence: ['receipt'],
  },
  'medicaid-auditor.json': {
    '@type': 'EP-RELIANCE-PROFILE-v1',
    profile_id: 'ep:profile:demo:medicaid-auditor@v1',
    party: 'Medicaid program auditor',
    description: 'Accepts an exhibit only with a device-bound signoff, scoped authority, the pinned benefit policy, a one-time authorization, and an eligibility check no older than fifteen minutes.',
    required_assurance: 'class_a',
    required_authority: true,
    max_revocation_staleness_sec: 900,
    accepted_registry_keys: REGISTRY_PIN,
    accepted_issuer_keys: [logKey.pub],
    accepted_policy_hashes: [BENEFIT_POLICY_HASH],
    required_evidence: ['receipt', 'authority_proof', 'revocation_freshness', 'consumption_proof'],
  },
  'hub-vendor.json': {
    '@type': 'EP-RELIANCE-PROFILE-v1',
    profile_id: 'ep:profile:demo:hub-vendor@v1',
    party: 'specialty hub vendor',
    description: 'Holds or releases shipments under its own contracted dispensing policy; the action must cite the policy hash the hub contracted for, not the payer benefit policy.',
    required_assurance: 'signed',
    required_authority: false,
    accepted_registry_keys: [],
    accepted_issuer_keys: [logKey.pub],
    accepted_policy_hashes: [HUB_CONTRACT_POLICY_HASH],
    required_evidence: ['receipt'],
  },
};

mkdirSync(join(HERE, 'profiles'), { recursive: true });
writeFileSync(join(HERE, 'specialty-pa-packet.json'), JSON.stringify(packet, null, 2) + '\n');
for (const [name, profile] of Object.entries(profiles)) {
  writeFileSync(join(HERE, 'profiles', name), JSON.stringify(profile, null, 2) + '\n');
}
console.log('wrote specialty-pa-packet.json and 5 profiles to', HERE);
