// SPDX-License-Identifier: Apache-2.0
//
// EP-NCPDP-RX-RELIANCE-PROFILE-v1 — specialty medication prior-auth reliance flow.
//
//   node examples/ncpdp/specialty-pa-reliance-flow.mjs
//
// The NCPDP-facing demo, run offline. A specialty-drug prior auth moves through:
//   1. prescriber agent submits the drug request (rides beside an NCPDP ePA / SCRIPT transaction);
//   2. payer/PBM returns an EP-RX-EVIDENCE-CHALLENGE-v1 (what evidence it needs to rely);
//   3. prescriber / pharmacy / hub resubmits an EP-RX-RELIANCE-PACKET-v1;
//   4. the kernel returns ONE closed rx verdict, and the whole packet exports as an appeal bundle.
//
// We are NOT replacing SCRIPT, Telecom, RTBP, ePA, Specialty Medication
// Enrollment, or the Audit Transaction Standard. This is a portable evidence
// sidecar bound to the transaction by an action digest. Fully synthetic: no PHI,
// no real member / prescriber / drug / plan; consent and clinical evidence are
// carried as signed DIGESTS, never raw records.
import crypto from 'node:crypto';
import { buildRxAppealBundle, commitRxEvidence, derivePairwisePatientRef, evaluateRxReliance, signRxArtifact, RX_VERDICTS } from '../../lib/ncpdp/rx-reliance.js';
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

// Actors: the hub transparency log, the intake agent (Class-B), the prescriber
// (Class-A device), the payer authority registry, and the consent / clinical /
// payer-denial issuers.
const logKey = ed();
const intake = ed();
const prescriber = p256();
const registryKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from('a7'.repeat(32), 'hex')]), format: 'der', type: 'pkcs8' });
const registryPub = crypto.createPublicKey(registryKey).export({ type: 'spki', format: 'der' }).toString('base64url');
const consentKey = ed();
const clinicalKey = ed();
const payerKey = ed();

const NCPDP_TXN_DIGEST = 'sha256:' + sha('ncpdp:epa:synthetic-pa-request:2026-07-08');
const BENEFIT_POLICY_HASH = 'sha256:' + sha('payer:formulary:specialty-tier4:planX@v7');
const NOW = Date.parse('2026-07-08T14:05:00.000Z');
const privacyKey = Buffer.from('61'.repeat(32), 'hex');
const privacyKeyId = 'payer-example-rx-privacy-2026-01';
const patientRef = derivePairwisePatientRef({ patientIdentifier: 'synthetic-member-001', relyingPartyId: 'payer.example', privacyKeyId, sectorSecret: privacyKey });

function signA(digestHex) {
  const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
  const authData = Buffer.concat([crypto.createHash('sha256').update('www.emiliaprotocol.ai').digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]);
  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
  return { authenticator_data: authData.toString('base64url'), client_data_json: clientDataJSON.toString('base64url'), signature: crypto.sign('sha256', signedData, prescriber.privateKey).toString('base64url') };
}

function buildReceipt() {
  const action = { ep_version: '1.0', action_type: 'rx.prior_auth.approve', organization_id: 'clinicX', target: { system: 'pbm.adjudication', resource: 'pa/specialty/synthetic-001' }, parameters: { drug: 'SYNTHETIC-SPECIALTY-DRUG', ncpdp_txn: NCPDP_TXN_DIGEST }, initiator: 'ep:entity:pa-intake-agent', policy_id: 'ep:policy:specialty-tier4-planX@v7', requested_at: '2026-07-08T14:00:00Z' };
  const action_hash = `sha256:${sha(canon(action))}`;
  const base = { ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash, policy_id: 'ep:policy:specialty-tier4-planX@v7', policy_hash: BENEFIT_POLICY_HASH, initiator: action.initiator, required_approvals: 2, issued_at: '2026-07-08T14:00:05Z', expires_at: '2026-07-08T14:15:05Z' };
  const ctx1 = { ...base, approver: 'ep:approver:intake-agent', approver_index: 1, nonce: 'n-1' };
  const ctx2 = { ...base, approver: 'ep:approver:prescriber', approver_index: 2, nonce: 'n-2' };
  const d1 = sha(canon(ctx1)); const d2 = sha(canon(ctx2));
  const signoffs = [
    { context_hash: `sha256:${d1}`, signature: crypto.sign(null, Buffer.from(d1, 'hex'), intake.privateKey).toString('base64url'), key_class: 'B', approver_key_id: 'ep:key:intake#1', signed_at: '2026-07-08T14:03:40Z' },
    { context_hash: `sha256:${d2}`, signature: 'unused', key_class: 'A', approver_key_id: 'ep:key:prescriber#1', signed_at: '2026-07-08T14:04:01Z', webauthn: signA(d2) },
  ];
  const receipt = { receipt_id: 'ep:receipt:pa-specialty-001', action, action_hash, contexts: [ctx1, ctx2], signoffs, consumption: { nonce: 'n-pa', state: 'COMMITTED', committed_at: '2026-07-08T14:04:02Z' } };
  const leaf = leafV2(canon(receipt));
  const root = pairV2(pairV2(leaf, sha('s1')), sha('s2'));
  const checkpoint = { tree_size: 4, root_hash: `sha256:${root}`, log_key_id: 'ep:log:hub#1', merkle_alg: 'EP-MERKLE-v2' };
  const log_signature = crypto.sign(null, crypto.createHash('sha256').update(canon(checkpoint), 'utf8').digest(), logKey.privateKey).toString('base64url');
  receipt.log_proof = { alg: 'EP-MERKLE-v2', leaf_hash: `sha256:${leaf}`, leaf_index: 0, inclusion_path: [{ hash: sha('s1'), position: 'right' }, { hash: sha('s2'), position: 'right' }], checkpoint: { ...checkpoint, log_signature } };
  return receipt;
}

const receipt = buildReceipt();
const ACTION = { action_type: 'rx.prior_auth.approve', organization_id: 'clinicX', policy_hash: BENEFIT_POLICY_HASH, action_hash: receipt.action_hash };
const KEYS = {
  'ep:key:intake#1': { approver_id: 'ep:approver:intake-agent', public_key: intake.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
  'ep:key:prescriber#1': { approver_id: 'ep:approver:prescriber', public_key: prescriber.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
};
const opts = { approverKeys: KEYS, logPublicKey: logKey.pub, rpId: 'www.emiliaprotocol.ai' };

// Step 2: the payer/PBM's EP-RX-EVIDENCE-CHALLENGE-v1.
const challenge = {
  '@type': 'EP-RX-EVIDENCE-CHALLENGE-v1',
  transaction: 'ncpdp.epa',
  required_assurance: 'class_a',
  required: {
    prescriber_authority: true,
    patient_consent: true,
    clinical_evidence: true,
    benefit_policy_hash: BENEFIT_POLICY_HASH,
    benefit_freshness_sec: 3600,
    revocation_freshness_sec: 3600,
    signed_denial_required: true,
  },
  accepted_registry_keys: [{ issuer_id: 'auth_prescriber', organization_id: 'clinicX', public_key: registryPub, min_epoch: 9, registry_head: 'sha256:' + '22'.repeat(32) }],
  accepted_issuer_keys: [logKey.pub],
  accepted_consent_keys: [consentKey.pub],
  accepted_clinical_keys: [clinicalKey.pub],
  accepted_payer_keys: [payerKey.pub],
};

// Reusable leg builders.
const prescriberAuthority = () => signAuthorityProof({
  authority_id: 'auth_prescriber', subject: 'ep:approver:prescriber', organization_id: 'clinicX', role: 'prescriber',
  scope: ['rx.prior_auth.approve'], limits: {},
  validity: { from: '2026-01-01T00:00:00.000Z', to: '2027-01-01T00:00:00.000Z' },
  revocation: { status: 'not_revoked', checked_at: '2026-07-08T13:59:00.000Z' },
  registry_head: 'sha256:' + '22'.repeat(32), registry_epoch: 9, policy_hash: BENEFIT_POLICY_HASH, issued_at: '2026-07-08T13:59:00.000Z',
}, registryKey);
const consent = () => signRxArtifact({ '@type': 'EP-RX-CONSENT-v1', action_hash: receipt.action_hash, privacy_key_id: privacyKeyId, subject_ref: patientRef, consent_digest: commitRxEvidence({ evidenceType: 'consent', record: { synthetic: 'consent-record' }, privacyKeyId, sectorSecret: privacyKey }), issued_at: '2026-07-08T13:50:00.000Z' }, consentKey.privateKey);
const clinical = () => signRxArtifact({ '@type': 'EP-RX-CLINICAL-v1', action_hash: receipt.action_hash, privacy_key_id: privacyKeyId, evidence_digest: commitRxEvidence({ evidenceType: 'clinical', record: { synthetic: 'dx-lab-bundle' }, privacyKeyId, sectorSecret: privacyKey }), criteria: 'step-therapy-met', issued_at: '2026-07-08T13:52:00.000Z' }, clinicalKey.privateKey);
const denial = () => signRxArtifact({ '@type': 'EP-RX-DENIAL-v1', action_hash: receipt.action_hash, privacy_key_id: privacyKeyId, reason_code: 'NCPDP:step-therapy-not-met', reason_digest: commitRxEvidence({ evidenceType: 'denial', record: { synthetic: 'denial-rationale' }, privacyKeyId, sectorSecret: privacyKey }), appeal_url: 'https://payer.example/appeals', issued_at: '2026-07-08T14:04:30.000Z' }, payerKey.privateKey);
const freshBenefit = { checked_at: '2026-07-08T14:00:00.000Z', policy_hash: BENEFIT_POLICY_HASH };

function packet(over = {}) {
  return {
    '@type': 'EP-RX-RELIANCE-PACKET-v1', action: ACTION, receipt,
    authority_proof: prescriberAuthority(), patient_consent: consent(), clinical_evidence: clinical(),
    benefit_check: freshBenefit, revocation_state: { checked_at: '2026-07-08T14:00:00.000Z' },
    determination: 'approve', ...over,
  };
}

const run = (p) => evaluateRxReliance({ challenge, packet: p, now: NOW }, opts);
const line = (label, v) => console.log(`${(v === 'rx_rely' ? 'RELY ' : 'HOLD ')} ${label.padEnd(50)} -> ${v}`);

console.log('\nSpecialty-med prior auth reliance flow (synthetic; sidecar to NCPDP ' + NCPDP_TXN_DIGEST.slice(0, 20) + '...).');
console.log('The payer, pharmacy, hub, and auditor all compute the SAME verdict over the same request.\n');

const attempts = [
  ['resubmit missing patient consent', packet({ patient_consent: undefined })],
  ['resubmit missing diagnosis/lab evidence', packet({ clinical_evidence: undefined })],
  ['prescriber authority scoped to a different action', packet({ authority_proof: signAuthorityProof({ authority_id: 'auth_prescriber', subject: 'ep:approver:prescriber', organization_id: 'clinicX', role: 'prescriber', scope: ['rx.refill.approve'], limits: {}, validity: { from: '2026-01-01T00:00:00.000Z', to: '2027-01-01T00:00:00.000Z' }, revocation: { status: 'not_revoked', checked_at: '2026-07-08T13:59:00.000Z' }, registry_head: 'sha256:' + '22'.repeat(32), registry_epoch: 9, policy_hash: BENEFIT_POLICY_HASH, issued_at: '2026-07-08T13:59:00.000Z' }, registryKey) })],
  ['RTBP check cites the wrong formulary policy', packet({ benefit_check: { ...freshBenefit, policy_hash: 'sha256:' + sha('wrong-formulary') } })],
  ['RTBP benefit check is stale', packet({ benefit_check: { checked_at: '2026-07-01T00:00:00.000Z', policy_hash: BENEFIT_POLICY_HASH } })],
  ['payer denies but the denial is not signed', packet({ determination: 'deny', signed_denial: undefined })],
  ['APPROVE: all evidence composes', packet()],
  ['DENY: signed, reasoned, appeal-ready (rely on the denial)', packet({ determination: 'deny', signed_denial: denial() })],
];

const results = attempts.map(([label, p]) => { const r = run(p); line(label, r.verdict); return r.verdict; });
const expected = ['rx_do_not_rely_missing_patient_consent', 'rx_do_not_rely_missing_clinical_evidence', 'rx_do_not_rely_missing_prescriber_authority', 'rx_do_not_rely_policy_mismatch', 'rx_do_not_rely_stale_benefit', 'rx_do_not_rely_signed_denial_required', 'rx_rely', 'rx_rely'];

// The appeal / audit bundle for the approved determination.
const approved = packet();
const approvedResult = run(approved);
const bundle = buildRxAppealBundle({ challenge, packet: approved, result: approvedResult, now: '2026-07-08T14:05:00.000Z', privacyKey, privacyKeyId });
console.log(`\nAppeal/audit bundle exported: ${bundle['@type']} ${bundle.bundle_digest.slice(0, 26)}... (PHI-minimized, keyed evidence references).`);

const ok = results.every((v, i) => v === expected[i]) && RX_VERDICTS.includes(approvedResult.verdict);
console.log(`\n${ok ? 'OK — one closed reliance verdict per submission; rx_rely covers both a dispensable approval and a signed, appeal-ready denial. NCPDP transaction untouched, EMILIA sidecar carries the admissibility.' : 'FAILED — Rx reliance flow is wrong.'}`);
process.exit(ok ? 0 : 1);
