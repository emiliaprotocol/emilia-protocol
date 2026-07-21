// SPDX-License-Identifier: Apache-2.0
//
// OAIP oversight receipt demo — a Utah AI Sandbox pilot emits a verifiable
// per-action clinician-approval receipt. The regulator (OAIP) validates the
// pilot's monthly report OFFLINE, without trusting the pilot's servers and
// WITHOUT receiving any PHI.
//
// Maps directly to two items on OAIP's Trusted-Auditor checklist:
//   - "Validating company reports ... required to submit ... each month"
//   - "Ongoing monitoring dashboard ... verified operating data"
//
// The receipt binds the EXACT action + the NAMED LICENSED approver + the time,
// signed on the approver's device key. It carries NO clinical content: only a
// salted digest of the patient reference, so the log is shareable PHI-free.
//
//   node examples/oaip-oversight-receipt/demo.mts

import crypto from 'node:crypto';
import {
  issueFromKeyBundle, generateIssuerKeyBundle, formatLogKeyId, policyHash, canonicalize,
} from '../../packages/issue/index.js';
import { verifyTrustReceipt } from '../../packages/verify/index.js';

const sha256hex = (s: string): string => crypto.createHash('sha256').update(s).digest('hex');

/**
 * @typedef {Object} DemoActionParams
 * @property {string} drug
 * @property {string} patient_ref
 * @property {string} ai_recommendation
 * @property {string} clinician_decision
 * @property {boolean} irreversible
 */
/**
 * @typedef {Object} DemoAction
 * @property {{system: string, resource: string}} target
 * @property {DemoActionParams} parameters
 * @property {string} policy_id
 */

// ── The pilot's policy and its enrolled licensed approver ────────────────────
// In production the approver key is device-bound and enrolled once; OAIP (or its
// auditor) pins the public key at enrollment. Here it is generated for the demo.
const policy = {
  policy_id: 'oaip:pilot:rx-renewal@v1',
  rule: 'a licensed prescriber approves each AI-recommended renewal before it is dispensed',
};
const keys = generateIssuerKeyBundle({
  approverId: 'npi:1730123456',                 // the named licensed clinician (NPI)
  approverKeyId: 'oaip:key:dr-alvarez-md#1',
  logKeyId: formatLogKeyId('rx-renewal-pilot'),
});

// PHI stays out of the receipt. Only a salted digest of the patient reference
// travels, so a monthly log is shareable with OAIP without a BAA.
const patientRef = (mrn) => `ref:sha256:${sha256hex('pilot-salt:' + mrn).slice(0, 32)}`;

// One AI-recommended clinical decision the clinician signs off on.
function decision({ n, drug, mrn, at }: { n: string; drug: string; mrn: string; at: string }): any {
  return {
    ep_version: '1.0',
    action_type: 'clinical.rx.renewal.approve',
    organization_id: 'pilot:doctronic-style-rx',
    target: { system: 'pharmacy.eRx', resource: `renewal/${n}` },
    parameters: {
      drug,                              // material field, non-PHI
      patient_ref: patientRef(mrn),      // salted digest, NOT the MRN
      ai_recommendation: 'renew',
      clinician_decision: 'approved',
      irreversible: true,
    },
    initiator: 'ep:agent:rx-copilot',
    policy_id: policy.policy_id,
    requested_at: at,
  };
}

const MONTH = [
  { n: '0001', drug: 'lisinopril 10mg',      mrn: 'MRN-88213', at: '2026-07-02T14:03:00Z' },
  { n: '0002', drug: 'atorvastatin 20mg',    mrn: 'MRN-41190', at: '2026-07-05T09:40:00Z' },
  { n: '0003', drug: 'metformin 500mg',      mrn: 'MRN-77552', at: '2026-07-09T16:12:00Z' },
  { n: '0004', drug: 'levothyroxine 75mcg',  mrn: 'MRN-30021', at: '2026-07-14T11:27:00Z' },
];

// ── The pilot issues one signed receipt per clinician approval ───────────────
const monthlyLog: any[] = [];
for (const d of MONTH) {
  const action = decision(d);
  const { receipt, verification } = await issueFromKeyBundle({ keys, action, policy });
  monthlyLog.push({ receipt, verification });
}
console.log(`Pilot emitted ${monthlyLog.length} clinician-approval receipts for July.\n`);

// ── OAIP validates the monthly report OFFLINE, no server call, no PHI ────────
console.log('=== OAIP report validation (offline, no trust in the pilot) ===');
const expectedPolicy = policyHash(policy);
let approved = 0;
for (const { receipt, verification } of monthlyLog) {
  const r = verifyTrustReceipt(receipt as unknown as Record<string, unknown>, {
    approverKeys: verification.approver_keys,
    logPublicKey: verification.log_public_key,
  });
  const policyOk = receipt.action.policy_id === policy.policy_id;
  const humanApproved = (receipt.action as any).parameters.clinician_decision === 'approved';
  const ok = r.valid && policyOk && humanApproved;
  if (ok) approved++;
  console.log(
    `  ${(receipt.action as any).target.resource}  ${(receipt.action as any).parameters.drug.padEnd(20)}` +
    `  receipt:${r.valid ? 'valid' : 'INVALID'}  human-approved:${humanApproved}`,
  );
}
console.log(`\nMonthly report: ${approved}/${MONTH.length} decisions carry a verifiable ` +
  `licensed-clinician approval. PHI shared with OAIP: none.`);
console.log(`Policy pinned by OAIP: ${expectedPolicy.slice(0, 23)}...\n`);

// ── Refusals: the two ways a dishonest report fails closed ───────────────────
console.log('=== Refusal (a): pilot changed a decision after the clinician signed ===');
const { receipt: r0 } = monthlyLog[0];
const tampered = structuredClone(r0);
(tampered.action as any).parameters.drug = 'oxycodone 30mg';     // swap the signed drug
const vA = verifyTrustReceipt(tampered as unknown as Record<string, unknown>, {
  approverKeys: monthlyLog[0].verification.approver_keys,
  logPublicKey: monthlyLog[0].verification.log_public_key,
});
console.log(`  receipt after edit: ${vA.valid ? 'valid' : 'INVALID (refused)'} — the signature covers the exact action`);

console.log('\n=== Refusal (b): report claims approval under a key OAIP never pinned ===');
const rogue = generateIssuerKeyBundle({
  approverId: 'npi:0000000000', approverKeyId: 'rogue#1', logKeyId: formatLogKeyId('rogue'),
});
const forged = decision({ n: '9999', drug: 'lisinopril 10mg', mrn: 'MRN-88213', at: '2026-07-31T00:00:00Z' });
const { receipt: forgedReceipt } = await issueFromKeyBundle({ keys: rogue, action: forged, policy });
// OAIP verifies against the ENROLLED approver key, not the key in the report.
const vB = verifyTrustReceipt(forgedReceipt as unknown as Record<string, unknown>, {
  approverKeys: monthlyLog[0].verification.approver_keys,   // the pinned, enrolled key
  logPublicKey: monthlyLog[0].verification.log_public_key,
});
console.log(`  receipt under unpinned key: ${vB.valid ? 'valid' : 'INVALID (refused)'} — trust is the enrolled key, not the receipt's own key`);

console.log('\nEvery approval is checkable at creation, not sampled after the fact.');
console.log('OAIP validates the report from the bytes alone. No PHI, no server, no trust in the pilot.');
