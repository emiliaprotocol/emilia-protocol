// SPDX-License-Identifier: Apache-2.0
// Generated from verify-sample.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Verifies the committed EP WHO-leg sample for the verifiable-curtailment
// cross-vector, then demonstrates the two EP-side negative classes the joint
// vector set names: wrong-action splice and unsigned rely.
//
//   node examples/grace/cross-vector/verify-sample.mjs
//
// Offline: no network, no EMILIA service. The keys are pinned inside the
// committed sample; a relying party would pin them out of band.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyTrustReceipt } from '../../../packages/verify/index.js';
import { buildRelianceGapReport } from '../../../packages/verify/reliance-gap.js';
import { policyHash } from '../../../packages/issue/index.js';
const here = dirname(fileURLToPath(import.meta.url));
const sample = JSON.parse(readFileSync(join(here, 'ep-receipt.sample.json'), 'utf8'));
const { receipt, verification } = sample;
const pins = { approverKeys: verification.approver_keys, logPublicKey: verification.log_public_key };
console.log('=== WHO leg: the committed EP receipt, verified offline ===');
const ok = verifyTrustReceipt(receipt, pins);
console.log('valid:', ok.valid);
if (!ok.valid) {
    console.error(ok);
    process.exit(1);
}
const actionHash = receipt.action_hash ?? receipt.payload?.action_hash;
const receiptId = receipt.receipt_id ?? receipt.payload?.receipt_id;
console.log('receipt_id     :', receiptId);
console.log('subject digest :', actionHash);
console.log('join convention: human_authorization_ref = { receipt_id, action_hash }; the capsule (WHAT) and any third attestor claim (meter) bind the SAME subject digest.');
console.log('\n=== Negative 1: wrong-action splice ===');
const spliced = JSON.parse(JSON.stringify(receipt));
const p = spliced.action?.parameters ?? spliced.payload?.action?.parameters;
p.target_delta_w = '45000000'; // 12 MW approval presented for a 45 MW shed
const bad = verifyTrustReceipt(spliced, pins);
console.log('valid:', bad.valid, '| the approval does not transfer to a changed shed');
console.log('\n=== Negative 2: unsigned rely ===');
const profile = {
    '@type': 'EP-RELIANCE-PROFILE-v1',
    profile_id: 'ep:grace:cross-vector-demo@v1',
    party: 'settlement relying party (demo)',
    description: 'accepts the sample issuer key and policy hash; requires a receipt',
    required_assurance: 'signed',
    required_authority: false,
    accepted_registry_keys: [],
    accepted_issuer_keys: [verification.log_public_key],
    accepted_policy_hashes: [policyHash(sample.policy)],
    required_evidence: ['receipt'],
};
const packet = {
    evaluated_at: '2026-07-15T16:50:00-07:00',
    action: { ...receipt.action, action_hash: actionHash },
    evidence: [{ type: 'receipt', artifact: receipt }],
    context: { approver_keys: verification.approver_keys, log_public_key: verification.log_public_key },
};
const green = buildRelianceGapReport(packet, profile, {});
console.log('with the receipt :', green.kernel_verdict);
const stripped = JSON.parse(JSON.stringify(packet));
stripped.evidence = [];
const red = buildRelianceGapReport(stripped, profile, {});
console.log('receipt withheld :', red.kernel_verdict, '| reason:', (red.kernel_reasons ?? []).slice(0, 1).join(' '));
console.log('\nWHO leg holds; splice and unsigned rely refuse. The WHAT (capsule), CAN (demand), meter, and record legs verify in their own trust boundaries and join here by digest equality.');
