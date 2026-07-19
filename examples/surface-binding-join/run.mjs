// SPDX-License-Identifier: Apache-2.0
// The two-row join, runnable: a signed EP action carrying an EP-SURFACE-BINDING-v1
// reference to possession-row evidence, verified beside a reliance verdict.
//
//   node examples/surface-binding-join/run.mjs
//
// Rows join by digest equality; they never merge. The possession-row evidence here
// is a SYNTHETIC stand-in shaped like a condition-bounded credential presentation
// (WIMSE LIT style). Swap in a real presentation and nothing about the join changes:
// EP hashes the bytes; that row's own verifier judges their meaning.

import crypto from 'node:crypto';
import { issueFromKeyBundle, generateIssuerKeyBundle, formatLogKeyId, canonicalize, policyHash } from '../../packages/issue/index.js';
import { verifyTrustReceipt } from '../../packages/verify/index.js';
import { validateSurfaceBinding, bindSurfaceInto, verifySurfaceBinding, SURFACE_BINDING_VERSION } from '../../packages/verify/surface-binding.js';
import { buildRelianceGapReport } from '../../packages/verify/reliance-gap.js';

const sha256hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

// 1. Possession-row evidence (synthetic LIT-shaped presentation). Opaque to EP.
const possessionEvidence = Buffer.from(canonicalize({
  '@example': 'synthetic condition-bounded credential presentation, NOT a real LIT artifact',
  presentation_type: 'wimse-condition-bounded',
  platform_key_thumbprint: 'sha256:2f1b6f2e1a3d4c5b6a7988776655443322110000ffeeddccbbaa998877665544',
  conditions_asserted: ['user_verified_at_mint', 'device_sound'],
  presented_at: '2026-07-10T22:00:00Z',
}), 'utf8');

// 2. The binding: an opaque digest of that evidence, placed in the SIGNED action.
const binding = {
  '@version': SURFACE_BINDING_VERSION,
  surface_kind: 'wimse-condition-bounded',
  attestation_digest: `sha256:${sha256hex(possessionEvidence)}`,
  verifier_hint: 'possession row verifies in its own trust boundary; EP never judges it',
};
const v = validateSurfaceBinding(binding);
if (!v.ok) throw new Error(`binding invalid: ${v.errors.join('; ')}`);

const policy = { policy_id: 'ep:policy:join-demo@v1', rule: 'named human approves the exact action before it runs' };
const { action } = bindSurfaceInto({
  ep_version: '1.0',
  action_type: 'demo.join.commit',
  organization_id: 'org-join-demo',
  target: { system: 'join.demo', resource: 'txn/0001' },
  parameters: { irreversible: true, note: 'synthetic demo action' },
  initiator: 'ep:entity:demo-agent',
  policy_id: policy.policy_id,
  requested_at: '2026-07-10T22:00:05Z',
}, binding);

// 3. Authorization row: a named human signs the exact action (surface reference included).
const keys = generateIssuerKeyBundle({
  approverId: 'ep:approver:demo-operator',
  approverKeyId: 'ep:key:demo-operator#1',
  logKeyId: formatLogKeyId('join-demo'),
});
const { receipt, verification } = await issueFromKeyBundle({ keys, action, policy });

console.log('=== Row 1: authorization (EP receipt over the signed action) ===');
const r = verifyTrustReceipt(/** @type {any} */ (receipt), { approverKeys: verification.approver_keys, logPublicKey: verification.log_public_key });
console.log('receipt valid:', r.valid);

console.log('\n=== Row 2 join: surface binding covered by the human signature ===');
const sb = verifySurfaceBinding(receipt, possessionEvidence);
console.log('binding present, digest_match:', sb.checks.present, sb.checks.digest_match, '| surface_kind:', sb.binding?.surface_kind);

console.log('\n=== Substitution attempt: swap the claimed possession evidence ===');
const swapped = Buffer.from('{"different":"evidence"}', 'utf8');
const sb2 = verifySurfaceBinding(receipt, swapped);
console.log('digest_match:', sb2.checks.digest_match, '| reason:', sb2.reason);

console.log('\n=== Reliance verdict beside it (same receipt as evidence) ===');
const profile = {
  '@type': 'EP-RELIANCE-PROFILE-v1',
  profile_id: 'ep:profile:join-demo@v1',
  party: 'relying party (demo)',
  description: 'accepts the demo issuer key and the demo policy hash; requires a receipt',
  required_assurance: 'signed',
  required_authority: false,
  accepted_registry_keys: [],
  accepted_issuer_keys: [verification.log_public_key],
  accepted_policy_hashes: [policyHash(policy)],
  required_evidence: ['receipt'],
};
const packet = {
  evaluated_at: '2026-07-10T22:01:00Z',
  action: { ...receipt.action, action_hash: receipt.action_hash },
  evidence: [{ type: 'receipt', artifact: receipt }],
  context: { approver_keys: verification.approver_keys, log_public_key: verification.log_public_key },
};
const green = buildRelianceGapReport(packet, profile, {});
console.log('with the receipt   :', green.kernel_verdict);

const stripped = JSON.parse(JSON.stringify(packet));
stripped.evidence = [];
const red = buildRelianceGapReport(stripped, profile, {});
console.log('receipt withheld   :', red.kernel_verdict, '| reason:', (red.kernel_reasons ?? []).slice(0,1).join(' '));

console.log('\nRows joined by digest equality. Neither row substitutes for the other.');
