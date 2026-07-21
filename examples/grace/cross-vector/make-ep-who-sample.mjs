// SPDX-License-Identifier: Apache-2.0
// Generated from make-ep-who-sample.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Generates the committed EP WHO-leg sample for the verifiable-curtailment
// cross-vector (AAC Class-1 capsule as WHAT + EP-RECEIPT as WHO, joined by a
// shared subject digest and human_authorization_ref).
//
//   node examples/grace/cross-vector/make-ep-who-sample.mjs
//
// Writes ep-receipt.sample.json (the signed receipt + pinned verification keys).
// Regenerating produces a NEW receipt under fresh keys; the committed sample is
// the stable one counterparties bind to. Verify it with verify-sample.mjs.
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import crypto from 'node:crypto';
import { issueFromKeyBundle, generateIssuerKeyBundle, formatLogKeyId, canonicalize } from '../../../packages/issue/index.js';
const here = dirname(fileURLToPath(import.meta.url));
const sha256hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
// The CAN leg (the grid authority's signed curtailment demand) is another
// verifier's row. EP carries only its digest inside the signed action, the same
// opaque-digest pattern as EP-SURFACE-BINDING-v1: this row's bytes are judged by
// the demand leg's own verifier, in its own trust boundary.
const syntheticDemand = Buffer.from(canonicalize({
    '@example': 'synthetic curtailment demand, NOT a real grid-authority order',
    order_type: 'grid.curtailment',
    facility: 'dc-04',
    target_delta_w: '12000000',
    window: { start: '2026-07-15T17:00:00-07:00', end: '2026-07-15T21:00:00-07:00' },
}), 'utf8');
const action = {
    ep_version: '1.0',
    action_type: 'grid.curtailment.shed',
    organization_id: 'org-grace-flagship',
    target: { system: 'grace.curtailment', resource: 'facility/dc-04/feeder-2' },
    parameters: {
        target_delta_w: '12000000',
        window_start: '2026-07-15T17:00:00-07:00',
        window_end: '2026-07-15T21:00:00-07:00',
        curtailment_order_digest: `sha256:${sha256hex(syntheticDemand)}`,
        baseline_method_hash: 'sha256:9d2f0f2c1a7e4b7f8c1d3e5a6b8c0d2e4f60718293a4b5c6d7e8f9a0b1c2d3e4',
    },
    initiator: 'ep:entity:grace-scheduler',
    policy_id: 'ep:grace:curtailment-settlement:v1',
    requested_at: '2026-07-15T16:45:00-07:00',
};
const keys = generateIssuerKeyBundle({
    approverId: 'ep:approver:grid-ops-director',
    approverKeyId: 'ep:key:grid-ops-director#1',
    logKeyId: formatLogKeyId('grace-flagship'),
});
const policy = { policy_id: action.policy_id, rule: 'a named human authorizes the exact shed before the controller acts' };
const { receipt, verification } = await issueFromKeyBundle({ keys, action, policy });
const sample = {
    '@purpose': 'EP WHO-leg sample for the verifiable-curtailment cross-vector. The subject digest for the composition join is receipt.action_hash; human_authorization_ref = { receipt_id, action_hash }.',
    policy,
    receipt,
    verification: {
        approver_keys: verification.approver_keys,
        log_public_key: verification.log_public_key,
    },
};
writeFileSync(join(here, 'ep-receipt.sample.json'), JSON.stringify(sample, null, 2) + '\n');
console.log('wrote ep-receipt.sample.json');
// Defensive fallback for an alternate (pre-v1) nested receipt shape; the current
// AuthorizationReceipt type doesn't declare `.payload`, so this is a type-only cast.
console.log('receipt_id      :', receipt.receipt_id ?? receipt.payload?.receipt_id);
console.log('subject digest  :', receipt.action_hash ?? receipt.payload?.action_hash);
