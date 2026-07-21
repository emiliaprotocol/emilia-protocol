// SPDX-License-Identifier: Apache-2.0
// Generated from authority-closure-vector.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-AUTHORITY-REGISTRY-v1 + EP-AUTHORITY-PROOF-v1 — the authority-to-admissibility closure.
//
//   node examples/authority/authority-closure-vector.mjs
//
// Runs the whole chain offline, no account, no database:
//   identity -> ceremony -> AUTHORITY -> policy -> receipt -> admissibility
//
// It proves the distinction the rest of the stack cannot make alone:
//   * "someone signed"                                  (a signature)
//   * "a named human approved"                          (a Class-A signoff)
//   * "the RIGHT human had authority for THIS action"   (this layer)
//   * "this evidence is admissible for reliance"        (pinned acceptance)
import crypto from 'node:crypto';
import { snapshotStore, resolveAuthority } from '../../lib/authority/store.js';
import { authorityBinding } from '../../lib/authority/resolver.js';
import { applyAuthorityEnforcement } from '../../lib/authority/enforcement.js';
import { buildRegistrySnapshot } from '../../lib/authority/registry-head.js';
import { signAuthorityProof, verifyAuthorityProof } from '../../lib/authority/proof.js';
const AT = '2026-07-07T00:00:00.000Z';
const POLICY_HASH = 'sha256:' + 'ab'.repeat(32);
// Deterministic registry issuer key (fixed seed → reproducible signature).
function keyFromSeedHex(hex) {
    const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(hex, 'hex')]);
    return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}
const registryKey = keyFromSeedHex('a1'.repeat(32));
const registryPub = crypto.createPublicKey(registryKey).export({ type: 'spki', format: 'der' }).toString('base64url');
// ── The org's authority registry (epoch 17): the CFO may release payments up to
//    $50k; delegated from her, a manager may release up to $10k. ───────────────
const entries = [
    { authority_id: 'auth_cfo', subject_type: 'human_approver', subject_ref: 'ada-cfo', organization_id: 'acme',
        role: 'cfo', assurance_class: 'A', status: 'active',
        valid_from: '2026-01-01T00:00:00.000Z', valid_to: '2027-01-01T00:00:00.000Z', revoked_at: null,
        action_scopes: ['large_payment_release'], max_amount_usd: 50000, currency: 'USD', delegation_parent: null, policy_hash: null },
    { authority_id: 'auth_mgr', subject_type: 'human_approver', subject_ref: 'ben-mgr', organization_id: 'acme',
        role: 'manager', assurance_class: 'A', status: 'active',
        valid_from: '2026-01-01T00:00:00.000Z', valid_to: '2027-01-01T00:00:00.000Z', revoked_at: null,
        action_scopes: ['large_payment_release'], max_amount_usd: 10000, currency: 'USD', delegation_parent: 'auth_cfo', policy_hash: null },
];
const store = snapshotStore({ epoch: 17, entries });
const snapshot = buildRegistrySnapshot(17, entries);
function log(title) { console.log(`\n=== ${title} ===`); }
// ── LEG 1: the CFO releases $40k. Authorized: in role, in scope, within limit. ─
log('LEG 1 — CFO releases $40,000 (within her $50k authority)');
const cfoInput = { organization_id: 'acme', approver_id: 'ada-cfo', action_type: 'large_payment_release',
    amount: 40000, currency: 'USD', policy_hash: POLICY_HASH, issued_at: AT };
const cfo = await resolveAuthority(store, cfoInput);
const cfoBinding = authorityBinding(cfo);
const cfoEnf = applyAuthorityEnforcement({ verdict: cfo.verdict, isCritical: true, mode: 'enforce_critical' });
console.log('verdict           :', cfo.verdict);
console.log('receipt binding   :', JSON.stringify(cfoBinding, null, 0));
console.log('enforce_critical  :', cfoEnf.admissibility, `(block=${cfoEnf.block})`);
// Portable proof: the registry signs what it held; a relying party pins the key.
const proof = signAuthorityProof({
    authority_id: cfo.authority_id, subject: 'ada-cfo', organization_id: 'acme', role: cfo.role,
    scope: cfo.scope, limits: { max_amount_usd: cfo.max_amount_usd, currency: 'USD' },
    validity: { from: '2026-01-01T00:00:00.000Z', to: '2027-01-01T00:00:00.000Z' },
    registry_head: cfoBinding.authority_registry_head, registry_epoch: 17, policy_hash: POLICY_HASH, issued_at: AT,
}, registryKey);
const accepted = verifyAuthorityProof(proof, {
    // authority_id is non-null here: it came from the successful CFO resolution above.
    pinnedRegistryKeys: [{ issuer_id: proof.authority_id, public_key: registryPub }],
    expectMinEpoch: 17,
});
const unpinned = verifyAuthorityProof(proof, { pinnedRegistryKeys: [] });
console.log('proof (pinned)    : verified=%s accepted=%s', accepted.verified, accepted.accepted);
console.log('proof (unpinned)  : verified=%s accepted=%s reason=%s', unpinned.verified, unpinned.accepted, unpinned.reason);
// ── LEG 2: the manager tries $40k. His delegated authority caps at $10k. ───────
log('LEG 2 — Manager attempts $40,000 (his delegated authority caps at $10k)');
const mgr = await resolveAuthority(store, { organization_id: 'acme', approver_id: 'ben-mgr',
    action_type: 'large_payment_release', amount: 40000, currency: 'USD', policy_hash: POLICY_HASH, issued_at: AT });
const mgrEnf = applyAuthorityEnforcement({ verdict: mgr.verdict, isCritical: true, mode: 'enforce_critical' });
console.log('verdict           :', mgr.verdict, `(${mgr.detail})`);
console.log('enforce_critical  :', mgrEnf.admissibility, `code=${mgrEnf.code} block=${mgrEnf.block}`);
// ── LEG 3: a stranger with no authority record. Fail closed, not "unknown-allow". ─
log('LEG 3 — Stranger with no authority record');
const stranger = await resolveAuthority(store, { organization_id: 'acme', approver_id: 'mallory',
    action_type: 'large_payment_release', amount: 100, currency: 'USD', policy_hash: POLICY_HASH, issued_at: AT });
const strangerEnf = applyAuthorityEnforcement({ verdict: stranger.verdict, isCritical: true, mode: 'enforce_default' });
console.log('verdict           :', stranger.verdict);
console.log('enforce_default   :', strangerEnf.admissibility, `code=${strangerEnf.code} block=${strangerEnf.block}`);
// ── Assertions: the closure holds. ────────────────────────────────────────────
log('CLOSURE ASSERTIONS');
const checks = [
    ['CFO $40k is authorized', cfo.verdict === 'authorized'],
    ['CFO receipt binds registry head + epoch', /^sha256:[0-9a-f]{64}$/.test(cfoBinding.authority_registry_head) && cfoBinding.authority_registry_epoch === 17],
    ['portable proof accepted only when the registry key is pinned', accepted.accepted === true && unpinned.accepted === false],
    ['manager $40k exceeds his $10k delegated cap (amount_exceeded)', mgr.verdict === 'amount_exceeded'],
    ['manager $40k is NOT admissible under enforce_critical', mgrEnf.block === true && mgrEnf.admissibility === 'not_admissible'],
    ['stranger is unknown_authority, not "unknown but allow"', stranger.verdict === 'unknown_authority'],
    ['stranger is refused, coded authority_unresolved', strangerEnf.block === true && strangerEnf.code === 'authority_unresolved'],
    ['registry head is stable for the snapshot', snapshot.head === cfoBinding.authority_registry_head],
];
let allOk = true;
for (const [label, ok] of checks) {
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
    if (!ok)
        allOk = false;
}
console.log(`\n${allOk ? 'OK — the authority-to-admissibility closure holds end to end.' : 'FAILED — closure broken.'}`);
process.exit(allOk ? 0 : 1);
