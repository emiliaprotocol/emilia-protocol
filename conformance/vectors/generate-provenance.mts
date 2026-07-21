// SPDX-License-Identifier: Apache-2.0
// Generator for executable EP-PROVENANCE-CHAIN-v1 conformance vectors. Mints REAL
// bundles (Class-A receipts + Ed25519 delegation proofs) via packages/issue +
// lib/provenance, so JS, Python, and Go verify the SAME bytes identically.
// Run: node generate-provenance.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { assembleProvenance } from '../../lib/provenance/chain.js';
import {
  canonicalize, buildContexts, collectSignoffs, assembleAuthorizationReceipt,
  policyHash as computePolicyHash, generateEd25519KeyPair,
} from '../../packages/issue/index.js';

const NOW = Date.parse('2026-06-13T12:00:00.000Z');
const ISSUED_AT = '2026-06-13T11:00:00.000Z';
const EXPIRES_AT = '2026-06-13T18:00:00.000Z';
const FLAG_UP = 0x01; const FLAG_UV = 0x04;

function newP256() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, publicKeyB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
/**
 * @param {{ approverKeyId: string, privateKey: *, signedAt: string }} params
 * @returns {import('../../packages/issue/index.js').Signer}
 */
function classASigner({ approverKeyId, privateKey, signedAt }): any {
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
async function mintReceipt(approver, approverKeyId) {
  const action = { action_type: 'payment.release', policy_id: 'pol:test', initiator: 'ep:agent:1', params: { amount: 100 } };
  const kp = newP256(); const logKp = generateEd25519KeyPair();
  const contexts = buildContexts({ action, policyHash: computePolicyHash({ policy_id: action.policy_id }), approvers: [approver], requiredApprovals: 1, issuedAt: ISSUED_AT, expiresAt: EXPIRES_AT });
  const signoffs = await collectSignoffs(contexts, [classASigner({ approverKeyId, signedAt: ISSUED_AT, privateKey: kp.privateKey })]);
  const receipt = assembleAuthorizationReceipt({ receiptId: `ep:receipt:${crypto.randomBytes(8).toString('base64url')}`, action, contexts, signoffs, committedAt: '2026-06-13T11:30:00.000Z', log: { privateKey: logKp.privateKey, logKeyId: 'ep:log:test#1' } });
  return { receipt, verification: { approver_keys: { [approverKeyId]: { approver_id: approver, public_key: kp.publicKeyB64u, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2036-01-01T00:00:00Z' } }, log_public_key: logKp.publicKeyB64u, rp_id: 'rp', allowed_origins: ['https://test.emilia'] } };
}
const PROOF_FIELDS = ['delegation_id', 'delegator', 'delegatee', 'scope', 'max_value_usd', 'expires_at', 'constraints'];
function signedLink(link, kp) {
  const subset = {}; for (const f of PROOF_FIELDS) subset[f] = link[f] ?? null;
  const payload = Buffer.from(canonicalize(subset), 'utf8');
  return { ...link, proof: { algorithm: 'Ed25519', signed_payload_b64u: payload.toString('base64url'), signature_b64u: crypto.sign(null, payload, kp.privateKey).toString('base64url'), public_key: kp.publicKeyB64u } };
}

async function buildBundle() {
  const root = await mintReceipt('ep:approver:dir', 'ep:key:dir#1');
  const approval = await mintReceipt('ep:approver:dir', 'ep:key:dir#1');
  const dk = generateEd25519KeyPair();
  const link = signedLink({ delegation_id: 'dlg:1', parent_ref: 'ep:approver:dir', delegator: 'ep:approver:dir', delegatee: 'ep:agent:1', scope: ['payment.release'], max_value_usd: 1000, expires_at: EXPIRES_AT, constraints: {} }, dk);
  const doc = assembleProvenance({ rootSignoff: root, delegationChain: [link], actionApproval: approval, execution: { action_hash: approval.receipt.action_hash, irreversible: true, executed_at: ISSUED_AT } });
  return {
    doc,
    root_verification: structuredClone(root.verification),
    action_verification: structuredClone(approval.verification),
    delegation_keys: { 'ep:approver:dir': { public_key: dk.publicKeyB64u } },
  };
}

// Two-hop chain: root -> agentA (constraints {max_calls:5}) -> agentB. The leaf
// either NARROWS (max_calls<=5, accept) or RELAXES (max_calls>5, reject).
/**
 * @param {number} leafMaxCalls
 * @param {number|string} [leafCap]
 */
async function buildTwoHop(leafMaxCalls, leafCap = 500) {
  const root = await mintReceipt('ep:approver:dir', 'ep:key:dir#1');
  const approval = await mintReceipt('ep:approver:dir', 'ep:key:dir#1');
  const dirKp = generateEd25519KeyPair();
  const agentAKp = generateEd25519KeyPair();
  const link1 = signedLink({ delegation_id: 'dlg:1', parent_ref: 'ep:approver:dir', delegator: 'ep:approver:dir', delegatee: 'ep:agent:A', scope: ['payment.release'], max_value_usd: 1000, expires_at: EXPIRES_AT, constraints: { max_calls: 5 } }, dirKp);
  const link2 = signedLink({ delegation_id: 'dlg:2', parent_ref: 'ep:agent:A', delegator: 'ep:agent:A', delegatee: 'ep:agent:1', scope: ['payment.release'], max_value_usd: leafCap, expires_at: EXPIRES_AT, constraints: { max_calls: leafMaxCalls } }, agentAKp);
  const doc = assembleProvenance({ rootSignoff: root, delegationChain: [link1, link2], actionApproval: approval, execution: { action_hash: approval.receipt.action_hash, irreversible: true, executed_at: ISSUED_AT } });
  return {
    doc,
    root_verification: structuredClone(root.verification),
    action_verification: structuredClone(approval.verification),
    delegation_keys: { 'ep:approver:dir': { public_key: dirKp.publicKeyB64u }, 'ep:agent:A': { public_key: agentAKp.publicKeyB64u } },
  };
}

const V: any[] = [];
const add = (id, expectValid, b) => V.push({
  id,
  expect: { valid: expectValid },
  provenance_chain: b.doc,
  root_verification: b.root_verification,
  action_verification: b.action_verification,
  delegation_keys: b.delegation_keys,
  now_ms: NOW,
});

add('accept_valid_chain', true, await buildBundle());
{ const b = await buildBundle(); b.doc.delegation_chain[0].scope = ['treasury.wire']; add('reject_scope_violation', false, b); }
{ const b = await buildBundle(); b.doc.delegation_chain[0].max_value_usd = 999999; add('reject_tampered_proof', false, b); }
{ const b = await buildBundle(); b.delegation_keys = {} as any; add('reject_unpinned_delegator', false, b); }
{ const b = await buildBundle(); (b as any).root_verification = null; (b as any).action_verification = null; add('reject_presenter_supplied_trust_roots', false, b); }
{ const b = await buildBundle(); delete (b.root_verification as any).rp_id; add('reject_root_profile_without_rp_id', false, b); }
{ const b = await buildBundle(); delete (b.root_verification as any).allowed_origins; add('reject_root_profile_without_allowed_origins', false, b); }
{ const b = await buildBundle(); (b.root_verification as any).rp_id = 'attacker.example'; add('reject_root_profile_wrong_rp_id', false, b); }
{ const b = await buildBundle(); (b.root_verification as any).allowed_origins = ['https://attacker.example']; add('reject_root_profile_wrong_origin', false, b); }
{ const b = await buildBundle(); delete (b.action_verification as any).rp_id; add('reject_action_profile_without_rp_id', false, b); }
{ const b = await buildBundle(); (b.action_verification as any).allowed_origins = ['https://attacker.example']; add('reject_action_profile_wrong_origin', false, b); }
add('accept_two_hop_constraints_narrowed', true, await buildTwoHop(3));
add('reject_constraints_relaxed', false, await buildTwoHop(50));
// Leaf validly SIGNED over a non-numeric cap under a numeric parent: the signature
// checks out but cap containment must fail closed in all three ports (the JS-sibling
// value-cap fail-open the sweep found). Constraints are narrowed so ONLY the cap fails.
add('reject_nonnumeric_child_cap', false, await buildTwoHop(3, 'abc' as any));

const suite = {
  suite: 'EP-PROVENANCE-CHAIN-v1',
  profile: 'Executable provenance-chain vectors (real receipts + delegation proofs). verifyProvenanceOffline requires relying-party root/action verification profiles, including RP ID and exact allowed origins, plus delegationKeys and now.',
  vectors_version: '1.0.0',
  count: V.length,
  vectors: V,
};
writeFileSync(new URL('./provenance.exec.v1.json', import.meta.url), JSON.stringify(suite, null, 2) + '\n');
console.log(`wrote provenance.exec.v1.json — ${V.length} vectors`);
