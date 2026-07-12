// SPDX-License-Identifier: Apache-2.0
//
// Generates aec-role.v1.json — the EP-AEC role-substitution suite with REAL
// signatures and ROLE-SCOPED pins, run cross-language (JS/Python/Go) through the
// built-in ep-receipt verifier. Unlike aec.json (which stubs every verifier and
// tests only composition mechanics), this suite exercises actual Ed25519
// signatures, role-scoped trust anchors, and signed action binding — the exact
// surface the stub-based suite cannot detect. Backs the security-case claim
// aec-role-substitution-refused.
//
//   node conformance/vectors/generate-aec-role.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { canonicalize } from '../../packages/verify/index.js';

const here = dirname(fileURLToPath(import.meta.url));

// Deterministic Ed25519 keys from fixed 32-byte seeds (stable vector bytes).
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
function keyFromSeed(seedHex) {
  const seed = Buffer.from(seedHex, 'hex');
  const privateKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
  return { privateKey, pub };
}
const human = keyFromSeed('11'.repeat(32));
const machine = keyFromSeed('22'.repeat(32));
const attackerA = keyFromSeed('33'.repeat(32));
const attackerB = keyFromSeed('44'.repeat(32));
const sign = (payload, privateKey) => crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url');

const action = { action_type: 'wire.release', target: 'treasury.example/wire/8841', amount: '25000.00', currency: 'USD' };
const otherAction = { ...action, amount: '999999.00' };
const digest = (a) => `sha256:${crypto.createHash('sha256').update(canonicalize(a), 'utf8').digest('hex')}`;
const DA = digest(action);
const DO = digest(otherAction);

// A genuine EP-RECEIPT-v1 whose SIGNED payload binds `boundDigest`, signed by
// `signer`, naming `namedPub` as its operator key. `extra` overrides top-level.
function receipt({ boundDigest, signer, namedPub, extra = {} }) {
  const payload = { receipt_id: 'tr_role', issuer: 'ep:approver:cfo', subject: 'wire-8841', action_digest: boundDigest, created_at: '2026-07-11T12:00:02Z' };
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: sign(payload, signer) }, operator_public_key: namedPub, ...extra };
}
const chain = (requirement, components) => ({ '@version': 'EP-AEC-v1', action, requirement, components });
const policyLeg = (label) => ({ type: 'policy_decision', ...(label ? { label } : {}), evidence: { valid: true, action_digest: DA } });

const vectors = [
  {
    id: 'accept_pinned_human_receipt',
    description: 'A genuine EP-RECEIPT-v1 signed by the human key pinned FOR the ep-receipt role, binding this action in its signed payload, verifies.',
    expect: { valid: true },
    stub_types: [],
    keys_by_type: { 'ep-receipt': { [human.pub]: human.pub } },
    aec_chain: chain('ep-receipt', [{ type: 'ep-receipt', evidence: receipt({ boundDigest: DA, signer: human.privateKey, namedPub: human.pub }) }]),
  },
  {
    id: 'reject_unpinned_key',
    description: 'A validly signed receipt whose operator key is pinned for NO role is refused (fail closed without a role-scoped anchor).',
    expect: { valid: false },
    stub_types: [],
    keys_by_type: { 'ep-receipt': { [human.pub]: human.pub } },
    aec_chain: chain('ep-receipt', [{ type: 'ep-receipt', evidence: receipt({ boundDigest: DA, signer: machine.privateKey, namedPub: machine.pub }) }]),
  },
  {
    id: 'reject_cross_role_key',
    description: 'CROSS-ROLE KEY CONFUSION: the machine key is pinned, but only for the policy_decision role. Its own signed object, relabeled EP-RECEIPT-v1 and binding this action, must not fill the human role.',
    expect: { valid: false },
    stub_types: [],
    keys_by_type: { 'ep-receipt': { [human.pub]: human.pub }, policy_decision: { [machine.pub]: machine.pub } },
    aec_chain: chain('ep-receipt', [{ type: 'ep-receipt', evidence: receipt({ boundDigest: DA, signer: machine.privateKey, namedPub: machine.pub }) }]),
  },
  {
    id: 'reject_unsigned_binding',
    description: 'A receipt validly signed over a DIFFERENT action, with only the unsigned top-level action_hash spoofed to this action, does not bind this action.',
    expect: { valid: false },
    stub_types: [],
    keys_by_type: { 'ep-receipt': { [human.pub]: human.pub } },
    aec_chain: chain('ep-receipt', [{ type: 'ep-receipt', evidence: receipt({ boundDigest: DO, signer: human.privateKey, namedPub: human.pub, extra: { action_hash: DA } }) }]),
  },
  {
    id: 'reject_label_collision',
    description: 'A policy_decision leg (a permissive stub) LABELED "ep-receipt" must not satisfy the registered ep-receipt requirement token.',
    expect: { valid: false },
    stub_types: ['policy_decision'],
    keys_by_type: { 'ep-receipt': { [human.pub]: human.pub } },
    aec_chain: chain('policy_decision AND ep-receipt', [policyLeg('ep-receipt')]),
  },
  {
    id: 'accept_policy_plus_human',
    description: 'CONTROL: a policy leg plus a genuine human receipt (pinned for ep-receipt) satisfies "policy_decision AND ep-receipt".',
    expect: { valid: true },
    stub_types: ['policy_decision'],
    keys_by_type: { 'ep-receipt': { [human.pub]: human.pub } },
    aec_chain: chain('policy_decision AND ep-receipt', [policyLeg(null), { type: 'ep-receipt', evidence: receipt({ boundDigest: DA, signer: human.privateKey, namedPub: human.pub }) }]),
  },
  {
    id: 'reject_forged_quorum_unpinned_keys',
    description: 'FORGED QUORUM: an attacker builds an entire distinct-human quorum under device keys it generated. No member key is pinned under keysByType["ep-quorum"], so the ep-quorum leg fails closed BEFORE any signature check — verifyQuorum only checks internal consistency against the quorum\'s own declared keys and must never be trusted without pinned approvers.',
    expect: { valid: false },
    stub_types: [],
    keys_by_type: { 'ep-quorum': { [human.pub]: human.pub } },
    aec_chain: chain('ep-quorum', [{
      type: 'ep-quorum',
      label: 'two-person-rule',
      evidence: {
        '@type': 'ep.quorum',
        action_hash: DA,
        policy: { mode: 'threshold', required: 2, distinct_humans: true, window_sec: 172800, approvers: [{ role: 'a', approver: 'ep:approver:attacker-a' }, { role: 'b', approver: 'ep:approver:attacker-b' }] },
        members: [
          { role: 'a', approver_public_key: attackerA.pub, signoff: {} },
          { role: 'b', approver_public_key: attackerB.pub, signoff: {} },
        ],
      },
    }]),
  },
];

const suite = {
  suite: 'EP-AEC-ROLE-v1',
  vectors_version: '1.0.0',
  description:
    'EP-AEC role-substitution suite with REAL Ed25519 signatures and role-scoped pins, run cross-language through the built-in ep-receipt verifier. '
    + 'Each vector: build the stub verifiers named in stub_types (permissive: valid iff evidence.valid !== false, digest = evidence.action_digest), '
    + 'run verifyAuthorizationChain(aec_chain, { keysByType: keys_by_type, verifiers, requirement }), and compare allow to expect.valid.',
  algorithm: 'Ed25519 over RFC 8785 (JCS) canonical payload bytes; role-scoped trust anchors',
  count: vectors.length,
  vectors,
};

writeFileSync(resolve(here, 'aec-role.v1.json'), JSON.stringify(suite, null, 1) + '\n');
console.log(`wrote aec-role.v1.json (${vectors.length} vectors)`);
