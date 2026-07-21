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
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { canonicalize } from '../../packages/verify/index.js';

const here = dirname(fileURLToPath(import.meta.url));

// Deterministic Ed25519 keys from fixed 32-byte seeds (stable vector bytes).
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
function keyFromSeed(seedHex: string) {
  const seed = Buffer.from(seedHex, 'hex');
  const privateKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  // Node's crypto.createPublicKey accepts a private KeyObject at runtime (it derives
  // the public key), but @types/node's overloads don't include KeyObject — cast only.
  const pub = crypto.createPublicKey(privateKey as any).export({ type: 'spki', format: 'der' }).toString('base64url');
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
const clone = (value) => JSON.parse(JSON.stringify(value));

// Reuse a stable, real WebAuthn threshold quorum from the shared quorum suite.
// This lets AEC exercise profile admission without minting a second crypto corpus.
const quorumSuite = JSON.parse(readFileSync(resolve(here, 'quorum.v1.json'), 'utf8'));
const thresholdQuorum = clone(quorumSuite.vectors.find((v) => v.id === 'accept_threshold_2of3').quorum);
const crossOriginQuorum = clone(quorumSuite.vectors.find((v) => v.id === 'reject_cross_origin_ceremony').quorum);
const quorumAction = { amount: 40_000_000, currency: 'USD', target: 'program/aegis-1' };
const quorumProfile = (quorum = thresholdQuorum) => ({
  policy: clone(quorum.policy),
  rp_id: 'emiliaprotocol.ai',
  allowed_origins: ['https://www.emiliaprotocol.ai'],
  context_policy: 'policy_aegis_quorum',
  max_age_sec: 900,
  registry_checked_at: '2026-06-11T00:02:30.000Z',
  max_registry_age_sec: 300,
  approvers: Object.fromEntries(quorum.members.map((m) => [m.approver_public_key, {
    public_key: m.approver_public_key,
    approver_id: m.signoff.context.approver,
    roles: [m.role],
    status: 'active',
    valid_from: '2026-01-01T00:00:00.000Z',
    valid_to: '2027-01-01T00:00:00.000Z',
    revoked_at: null,
  }])),
});

const trustSuite = JSON.parse(readFileSync(resolve(here, 'trust-receipt.exec.v1.json'), 'utf8'));
const trustVector = trustSuite.vectors.find((v) => v.id === 'accept_valid_receipt');
const crossOriginTrustVector = trustSuite.vectors.find((v) => v.id === 'reject_cross_origin_ceremony');
const trustReceipt = clone(trustVector.trust_receipt);
const trustAction = clone(trustReceipt.action);
const trustApproverKeys = clone(trustVector.verification.approver_keys);
for (const entry of Object.values(trustApproverKeys)) {
  (entry as any).status = 'active';
  (entry as any).revoked_at = null;
}
const trustProfile = {
  approver_keys: trustApproverKeys,
  log_public_key: trustVector.verification.log_public_key,
  rp_id: 'rp',
  allowed_origins: ['https://test.emilia'],
  expected_policy_hash: trustReceipt.contexts[0].policy_hash,
  max_age_sec: 3600,
  registry_checked_at: '2026-06-13T11:30:00.000Z',
  max_registry_age_sec: 300,
};
const crossOriginTrustApproverKeys = clone(crossOriginTrustVector.verification.approver_keys);
for (const entry of Object.values(crossOriginTrustApproverKeys)) {
  (entry as any).status = 'active';
  (entry as any).revoked_at = null;
}
const crossOriginTrustProfile = {
  ...trustProfile,
  approver_keys: crossOriginTrustApproverKeys,
  log_public_key: crossOriginTrustVector.verification.log_public_key,
  expected_policy_hash: crossOriginTrustVector.trust_receipt.contexts[0].policy_hash,
};

// A genuine EP-RECEIPT-v1 whose SIGNED payload binds `boundDigest`, signed by
// `signer`, naming `namedPub` as its operator key. `extra` overrides top-level.
function receipt({ boundDigest, signer, namedPub, extra = {} }) {
  const payload = { receipt_id: 'tr_role', issuer: 'ep:approver:cfo', subject: 'wire-8841', action_digest: boundDigest, created_at: '2026-07-11T12:00:02Z' };
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: sign(payload, signer) }, operator_public_key: namedPub, ...extra };
}
const chain = (requirement, components, actionObject = action) => ({ '@version': 'EP-AEC-v1', action: actionObject, requirement, components });
const policyLeg = (label, actionDigest = DA) => ({ type: 'policy_decision', ...(label ? { label } : {}), evidence: { valid: true, action_digest: actionDigest } });

const vectors = [
  {
    id: 'accept_pinned_human_receipt',
    description: 'A Section 6.2 Trust Receipt with a pinned Class-A WebAuthn approver, RP audience, policy, log key, and freshness profile verifies.',
    expect: { valid: true },
    stub_types: [],
    policies_by_type: { 'ep-receipt': trustProfile },
    verification_time: '2026-06-13T11:31:00.000Z',
    aec_chain: chain('ep-receipt', [{ type: 'ep-receipt', evidence: trustReceipt }], trustAction),
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
    description: 'CONTROL: a policy leg plus a fresh, profile-bound Class-A Trust Receipt satisfies "policy_decision AND ep-receipt".',
    expect: { valid: true },
    stub_types: ['policy_decision'],
    policies_by_type: { 'ep-receipt': trustProfile },
    verification_time: '2026-06-13T11:31:00.000Z',
    aec_chain: chain('policy_decision AND ep-receipt', [policyLeg(null, trustReceipt.action_hash), { type: 'ep-receipt', evidence: trustReceipt }], trustAction),
  },
  {
    id: 'reject_forged_quorum_unpinned_keys',
    description: 'FORGED QUORUM: an attacker builds an entire distinct-human quorum under device keys it generated. The ep-quorum leg fails closed because the relying party supplied no exact policy, RP ID, context policy, or enrolled approver directory.',
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
  {
    id: 'reject_presenter_chosen_requirement',
    description: 'A valid bundle evaluated only under the presenter requirement never produces relying-party allow.',
    expect: { valid: false },
    stub_types: ['policy_decision'],
    no_requirement_pin: true,
    aec_chain: chain('policy_decision', [policyLeg(null)]),
  },
  {
    id: 'reject_presenter_weak_bar_rp_bar_unsatisfied',
    description: 'The presenter\'s policy-plus-human bar passes, but the relying party also requires a quorum; the missing RP-required leg must deny.',
    expect: { valid: false },
    stub_types: ['policy_decision'],
    policies_by_type: { 'ep-receipt': trustProfile },
    verification_time: '2026-06-13T11:31:00.000Z',
    relying_party_requirement: 'policy_decision AND ep-receipt AND ep-quorum',
    aec_chain: chain('policy_decision AND ep-receipt', [
      policyLeg(null, trustReceipt.action_hash),
      { type: 'ep-receipt', evidence: trustReceipt },
    ], trustAction),
  },
  {
    id: 'reject_missing_expected_action',
    description: 'Internal same-action agreement is not enough when the executor did not pin the action it will perform.',
    expect: { valid: false },
    stub_types: ['policy_decision'],
    no_expected_action_pin: true,
    aec_chain: chain('policy_decision', [policyLeg(null)]),
  },
  {
    id: 'reject_wrong_expected_action',
    description: 'A valid bundle over one action is refused when the executor independently expects another action.',
    expect: { valid: false },
    stub_types: ['policy_decision'],
    expected_action_digest: DO,
    aec_chain: chain('policy_decision', [policyLeg(null)]),
  },
  {
    id: 'reject_unbound_role_label',
    description: 'Presenter label cfo is display metadata and cannot create an authorization role.',
    expect: { valid: false },
    stub_types: ['policy_decision'],
    aec_chain: chain('cfo', [policyLeg('cfo')]),
  },
  {
    id: 'reject_malformed_requirement_chars',
    description: 'A parser must consume the full requirement; ignored punctuation cannot turn a malformed bar into a valid one.',
    expect: { valid: false },
    stub_types: ['policy_decision'],
    aec_chain: chain('policy_decision!!!', [policyLeg(null)]),
  },
  {
    id: 'reject_reserved_verifier_override',
    description: 'A custom verifier cannot replace the reserved ep-receipt built-in with a permissive policy stub.',
    expect: { valid: false },
    stub_types: ['ep-receipt'],
    aec_chain: chain('ep-receipt', [{ type: 'ep-receipt', evidence: { valid: true, action_digest: DA } }]),
  },
  {
    id: 'reject_malformed_null_component',
    description: 'A null component is a typed refusal, never a verifier crash.',
    expect: { valid: false },
    stub_types: ['policy_decision'],
    aec_chain: chain('policy_decision', [null]),
  },
  {
    id: 'accept_profile_bound_quorum',
    description: 'A real 2-of-3 WebAuthn quorum is accepted only under the exact RP-pinned policy, audience, context policy, and approver directory.',
    expect: { valid: true },
    stub_types: [],
    policies_by_type: { 'ep-quorum': quorumProfile() },
    aec_chain: { '@version': 'EP-AEC-v1', action: quorumAction, requirement: 'ep-quorum', components: [{ type: 'ep-quorum', evidence: thresholdQuorum }] },
  },
  {
    id: 'reject_weaker_presented_quorum_policy',
    description: 'A valid quorum document cannot downgrade the RP-pinned threshold by presenting a different policy.',
    expect: { valid: false },
    stub_types: [],
    policies_by_type: { 'ep-quorum': { ...quorumProfile(), policy: { ...thresholdQuorum.policy, required: 3 } } },
    aec_chain: { '@version': 'EP-AEC-v1', action: quorumAction, requirement: 'ep-quorum', components: [{ type: 'ep-quorum', evidence: thresholdQuorum }] },
  },
  {
    id: 'reject_wrong_quorum_rp_id',
    description: 'Valid WebAuthn signatures for one RP are refused under a different relying-party audience.',
    expect: { valid: false },
    stub_types: [],
    policies_by_type: { 'ep-quorum': { ...quorumProfile(), rp_id: 'wrong.example' } },
    aec_chain: { '@version': 'EP-AEC-v1', action: quorumAction, requirement: 'ep-quorum', components: [{ type: 'ep-quorum', evidence: thresholdQuorum }] },
  },
  {
    id: 'reject_wrong_quorum_origin',
    description: 'A valid quorum is refused when its signed WebAuthn client origin is outside the relying-party allowlist.',
    expect: { valid: false },
    stub_types: [],
    policies_by_type: { 'ep-quorum': { ...quorumProfile(), allowed_origins: ['https://wrong.example'] } },
    aec_chain: { '@version': 'EP-AEC-v1', action: quorumAction, requirement: 'ep-quorum', components: [{ type: 'ep-quorum', evidence: thresholdQuorum }] },
  },
  {
    id: 'reject_cross_origin_quorum_ceremony',
    description: 'A signed cross-origin quorum ceremony is refused even when the visible origin string is allowlisted.',
    expect: { valid: false },
    stub_types: [],
    policies_by_type: { 'ep-quorum': quorumProfile(crossOriginQuorum) },
    aec_chain: { '@version': 'EP-AEC-v1', action: quorumAction, requirement: 'ep-quorum', components: [{ type: 'ep-quorum', evidence: crossOriginQuorum }] },
  },
  {
    id: 'reject_stale_quorum',
    description: 'A cryptographically valid historical quorum is refused after its signed authorization window and the RP max-age limit.',
    expect: { valid: false },
    stub_types: [],
    policies_by_type: { 'ep-quorum': quorumProfile() },
    verification_time: '2026-06-11T01:00:01.000Z',
    aec_chain: { '@version': 'EP-AEC-v1', action: quorumAction, requirement: 'ep-quorum', components: [{ type: 'ep-quorum', evidence: thresholdQuorum }] },
  },
  {
    id: 'reject_stale_approver_registry',
    description: 'A valid quorum is refused when the relying-party approver registry snapshot is older than its pinned freshness limit.',
    expect: { valid: false },
    stub_types: [],
    policies_by_type: { 'ep-quorum': { ...quorumProfile(), registry_checked_at: '2026-06-10T00:00:00.000Z' } },
    aec_chain: { '@version': 'EP-AEC-v1', action: quorumAction, requirement: 'ep-quorum', components: [{ type: 'ep-quorum', evidence: thresholdQuorum }] },
  },
  {
    id: 'reject_stale_human_receipt',
    description: 'A valid Class-A Trust Receipt is refused when evaluated after the pinned freshness limit.',
    expect: { valid: false },
    stub_types: [],
    policies_by_type: { 'ep-receipt': trustProfile },
    verification_time: '2026-06-13T13:00:01.000Z',
    aec_chain: chain('ep-receipt', [{ type: 'ep-receipt', evidence: trustReceipt }], trustAction),
  },
  {
    id: 'reject_wrong_receipt_origin',
    description: 'A valid Class-A Trust Receipt is refused when its signed WebAuthn client origin is outside the relying-party allowlist.',
    expect: { valid: false },
    stub_types: [],
    policies_by_type: { 'ep-receipt': { ...trustProfile, allowed_origins: ['https://wrong.example'] } },
    verification_time: '2026-06-13T11:31:00.000Z',
    aec_chain: chain('ep-receipt', [{ type: 'ep-receipt', evidence: trustReceipt }], trustAction),
  },
  {
    id: 'reject_cross_origin_receipt_ceremony',
    description: 'A signed cross-origin Class-A receipt ceremony is refused even when the visible origin string is allowlisted.',
    expect: { valid: false },
    stub_types: [],
    policies_by_type: { 'ep-receipt': crossOriginTrustProfile },
    verification_time: '2026-06-13T11:31:00.000Z',
    aec_chain: chain('ep-receipt', [{ type: 'ep-receipt', evidence: crossOriginTrustVector.trust_receipt }], crossOriginTrustVector.trust_receipt.action),
  },
  {
    id: 'reject_bare_operator_receipt_as_human',
    description: 'A valid Ed25519 operator envelope cannot satisfy the human ep-receipt role without a Class-A ceremony.',
    expect: { valid: false },
    stub_types: [],
    keys_by_type: { 'ep-receipt': { [human.pub]: human.pub } },
    aec_chain: chain('ep-receipt', [{ type: 'ep-receipt', evidence: receipt({ boundDigest: DA, signer: human.privateKey, namedPub: human.pub }) }]),
  },
  {
    id: 'reject_revoked_class_a_approver',
    description: 'A cryptographically valid Class-A receipt is refused when its RP-pinned directory entry is revoked.',
    expect: { valid: false },
    stub_types: [],
    policies_by_type: { 'ep-receipt': (() => {
      const profile = clone(trustProfile);
      const entry = Object.values(profile.approver_keys)[0] as any;
      entry.status = 'revoked';
      entry.revoked_at = '2026-06-13T11:15:00.000Z';
      return profile;
    })() },
    verification_time: '2026-06-13T11:31:00.000Z',
    aec_chain: chain('ep-receipt', [{ type: 'ep-receipt', evidence: trustReceipt }], trustAction),
  },
  {
    id: 'reject_quorum_approver_alias',
    description: 'A pinned key cannot be reassigned to a different approver identity by the presenter.',
    expect: { valid: false },
    stub_types: [],
    policies_by_type: { 'ep-quorum': (() => {
      const profile = quorumProfile();
      profile.approvers[thresholdQuorum.members[0].approver_public_key].approver_id = 'ep:approver:someone_else';
      return profile;
    })() },
    aec_chain: { '@version': 'EP-AEC-v1', action: quorumAction, requirement: 'ep-quorum', components: [{ type: 'ep-quorum', evidence: thresholdQuorum }] },
  },
  {
    id: 'reject_quorum_distinct_humans_omitted',
    description: 'Safety-critical quorum admission requires distinct_humans true explicitly; omission cannot select a permissive default.',
    expect: { valid: false },
    stub_types: [],
    policies_by_type: { 'ep-quorum': (() => {
      const q = clone(thresholdQuorum); delete q.policy.distinct_humans;
      return quorumProfile(q);
    })() },
    aec_chain: { '@version': 'EP-AEC-v1', action: quorumAction, requirement: 'ep-quorum', components: [{ type: 'ep-quorum', evidence: (() => { const q = clone(thresholdQuorum); delete q.policy.distinct_humans; return q; })() }] },
  },
  {
    id: 'reject_unknown_quorum_mode',
    description: 'An unknown policy mode is refused rather than silently interpreted as threshold.',
    expect: { valid: false },
    stub_types: [],
    policies_by_type: { 'ep-quorum': (() => { const q = clone(thresholdQuorum); q.policy.mode = 'threshhold'; return quorumProfile(q); })() },
    aec_chain: { '@version': 'EP-AEC-v1', action: quorumAction, requirement: 'ep-quorum', components: [{ type: 'ep-quorum', evidence: (() => { const q = clone(thresholdQuorum); q.policy.mode = 'threshhold'; return q; })() }] },
  },
];

// `allow` is a relying-party acceptance result, so every vector pins the bar
// out of band. The chain's own requirement remains a presenter claim only.
for (const vector of vectors) {
  if (!vector.no_requirement_pin) {
    (vector as any).requirement = (vector as any).relying_party_requirement ?? (vector as any).aec_chain.requirement;
  }
  if (!vector.no_expected_action_pin && !vector.expected_action_digest) {
    vector.expected_action_digest = digest(vector.aec_chain.action);
  }
  if (vector.policies_by_type?.['ep-quorum'] && !vector.verification_time) {
    vector.verification_time = '2026-06-11T00:03:00.000Z';
  }
  delete vector.no_requirement_pin;
  delete vector.no_expected_action_pin;
  delete vector.relying_party_requirement;
}

const suite = {
  suite: 'EP-AEC-ROLE-v1',
  vectors_version: '1.0.0',
  description:
    'EP-AEC acceptance suite with REAL Ed25519 and Class-A WebAuthn signatures plus RP-scoped profiles, run cross-language through the built-in verifiers. '
    + 'Each vector: build the stub verifiers named in stub_types (permissive: valid iff evidence.valid !== false, digest = evidence.action_digest), '
    + 'run verifyAuthorizationChain with the vector requirement, expected action, verification time, and profiles, then compare allow to expect.valid.',
  algorithm: 'Ed25519 and Class-A WebAuthn over RFC 8785 (JCS) canonical bytes; RP-scoped acceptance profiles',
  count: vectors.length,
  vectors,
};

writeFileSync(resolve(here, 'aec-role.v1.json'), JSON.stringify(suite, null, 1) + '\n');
console.log(`wrote aec-role.v1.json (${vectors.length} vectors)`);
