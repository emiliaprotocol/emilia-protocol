// SPDX-License-Identifier: Apache-2.0
// Role non-substitution — the semantic differential behind the boundary suite's
// policy_decision_presented_as_human_authorization vector.
//
// The invariant, stated exactly: a cryptographically valid and TRUSTED machine
// policy decision for the SAME action cannot satisfy a relying party's
// human-authorization requirement. Not because its JSON fails to parse as an
// EP receipt (that is the boundary vector's weaker, cross-language check), but
// because evidence roles do not substitute: a filled policy_decision leg
// leaves the ep-receipt leg empty, and the relying party's pinned requirement
// fails closed on the empty leg.
//
// Three parts, all real Ed25519 over EP-canonical bytes, no stubs:
//   1. POSITIVE — the machine decision verifies IN ITS OWN ROLE (policy_decision).
//   2. NEGATIVE — the same valid, trusted, same-digest artifact cannot fill the
//      ep-receipt role, whether substituted crudely (typed as ep-receipt) or
//      presented under the presenter's own weaker requirement against a pinned
//      relying-party bar.
//   3. CONTROL — a genuine EP receipt fills the ep-receipt leg and the same
//      pinned bar allows.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import { canonicalize } from '../packages/verify/index.js';
import { actionDigest, verifyAuthorizationChain, AEC_VERSION } from '../packages/verify/evidence-chain.js';

function ed25519() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
const signCanonical = (payload, privateKey) =>
  crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url');

// One canonical action, shared by every artifact below.
const action = {
  action_type: 'wire.release',
  target: 'treasury.example/wire/8841',
  amount: '25000.00',
  currency: 'USD',
};
const D = actionDigest(action);
const DIGEST = `sha256:${D}`;

// The machine: a policy engine whose key the relying party genuinely trusts.
const machine = ed25519();
const policyDecisionDoc = {
  '@version': 'ACCESS-DECISION-RECORD-v1',
  payload: {
    decision_id: 'dec_rns_1',
    decision: 'allow',
    decision_maker: 'policy-engine:gateway-7',
    tool: 'wire.release',
    approval_state: 'granted',
    action_digest: DIGEST,
    issued_at: '2026-07-11T12:00:00Z',
  },
};
policyDecisionDoc.signature = { algorithm: 'Ed25519', value: signCanonical(policyDecisionDoc.payload, machine.privateKey) };

// The relying party's OWN verifier for the policy_decision role: real signature
// check against the pinned machine key, digest taken from the signed payload.
const policyDecisionVerifier = (evidence) => {
  try {
    if (evidence?.['@version'] !== 'ACCESS-DECISION-RECORD-v1') return { valid: false, action_digest: null };
    const keyObject = crypto.createPublicKey({ key: Buffer.from(machine.pub, 'base64url'), format: 'der', type: 'spki' });
    const ok = crypto.verify(
      null,
      Buffer.from(canonicalize(evidence.payload), 'utf8'),
      keyObject,
      Buffer.from(evidence.signature?.value ?? '', 'base64url'),
    );
    return { valid: ok && evidence.payload.decision === 'allow', action_digest: evidence.payload.action_digest };
  } catch {
    return { valid: false, action_digest: null };
  }
};

// The human: a genuine EP-RECEIPT-v1 over the same action, for the control leg.
const human = ed25519();
const receiptPayload = {
  receipt_id: 'tr_rns_1',
  issuer: 'ep:approver:cfo',
  subject: 'wire.release/wire-8841',
  action_digest: DIGEST,
  created_at: '2026-07-11T12:00:02Z',
};
const epReceiptDoc = {
  '@version': 'EP-RECEIPT-v1',
  payload: receiptPayload,
  signature: { algorithm: 'Ed25519', value: signCanonical(receiptPayload, human.privateKey) },
  // Read by the built-in ep-receipt component verifier:
  operator_public_key: human.pub,
  action_hash: DIGEST,
};

const opts = { verifiers: { policy_decision: policyDecisionVerifier } };

describe('role non-substitution: machine policy allowed is never named human approved', () => {
  it('POSITIVE: the signed decision record verifies in its own role, bound to the action', () => {
    const r = verifyAuthorizationChain({
      '@version': AEC_VERSION,
      action,
      requirement: 'policy_decision',
      components: [{ type: 'policy_decision', evidence: policyDecisionDoc }],
    }, opts);
    expect(r.allow).toBe(true);
    expect(r.components[0]).toMatchObject({ valid: true, bound: true });
  });

  it('NEGATIVE: the same valid artifact typed as ep-receipt does not verify in that role', () => {
    const r = verifyAuthorizationChain({
      '@version': AEC_VERSION,
      action,
      requirement: 'ep-receipt',
      components: [{ type: 'ep-receipt', evidence: { ...policyDecisionDoc, operator_public_key: machine.pub, action_hash: DIGEST } }],
    }, opts);
    expect(r.allow).toBe(false);
    expect(r.components[0].valid).toBe(false);
  });

  it('NEGATIVE: under the relying party\'s pinned bar, a filled policy leg never satisfies the empty human leg', () => {
    const presented = {
      '@version': AEC_VERSION,
      action,
      // The presenter's own sufficiency claim — which WOULD pass on its own.
      requirement: 'policy_decision',
      components: [{ type: 'policy_decision', evidence: policyDecisionDoc }],
    };
    const r = verifyAuthorizationChain(presented, { ...opts, requirement: 'policy_decision AND ep-receipt' });
    expect(r.requirement_source).toBe('relying_party');
    // The machine leg verified and bound — the refusal is purely the unfilled
    // human-authorization role, not any defect in the presented artifact.
    expect(r.components[0]).toMatchObject({ type: 'policy_decision', valid: true, bound: true });
    expect(r.allow).toBe(false);
    expect(r.reasons.join(' ')).toContain('requirement not satisfied');
  });

  it('CONTROL: a genuine EP receipt fills the human leg and the same pinned bar allows', () => {
    const r = verifyAuthorizationChain({
      '@version': AEC_VERSION,
      action,
      requirement: 'policy_decision',
      components: [
        { type: 'policy_decision', evidence: policyDecisionDoc },
        { type: 'ep-receipt', evidence: epReceiptDoc },
      ],
    }, { ...opts, requirement: 'policy_decision AND ep-receipt' });
    expect(r.allow).toBe(true);
    expect(r.components.map((c) => [c.type, c.valid, c.bound])).toEqual([
      ['policy_decision', true, true],
      ['ep-receipt', true, true],
    ]);
  });
});
