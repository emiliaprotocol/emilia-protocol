// SPDX-License-Identifier: Apache-2.0
// Role non-substitution — the semantic invariant behind the boundary suite's
// policy_decision_presented_as_human_authorization vector, exercised against
// the EP-AEC reference composition verifier.
//
// Invariant, stated exactly: a cryptographically valid and TRUSTED machine
// policy decision for the SAME action cannot satisfy a relying party's
// human-authorization requirement — and the ways an attacker might try to make
// it satisfy that requirement all fail closed. Each negative below is a REAL
// substitution attempt (not a malformed fixture), and the point is that the
// verifier refuses it:
//   1. POSITIVE  — the signed machine decision verifies in its OWN role.
//   2. NEGATIVE  — presenter LABEL collision: a policy leg labeled 'ep-receipt'
//      does not satisfy the ep-receipt requirement token.
//   3. NEGATIVE  — VERSION relabel: the machine's own signed object relabeled
//      @version:EP-RECEIPT-v1 with its own key named does not fill the human
//      leg (the key is not relying-party-pinned).
//   4. NEGATIVE  — UNSIGNED binding: a genuine human receipt signed over a
//      DIFFERENT action, with only the unsigned top-level action_hash spoofed
//      to this action, does not bind this action.
//   5. CONTROL   — a genuine EP receipt, signed over THIS action with a
//      relying-party-pinned human key, DOES satisfy the same pinned bar.
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
const action = { action_type: 'wire.release', target: 'treasury.example/wire/8841', amount: '25000.00', currency: 'USD' };
const D = actionDigest(action);
const DIGEST = `sha256:${D}`;

// The machine: a policy engine whose key the relying party genuinely trusts for
// its OWN role (policy_decision), and NOT as a human-authorization key.
const machine = ed25519();
const policyDecisionDoc = {
  '@version': 'ACCESS-DECISION-RECORD-v1',
  payload: {
    decision_id: 'dec_rns_1', decision: 'allow', decision_maker: 'policy-engine:gateway-7',
    tool: 'wire.release', approval_state: 'granted', action_digest: DIGEST, issued_at: '2026-07-11T12:00:00Z',
  },
};
policyDecisionDoc.signature = { algorithm: 'Ed25519', value: signCanonical(policyDecisionDoc.payload, machine.privateKey) };

// The relying party's verifier for the policy_decision role: real signature
// check against the pinned machine key; digest taken from the signed payload.
const policyDecisionVerifier = (evidence) => {
  try {
    if (evidence?.['@version'] !== 'ACCESS-DECISION-RECORD-v1') return { valid: false, action_digest: null };
    const keyObject = crypto.createPublicKey({ key: Buffer.from(machine.pub, 'base64url'), format: 'der', type: 'spki' });
    const ok = crypto.verify(null, Buffer.from(canonicalize(evidence.payload), 'utf8'), keyObject, Buffer.from(evidence.signature?.value ?? '', 'base64url'));
    return { valid: ok && evidence.payload.decision === 'allow', action_digest: evidence.payload.action_digest };
  } catch {
    return { valid: false, action_digest: null };
  }
};

// The human: a genuine EP-RECEIPT-v1 over the same action. The action digest is
// carried INSIDE the signed payload, so the binding is cryptographic.
const human = ed25519();
const receiptPayload = { receipt_id: 'tr_rns_1', issuer: 'ep:approver:cfo', subject: 'wire.release/wire-8841', action_digest: DIGEST, created_at: '2026-07-11T12:00:02Z' };
const epReceiptDoc = {
  '@version': 'EP-RECEIPT-v1',
  payload: receiptPayload,
  signature: { algorithm: 'Ed25519', value: signCanonical(receiptPayload, human.privateKey) },
  operator_public_key: human.pub,
};

// Relying-party pinning: the machine key is pinned ONLY for its policy role via
// the custom verifier; the human key is the one pinned for ep-receipt.
const opts = { verifiers: { policy_decision: policyDecisionVerifier }, keys: { [human.pub]: human.pub } };
const pinnedBar = 'policy_decision AND ep-receipt';

describe('role non-substitution: machine policy allowed is never named human approved', () => {
  it('POSITIVE: the signed decision record verifies in its own role, bound to the action', () => {
    const r = verifyAuthorizationChain({
      '@version': AEC_VERSION, action, requirement: 'policy_decision',
      components: [{ type: 'policy_decision', evidence: policyDecisionDoc }],
    }, opts);
    expect(r.allow).toBe(true);
    expect(r.components[0]).toMatchObject({ valid: true, bound: true });
  });

  it('NEGATIVE (label collision): a policy leg labeled "ep-receipt" does not satisfy the human token', () => {
    const r = verifyAuthorizationChain({
      '@version': AEC_VERSION, action, requirement: 'policy_decision',
      // Attack: relabel the valid, trusted, same-digest machine leg as 'ep-receipt'.
      components: [{ type: 'policy_decision', label: 'ep-receipt', evidence: policyDecisionDoc }],
    }, { ...opts, requirement: pinnedBar });
    // The machine leg still verifies in its own role, but the label must not
    // fill the registered ep-receipt type token.
    expect(r.components[0]).toMatchObject({ type: 'policy_decision', valid: true, bound: true });
    expect(r.allow).toBe(false);
  });

  it('NEGATIVE (version relabel): the machine object relabeled EP-RECEIPT-v1 with its own key is not human authorization', () => {
    const smuggled = { ...policyDecisionDoc, '@version': 'EP-RECEIPT-v1', operator_public_key: machine.pub, action_hash: DIGEST };
    const r = verifyAuthorizationChain({
      '@version': AEC_VERSION, action, requirement: 'ep-receipt',
      components: [{ type: 'ep-receipt', evidence: smuggled }],
    }, opts);
    // The machine key is not pinned for the ep-receipt role, so it fails closed.
    expect(r.components[0].valid).toBe(false);
    expect(r.allow).toBe(false);
  });

  it('NEGATIVE (unsigned binding): a human receipt signed over a DIFFERENT action does not bind this one', () => {
    const otherAction = { ...action, amount: '999999.00' };
    const otherPayload = { receipt_id: 'tr_rns_evil', issuer: 'ep:approver:cfo', subject: 'x', action_digest: `sha256:${actionDigest(otherAction)}`, created_at: '2026-07-11T12:00:00Z' };
    const spoofed = {
      '@version': 'EP-RECEIPT-v1', payload: otherPayload,
      signature: { algorithm: 'Ed25519', value: signCanonical(otherPayload, human.privateKey) },
      operator_public_key: human.pub,
      action_hash: DIGEST, // unsigned top-level spoof to THIS action — must not count
    };
    const r = verifyAuthorizationChain({
      '@version': AEC_VERSION, action, requirement: 'ep-receipt',
      components: [{ type: 'ep-receipt', evidence: spoofed }],
    }, opts);
    // Signature is valid, but the SIGNED payload binds a different action, so the
    // leg is not bound to this chain and cannot satisfy the requirement.
    expect(r.components[0].bound).toBe(false);
    expect(r.allow).toBe(false);
  });

  it('CONTROL: a genuine EP receipt with a pinned human key satisfies the same pinned bar', () => {
    const r = verifyAuthorizationChain({
      '@version': AEC_VERSION, action, requirement: 'policy_decision',
      components: [
        { type: 'policy_decision', evidence: policyDecisionDoc },
        { type: 'ep-receipt', evidence: epReceiptDoc },
      ],
    }, { ...opts, requirement: pinnedBar });
    expect(r.allow).toBe(true);
    expect(r.components.map((c) => [c.type, c.valid, c.bound])).toEqual([
      ['policy_decision', true, true],
      ['ep-receipt', true, true],
    ]);
  });
});
