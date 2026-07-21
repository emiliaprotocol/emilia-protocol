/**
 * EP-EXECUTION-INTEGRITY-v1 — adversarial conformance suite.
 *
 * For each attack catalogued in conformance/vectors/execution-integrity.v1.json
 * we build an attestation that MUST verify { valid:false }, plus one well-formed
 * attestation that MUST verify { valid:true }. The executor signatures are minted
 * LIVE here (real Ed25519 over canonical bytes) so the negatives are genuine
 * forgery / drift attempts, not hand-edited JSON that would have failed for some
 * unrelated reason.
 *
 * The EXECUTION-INTEGRITY binding is ADDITIVE over the FROZEN EP-RECEIPT-v1: it
 * composes the same canonicalize()/actionHash() as @emilia-protocol/issue and
 * adds exactly one new trust input — the executor's attested signature. The
 * executor is a party EP IDENTIFIES BUT NEVER TRUSTS (mirrors PIP-007): its
 * signature attributes the executed-action claim to a named key, granting no
 * authority. FAIL CLOSED on drift, missing attestation for an irreversible
 * action, or a forged/unbound/unpinned executor signature.
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  bindExecution,
  verifyExecutionIntegrity,
  EXECUTION_INTEGRITY_VERSION,
} from '../lib/execution/integrity.js';

import {
  canonicalize,
  actionHash,
  generateEd25519KeyPair,
} from '../packages/issue/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = JSON.parse(
  readFileSync(path.join(__dirname, '..', 'conformance', 'vectors', 'execution-integrity.v1.json'), 'utf8'),
);

// ── reference material ───────────────────────────────────────────────────────
// The approved Action Object (action A). Its action_hash is what the receipt
// committed to; the executor must attest it ran exactly this.
const APPROVED_ACTION = {
  action_type: 'payment.release',
  policy_id: 'policy.wires',
  initiator: 'ep:agent:worker',
  target_resource_id: 'wire/8841',
  amount: 2_400_000,
  currency: 'USD',
};
const APPROVED_HASH = actionHash(APPROVED_ACTION); // "sha256:<hex>"

// A DIFFERENT action (action B) the executor might actually run — drift.
const DRIFTED_ACTION = {
  ...APPROVED_ACTION,
  target_resource_id: 'wire/9999', // different beneficiary
  amount: 4_000_000,
};

const EXECUTOR_ID = 'ep:executor:emilia-primary';
const executorKp = generateEd25519KeyPair();

/** The executor signer: signs the canonical attestation bytes with its own key. */
function executorSigner(kp = executorKp) {
  return {
    executorId: EXECUTOR_ID,
    publicKeyB64u: kp.publicKeyB64u,
    sign: (bytes) => crypto.sign(null, bytes, kp.privateKey).toString('base64url'),
  };
}

/** Pinned executor-key map the verifier trusts (identified-AND-pinned). */
function pinnedKeys(kp = executorKp) {
  return { [EXECUTOR_ID]: { public_key: kp.publicKeyB64u } };
}

// A minimal frozen-shaped receipt reference: the verifier only reads action_hash
// off it. We never modify or re-sign EP-RECEIPT-v1 here.
const RECEIPT = { action_hash: APPROVED_HASH, receipt_id: 'ep:receipt:test#1' };

const byId = (list, id) => list.find((v) => v.id === id);

describe('EP-EXECUTION-INTEGRITY-v1 — version + assembly', () => {
  it('exposes the wire version', () => {
    expect(EXECUTION_INTEGRITY_VERSION).toBe('EP-EXECUTION-INTEGRITY-v1');
  });

  it('bindExecution refuses to attest drift (the executed call != approved hash)', () => {
    // bindExecution is the HONEST issuer-side gate: it MUST NOT mint an
    // attestation claiming a match when the executed call drifts. (Mirrors the
    // signEvidenceReceipt honesty gate: a signature asserts a fact that was true.)
    expect(() =>
      bindExecution({
        approvedActionHash: APPROVED_HASH,
        executedAction: DRIFTED_ACTION,
        irreversible: true,
        signer: executorSigner(),
      }),
    ).toThrow(/drift/i);
  });
});

describe('EP-EXECUTION-INTEGRITY-v1 — must_reject vectors', () => {
  it('a_execution_drift — executed canonical hash != approved action_hash', () => {
    // Force a drifted attestation past the honest issuer gate to test the verifier.
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      irreversible: true,
      signer: executorSigner(),
    });
    // Swap in the drifted executed action AND re-sign over the tampered bytes so
    // this is genuine drift, not a signature/binding failure.
    const drifted = reSign(
      { ...att, executed_action: DRIFTED_ACTION, executed_action_hash: actionHash(DRIFTED_ACTION) },
      executorKp,
    );
    const r = verifyExecutionIntegrity(drifted, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.executed_hash_matches_approved).toBe(false);
    expect(byId(VECTORS.must_reject, 'a_execution_drift').expected.failing_check)
      .toBe('executed_hash_matches_approved');
  });

  it('b_claimed_hash_not_recomputed — self-declared hash != recomputed hash', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      irreversible: true,
      signer: executorSigner(),
    });
    // Lie: keep executed_action_hash = approved H_A, but swap executed_action to B.
    // (re-sign over the lying combination so it is not a signature failure.)
    const lying = reSign(
      { ...att, executed_action: DRIFTED_ACTION /* executed_action_hash stays H_A */ },
      executorKp,
    );
    const r = verifyExecutionIntegrity(lying, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.executed_hash_self_consistent).toBe(false);
  });

  it('c_missing_attestation_irreversible — irreversible action, no attestation', () => {
    const r = verifyExecutionIntegrity(null, RECEIPT, {
      executorKeys: pinnedKeys(),
      irreversible: true,
    });
    expect(r.valid).toBe(false);
    expect(r.checks.attestation_present).toBe(false);
  });

  it('d_forged_executor_signature — signature does not verify under pinned key', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      irreversible: true,
      signer: executorSigner(),
    });
    const forged = { ...att, signature_b64u: Buffer.from('not-a-real-signature').toString('base64url') };
    const r = verifyExecutionIntegrity(forged, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.executor_signature_valid).toBe(false);
  });

  it('e_signature_over_other_bytes — signature valid but over different bytes', () => {
    // Sign a truthful attestation, then tamper a SIGNED field that does NOT cause
    // drift (executed_at) WITHOUT re-signing. The executed_action still matches
    // the approved hash (drift + self-consistency pass), but the signature was
    // made over the OLD executed_at, so it no longer binds the PRESENTED bytes.
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      irreversible: true,
      signer: executorSigner(),
    });
    const swapped = {
      ...att,
      executed_at: '1999-01-01T00:00:00.000Z', // tampered after signing
      // signature_b64u intentionally left as the original (over the real executed_at).
    };
    const r = verifyExecutionIntegrity(swapped, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(false);
    expect(r.checks.signature_binds_attestation).toBe(false);
    // drift + self-consistency must still PASS so the binding failure is isolated.
    expect(r.checks.executed_hash_matches_approved).toBe(true);
    expect(r.checks.executed_hash_self_consistent).toBe(true);
  });

  it('f_unpinned_executor_key — key not in the verifier pin set', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      irreversible: true,
      signer: executorSigner(),
    });
    // Verifier pins a DIFFERENT executor key — the presented attestation's key is
    // identified (named) but NOT trusted (not pinned).
    const otherKp = generateEd25519KeyPair();
    const r = verifyExecutionIntegrity(att, RECEIPT, {
      executorKeys: { [EXECUTOR_ID]: { public_key: otherKp.publicKeyB64u } },
    });
    expect(r.valid).toBe(false);
    expect(r.checks.executor_key_pinned).toBe(false);
  });
});

describe('EP-EXECUTION-INTEGRITY-v1 — must_accept vector', () => {
  it('g_well_formed_match — executed == approved, signed by pinned executor key', () => {
    const att = bindExecution({
      approvedActionHash: APPROVED_HASH,
      executedAction: APPROVED_ACTION,
      irreversible: true,
      signer: executorSigner(),
    });
    const r = verifyExecutionIntegrity(att, RECEIPT, { executorKeys: pinnedKeys() });
    expect(r.valid).toBe(true);
    expect(r.errors).toEqual([]);
    // every gating check passed
    for (const [k, v] of Object.entries(r.checks)) {
      expect(v, `check ${k}`).toBe(true);
    }
  });

  it('a missing attestation is permitted (vacuous) ONLY when reversibility is independently asserted', () => {
    // A producer's own irreversible:false self-label must NOT drop the requirement:
    // a bare flag is not an independent assertion, so the gate stays closed.
    const producerSelfLabel = verifyExecutionIntegrity(null, RECEIPT, {
      executorKeys: pinnedKeys(),
      irreversible: false, // producer self-label — untrusted on its own
    });
    expect(producerSelfLabel.valid).toBe(false);
    expect(producerSelfLabel.checks.attestation_present).toBe(false);

    // Only an INDEPENDENT verifier-side assertion of reversibility makes the
    // missing attestation vacuously acceptable.
    const verifierAssertsReversible = verifyExecutionIntegrity(null, RECEIPT, {
      executorKeys: pinnedKeys(),
      reversibilityAsserted: () => true,
    });
    expect(verifierAssertsReversible.valid).toBe(true);
  });
});

// ── helper: re-sign a (possibly tampered) attestation over its canonical bytes ─
// Used by the negative tests that need genuine drift WITHOUT a signature failure.
// It reproduces the issuer's signed-payload construction so the forensic target
// of each negative is the intended check, not an incidental signature break.
function reSign(att, kp) {
  // Mirror lib/execution/integrity.js executionSignedPayload() EXACTLY so a
  // re-signed (possibly tampered) attestation produces genuine drift / lying-hash
  // negatives WITHOUT an incidental signature break — the forensic target of each
  // negative is then the intended check, not an accidental signature mismatch.
  const payload = canonicalize({
    '@version': 'EP-EXECUTION-INTEGRITY-v1',
    approved_action_hash: att.approved_action_hash,
    binding_status: att.binding_status ?? 'match',
    executed_action: att.executed_action ?? null,
    executed_action_hash: att.executed_action_hash,
    executed_at: att.executed_at ?? null,
    execution_id: att.execution_id ?? null,
    executor_id: att.executor_id ?? att.proof?.executor_key_id ?? null,
  });
  const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), kp.privateKey).toString('base64url');
  return { ...att, signature_b64u: sig };
}
