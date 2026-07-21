// SPDX-License-Identifier: Apache-2.0
//
// Assurance-proof binding — an EP-ASSURANCE-PROOF-v1 is bound to the receipt it
// was issued for and cannot be transferred.
//
// The approver signoffs inside an assurance proof sign a digest over
// proofContext(doc) = { receipt_id, claim_hash = sha256(canonicalize(claim)) },
// and evaluateReceiptAssurance RECOMPUTES that digest from the presented doc on
// every call. So a proof that legitimately earns class_a / quorum for one
// receipt must NOT still evaluate as class_a / quorum when:
//   (a) it is transplanted onto a different receipt (different receipt_id), or
//   (b) the receipt's claim is edited after the proof was produced.
//
// Assumption this pins: the assurance tier binds to receipt_id + the full claim.
// (It deliberately does NOT bind subject / issuer / created_at into the approver
// digest — those are covered by receipt-level verification, not here.)
//
// Regression for: "assurance proof does not transfer across receipt/claim."

import { describe, it, expect } from 'vitest';
import { evaluateReceiptAssurance } from '../packages/require-receipt/index.js';
import { createEg1Harness } from '../packages/gate/eg1-conformance.js';

const CLASS_A_ACTION = { action_type: 'payment.release' };

function deepClone(o) { return JSON.parse(JSON.stringify(o)); }

function assuranceOpts(h) {
  return {
    approverKeys: h.approverKeys,
    rpId: h.rpId,
    allowedOrigins: h.allowedOrigins,
  };
}

describe('assurance-proof binding (non-transferable)', () => {
  it('a freshly-minted proof-backed receipt earns class_a against the pinned keys', () => {
    const h = createEg1Harness({ action: CLASS_A_ACTION, idPrefix: 'bind_ok' });
    const doc = h.mint({ outcome: 'allow_with_signoff' }); // real Class-A device signoff

    const r = evaluateReceiptAssurance(doc, 'class_a', assuranceOpts(h));
    expect(r.ok).toBe(true);
    expect(r.have).toBe('class_a');
  });

  it('REFUSES a proof transplanted onto a different receipt (receipt_id rebind)', () => {
    const h = createEg1Harness({ action: CLASS_A_ACTION, idPrefix: 'bind_xfer' });
    const donor = h.mint({ outcome: 'allow_with_signoff' });
    const victim = h.mint({ outcome: 'allow' }); // software-only, its own distinct receipt_id

    // Move the donor's valid assurance_proof onto the victim doc verbatim.
    const forged = deepClone(victim);
    forged.payload.assurance_proof = deepClone(donor.payload.assurance_proof);

    const r = evaluateReceiptAssurance(forged, 'class_a', assuranceOpts(h));
    // The recomputed proofContext uses the victim's receipt_id, so the donor's
    // signatures no longer verify — fail closed, drop to software.
    expect(r.ok).toBe(false);
    expect(r.have).toBe('software');
  });

  it('REFUSES after a claim edit (claim_hash rebind)', () => {
    const h = createEg1Harness({ action: CLASS_A_ACTION, idPrefix: 'bind_claim' });
    const doc = h.mint({ outcome: 'allow_with_signoff' });

    // Sanity: it earns class_a before the edit.
    expect(evaluateReceiptAssurance(doc, 'class_a', assuranceOpts(h)).have).toBe('class_a');

    // Edit any claim field after the proof was produced. proofContext hashes the
    // WHOLE claim, so claim_hash changes and the approver digest no longer matches.
    const edited = deepClone(doc);
    edited.payload.claim.amount_usd = 1_000_000;

    const r = evaluateReceiptAssurance(edited, 'class_a', assuranceOpts(h));
    expect(r.ok).toBe(false);
    expect(r.have).toBe('software');
  });
});
