/**
 * EP-DISPLAY-ATTESTATION-v1 — WYSIWYS adversarial conformance suite.
 *
 * For each attack catalogued in conformance/vectors/wysiwys.v1.json we build
 * material that MUST verify { valid:false }, plus the well-formed cases that
 * MUST verify { valid:true }. The cryptographic material (Ed25519 keys, real
 * detached proofs over canonical bytes) is minted LIVE here so the negatives
 * are genuine forgery attempts, not hand-edited JSON that would fail for an
 * unrelated reason.
 *
 * The display attestation is ADDITIVE over the FROZEN EP-RECEIPT-v1 (PIP-001):
 * it composes the same canonicalize()/actionHash() as @emilia-protocol/issue
 * and adds exactly one new local primitive — detached Ed25519 verification of
 * the signing client's claim — which grants no trust on its own. The renderer
 * is a PURE deterministic function of the signed action.
 *
 * HONEST RESIDUAL: these tests prove the verifier rejects a rendering that is
 * not a deterministic function of the SIGNED action, and rejects a missing or
 * forged attestation on a high-stakes action. They do NOT — and cannot — prove
 * a compromised signing device showed the human the truth. That residual is out
 * of scope; it is addressed by device/TEE attestation, a layer above this
 * profile. See docs/EP-WYSIWYS-SPEC.md §Residual Risk.
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { actionHash, generateEd25519KeyPair, canonicalize } from '../packages/issue/index.js';
import crypto from 'node:crypto';
import {
  renderAction,
  buildDisplayAttestation,
  verifyDisplayAttestation,
  DISPLAY_ATTESTATION_VERSION,
  RENDER_PROFILE,
} from '../lib/wysiwys/render.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = JSON.parse(
  readFileSync(path.join(__dirname, '..', 'conformance', 'vectors', 'wysiwys.v1.json'), 'utf8'),
);
const REJECT = Object.fromEntries(VECTORS.must_reject.map((v) => [v.id, v]));
const ACCEPT = Object.fromEntries(VECTORS.must_accept.map((v) => [v.id, v]));

function spkiB64u(publicKey) {
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}
function ed25519() {
  const kp = generateEd25519KeyPair();
  return { ...kp, publicKeyB64u: spkiB64u(kp.publicKey) };
}

// ── The action the human actually approved (the EXACT bytes action_hash commits
// to). The headline high-stakes example from the spec: an $82,000 wire. ───────
const SIGNED = Object.freeze({
  action_type: 'payment.release',
  target_resource_id: 'wire/8841',
  organization_id: 'org:acme',
  actor_id: 'ep:agent:worker-7',
  policy_id: 'ep:policy:wires-over-100k@v12',
  amount: 82000,
  currency: 'USD',
  requested_at: '2026-06-13T17:21:04.000Z',
  risk_flags: ['new_destination'],
});
const SIGNED_HASH = actionHash(SIGNED);

// The CHEAP action a hostile signing surface would substitute: shows $1.
const CHEAP = Object.freeze({ ...SIGNED, amount: 1 });

// A low-stakes action (well under any sane high-stakes threshold).
const LOW_STAKES = Object.freeze({ ...SIGNED, amount: 12, risk_flags: [] });

describe('WYSIWYS renderAction() is a pure deterministic function of the signed action', () => {
  it('is byte-identical for equal actions and binds to the frozen action hash', () => {
    const a = renderAction(SIGNED);
    const b = renderAction({ ...SIGNED });
    expect(a.display_hash).toBe(b.display_hash);
    expect(a.action_hash).toBe(SIGNED_HASH);
    // The human-readable text actually contains the high-stakes amount.
    expect(a.text).toContain('Amount: 82000');
  });

  it('changing a rendered field (the amount) changes the rendering', () => {
    expect(renderAction(CHEAP).display_hash).not.toBe(renderAction(SIGNED).display_hash);
  });
});

describe('EP-DISPLAY-ATTESTATION-v1 — must reject (fail closed)', () => {
  // (a) rendering inconsistent with the signed action: shows $1, action is $82k.
  it(REJECT.a_rendering_inconsistent_with_action_hash.id, () => {
    // The signing surface renders/attests the CHEAP ($1) action, then forces the
    // attestation's action_hash to look like the signed ($82k) one.
    const att = buildDisplayAttestation({ action: CHEAP });
    att.action_hash = SIGNED_HASH;
    // Verifier re-renders the SIGNED $82k action; the attested display_hash
    // (for a $1 rendering) does not match.
    const res = verifyDisplayAttestation(SIGNED, att);
    expect(res.valid).toBe(false);
    expect(res.checks.display_hash_match).toBe(false);
  });

  // (b) required display attestation missing for a high-stakes action.
  it(REJECT.b_missing_display_attestation_high_stakes.id, () => {
    const res = verifyDisplayAttestation(SIGNED, null, { requireDisplayAttestation: true });
    expect(res.valid).toBe(false);
    expect(res.checks.attestation_present).toBe(false);
  });

  // (c) forged attestation — signature over UNRELATED bytes.
  it(REJECT.c_forged_display_attestation_unrelated_bytes.id, () => {
    const signer = ed25519();
    // Honest rendering + a proof whose signature is over unrelated bytes.
    const att = buildDisplayAttestation({ action: SIGNED });
    const garbage = Buffer.from(canonicalize({ unrelated: 'bytes', n: 7 }), 'utf8');
    att.proof = {
      algorithm: 'Ed25519',
      signer_key_id: 'ep:key:client#1',
      signed_payload_b64u: garbage.toString('base64url'),
      signature_b64u: crypto.sign(null, garbage, signer.privateKey).toString('base64url'),
      public_key: signer.publicKeyB64u,
    };
    const res = verifyDisplayAttestation(SIGNED, att, {
      displaySignerKeys: { 'ep:key:client#1': { public_key: signer.publicKeyB64u } },
    });
    expect(res.valid).toBe(false);
    expect(res.checks.proof_signed).toBe(false);
  });

  // (c2) forged attestation — signed by the WRONG key.
  it(REJECT.c2_forged_display_attestation_wrong_key.id, () => {
    const realSigner = ed25519();
    const attacker = ed25519();
    // Honest rendering, but signed by the attacker key while claiming the real id.
    const att = buildDisplayAttestation({
      action: SIGNED,
      signer: {
        signer_key_id: 'ep:key:client#1',
        privateKey: attacker.privateKey,
        publicKeyB64u: attacker.publicKeyB64u,
      },
    });
    const res = verifyDisplayAttestation(SIGNED, att, {
      displaySignerKeys: { 'ep:key:client#1': { public_key: realSigner.publicKeyB64u } },
    });
    expect(res.valid).toBe(false);
    expect(res.checks.proof_signed).toBe(false);
  });

  // (c3) signed attestation whose signer is NOT pinned by the verifier.
  it(REJECT.c3_unpinned_display_signer_key.id, () => {
    const signer = ed25519();
    // Honest rendering + a real signature over the correct payload, but the
    // verifier pins NO key for this signer_key_id. The signature is therefore
    // checkable only against the producer's self-asserted key, which proves
    // nothing — fail closed (mirrors execution-integrity's f_unpinned_executor_key).
    const att = buildDisplayAttestation({
      action: SIGNED,
      signer: {
        signer_key_id: 'ep:key:client#1',
        privateKey: signer.privateKey,
        publicKeyB64u: signer.publicKeyB64u,
      },
    });
    const res = verifyDisplayAttestation(SIGNED, att, { requireSignedAttestation: true });
    expect(res.valid).toBe(false);
    expect(res.checks.proof_signed).toBe(false);
  });

  // (d) attestation binds a DIFFERENT action_hash than the signed action.
  it(REJECT.d_attestation_binds_wrong_action_hash.id, () => {
    const att = buildDisplayAttestation({ action: SIGNED });
    att.action_hash = actionHash(CHEAP); // swap the bound action hash
    const res = verifyDisplayAttestation(SIGNED, att);
    expect(res.valid).toBe(false);
    expect(res.checks.display_hash_match).toBe(false);
  });
});

describe('EP-DISPLAY-ATTESTATION-v1 — must accept', () => {
  // (z) well-formed, signed high-stakes attestation.
  it(ACCEPT.z_well_formed_high_stakes_signed.id, () => {
    const signer = ed25519();
    const att = buildDisplayAttestation({
      action: SIGNED,
      signer: {
        signer_key_id: 'ep:key:client#1',
        privateKey: signer.privateKey,
        publicKeyB64u: signer.publicKeyB64u,
      },
    });
    const res = verifyDisplayAttestation(SIGNED, att, {
      requireDisplayAttestation: true,
      requireSignedAttestation: true,
      displaySignerKeys: { 'ep:key:client#1': { public_key: signer.publicKeyB64u } },
    });
    expect(res.errors, JSON.stringify(res, null, 2)).toEqual([]);
    expect(res.valid).toBe(true);
    expect(res.checks.render_deterministic).toBe(true);
    expect(res.checks.display_hash_match).toBe(true);
    expect(res.checks.proof_signed).toBe(true);
    expect(att['@version']).toBe(DISPLAY_ATTESTATION_VERSION);
    expect(att.render_profile).toBe(RENDER_PROFILE);
  });

  // (z2) low-stakes action, no attestation required, none supplied -> accept.
  it(ACCEPT.z2_well_formed_low_stakes_no_attestation.id, () => {
    const res = verifyDisplayAttestation(LOW_STAKES, null, { requireDisplayAttestation: false });
    expect(res.valid).toBe(true);
    expect(res.checks.render_deterministic).toBe(true);
  });
});

// Catalogue/test parity — every catalogued id is exercised by name above.
describe('EP-DISPLAY-ATTESTATION-v1 — vector catalogue parity', () => {
  it('catalogue is the expected wire tag, and every id is asserted by name', () => {
    expect(VECTORS.wire_tag).toBe('EP-DISPLAY-ATTESTATION-v1');
    expect(VECTORS.must_reject).toHaveLength(6);
    expect(VECTORS.must_accept).toHaveLength(2);
    const asserted = new Set([...Object.keys(REJECT), ...Object.keys(ACCEPT)]);
    for (const v of [...VECTORS.must_reject, ...VECTORS.must_accept]) {
      expect(asserted.has(v.id)).toBe(true);
    }
  });
});
