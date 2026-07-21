// SPDX-License-Identifier: Apache-2.0
//
// Locks the uncovered branches/lines of lib/wysiwys/render.js: renderAction()
// TypeError on non-object input; the FULL-action binding property (decoy/unread
// field changes shift display_hash); the absence marker (∅) for null/undefined;
// risk_flags array/scalar/empty variants; and every fail-closed return in
// verifyDisplayAttestation() / verifyDetachedEd25519() — render_mismatch on
// action_hash and on display_hash, missing_required_attestation,
// invalid_attestation_version, proof_algorithm, proof_payload_mismatch,
// proof_key_unbound, proof_signature (catch + bad-sig), and
// missing_required_signature — plus the unpinned-key acceptance path.

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import { actionHash, canonicalize, generateEd25519KeyPair } from '../packages/issue/index.js';
import {
  renderAction,
  buildDisplayAttestation,
  verifyDisplayAttestation,
  DISPLAY_ATTESTATION_VERSION,
  RENDER_PROFILE,
} from '../lib/wysiwys/render.js';

function ed25519() {
  const kp = generateEd25519KeyPair();
  return {
    ...kp,
    publicKeyB64u: kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

// The reference high-stakes action (an $82,000 wire).
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

function signedAtt(action, keyId = 'ep:key:client#1', signer = ed25519()) {
  const att = buildDisplayAttestation({
    action,
    signer: {
      signer_key_id: keyId,
      privateKey: signer.privateKey,
      publicKeyB64u: signer.publicKeyB64u,
    },
  });
  return { att, signer };
}

// ── renderAction: non-object input throws TypeError (line 117) ──────────────
describe('renderAction() rejects non-object input with TypeError', () => {
  for (const bad of [null, undefined, 'string', 42, true, Symbol('x')]) {
    it(`throws TypeError for ${String(bad)}`, () => {
      expect(() => renderAction(bad)).toThrow(TypeError);
      expect(() => renderAction(bad)).toThrow(/canonical Action Object/);
    });
  }
});

// ── renderValue / absence marker / risk_flags variants ──────────────────────
describe('renderAction() value rendering: absence marker and risk_flags variants', () => {
  it('renders the ∅ absence marker for null and for undefined fields', () => {
    const withNulls = { action_type: 'x' }; // every other field undefined
    const r = renderAction(withNulls);
    // 8 of 9 fields absent -> the marker appears for each missing field.
    expect(r.text).toContain('Target: ∅');
    expect(r.text).toContain('Amount: ∅');
    expect(r.text).toContain('Risk signals: ∅');
    const explicitNull = renderAction({ ...withNulls, amount: null });
    expect(explicitNull.text).toContain('Amount: ∅');
  });

  it('renders an empty risk_flags array as the absence marker', () => {
    const r = renderAction({ ...SIGNED, risk_flags: [] });
    expect(r.text).toContain('Risk signals: ∅');
  });

  it('renders a multi-element risk_flags array joined with the middle dot', () => {
    const r = renderAction({ ...SIGNED, risk_flags: ['a', 'b', 'c'] });
    expect(r.text).toContain('Risk signals: a · b · c');
  });

  it('coerces a SCALAR risk_flags value into a single-element rendering', () => {
    const r = renderAction({ ...SIGNED, risk_flags: 'solo_flag' });
    expect(r.text).toContain('Risk signals: solo_flag');
    // scalar 'x' renders to the SAME human-readable text as ['x'] — renderValue
    // wraps the scalar. The text/value rendering is identical...
    const wrapped = renderAction({ ...SIGNED, risk_flags: ['solo_flag'] });
    expect(r.text).toBe(wrapped.text);
    // ...but display_hash legitimately DIFFERS: it binds to the full signed
    // action via actionHash, and the scalar action and the array action are
    // distinct signed bytes. The binding to the full action is intended.
    expect(r.action_hash).not.toBe(wrapped.action_hash);
    expect(r.display_hash).not.toBe(wrapped.display_hash);
  });

  it('coerces a numeric scalar risk_flags value via String()', () => {
    const r = renderAction({ ...SIGNED, risk_flags: 7 });
    expect(r.text).toContain('Risk signals: 7');
  });

  it('renders numbers via canonical JSON (locale-independent), strings as-is', () => {
    const r = renderAction({ ...SIGNED, amount: 82000.5 });
    expect(r.text).toContain('Amount: 82000.5');
    // No thousands separators / locale formatting ever.
    expect(r.text).not.toContain('82,000');
  });

  it('renders amount 0 (falsy number) as "0", not the absence marker', () => {
    const r = renderAction({ ...SIGNED, amount: 0 });
    expect(r.text).toContain('Amount: 0');
    expect(r.text).not.toContain('Amount: ∅');
  });
});

// ── WYSIWYS binding: rendering binds to the FULL signed action ───────────────
describe('renderAction() binds to the full signed action (no decoy escapes)', () => {
  it('binds display_hash to the frozen actionHash of the SAME action', () => {
    const r = renderAction(SIGNED);
    expect(r.action_hash).toBe(actionHash(SIGNED));
    expect(r.display_hash.startsWith('sha256:')).toBe(true);
  });

  it('changing an UNREAD decoy field (not in RENDER_FIELDS) still moves display_hash', () => {
    // memo is never rendered, but it changes actionHash, which is hashed INTO
    // the rendering object -> display_hash MUST change. This is the property the
    // task says not to weaken: bind to the full signed action, not just shown fields.
    const base = renderAction(SIGNED);
    const withDecoy = renderAction({ ...SIGNED, memo: 'attacker-controlled' });
    expect(withDecoy.action_hash).not.toBe(base.action_hash);
    expect(withDecoy.display_hash).not.toBe(base.display_hash);
    // ...even though the visible text is byte-identical.
    expect(withDecoy.text).toBe(base.text);
  });

  it('changing a rendered field (amount) moves both action_hash and display_hash', () => {
    const a = renderAction(SIGNED);
    const b = renderAction({ ...SIGNED, amount: 1 });
    expect(b.action_hash).not.toBe(a.action_hash);
    expect(b.display_hash).not.toBe(a.display_hash);
  });

  it('is byte-identical for structurally equal actions', () => {
    expect(renderAction({ ...SIGNED }).display_hash).toBe(renderAction({ ...SIGNED }).display_hash);
  });
});

// ── buildDisplayAttestation: unsigned vs signed shape, algorithm default ─────
describe('buildDisplayAttestation() shapes', () => {
  it('produces an unsigned attestation with no proof when no signer is given', () => {
    const att = buildDisplayAttestation({ action: SIGNED });
    expect(att.proof).toBeUndefined();
    expect(att['@version']).toBe(DISPLAY_ATTESTATION_VERSION);
    expect(att.render_profile).toBe(RENDER_PROFILE);
    expect(att.action_hash).toBe(actionHash(SIGNED));
  });

  it('defaults proof.algorithm to Ed25519 when signer omits it', () => {
    const s = ed25519();
    const att = buildDisplayAttestation({
      action: SIGNED,
      signer: { signer_key_id: 'k', privateKey: s.privateKey, publicKeyB64u: s.publicKeyB64u },
    });
    expect(att.proof.algorithm).toBe('Ed25519');
  });

  it('honors an explicit algorithm string on the signer (carried into proof)', () => {
    const s = ed25519();
    const att = buildDisplayAttestation({
      action: SIGNED,
      signer: {
        signer_key_id: 'k',
        privateKey: s.privateKey,
        publicKeyB64u: s.publicKeyB64u,
        algorithm: 'Ed25519-custom-label',
      },
    });
    // The label is carried verbatim; verifyDetachedEd25519 will reject it
    // because it is not exactly 'Ed25519' (proof_algorithm).
    expect(att.proof.algorithm).toBe('Ed25519-custom-label');
  });

  it('buildDisplayAttestation() with no args throws (renderAction on undefined)', () => {
    expect(() => buildDisplayAttestation()).toThrow(TypeError);
  });
});

// ── verifyDisplayAttestation: fail-closed paths ─────────────────────────────
describe('verifyDisplayAttestation() fail-closed', () => {
  it('rejects a missing canonical action', () => {
    const res = verifyDisplayAttestation(null, null);
    expect(res.valid).toBe(false);
    expect(res.errors).toContain('Missing canonical action');
    expect(res.display_hash).toBeNull();
  });

  it('rejects a non-object action (string)', () => {
    const res = verifyDisplayAttestation('not-an-object', null);
    expect(res.valid).toBe(false);
    expect(res.checks.render_deterministic).toBe(false);
  });

  it('fails closed when renderAction throws on the action (render failed)', () => {
    // A BigInt-valued field passes the typeof===object guard but makes the
    // frozen canonicalize()/actionHash() throw (BigInt is not JSON-serializable).
    // The verifier must catch and fail closed, never throw to the caller.
    const poison = { action_type: 'payment.release', amount: 10n };
    const res = verifyDisplayAttestation(poison, null, { requireDisplayAttestation: true });
    expect(res.valid).toBe(false);
    expect(res.checks.render_deterministic).toBe(false);
    expect(res.errors[0]).toMatch(/render failed:/);
    expect(res.display_hash).toBeNull();
  });

  it('accepts low-stakes with no attestation required and none supplied', () => {
    const res = verifyDisplayAttestation(SIGNED, null, { requireDisplayAttestation: false });
    expect(res.valid).toBe(true);
    expect(res.checks.render_deterministic).toBe(true);
    expect(res.checks.attestation_present).toBe(false);
    expect(res.display_hash).toBe(renderAction(SIGNED).display_hash);
  });

  it('rejects a missing attestation when required (missing_required_attestation)', () => {
    const res = verifyDisplayAttestation(SIGNED, null, { requireDisplayAttestation: true });
    expect(res.valid).toBe(false);
    expect(res.errors).toContain('missing_required_attestation');
    expect(res.checks.attestation_present).toBe(false);
  });

  // line 266: invalid_attestation_version
  it('rejects an attestation with a wrong @version (invalid_attestation_version)', () => {
    const att = buildDisplayAttestation({ action: SIGNED });
    att['@version'] = 'EP-DISPLAY-ATTESTATION-v0';
    const res = verifyDisplayAttestation(SIGNED, att);
    expect(res.valid).toBe(false);
    expect(res.errors).toContain('invalid_attestation_version');
    expect(res.checks.attestation_present).toBe(true);
  });

  it('rejects an attestation missing @version entirely', () => {
    const att = buildDisplayAttestation({ action: SIGNED });
    delete att['@version'];
    const res = verifyDisplayAttestation(SIGNED, att);
    expect(res.valid).toBe(false);
    expect(res.errors).toContain('invalid_attestation_version');
  });

  it('rejects when attested action_hash != frozen action hash (render_mismatch)', () => {
    const att = buildDisplayAttestation({ action: SIGNED });
    att.action_hash = actionHash({ ...SIGNED, amount: 1 }); // swap to the cheap hash
    const res = verifyDisplayAttestation(SIGNED, att);
    expect(res.valid).toBe(false);
    expect(res.errors[0]).toMatch(/render_mismatch: attested action_hash/);
    expect(res.checks.display_hash_match).toBe(false);
  });

  it('rejects when attested display_hash != re-derived rendering (render_mismatch)', () => {
    // Attestation for the cheap $1 action, but action_hash forced to the signed
    // one: action_hash matches, display_hash does not.
    const att = buildDisplayAttestation({ action: { ...SIGNED, amount: 1 } });
    att.action_hash = actionHash(SIGNED);
    const res = verifyDisplayAttestation(SIGNED, att);
    expect(res.valid).toBe(false);
    expect(res.errors[0]).toMatch(/render_mismatch: attested display_hash/);
    expect(res.checks.display_hash_match).toBe(false);
  });

  it('rejects an attestation whose action_hash is absent (hexOf falsy branch)', () => {
    // hexOf(undefined) -> '' (the String(h || '') fallback). An empty hash can
    // never equal the re-derived one, so the verifier fails closed.
    const att = buildDisplayAttestation({ action: SIGNED });
    delete att.action_hash;
    const res = verifyDisplayAttestation(SIGNED, att);
    expect(res.valid).toBe(false);
    expect(res.errors[0]).toMatch(/render_mismatch: attested action_hash/);
  });

  it('rejects an attestation whose display_hash is null (hexOf falsy branch)', () => {
    const att = buildDisplayAttestation({ action: SIGNED });
    att.display_hash = null; // action_hash still matches, display_hash falsy
    const res = verifyDisplayAttestation(SIGNED, att);
    expect(res.valid).toBe(false);
    expect(res.errors[0]).toMatch(/render_mismatch: attested display_hash/);
  });

  it('hexOf normalizes case + sha256: prefix when matching action_hash', () => {
    // Same hash, just upper-cased and with the prefix stripped on one side.
    const att = buildDisplayAttestation({ action: SIGNED });
    att.action_hash = att.action_hash.replace(/^sha256:/, '').toUpperCase();
    const res = verifyDisplayAttestation(SIGNED, att);
    // Still matches after normalization -> passes the render_mismatch gates.
    expect(res.valid).toBe(true);
    expect(res.checks.display_hash_match).toBe(true);
  });

  // ── proof verification paths ──────────────────────────────────────────────
  it('rejects a signed attestation when the signer is not pinned (no self-asserted trust)', () => {
    // No displaySignerKeys: the signer cannot be pinned, so the proof verifies
    // only under the producer's own self-asserted key — which proves nothing.
    // Fail closed; never report proof_signed true.
    const { att } = signedAtt(SIGNED);
    const res = verifyDisplayAttestation(SIGNED, att);
    expect(res.valid).toBe(false);
    expect(res.checks.proof_signed).toBe(false);
    expect(res.errors[0]).toMatch(/proof_invalid: signer_key_unpinned/);
  });

  it('accepts a well-formed signed attestation with a matching pinned key', () => {
    const { att, signer } = signedAtt(SIGNED);
    const res = verifyDisplayAttestation(SIGNED, att, {
      requireDisplayAttestation: true,
      requireSignedAttestation: true,
      displaySignerKeys: { 'ep:key:client#1': { public_key: signer.publicKeyB64u } },
    });
    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);
    expect(res.checks.proof_signed).toBe(true);
  });

  // proof_algorithm reason (line 186)
  it('rejects a proof whose algorithm is not Ed25519 (proof_algorithm)', () => {
    const { att } = signedAtt(SIGNED);
    att.proof.algorithm = 'RSA';
    const res = verifyDisplayAttestation(SIGNED, att);
    expect(res.valid).toBe(false);
    expect(res.errors[0]).toMatch(/proof_invalid: proof_algorithm/);
    expect(res.checks.proof_signed).toBe(false);
  });

  // proof_payload_mismatch (line 187)
  it('rejects a proof signing different payload bytes (proof_payload_mismatch)', () => {
    const signer = ed25519();
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
    expect(res.errors[0]).toMatch(/proof_invalid: proof_payload_mismatch/);
  });

  // proof_key_unbound (line 188-189) — wrong key while claiming a pinned id.
  it('rejects a proof signed by the wrong key vs the pinned key (proof_key_unbound)', () => {
    const realSigner = ed25519();
    const attacker = ed25519();
    const { att } = signedAtt(SIGNED, 'ep:key:client#1', attacker);
    const res = verifyDisplayAttestation(SIGNED, att, {
      displaySignerKeys: { 'ep:key:client#1': { public_key: realSigner.publicKeyB64u } },
    });
    expect(res.valid).toBe(false);
    expect(res.errors[0]).toMatch(/proof_invalid: proof_key_unbound/);
    expect(res.checks.proof_signed).toBe(false);
  });

  it('fails closed when the signer id is not in the pinned map (unpinned signer)', () => {
    // A pin registry is present but does not vouch for this attestation's signer:
    // there is no key to attribute the signature to, so it MUST be rejected
    // rather than verified under the producer's self-asserted key.
    const { att } = signedAtt(SIGNED, 'ep:key:unlisted');
    const res = verifyDisplayAttestation(SIGNED, att, {
      displaySignerKeys: { 'ep:key:someone-else': { public_key: ed25519().publicKeyB64u } },
    });
    expect(res.valid).toBe(false);
    expect(res.checks.proof_signed).toBe(false);
    expect(res.errors[0]).toMatch(/proof_invalid: signer_key_unpinned/);
  });

  // proof_signature: tampered signature bytes -> crypto.verify returns false.
  it('rejects a proof with a tampered (but well-formed) signature (proof_signature)', () => {
    const { att, signer } = signedAtt(SIGNED);
    const s2 = ed25519();
    // Re-sign the EXPECTED payload with a DIFFERENT key but keep the claimed
    // public_key. The signer IS pinned (so we reach the signature math), the
    // payload matches, but the signature does not verify under public_key, so
    // crypto.verify() returns false (proof_signature).
    att.proof.signature_b64u = crypto
      .sign(null, Buffer.from(att.proof.signed_payload_b64u, 'base64url'), s2.privateKey)
      .toString('base64url');
    const res = verifyDisplayAttestation(SIGNED, att, {
      displaySignerKeys: { 'ep:key:client#1': { public_key: signer.publicKeyB64u } },
    });
    expect(res.valid).toBe(false);
    expect(res.errors[0]).toMatch(/proof_invalid: proof_signature/);
  });

  // proof_signature via catch (line 204-205): malformed public key DER.
  it('rejects a proof with a malformed public key (catch -> proof_signature)', () => {
    const { att } = signedAtt(SIGNED);
    att.proof.public_key = Buffer.from('not-a-real-spki-key').toString('base64url');
    // Pin the (malformed) presented key so we pass the pin/binding gates and
    // reach crypto.createPublicKey(), which throws -> proof_signature.
    const res = verifyDisplayAttestation(SIGNED, att, {
      displaySignerKeys: { 'ep:key:client#1': { public_key: att.proof.public_key } },
    });
    expect(res.valid).toBe(false);
    expect(res.errors[0]).toMatch(/proof_invalid: proof_signature/);
  });

  it('rejects a proof with garbage (non-base64url decodable to key) public_key', () => {
    const { att } = signedAtt(SIGNED);
    att.proof.public_key = '!!!not-base64!!!';
    const res = verifyDisplayAttestation(SIGNED, att, {
      displaySignerKeys: { 'ep:key:client#1': { public_key: att.proof.public_key } },
    });
    expect(res.valid).toBe(false);
    expect(res.errors[0]).toMatch(/proof_invalid: proof_signature/);
  });

  // missing_required_signature (lines 296-298): unsigned att, signature required.
  it('rejects an unsigned attestation when a signature is required (missing_required_signature)', () => {
    const att = buildDisplayAttestation({ action: SIGNED }); // no proof
    const res = verifyDisplayAttestation(SIGNED, att, { requireSignedAttestation: true });
    expect(res.valid).toBe(false);
    expect(res.errors).toContain('missing_required_signature');
    expect(res.checks.proof_signed).toBe(false);
  });

  it('accepts an unsigned attestation when a signature is NOT required', () => {
    const att = buildDisplayAttestation({ action: SIGNED });
    const res = verifyDisplayAttestation(SIGNED, att, { requireSignedAttestation: false });
    expect(res.valid).toBe(true);
    // proof_signed stays null: signature was neither present nor required.
    expect(res.checks.proof_signed).toBeNull();
    expect(res.checks.display_hash_match).toBe(true);
  });

  it('uses an empty opts object by default (no opts argument)', () => {
    const att = buildDisplayAttestation({ action: SIGNED });
    const res = verifyDisplayAttestation(SIGNED, att);
    expect(res.valid).toBe(true);
  });
});
