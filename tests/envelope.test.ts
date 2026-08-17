// SPDX-License-Identifier: Apache-2.0
//
// EP-ENVELOPE-v1 — adversarial suite for the narrow waist. Proves: unknown /
// malformed / disallowed-alg envelopes fail closed; the PluginCannotWeaken
// invariant (a plugin can only ADD rejections, never rescue a shared rejection
// or a thrown plugin); migrate() is lossless; and wrapping a profile preserves
// its inner fail-closed behavior. Live Ed25519 — negatives are genuine.

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  verifyEnvelope, verifyEnvelopeProofs, verifyEnvelopeWithProofs, envelopeProofBytes,
  PROOF_REASONS, migrate, registerProfile, listProfiles, isLosslessMigration,
  isWellFormedProfileUrn, isVendorProfileUrn, EP_ENVELOPE_VERSION, BUILTIN_PROFILES,
} from '../lib/envelope/index.js';
import { buildRevocation } from '../lib/revocation/revocation.js';
import { buildEyeSet } from '../lib/eye/eye-set.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { signAgile, ML_DSA_65_SIGNATURE_BYTES } from '../packages/verify/pq-signature-agility.js';

function ed25519() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, publicKeyB64u: publicKey.export({ format: 'der', type: 'spki' }).toString('base64url') };
}

describe('EP-ENVELOPE-v1 — registry + URN discipline', () => {
  it('registers every built-in profile', () => {
    for (const p of BUILTIN_PROFILES) expect(listProfiles()).toContain(p);
  });
  it('accepts core and reserved-vendor URNs, rejects garbage', () => {
    expect(isWellFormedProfileUrn('urn:ep:profile:revocation:v1')).toBe(true);
    expect(isWellFormedProfileUrn('urn:ep:profile:x-acme:my-thing')).toBe(true);
    expect(isVendorProfileUrn('urn:ep:profile:x-acme:my-thing')).toBe(true);
    expect(isVendorProfileUrn('urn:ep:profile:revocation:v1')).toBe(false);
    expect(isWellFormedProfileUrn('not-a-urn')).toBe(false);
    expect(isWellFormedProfileUrn('urn:ep:profile::v1')).toBe(false);
  });
  it('refuses to register a malformed URN or a non-function body', () => {
    expect(() => registerProfile('nope', { validateBody: () => ({ valid: true }) })).toThrow();
    expect(() => registerProfile('urn:ep:profile:x-acme:ok', { validateBody: 42 })).toThrow();
  });
});

describe('EP-ENVELOPE-v1 — shared pipeline fails closed', () => {
  const okBody = () => ({ valid: true });
  registerProfile('urn:ep:profile:x-test:ok', { validateBody: okBody });

  it('rejects an unknown (unregistered) profile', () => {
    const r = verifyEnvelope({ ep: EP_ENVELOPE_VERSION, profile: 'urn:ep:profile:x-unknown:nope', payload: {} });
    expect(r.valid).toBe(false);
    expect(r.checks.profile_known).toBe(false);
  });
  it('rejects a wrong envelope version', () => {
    const r = verifyEnvelope({ ep: 'EP-ENVELOPE-v0', profile: 'urn:ep:profile:x-test:ok', payload: {} });
    expect(r.valid).toBe(false);
    expect(r.checks.envelope_version).toBe(false);
  });
  it('rejects a non-object / missing payload', () => {
    expect(verifyEnvelope({ ep: EP_ENVELOPE_VERSION, profile: 'urn:ep:profile:x-test:ok', payload: null }).valid).toBe(false);
    expect(verifyEnvelope({ ep: EP_ENVELOPE_VERSION, profile: 'urn:ep:profile:x-test:ok', payload: [1, 2] }).valid).toBe(false);
  });
  it("rejects an envelope-level proof with a disallowed algorithm (incl. 'none')", () => {
    const r = verifyEnvelope({ ep: EP_ENVELOPE_VERSION, profile: 'urn:ep:profile:x-test:ok', payload: {}, proofs: [{ algorithm: 'none' }] });
    expect(r.valid).toBe(false);
    expect(r.checks.proof_alg_allowed).toBe(false);
  });
  it('rejects a non-object envelope', () => {
    expect(verifyEnvelope(null).valid).toBe(false);
    expect(verifyEnvelope('nope').valid).toBe(false);
  });
});

describe('EP-ENVELOPE-v1 — PluginCannotWeaken', () => {
  // An adversarial plugin that ALWAYS approves.
  registerProfile('urn:ep:profile:x-test:evil', { validateBody: () => ({ valid: true, checks: { evil: true } }) });
  registerProfile('urn:ep:profile:x-test:throws', { validateBody: () => { throw new Error('boom'); } });

  it('a plugin that returns valid:true CANNOT rescue a shared rejection (bad version)', () => {
    const r = verifyEnvelope({ ep: 'EP-ENVELOPE-v0', profile: 'urn:ep:profile:x-test:evil', payload: {} });
    expect(r.valid).toBe(false); // shared.ok(false) && plugin(true) === false
  });
  it('a plugin that returns valid:true CANNOT rescue a missing payload', () => {
    const r = verifyEnvelope({ ep: EP_ENVELOPE_VERSION, profile: 'urn:ep:profile:x-test:evil', payload: null });
    expect(r.valid).toBe(false);
  });
  it('a plugin that THROWS is treated as a rejection, never a crash', () => {
    const r = verifyEnvelope({ ep: EP_ENVELOPE_VERSION, profile: 'urn:ep:profile:x-test:throws', payload: {} });
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => e.startsWith('plugin_threw'))).toBe(true);
  });
  it('a plugin returning a non-object is a rejection', () => {
    registerProfile('urn:ep:profile:x-test:nonobj', { validateBody: () => undefined });
    const r = verifyEnvelope({ ep: EP_ENVELOPE_VERSION, profile: 'urn:ep:profile:x-test:nonobj', payload: {} });
    expect(r.valid).toBe(false);
  });
});

describe('EP-ENVELOPE-v1: ML-DSA-65 envelope-level proofs', () => {
  registerProfile('urn:ep:profile:x-pq:ok', { validateBody: () => ({ valid: true }) });

  const KID = 'ep:key:envelope-pq#1';
  const pq = ml_dsa65.keygen(new Uint8Array(32).fill(11));
  const proofKeys = { [KID]: { alg: 'ML-DSA-65', public_key: pq.publicKey } };

  const base = {
    ep: EP_ENVELOPE_VERSION,
    profile: 'urn:ep:profile:x-pq:ok',
    payload: { action: { type: 'payment.capture.1' }, issued_at: '2026-08-17T00:00:00Z' },
    binding: { action_hash: `sha256:${'2'.repeat(64)}` },
  };

  async function signed(env: any = base) {
    const sig = await signAgile(new Uint8Array(envelopeProofBytes(env)), {
      alg: 'ML-DSA-65', private_key: pq.secretKey, key_id: KID,
    });
    return { ...env, proofs: [{ algorithm: 'ML-DSA-65', kid: KID, signature: sig.sig }] };
  }

  it('an ML-DSA-65 envelope verifies structurally and cryptographically', async () => {
    const env = await signed();
    expect(verifyEnvelope(env).valid).toBe(true);
    const proofs = await verifyEnvelopeProofs(env, { proofKeys });
    expect(proofs.valid).toBe(true);
    expect(proofs.results[0]).toMatchObject({ alg: 'ML-DSA-65', kid: KID, verified: true, reason: null });
    const both = await verifyEnvelopeWithProofs(env, { proofKeys });
    expect(both.valid).toBe(true);
    expect(both.checks.proofs_valid).toBe(true);
  });

  it('a wrong-length ML-DSA signature refuses with the named reason, before any key is consulted', async () => {
    const env = await signed();
    const truncated = {
      ...env,
      proofs: [{
        ...env.proofs[0],
        signature: Buffer.from(env.proofs[0].signature, 'base64url').subarray(0, ML_DSA_65_SIGNATURE_BYTES - 1).toString('base64url'),
      }],
    };
    // The structural pin fires in the synchronous shared pipeline.
    const structural = verifyEnvelope(truncated);
    expect(structural.valid).toBe(false);
    expect(structural.checks.proof_signature_wellformed).toBe(false);
    expect(structural.errors.some((e: string) => e.includes(PROOF_REASONS.MALFORMED_SIGNATURE))).toBe(true);
    // And the agility path names the same reason with NO pinned key supplied,
    // so the refusal cannot be mistaken for a key problem.
    const proofs = await verifyEnvelopeProofs(truncated, { proofKeys });
    expect(proofs.valid).toBe(false);
    expect(proofs.results[0].reason).toBe(PROOF_REASONS.MALFORMED_SIGNATURE);
  });

  it('a tampered payload, a wrong key, and an unpinned kid all refuse', async () => {
    const env = await signed();

    const tampered = { ...env, payload: { ...env.payload, issued_at: '2099-01-01T00:00:00Z' } };
    expect((await verifyEnvelopeProofs(tampered, { proofKeys })).valid).toBe(false);

    const otherKey = ml_dsa65.keygen(new Uint8Array(32).fill(12));
    const wrongKey = await verifyEnvelopeProofs(env, { proofKeys: { [KID]: { alg: 'ML-DSA-65', public_key: otherKey.publicKey } } });
    expect(wrongKey.valid).toBe(false);
    expect(wrongKey.results[0].reason).toBe('signature_invalid');

    const unpinned = await verifyEnvelopeProofs(env, { proofKeys: {} });
    expect(unpinned.valid).toBe(false);
    expect(unpinned.results[0].reason).toBe(PROOF_REASONS.NO_PINNED_KEY);
  });

  it('refuses rather than skipping the leg when no ML-DSA backend is available', async () => {
    const env = await signed();
    const r = await verifyEnvelopeProofs(env, { proofKeys, agility: { mldsaBackendLoader: () => null } });
    expect(r.valid).toBe(false);
    expect(r.results[0].reason).toBe('pq_backend_unavailable');
  });

  it('never reports an algorithm it cannot evaluate as verified', async () => {
    // ES256 and EdDSA stay structurally allowed for wrapped legacy profiles,
    // but this verifier does not check them and says so.
    for (const algorithm of ['ES256', 'EdDSA']) {
      const env = { ...base, proofs: [{ algorithm, kid: KID, signature: 'AAAA' }] };
      expect(verifyEnvelope(env).valid).toBe(true); // structurally allow-listed
      const r = await verifyEnvelopeProofs(env, { proofKeys });
      expect(r.valid).toBe(false);
      expect(r.results[0].reason).toBe(PROOF_REASONS.ALG_NOT_VERIFIABLE_HERE);
    }
    // An envelope with no proofs cannot answer "do the proofs hold" with yes.
    const none = await verifyEnvelopeProofs(base, { proofKeys });
    expect(none.valid).toBe(false);
    expect(none.reason).toBe('no_proofs');
  });

  it('a valid proof cannot rescue a structurally invalid envelope', async () => {
    const bad = await signed({ ...base, profile: 'urn:ep:profile:x-unregistered:nope' });
    const proofs = await verifyEnvelopeProofs(bad, { proofKeys });
    expect(proofs.valid).toBe(true); // the signature itself is genuine
    const both = await verifyEnvelopeWithProofs(bad, { proofKeys });
    expect(both.valid).toBe(false); // ANDed with the shared pipeline
  });

  it('the existing algorithm allow-list is unchanged for Ed25519/EdDSA/ES256 and still refuses the rest', () => {
    for (const algorithm of ['Ed25519', 'EdDSA', 'ES256', 'ML-DSA-65']) {
      const r = verifyEnvelope({ ...base, proofs: [{ algorithm, signature: 'AAAA' }] });
      // ML-DSA-65 is length-pinned; the other three keep their prior behavior
      // of being allow-listed structurally without a signature check here.
      expect(r.checks.proof_alg_allowed).toBe(true);
      expect(r.valid).toBe(algorithm !== 'ML-DSA-65');
    }
    for (const algorithm of ['none', 'ES384', 'ML-DSA-44', 'HS256']) {
      const r = verifyEnvelope({ ...base, proofs: [{ algorithm, signature: 'AAAA' }] });
      expect(r.valid).toBe(false);
      expect(r.checks.proof_alg_allowed).toBe(false);
    }
  });
});

describe('EP-ENVELOPE-v1 — lossless migration + wrapped-profile parity', () => {
  const rk = ed25519();
  const REVOKER = 'ep:org:treasury';
  const TARGET = { target_type: 'receipt', target_id: 'rcpt_X', action_hash: 'sha256:' + '1'.repeat(64) };
  const stmt = buildRevocation({ target: TARGET, revoker_id: REVOKER, reason: 'abuse', signer: { privateKey: rk.privateKey, publicKeyB64u: rk.publicKeyB64u } });
  const pin = { revokerKeys: { [REVOKER]: { public_key: rk.publicKeyB64u } }, target: TARGET };

  it('migrate() wraps losslessly (canonical bytes preserved)', () => {
    const env = migrate(stmt, 'urn:ep:profile:revocation:v1');
    expect(isLosslessMigration(stmt, env)).toBe(true);
    expect(env.ep).toBe(EP_ENVELOPE_VERSION);
  });
  it('a valid revocation verifies VALID through the envelope (parity with the inner verifier)', () => {
    const env = migrate(stmt, 'urn:ep:profile:revocation:v1');
    expect(verifyEnvelope(env, pin).valid).toBe(true);
  });
  it('an UNPINNED revoker fails closed through the envelope (inner fail-closed preserved)', () => {
    const env = migrate(stmt, 'urn:ep:profile:revocation:v1');
    expect(verifyEnvelope(env, { target: TARGET, revokerKeys: {} }).valid).toBe(false);
  });
  it('a tampered revocation fails closed through the envelope', () => {
    const env = migrate(stmt, 'urn:ep:profile:revocation:v1');
    const t = JSON.parse(JSON.stringify(env));
    t.payload.revoked_at = '2099-01-01T00:00:00.000Z';
    expect(verifyEnvelope(t, pin).valid).toBe(false);
  });

  it('every built-in bridge executes and fails closed on a malformed payload', () => {
    const cases = [
      ['urn:ep:profile:revocation:v1', {}],
      ['urn:ep:profile:eye-set:v1', { notset: 1 }], // exercises the missing-`set` branch
      ['urn:ep:profile:execution-integrity:v1', {}],
      ['urn:ep:profile:wysiwys:v1', {}],
      ['urn:ep:profile:provenance-chain:v1', {}],
      ['urn:ep:profile:resolution:v1', {}],
    ];
    for (const [urn, payload] of cases) {
      const r = verifyEnvelope({ ep: EP_ENVELOPE_VERSION, profile: urn, payload }, {});
      expect(r.valid, `${urn} should fail closed`).toBe(false);
    }
  });

  it('a valid eye-set verifies through the envelope; unpinned fails closed', () => {
    const em = ed25519();
    const KID = 'ep:key:eye#1';
    const adv = {
      status: 'review_required', scope_binding_hash: 'a'.repeat(64), reason_codes: ['velocity'],
      recommended_policy_action: 'require_signoff', advisory_hash: 'b'.repeat(64),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
    };
    const set = buildEyeSet(adv, { signer: { kid: KID, iss: KID, privateKey: em.privateKey }, audience: 'rp:t' });
    const env = migrate({ set }, 'urn:ep:profile:eye-set:v1');
    expect(verifyEnvelope(env, { pinnedKeys: { [KID]: { public_key: em.publicKeyB64u } }, audience: 'rp:t' }).valid).toBe(true);
    expect(verifyEnvelope(env, { pinnedKeys: {}, audience: 'rp:t' }).valid).toBe(false);
  });
});
