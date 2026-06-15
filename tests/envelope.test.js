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
  verifyEnvelope, migrate, registerProfile, listProfiles, isLosslessMigration,
  isWellFormedProfileUrn, isVendorProfileUrn, EP_ENVELOPE_VERSION, BUILTIN_PROFILES,
} from '../lib/envelope/index.js';
import { buildRevocation } from '../lib/revocation/revocation.js';
import { buildEyeSet } from '../lib/eye/eye-set.js';

function ed25519() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, publicKeyB64u: publicKey.export({ format: 'der', type: 'spki' }).toString('base64url') };
}

describe('EP-ENVELOPE-v1 — registry + URN discipline', () => {
  it('registers the five built-in profiles', () => {
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
