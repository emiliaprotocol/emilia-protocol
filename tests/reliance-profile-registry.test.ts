// SPDX-License-Identifier: Apache-2.0
// EP-RELIANCE-PROFILE-REGISTRY-v1 — sign/verify a regulated reliance profile,
// pinned by a registrar key + profile_id + epoch. verified≠accepted, fail-closed.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  signRelianceProfileEntry, verifyRelianceProfileEntry, profileRegistryEntryDigest,
  assertRelianceProfileBound,
} from '../packages/verify/reliance-profile-registry.js';
import { validateRelianceProfile } from '../packages/verify/reliance.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const SUITE = JSON.parse(readFileSync(resolve(ROOT, 'conformance/vectors/reliance-profile-registry.v1.json'), 'utf8'));
const seed = (name) => JSON.parse(readFileSync(resolve(ROOT, `public/schemas/reliance-profiles/${name}`), 'utf8'));

const registrarKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from('b3'.repeat(32), 'hex')]), format: 'der', type: 'pkcs8' });
const registrarPub = crypto.createPublicKey(registrarKey).export({ type: 'spki', format: 'der' }).toString('base64url');

const NCPDP = seed('ncpdp-specialty-pa.v1.json');
const baseEntry = () => signRelianceProfileEntry({ registry_id: 'emilia-registrar', profile_id: 'ncpdp.specialty-pa.v1', profile: NCPDP, registry_epoch: 3, issued_at: '2026-07-07T00:00:00.000Z' }, registrarKey);

function run(brk) {
  const entry = baseEntry();
  const opts = { pinnedRegistryKeys: [{ registry_id: 'emilia-registrar', public_key: registrarPub }] };
  switch (brk) {
    case 'none': break;
    case 'unpin_key': opts.pinnedRegistryKeys = []; break;
    case 'tamper_profile': entry.profile.required_assurance = 'signed'; break; // body changed after signing
    case 'tamper_profile_hash': entry.profile_hash = 'sha256:' + '00'.repeat(32); break;
    case 'tamper_signature': entry.signature.signature_b64u = Buffer.from('00'.repeat(64), 'hex').toString('base64url'); break;
    case 'expect_wrong_id': opts.expectProfileId = 'cms.prior-auth.v1'; break;
    case 'expect_higher_epoch': opts.expectMinEpoch = 99; break;
    case 'wrong_registry_id': opts.pinnedRegistryKeys[0].registry_id = 'attacker-registry'; break;
    case 'pin_omits_registry_id': delete opts.pinnedRegistryKeys[0].registry_id; break;
    case 'tamper_key_id': entry.signature.key_id = 'ep:reliance-registry-key:sha256:0000000000000000'; break;
    default: throw new Error(`unknown break ${brk}`);
  }
  return verifyRelianceProfileEntry(entry, opts);
}

describe('EP-RELIANCE-PROFILE-REGISTRY-v1 conformance', () => {
  for (const v of SUITE.vectors) {
    it(`${v.id}`, () => {
      const r = run(v.break);
      expect(r.verified).toBe(v.expect.verified);
      expect(r.accepted).toBe(v.expect.accepted);
      if (v.expect.reason) expect(r.reason).toBe(v.expect.reason);
    });
  }
});

describe('EP-RELIANCE-PROFILE-REGISTRY-v1 invariants', () => {
  it('a pinned entry resolves a well-formed profile the kernel accepts', () => {
    const r = run('none');
    expect(r.accepted).toBe(true);
    expect(r.profile['@type']).toBe('EP-RELIANCE-PROFILE-v1');
    expect(validateRelianceProfile(r.profile).ok).toBe(true);
  });

  it('the relying party overlays its OWN trust anchors onto the resolved profile', () => {
    const { profile } = run('none');
    // Published body fixes the regulatory shape; keys are empty and the relying
    // party overlays what IT trusts before evaluation.
    expect(profile.accepted_registry_keys).toEqual([]);
    const pinned = { ...profile, accepted_registry_keys: [{ public_key: 'RP-key' }], accepted_issuer_keys: ['RP-issuer'] };
    expect(pinned.required_assurance).toBe('class_a'); // regulatory floor preserved
    expect(pinned.accepted_registry_keys.length).toBe(1);
  });

  it('all seed profiles sign, verify, and are well-formed', () => {
    for (const [id, file] of [
      ['ncpdp.specialty-pa.v1', 'ncpdp-specialty-pa.v1.json'],
      ['cms.prior-auth.v1', 'cms-prior-auth.v1.json'],
      ['medi-cal.hospice-integrity.v1', 'medi-cal-hospice-integrity.v1.json'],
    ]) {
      const entry = signRelianceProfileEntry({ registry_id: 'emilia-registrar', profile_id: id, profile: seed(file), registry_epoch: 1 }, registrarKey);
      const r = verifyRelianceProfileEntry(entry, { pinnedRegistryKeys: [{ registry_id: 'emilia-registrar', public_key: registrarPub }] });
      expect(r.accepted).toBe(true);
      expect(r.entry_digest).toBe(profileRegistryEntryDigest(entry));
      expect(validateRelianceProfile(r.profile).ok).toBe(true);
    }
  });

  it('an unpinned entry is VERIFIED but NOT ACCEPTED (verified≠accepted)', () => {
    const r = run('unpin_key');
    expect(r.verified).toBe(true);
    expect(r.accepted).toBe(false);
    expect(r.reason).toBe('registry_key_not_pinned');
    expect(r.profile).not.toBeNull(); // profile surfaced for inspection, but not trusted
  });
});

// A verdict that hands back a LIVE reference to the entry's profile is not a
// verdict: the holder of an `accepted: true` result could rewrite the rule the
// acceptance was computed over (and, through the shared reference, the entry
// itself), leaving a result that describes bytes no entry_digest or
// profile_hash ever covered. The resolved profile is a frozen clone instead.
describe('EP-RELIANCE-PROFILE-REGISTRY-v1 resolved-profile immutability', () => {
  const PINNED = () => ({ pinnedRegistryKeys: [{ registry_id: 'emilia-registrar', public_key: registrarPub }] });
  const resolve = (opts, profile = NCPDP, profile_id = 'ncpdp.specialty-pa.v1') => {
    const entry = signRelianceProfileEntry({ registry_id: 'emilia-registrar', profile_id, profile, registry_epoch: 3 }, registrarKey);
    return { entry, r: verifyRelianceProfileEntry(entry, opts) };
  };
  // Strict-mode ESM throws on a frozen write; swallow it so the assertion that
  // follows proves the property (unchanged bytes) under either semantics.
  const attempt = (mutate) => { try { mutate(); } catch { /* frozen: TypeError is the other acceptable outcome */ } };

  it('an accepted verdict cannot be downgraded through its profile reference, and the entry is untouched', () => {
    const { entry, r } = resolve(PINNED());
    expect(r.accepted).toBe(true);
    expect(r.profile.required_assurance).toBe('class_a');
    expect(Object.isFrozen(r.profile)).toBe(true);

    attempt(() => { r.profile.required_assurance = 'signed'; });

    expect(r.profile.required_assurance).toBe('class_a');   // ineffective on the result
    expect(entry.profile.required_assurance).toBe('class_a'); // and no aliasing back into the entry
    expect(profileRegistryEntryDigest(entry)).toBe(entry.signature.entry_digest);
    expect(verifyRelianceProfileEntry(entry, PINNED()).accepted).toBe(true);
  });

  it('the resolved profile is a clone, never the entry object itself', () => {
    const { entry, r } = resolve(PINNED());
    expect(r.profile).not.toBe(entry.profile);
    expect(r.profile.required_evidence).not.toBe(entry.profile.required_evidence);
    expect(r.profile).toEqual(entry.profile); // same bytes, different object graph
  });

  it('the accepted result restates the profile_hash of the exact bytes it carries', () => {
    const { entry, r } = resolve(PINNED());
    expect(r.profile_hash).toBe(entry.profile_hash);
    expect(assertRelianceProfileBound(r)).toEqual({ ok: true, reason: null, profile_hash: entry.profile_hash });
  });

  it('nested objects and arrays inside the resolved profile are frozen too', () => {
    const deep = seed('medi-cal-hospice-integrity.v1.json');
    const { entry, r } = resolve(PINNED(), deep, 'medi-cal.hospice-integrity.v1');
    expect(r.accepted).toBe(true);

    const nested = r.profile.x_emilia_program_integrity;
    const action = nested.action_control_manifest.actions[0];
    expect(Object.isFrozen(nested)).toBe(true);
    expect(Object.isFrozen(nested.privacy)).toBe(true);
    expect(Object.isFrozen(r.profile.required_evidence)).toBe(true);
    expect(Object.isFrozen(action)).toBe(true);
    expect(Object.isFrozen(action.control.execution_binding.required_fields)).toBe(true);

    attempt(() => { nested.privacy.reference_artifact = 'real PHI'; });
    attempt(() => { action.risk = 'low'; });
    attempt(() => { action.receipt_required = false; });
    attempt(() => { r.profile.required_evidence.push('nothing'); });
    attempt(() => { r.profile.required_evidence[0] = 'nothing'; });

    expect(nested.privacy.reference_artifact).toBe('PHI-free and synthetic');
    expect(action.risk).toBe('critical');
    expect(action.receipt_required).toBe(true);
    expect(r.profile.required_evidence).toEqual(deep.required_evidence);
    expect(entry.profile.x_emilia_program_integrity.privacy.reference_artifact).toBe('PHI-free and synthetic');
    expect(assertRelianceProfileBound(r).ok).toBe(true);
  });

  it('assertRelianceProfileBound refuses a result whose profile was swapped for a downgraded copy', () => {
    const { r } = resolve(PINNED());
    const downgraded = { ...structuredClone(r.profile), required_assurance: 'signed' };
    const swapped = { ...r, profile: downgraded };

    expect(swapped.accepted).toBe(true); // the verdict still SAYS accepted...
    expect(assertRelianceProfileBound(swapped)).toEqual({ ok: false, reason: 'profile_hash_mismatch', profile_hash: null });

    r.profile = downgraded; // the same swap performed in place on the result object
    expect(assertRelianceProfileBound(r).ok).toBe(false);
    expect(assertRelianceProfileBound(r).reason).toBe('profile_hash_mismatch');
  });

  it('assertRelianceProfileBound is a byte check, not an identity check, and fails closed on a missing binding', () => {
    const { r } = resolve(PINNED());
    // A consumer's own mutable clone of the same bytes still binds: the guard
    // asserts what the profile IS, not which object it is.
    expect(assertRelianceProfileBound({ ...r, profile: structuredClone(r.profile) }).ok).toBe(true);
    expect(assertRelianceProfileBound(null).reason).toBe('result_malformed');
    expect(assertRelianceProfileBound({ profile: null, profile_hash: r.profile_hash }).reason).toBe('profile_missing');
    expect(assertRelianceProfileBound({ profile: r.profile }).reason).toBe('profile_hash_missing_or_malformed');
    expect(assertRelianceProfileBound(verifyRelianceProfileEntry({}, PINNED())).ok).toBe(false);
  });

  it('cloning a profile carrying a literal __proto__ member neither pollutes a prototype nor moves the hash', () => {
    // JSON.parse is the realistic source: it makes __proto__ an OWN property,
    // which canonicalize() hashes. A clone built by assignment would silently
    // drop it (breaking profile_hash) or swap a prototype instead.
    const hostile = { ...NCPDP, ...JSON.parse('{"x_note":{"__proto__":{"polluted":true}}}') };
    const { entry, r } = resolve(PINNED(), hostile, 'hostile.proto.v1');

    expect(r.accepted).toBe(true);
    expect(r.profile_hash).toBe(entry.profile_hash);
    expect(assertRelianceProfileBound(r).ok).toBe(true);
    expect(Object.isFrozen(r.profile.x_note)).toBe(true);
    expect(({} as any).polluted).toBeUndefined();
    expect((Object.prototype as any).polluted).toBeUndefined();
  });

  it('a verified-but-unpinned result also resolves a frozen, non-aliased profile', () => {
    const { entry, r } = resolve({ pinnedRegistryKeys: [] });
    expect(r.verified).toBe(true);
    expect(r.accepted).toBe(false);
    expect(r.reason).toBe('registry_key_not_pinned');
    expect(r.profile).not.toBe(entry.profile);
    expect(Object.isFrozen(r.profile)).toBe(true);

    attempt(() => { r.profile.required_assurance = 'signed'; });

    expect(r.profile.required_assurance).toBe('class_a');
    expect(entry.profile.required_assurance).toBe('class_a');
    expect(assertRelianceProfileBound(r).ok).toBe(true); // bound, but still not accepted
  });
});
