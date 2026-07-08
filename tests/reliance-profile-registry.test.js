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
} from '../packages/verify/reliance-profile-registry.js';
import { validateRelianceProfile } from '../packages/verify/reliance.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const SUITE = JSON.parse(readFileSync(resolve(ROOT, 'conformance/vectors/reliance-profile-registry.v1.json'), 'utf8'));
const seed = (name) => JSON.parse(readFileSync(resolve(ROOT, `public/schemas/reliance-profiles/${name}`), 'utf8'));

const registrarKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from('b3'.repeat(32), 'hex')]), format: 'der', type: 'pkcs8' });
const registrarPub = crypto.createPublicKey(registrarKey).export({ type: 'spki', format: 'der' }).toString('base64url');

const NCPDP = seed('ncpdp-specialty-pa.v1.json');
const baseEntry = () => signRelianceProfileEntry({ profile_id: 'ncpdp.specialty-pa.v1', profile: NCPDP, registry_epoch: 3, issued_at: '2026-07-07T00:00:00.000Z' }, registrarKey);

function run(brk) {
  const entry = baseEntry();
  const opts = { pinnedRegistryKeys: [{ issuer_id: 'emilia-registrar', public_key: registrarPub }] };
  switch (brk) {
    case 'none': break;
    case 'unpin_key': opts.pinnedRegistryKeys = []; break;
    case 'tamper_profile': entry.profile.required_assurance = 'signed'; break; // body changed after signing
    case 'tamper_profile_hash': entry.profile_hash = 'sha256:' + '00'.repeat(32); break;
    case 'tamper_signature': entry.signature.signature_b64u = Buffer.from('00'.repeat(64), 'hex').toString('base64url'); break;
    case 'expect_wrong_id': opts.expectProfileId = 'cms.prior-auth.v1'; break;
    case 'expect_higher_epoch': opts.expectMinEpoch = 99; break;
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

  it('both seed profiles sign, verify, and are well-formed', () => {
    for (const [id, file] of [['ncpdp.specialty-pa.v1', 'ncpdp-specialty-pa.v1.json'], ['cms.prior-auth.v1', 'cms-prior-auth.v1.json']]) {
      const entry = signRelianceProfileEntry({ profile_id: id, profile: seed(file), registry_epoch: 1 }, registrarKey);
      const r = verifyRelianceProfileEntry(entry, { pinnedRegistryKeys: [{ public_key: registrarPub }] });
      expect(r.accepted).toBe(true);
      expect(r.entry_digest).toBe(profileRegistryEntryDigest(entry));
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
