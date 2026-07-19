// SPDX-License-Identifier: Apache-2.0
//
// EP-CRYPTO-PROFILE — fail-closed crypto-boundary selector.

import { describe, it, expect, afterEach } from 'vitest';
import {
  CRYPTO_PROFILE_IDS,
  getActiveCryptoProfile,
  isAlgAllowed,
  assertAlgAllowed,
  assertProfileSatisfied,
} from '../lib/crypto/profile.js';

afterEach(() => { delete process.env.EP_CRYPTO_PROFILE; });

describe('crypto profile selector', () => {
  it('defaults to the default profile (Ed25519 + ES256)', () => {
    const p = getActiveCryptoProfile();
    expect(p.id).toBe('default');
    expect(p.sign_algs).toContain('Ed25519');
    expect(p.sign_algs).toContain('ES256');
    expect(p.fips_boundary).toBe(false);
  });

  it('fails closed on an unknown profile (no silent fallback)', () => {
    process.env.EP_CRYPTO_PROFILE = 'totally-made-up';
    expect(() => getActiveCryptoProfile()).toThrowError(/Unknown EP_CRYPTO_PROFILE/);
    try { getActiveCryptoProfile(); } catch (e) { expect(e.code).toBe('unknown_crypto_profile'); }
  });

  it('default profile permits both Ed25519 and ES256', () => {
    const p = getActiveCryptoProfile('default');
    expect(isAlgAllowed('Ed25519', p)).toBe(true);
    expect(isAlgAllowed('ES256', p)).toBe(true);
    expect(assertAlgAllowed('Ed25519', p)).toEqual({ ok: true, profile: 'default' });
  });

  it('fips profile REFUSES Ed25519 (thin validated-module coverage) and permits ES256', () => {
    const p = getActiveCryptoProfile('fips');
    expect(p.fips_boundary).toBe(true);
    expect(isAlgAllowed('ES256', p)).toBe(true);
    expect(isAlgAllowed('Ed25519', p)).toBe(false);
    expect(() => assertAlgAllowed('Ed25519', p)).toThrowError(/not permitted under crypto profile "fips"/);
    try { assertAlgAllowed('Ed25519', p); } catch (e) { expect(e.code).toBe('alg_outside_crypto_profile'); }
  });

  it('fips profile is not "satisfied" without a validated-module custody signer', () => {
    const noCustody = assertProfileSatisfied({ custodyMode: 'env', profileId: 'fips' });
    expect(noCustody.ok).toBe(false);
    expect(noCustody.reasons.join(' ')).toMatch(/kms or hsm/);

    const withCustody = assertProfileSatisfied({ custodyMode: 'kms', profileId: 'fips' });
    expect(withCustody.ok).toBe(true);
  });

  it('default profile is satisfied regardless of custody mode (no FIPS requirement)', () => {
    expect(assertProfileSatisfied({ custodyMode: 'env', profileId: 'default' }).ok).toBe(true);
  });

  it('exposes exactly the two known profile ids', () => {
    expect([...CRYPTO_PROFILE_IDS].sort()).toEqual(['default', 'fips']);
  });
});
