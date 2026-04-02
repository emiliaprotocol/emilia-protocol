/**
 * EP Handshake — Claim normalization tests.
 *
 * Tests canonical claim vocabulary, normalizeClaims, and claimsToCanonicalHash.
 * Pure functions — no mocks needed.
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import {
  CANONICAL_CLAIMS,
  normalizeClaims,
  claimsToCanonicalHash,
  computePresentationHash,
} from '../lib/handshake/normalize.js';

// ── normalizeClaims: direct canonical keys ──────────────────────────────────

describe('normalizeClaims — direct canonical keys', () => {
  it('passes through a single canonical key unchanged', () => {
    const result = normalizeClaims({ legal_name: 'Alice' });
    expect(result).toEqual({ legal_name: 'Alice' });
  });

  it('passes through multiple canonical keys unchanged', () => {
    const result = normalizeClaims({
      legal_entity: 'Acme Corp',
      kyc_verified: true,
    });
    expect(result).toEqual({
      kyc_verified: true,
      legal_entity: 'Acme Corp',
    });
  });
});

// ── normalizeClaims: roles array expansion ──────────────────────────────────

describe('normalizeClaims — roles array expansion', () => {
  it('expands a roles array with one canonical entry', () => {
    const result = normalizeClaims({ roles: ['authorized_signer'] });
    expect(result).toEqual({ authorized_signer: true });
  });

  it('expands a roles array with multiple canonical entries', () => {
    const result = normalizeClaims({
      roles: ['authorized_signer', 'role_authority'],
    });
    expect(result).toEqual({
      authorized_signer: true,
      role_authority: true,
    });
  });
});

// ── normalizeClaims: boolean-like strings ───────────────────────────────────

describe('normalizeClaims — boolean-like string coercion', () => {
  it('coerces "yes" to true', () => {
    const result = normalizeClaims({ authorized_signer: 'yes' });
    expect(result).toEqual({ authorized_signer: true });
  });

  it('coerces "true" and "1" to true', () => {
    const result = normalizeClaims({
      kyc_verified: 'true',
      aml_verified: '1',
    });
    expect(result).toEqual({
      aml_verified: true,
      kyc_verified: true,
    });
  });
});

// ── normalizeClaims: unknown keys ───────────────────────────────────────────

describe('normalizeClaims — unknown key filtering', () => {
  it('drops keys that are not in the canonical vocabulary', () => {
    const result = normalizeClaims({
      legal_name: 'Bob',
      favorite_color: 'blue',
      random_field: 42,
    });
    expect(result).toEqual({ legal_name: 'Bob' });
    expect(result).not.toHaveProperty('favorite_color');
    expect(result).not.toHaveProperty('random_field');
  });
});

// ── normalizeClaims: determinism ────────────────────────────────────────────

describe('normalizeClaims — determinism', () => {
  it('produces the same output regardless of input key order', () => {
    const a = normalizeClaims({
      kyc_verified: true,
      legal_name: 'Alice',
      aml_verified: 'yes',
    });
    const b = normalizeClaims({
      aml_verified: 'yes',
      legal_name: 'Alice',
      kyc_verified: true,
    });
    expect(a).toEqual(b);
    // Verify key order is sorted
    expect(Object.keys(a)).toEqual(['aml_verified', 'kyc_verified', 'legal_name']);
  });
});

// ── Equivalent raw inputs → same normalized form ────────────────────────────

describe('normalizeClaims — equivalent raw inputs', () => {
  it('maps dotted key path to same canonical form as direct key', () => {
    const direct = normalizeClaims({ legal_name: 'Alice' });
    const dotted = normalizeClaims({ 'identity.legal_name': 'Alice' });
    expect(direct).toEqual(dotted);
  });

  it('maps roles array entry and direct boolean to same form', () => {
    const fromRoles = normalizeClaims({ roles: ['authorized_signer'] });
    const fromDirect = normalizeClaims({ authorized_signer: true });
    expect(fromRoles).toEqual(fromDirect);
  });
});

// ── claimsToCanonicalHash ───────────────────────────────────────────────────

describe('claimsToCanonicalHash', () => {
  it('produces deterministic hash for same claims', () => {
    const claims = { aml_verified: true, legal_name: 'Alice' };
    const h1 = claimsToCanonicalHash(claims);
    const h2 = claimsToCanonicalHash(claims);
    expect(h1).toBe(h2);
    expect(typeof h1).toBe('string');
    expect(h1).toHaveLength(64); // SHA-256 hex
  });

  it('produces different hash for different claims', () => {
    const h1 = claimsToCanonicalHash({ legal_name: 'Alice' });
    const h2 = claimsToCanonicalHash({ legal_name: 'Bob' });
    expect(h1).not.toBe(h2);
  });
});

// ── Empty claims ────────────────────────────────────────────────────────────

describe('normalizeClaims — edge cases', () => {
  it('returns empty object for empty input', () => {
    expect(normalizeClaims({})).toEqual({});
    expect(normalizeClaims(null)).toEqual({});
    expect(normalizeClaims(undefined)).toEqual({});
  });
});

// ── Backward compatibility ──────────────────────────────────────────────────

describe('computePresentationHash — backward compat', () => {
  it('still computes a SHA-256 hash from string or object input', () => {
    const hashStr = computePresentationHash('hello');
    expect(typeof hashStr).toBe('string');
    expect(hashStr).toHaveLength(64);

    const hashObj = computePresentationHash({ foo: 'bar' });
    expect(typeof hashObj).toBe('string');
    expect(hashObj).toHaveLength(64);

    // Same input → same hash
    expect(computePresentationHash('hello')).toBe(hashStr);
  });
});

// ── coerceBooleanLike: FALSY_STRINGS path (line 77) ─────────────────────────

describe('normalizeClaims — boolean-like falsy strings (line 77)', () => {
  it('coerces "no" to false', () => {
    const result = normalizeClaims({ authorized_signer: 'no' });
    expect(result).toEqual({ authorized_signer: false });
  });

  it('coerces "false" to false', () => {
    const result = normalizeClaims({ kyc_verified: 'false' });
    expect(result).toEqual({ kyc_verified: false });
  });

  it('coerces "0" to false', () => {
    const result = normalizeClaims({ aml_verified: '0' });
    expect(result).toEqual({ aml_verified: false });
  });
});

// ── roles array with unrecognized role → canonical null, if(canonical) false (line 134) ──

describe('normalizeClaims — roles with unrecognized role', () => {
  it('skips unrecognized role names in roles array', () => {
    const result = normalizeClaims({ roles: ['authorized_signer', 'totally_unknown_role_xyz'] });
    // authorized_signer should be included, unknown should not appear
    expect(result).toHaveProperty('authorized_signer', true);
    expect(result).not.toHaveProperty('totally_unknown_role_xyz');
  });
});

// ── claimsToCanonicalHash with null/undefined input (line 165 branch) ────────

describe('claimsToCanonicalHash — null/undefined input (line 165)', () => {
  it('returns a hash when called with null', () => {
    const h = claimsToCanonicalHash(null);
    expect(typeof h).toBe('string');
    expect(h).toHaveLength(64);
  });

  it('returns a hash when called with undefined', () => {
    const h = claimsToCanonicalHash(undefined);
    expect(typeof h).toBe('string');
  });
});
