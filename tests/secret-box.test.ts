/**
 * Secret box — AES-256-GCM at-rest encryption for stored credentials.
 * Round-trip, tamper rejection, and the plaintext-passthrough rollout path.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'node:crypto';
import { seal, open, isSealed } from '../lib/crypto/secret-box.js';

beforeAll(() => {
  process.env.EP_SECRET_KEY = crypto.randomBytes(32).toString('hex');
});

describe('secret-box', () => {
  it('round-trips a secret', () => {
    const boxed = seal('okta-client-secret-123');
    expect(isSealed(boxed)).toBe(true);
    expect(boxed).not.toContain('okta-client-secret-123');
    expect(open(boxed)).toBe('okta-client-secret-123');
  });

  it('two seals of the same value differ (fresh IV) but both open', () => {
    const a = seal('same');
    const b = seal('same');
    expect(a).not.toBe(b);
    expect(open(a)).toBe('same');
    expect(open(b)).toBe('same');
  });

  it('a tampered ciphertext throws (never decrypts plausibly)', () => {
    const boxed = seal('secret');
    const raw = Buffer.from(boxed.slice('epenc:v1:'.length), 'base64url');
    raw[14] ^= 0xff; // flip a ciphertext byte
    const tampered = 'epenc:v1:' + raw.toString('base64url');
    expect(() => open(tampered)).toThrow();
  });

  it('a value sealed under a different key throws', () => {
    const boxed = seal('secret');
    const prev = process.env.EP_SECRET_KEY;
    process.env.EP_SECRET_KEY = crypto.randomBytes(32).toString('hex');
    expect(() => open(boxed)).toThrow();
    process.env.EP_SECRET_KEY = prev;
  });

  it('passes plaintext (pre-encryption rows) through unchanged', () => {
    expect(open('legacy-plaintext-secret')).toBe('legacy-plaintext-secret');
    expect(isSealed('legacy-plaintext-secret')).toBe(false);
  });

  it('passes null/empty through unchanged on both sides', () => {
    expect(seal(null)).toBe(null);
    expect(seal('')).toBe('');
    expect(open(null)).toBe(null);
    expect(open('')).toBe('');
  });

  it('rejects a truncated box', () => {
    expect(() => open('epenc:v1:AAAA')).toThrow(/too short/);
  });
});
