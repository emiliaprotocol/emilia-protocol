/**
 * lib/commit.js — extended coverage for signing key configuration paths.
 *
 * Uncovered lines:
 *   188      getSigningKeypair: isProduction=true, no signing key → throws FATAL error
 *   211-212  getSigningKeypair: signingKey + trustedKeys → registers additional keys
 *   278      verifySignature: catch block → returns false
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock supabase to prevent DB calls
vi.mock('../lib/supabase.js', () => ({
  getServiceClient: vi.fn(() => ({
    from: vi.fn(() => ({
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      insert: vi.fn().mockResolvedValue({ data: null, error: null }),
      single: vi.fn().mockResolvedValue({ data: null, error: null }),
    })),
  })),
}));

vi.mock('../lib/canonical-evaluator.js', () => ({
  canonicalEvaluate: vi.fn().mockResolvedValue({ score: 0.8, confidence: 0.9 }),
}));

vi.mock('../lib/delegation.js', () => ({
  verifyDelegation: vi.fn().mockResolvedValue({ valid: true }),
}));

import { _internals, _resetForTesting } from '../lib/commit.js';

beforeEach(() => {
  vi.clearAllMocks();
  _resetForTesting();
  // Clean up env vars set during tests
  delete process.env.EP_COMMIT_SIGNING_KEY;
  delete process.env.EP_COMMIT_SIGNING_KEYS;
  delete process.env.NODE_ENV_OVERRIDE;
});

// ── Lines 211-212: trustedKeys registered alongside signingKey ─────────────────

describe('getSigningKeypair — trustedKeys registration (lines 211-212)', () => {
  it('registers additional trusted keys when EP_COMMIT_SIGNING_KEYS is set', () => {
    // Generate a valid 32-byte base64 signing key
    const signingKey = 'IQXA4YvoCmbe5MwI0galT1c8AR8CjUNq92WsUHucP34=';

    // A second public key for trustedKeys (32 bytes in base64)
    const rotatedPubKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
    const trustedKeysJson = JSON.stringify({ 'ep-signing-key-2': rotatedPubKey });

    process.env.EP_COMMIT_SIGNING_KEY = signingKey;
    process.env.EP_COMMIT_SIGNING_KEYS = trustedKeysJson;

    // Calling getPublicKeyBase64 triggers ensureKeypair() → getSigningKeypair()
    const pubKeyBase64 = _internals.getPublicKeyBase64();
    expect(typeof pubKeyBase64).toBe('string');

    // The rotated key should be registered
    const allKeys = _internals.getAllTrustedKeys();
    const kids = allKeys.map((k) => k.kid);
    expect(kids).toContain('ep-signing-key-2');
  });
});

// ── Line 188: isProduction=true, no signing key → throws FATAL ──────────────

describe('getSigningKeypair — production without signing key (line 188)', () => {
  it('throws FATAL error when NODE_ENV=production and no signing key', () => {
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    delete process.env.EP_COMMIT_SIGNING_KEY;

    expect(() => _internals.getPublicKeyBase64()).toThrow(
      'FATAL: EP_COMMIT_SIGNING_KEY is required in production'
    );

    process.env.NODE_ENV = originalNodeEnv;
  });
});

// ── Line 278: verifySignature catch → returns false ──────────────────────────

describe('verifySignature — catch block returns false (line 278)', () => {
  it('returns false when signature verification throws (bad signature format)', () => {
    const result = _internals.verifySignature('payload-text', 'not-a-valid-base64-signature!!!', 'not-a-valid-key');
    expect(result).toBe(false);
  });
});
