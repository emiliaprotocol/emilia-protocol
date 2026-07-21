// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  authorityAssertionBytes,
  bytesDigest,
  canonicalDigest,
  createReleaseLockCrypto,
  isDigest,
  isHmacDigest,
  randomOpaqueId,
  randomReleaseLockId,
  randomToken,
  timingSafeTextEqual,
  validRawToken,
} from './crypto.js';

const TOKEN_KEY = Buffer.alloc(32, 1);
const CONTACT_KEY = Buffer.alloc(32, 2);

function config(authorityKeys = {}) {
  return {
    tokenKey: TOKEN_KEY,
    contactKey: CONTACT_KEY,
    authorityKeys,
  };
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('Release Lock cryptographic configuration', () => {
  it('accepts binary, hexadecimal, and canonical base64url symmetric keys', () => {
    for (const tokenKey of [
      TOKEN_KEY,
      new Uint8Array(TOKEN_KEY),
      TOKEN_KEY.toString('hex'),
      TOKEN_KEY.toString('base64url'),
    ]) {
      expect(createReleaseLockCrypto({
        tokenKey,
        contactKey: CONTACT_KEY,
        authorityKeys: {},
      }).session().token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    }
  });

  it.each([
    [undefined],
    [null],
    [Buffer.alloc(31)],
    ['00'],
    ['not-a-key'],
  ])('fails closed on weak or missing symmetric key material %#', (tokenKey) => {
    expect(() => createReleaseLockCrypto({
      tokenKey,
      contactKey: CONTACT_KEY,
      authorityKeys: {},
    })).toThrow(expect.objectContaining({ code: 'release_lock_crypto_unconfigured' }));
  });

  it('loads the provider key map from JSON and verifies a portable assertion', () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const publicKey = pair.publicKey.export({ format: 'der', type: 'spki' })
      .toString('base64url');
    const authorityKeys = {
      project_directory: {
        'directory-key-1': {
          algorithm: 'Ed25519',
          public_key: publicKey,
        },
      },
    };
    vi.stubEnv('RELEASE_LOCK_AUTHORITY_KEYS_JSON', JSON.stringify(authorityKeys));
    const suite = createReleaseLockCrypto({
      tokenKey: TOKEN_KEY,
      contactKey: CONTACT_KEY,
    });
    const assertion = {
      '@version': 'EP-RELEASE-LOCK-AUTHORITY-ASSERTION-v1',
      algorithm: 'Ed25519',
      provider: 'project_directory',
      key_id: 'directory-key-1',
      reference: 'reference-1',
      role: 'customer',
      party_id: 'customer:1',
      subject_digest: `sha256:${'1'.repeat(64)}`,
      contact_binding_digest: `hmac-sha256:${'2'.repeat(64)}`,
      verified_at: '2030-01-01T00:00:00.000Z',
      expires_at: '2030-01-02T00:00:00.000Z',
    };
    const signature = crypto.sign(
      null,
      authorityAssertionBytes(assertion),
      pair.privateKey,
    ).toString('base64url');
    expect(suite.verifyAuthorityAssertion(assertion, signature)).toBe(true);
    expect(suite.verifyAuthorityAssertion(
      { ...assertion, party_id: 'attacker:1' },
      signature,
    )).toBe(false);
    expect(suite.verifyAuthorityAssertion(
      { ...assertion, key_id: 'missing-key' },
      signature,
    )).toBe(false);
  });

  it('refuses malformed authority-key configuration without partial loading', () => {
    const p256 = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
      .publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const invalid = [
      null,
      [],
      { 'Bad Provider': {} },
      { provider: null },
      { provider: [] },
      { provider: { x: null } },
      { provider: { x: [] } },
      { provider: { x: { algorithm: 'ES256', public_key: p256 } } },
      { provider: { x: { algorithm: 'Ed25519' } } },
      { provider: { x: { algorithm: 'Ed25519', public_key: '*' } } },
      { provider: { x: { algorithm: 'Ed25519', public_key: 'AQ' } } },
      { provider: { x: { algorithm: 'Ed25519', public_key: p256 } } },
    ];
    for (const authorityKeys of invalid) {
      expect(() => createReleaseLockCrypto(config(authorityKeys)))
        .toThrow(expect.objectContaining({ code: 'release_lock_crypto_unconfigured' }));
    }
  });

  it('refuses malformed authority JSON from the environment', () => {
    vi.stubEnv('RELEASE_LOCK_AUTHORITY_KEYS_JSON', '{bad json');
    expect(() => createReleaseLockCrypto({
      tokenKey: TOKEN_KEY,
      contactKey: CONTACT_KEY,
    })).toThrow(expect.objectContaining({ code: 'release_lock_crypto_unconfigured' }));
  });

  it('refuses malformed assertion/signature shapes before verification', () => {
    const suite = createReleaseLockCrypto(config());
    expect(suite.verifyAuthorityAssertion(null, '')).toBe(false);
    expect(suite.verifyAuthorityAssertion(
      { provider: 'INVALID', key_id: 'key-id' },
      'A'.repeat(86),
    )).toBe(false);
    expect(suite.verifyAuthorityAssertion(
      { provider: 'provider', key_id: 'x' },
      'A'.repeat(86),
    )).toBe(false);
    expect(suite.verifyAuthorityAssertion(
      { provider: 'provider', key_id: 'key-id' },
      'short',
    )).toBe(false);
  });
});

describe('Release Lock cryptographic primitives', () => {
  it('domain-separates and validates all opaque capability classes', () => {
    const suite = createReleaseLockCrypto(config());
    const invitation = suite.invitation();
    const pairing = suite.pairing();
    const session = suite.session();
    expect(suite.invitationDigest(invitation.token)).toBe(invitation.digest);
    expect(suite.pairingDigest(pairing.token)).toBe(pairing.digest);
    expect(suite.sessionDigest(session.token)).toBe(session.digest);
    expect(new Set([invitation.digest, pairing.digest, session.digest]).size).toBe(3);
    expect(() => suite.invitationDigest('invalid')).toThrow(
      expect.objectContaining({ code: 'invitation_invalid' }),
    );
    expect(() => suite.pairingDigest('invalid')).toThrow(
      expect.objectContaining({ code: 'pairing_invalid' }),
    );
    expect(() => suite.sessionDigest('invalid')).toThrow(
      expect.objectContaining({ code: 'session_invalid' }),
    );
  });

  it('rejects non-canonical proof inputs and produces bounded digests', () => {
    const suite = createReleaseLockCrypto(config());
    expect(() => authorityAssertionBytes({ value: 1n })).toThrow(
      expect.objectContaining({ code: 'authority_verification_invalid' }),
    );
    expect(() => canonicalDigest({ value: 1n })).toThrow(
      expect.objectContaining({ code: 'non_canonical_value' }),
    );
    expect(() => suite.contactProofDigest({ value: 1n })).toThrow(
      expect.objectContaining({ code: 'contact_verification_invalid' }),
    );
    expect(canonicalDigest({ b: 2, a: 1 })).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(bytesDigest(Buffer.from('a'))).not.toBe(bytesDigest());
    expect(suite.contactDigest('email', 'user@example.com'))
      .toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
  });

  it('validates random-source output and opaque identifier prefixes', () => {
    expect(randomReleaseLockId(() => Buffer.alloc(16, 3)))
      .toBe(`rlk_${'03'.repeat(16)}`);
    expect(randomOpaqueId('effect', () => Buffer.alloc(16, 4)))
      .toBe(`effect_${'04'.repeat(16)}`);
    for (const prefix of [null, '', 'A', 'a-', 'a'.repeat(22)]) {
      expect(() => randomOpaqueId(prefix)).toThrow(TypeError);
    }
    expect(() => randomToken(() => new Uint8Array(32))).toThrow(
      'secure random source returned an invalid token',
    );
    expect(() => randomToken(() => Buffer.alloc(31))).toThrow(
      'secure random source returned an invalid token',
    );
    expect(() => createReleaseLockCrypto({
      ...config(),
      randomBytes: 'not-a-function',
    })).toThrow(TypeError);
  });

  it('accepts only canonical 32-byte base64url tokens and constant-time text inputs', () => {
    const token = Buffer.alloc(32, 5).toString('base64url');
    expect(validRawToken(token)).toBe(true);
    for (const invalid of [null, '', 'x'.repeat(42), 'x'.repeat(44), '*'.repeat(43)]) {
      expect(validRawToken(invalid)).toBe(false);
    }
    expect(timingSafeTextEqual('same', 'same')).toBe(true);
    expect(timingSafeTextEqual('same', 'diff')).toBe(false);
    expect(timingSafeTextEqual('short', 'longer')).toBe(false);
    expect(timingSafeTextEqual(null, 'same')).toBe(false);
  });

  it('recognizes only typed cryptographic digests', () => {
    expect(isDigest(`sha256:${'a'.repeat(64)}`)).toBe(true);
    expect(isDigest(`hmac-sha256:${'a'.repeat(64)}`)).toBe(false);
    expect(isDigest(null)).toBe(false);
    expect(isHmacDigest(`hmac-sha256:${'b'.repeat(64)}`)).toBe(true);
    expect(isHmacDigest(`sha256:${'b'.repeat(64)}`)).toBe(false);
    expect(isHmacDigest(null)).toBe(false);
  });
});
