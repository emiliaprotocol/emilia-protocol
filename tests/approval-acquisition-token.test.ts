// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  decryptPollToken,
  encryptPollToken,
  generateApprovalPollToken,
  generateApprovalRequestId,
  hashPollToken,
} from '../lib/approval-acquisition/token.ts';

const ORIGINAL_KEY = process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY;
const ORIGINAL_KEYRING = process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING;
const ORIGINAL_ACTIVE_KEY_ID = process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID;

const KEY_V1 = Buffer.alloc(32, 7).toString('base64');
const KEY_V2 = Buffer.alloc(32, 8).toString('base64');

function configureKeyring(activeKeyId: string, keys: Record<string, string>) {
  delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY;
  process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID = activeKeyId;
  process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING = JSON.stringify(keys);
}

function validTokenAndScope() {
  const token = `apt_${'a'.repeat(48)}`;
  return {
    token,
    scope: {
      requestId: `apr_${'b'.repeat(32)}`,
      tenantId: 'tenant-a',
      environment: 'production',
      requesterKeyId: 'key-a',
      pollTokenHash: hashPollToken(token),
    },
  };
}

describe('approval poll-token custody', () => {
  beforeEach(() => {
    configureKeyring('2026-07-v1', { '2026-07-v1': KEY_V1 });
  });
  afterEach(() => {
    if (ORIGINAL_KEY === undefined) delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY;
    else process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY = ORIGINAL_KEY;
    if (ORIGINAL_KEYRING === undefined) delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING;
    else process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING = ORIGINAL_KEYRING;
    if (ORIGINAL_ACTIVE_KEY_ID === undefined) delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID;
    else process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID = ORIGINAL_ACTIVE_KEY_ID;
  });

  it('stores authenticated ciphertext and recovers only under the exact row scope', () => {
    const token = `apt_${'a'.repeat(48)}`;
    const scope = {
      requestId: `apr_${'b'.repeat(32)}`,
      tenantId: 'tenant-a',
      environment: 'production',
      requesterKeyId: 'key-a',
      pollTokenHash: hashPollToken(token),
    };
    const sealed = encryptPollToken(token, scope);
    expect(sealed.keyId).toBe('2026-07-v1');
    expect(sealed.ciphertext).toMatch(/^epat1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(JSON.stringify(sealed)).not.toContain(token);
    expect(decryptPollToken(sealed, scope)).toBe(token);
    expect(() => decryptPollToken(sealed, { ...scope, tenantId: 'tenant-b' })).toThrow();
    expect(() => decryptPollToken(sealed, { ...scope, environment: 'staging' })).toThrow();
    expect(() => decryptPollToken(sealed, { ...scope, requesterKeyId: 'key-b' })).toThrow();
  });

  it('recovers an existing envelope after active-key rotation while the old key remains in the keyring', () => {
    const token = `apt_${'a'.repeat(48)}`;
    const scope = {
      requestId: `apr_${'b'.repeat(32)}`,
      tenantId: 'tenant-a',
      environment: 'production',
      requesterKeyId: 'key-a',
      pollTokenHash: hashPollToken(token),
    };
    const sealedV1 = encryptPollToken(token, scope);

    configureKeyring('2026-08-v2', {
      '2026-07-v1': KEY_V1,
      '2026-08-v2': KEY_V2,
    });

    expect(decryptPollToken(sealedV1, scope)).toBe(token);
    expect(encryptPollToken(token, scope).keyId).toBe('2026-08-v2');

    configureKeyring('2026-08-v2', { '2026-08-v2': KEY_V2 });
    expect(() => decryptPollToken(sealedV1, scope)).toThrow('approval_token_encryption_key_unknown');
  });

  it('decrypts committed-migration legacy envelopes until their key is intentionally retired', () => {
    delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING;
    delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID;
    process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY = KEY_V1;
    const token = `apt_${'a'.repeat(48)}`;
    const scope = {
      requestId: `apr_${'b'.repeat(32)}`,
      tenantId: 'tenant-a',
      environment: 'production',
      requesterKeyId: 'key-a',
      pollTokenHash: hashPollToken(token),
    };
    const iv = Buffer.alloc(12, 3);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(KEY_V1, 'base64'), iv);
    cipher.setAAD(Buffer.from(JSON.stringify([
      'EP-APPROVAL-v1',
      scope.requestId,
      scope.tenantId,
      scope.environment,
      scope.requesterKeyId,
      scope.pollTokenHash,
    ]), 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
    const legacy = {
      keyId: 'legacy-v1',
      ciphertext: ciphertext.toString('base64url'),
      iv: iv.toString('base64url'),
      tag: cipher.getAuthTag().toString('base64url'),
    };

    expect(decryptPollToken(legacy, scope)).toBe(token);
    expect(() => decryptPollToken(legacy, { ...scope, environment: 'staging' })).toThrow();
  });

  it('rejects unknown key ids and authenticates the envelope key id as AAD', () => {
    const token = `apt_${'a'.repeat(48)}`;
    const scope = {
      requestId: `apr_${'b'.repeat(32)}`,
      tenantId: 'tenant-a',
      environment: 'production',
      requesterKeyId: 'key-a',
      pollTokenHash: hashPollToken(token),
    };
    configureKeyring('2026-07-v1', {
      '2026-07-v1': KEY_V1,
      '2026-08-v2': KEY_V1,
    });
    const sealed = encryptPollToken(token, scope);
    const [version, , payload] = sealed.ciphertext.split('.');
    const relabeled = {
      ...sealed,
      keyId: '2026-08-v2',
      ciphertext: `${version}.${Buffer.from('2026-08-v2').toString('base64url')}.${payload}`,
    };
    expect(() => decryptPollToken(relabeled, scope)).toThrow('approval_poll_token_ciphertext_invalid');

    const unknown = {
      ...sealed,
      keyId: 'unknown-v9',
      ciphertext: `${version}.${Buffer.from('unknown-v9').toString('base64url')}.${payload}`,
    };
    expect(() => decryptPollToken(unknown, scope)).toThrow('approval_token_encryption_key_unknown');
  });

  it('refuses an absent or malformed production encryption key', () => {
    delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY;
    delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING;
    delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID;
    expect(() => encryptPollToken(`apt_${'a'.repeat(48)}`, {
      requestId: `apr_${'b'.repeat(32)}`,
      tenantId: 'tenant-a',
      environment: 'production',
      requesterKeyId: 'key-a',
      pollTokenHash: `sha256:${'c'.repeat(64)}`,
    })).toThrow('approval_token_encryption_key_unavailable');
  });

  it('generates closed identifiers and rejects malformed polling capabilities', () => {
    expect(generateApprovalRequestId()).toMatch(/^apr_[a-f0-9]{32}$/);
    expect(generateApprovalPollToken()).toMatch(/^apt_[a-f0-9]{48}$/);
    expect(() => hashPollToken('apt_short')).toThrow('approval_poll_token_invalid');
    expect(() => encryptPollToken('apt_short', validTokenAndScope().scope))
      .toThrow('approval_poll_token_invalid');
  });

  it.each([
    ['not-json', '2026-07-v1'],
    ['null', '2026-07-v1'],
    ['[]', '2026-07-v1'],
    ['{}', '2026-07-v1'],
    [JSON.stringify(Object.fromEntries(Array.from({ length: 33 }, (_, index) => [`key-${index}`, KEY_V1]))), 'key-0'],
    [JSON.stringify({ 'bad key': KEY_V1 }), 'bad key'],
    [JSON.stringify({ '2026-07-v1': 'short' }), '2026-07-v1'],
    [JSON.stringify({ '2026-07-v1': '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!' }), '2026-07-v1'],
    [JSON.stringify({ '2026-07-v1': Buffer.alloc(31).toString('base64') }), '2026-07-v1'],
    [JSON.stringify({ '2026-07-v1': KEY_V1 }), 'missing-key'],
    [JSON.stringify({ '2026-07-v1': KEY_V1 }), 'bad key'],
  ])('fails closed on malformed keyring %#', (serialized, activeKeyId) => {
    delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY;
    process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING = serialized;
    process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID = activeKeyId;
    const { token, scope } = validTokenAndScope();
    expect(() => encryptPollToken(token, scope)).toThrow('approval_token_encryption_key_unavailable');
  });

  it.each([
    { requestId: 'apr_bad' },
    { pollTokenHash: 'sha256:bad' },
    { tenantId: '' },
    { environment: '' },
    { requesterKeyId: '' },
  ])('refuses an invalid authenticated scope %#', (mutation) => {
    const { token, scope } = validTokenAndScope();
    expect(() => encryptPollToken(token, { ...scope, ...mutation }))
      .toThrow('approval_token_scope_invalid');
  });

  it('supports a base64url key and refuses malformed versioned envelopes', () => {
    configureKeyring('2026-07-v1', { '2026-07-v1': Buffer.alloc(32, 255).toString('base64url') });
    const { token, scope } = validTokenAndScope();
    const sealed = encryptPollToken(token, scope);
    const [version, encodedKeyId, payload] = sealed.ciphertext.split('.');
    expect(decryptPollToken(sealed, scope)).toBe(token);

    const malformed = [
      { ...sealed, keyId: '' },
      { ...sealed, ciphertext: 1 as unknown as string },
      { ...sealed, ciphertext: `${version}.%%%INVALID%%%.${payload}` },
      { ...sealed, ciphertext: `${version}.${Buffer.from('other-key').toString('base64url')}.${payload}` },
      { ...sealed, ciphertext: `epat2.${encodedKeyId}.${payload}` },
      { ...sealed, ciphertext: `${version}.${encodedKeyId}.${payload}.extra` },
      { ...sealed, iv: Buffer.alloc(11).toString('base64url') },
      { ...sealed, tag: Buffer.alloc(15).toString('base64url') },
      { ...sealed, ciphertext: `${version}.${encodedKeyId}.${Buffer.alloc(15).toString('base64url')}` },
      { ...sealed, ciphertext: `${version}.${encodedKeyId}.${Buffer.alloc(257).toString('base64url')}` },
      { ...sealed, tag: Buffer.alloc(16, 9).toString('base64url') },
      { ...sealed, iv: undefined as unknown as string },
      { ...sealed, tag: undefined as unknown as string },
      { ...sealed, ciphertext: `${version}.${encodedKeyId}.` },
    ];
    for (const candidate of malformed) {
      expect(() => decryptPollToken(candidate, scope)).toThrow('approval_poll_token_ciphertext_invalid');
    }
  });

  it('refuses a keyring without an explicitly selected active key', () => {
    delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY;
    process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING = JSON.stringify({ '2026-07-v1': KEY_V1 });
    delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID;
    const { token, scope } = validTokenAndScope();
    expect(() => encryptPollToken(token, scope)).toThrow('approval_token_encryption_key_unavailable');
  });

  it('refuses malformed legacy envelopes and valid ciphertext bound to the wrong token hash', () => {
    delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEYRING;
    delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_ACTIVE_KEY_ID;
    process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY = KEY_V1;
    const { token, scope } = validTokenAndScope();
    const wrongHashScope = { ...scope, pollTokenHash: `sha256:${'f'.repeat(64)}` };
    const mismatched = encryptPollToken(token, wrongHashScope);
    expect(() => decryptPollToken(mismatched, wrongHashScope))
      .toThrow('approval_poll_token_ciphertext_invalid');

    const malformedLegacy = [
      { keyId: 'not-legacy', ciphertext: 'abcd', iv: 'abcd', tag: 'abcd' },
      { keyId: 'legacy-v1', ciphertext: 'bad.value', iv: 'abcd', tag: 'abcd' },
      { keyId: 'legacy-v1', ciphertext: '%%%bad%%%', iv: 'abcd', tag: 'abcd' },
    ];
    for (const candidate of malformedLegacy) {
      expect(() => decryptPollToken(candidate, scope)).toThrow('approval_poll_token_ciphertext_invalid');
    }
  });
});
