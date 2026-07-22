// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  decryptPollToken,
  encryptPollToken,
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
});
