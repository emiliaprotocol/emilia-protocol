// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  decryptPollToken,
  encryptPollToken,
  hashPollToken,
} from '../lib/approval-acquisition/token.ts';

const ORIGINAL_KEY = process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY;

describe('approval poll-token custody', () => {
  beforeEach(() => {
    process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString('base64');
  });
  afterEach(() => {
    if (ORIGINAL_KEY === undefined) delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY;
    else process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY = ORIGINAL_KEY;
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
    expect(JSON.stringify(sealed)).not.toContain(token);
    expect(decryptPollToken(sealed, scope)).toBe(token);
    expect(() => decryptPollToken(sealed, { ...scope, tenantId: 'tenant-b' })).toThrow();
  });

  it('refuses an absent or malformed production encryption key', () => {
    delete process.env.EP_APPROVAL_TOKEN_ENCRYPTION_KEY;
    expect(() => encryptPollToken(`apt_${'a'.repeat(48)}`, {
      requestId: `apr_${'b'.repeat(32)}`,
      tenantId: 'tenant-a',
      environment: 'production',
      requesterKeyId: 'key-a',
      pollTokenHash: `sha256:${'c'.repeat(64)}`,
    })).toThrow('approval_token_encryption_key_unavailable');
  });
});
