// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { getApprovalAcquisitionConfig } from '@/lib/env.js';

export const APPROVAL_REQUEST_ID_PATTERN = /^apr_[a-f0-9]{32}$/;
export const APPROVAL_POLL_TOKEN_PATTERN = /^apt_[a-f0-9]{48}$/;
export const APPROVAL_TOKEN_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;

export type ApprovalTokenScope = {
  requestId: string;
  tenantId: string;
  environment: string;
  requesterKeyId: string;
  pollTokenHash: string;
};

export type SealedPollToken = {
  ciphertext: string;
  iv: string;
  tag: string;
};

function encryptionKey(): Buffer {
  const raw = getApprovalAcquisitionConfig().tokenEncryptionKey;
  if (typeof raw !== 'string' || raw.length < 40 || raw.length > 48
      || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(raw)) {
    throw new Error('approval_token_encryption_key_unavailable');
  }
  let key: Buffer;
  try {
    key = Buffer.from(raw, raw.includes('-') || raw.includes('_') ? 'base64url' : 'base64');
  } catch {
    throw new Error('approval_token_encryption_key_unavailable');
  }
  if (key.length !== 32) throw new Error('approval_token_encryption_key_unavailable');
  return key;
}

function aad(scope: ApprovalTokenScope): Buffer {
  if (!APPROVAL_REQUEST_ID_PATTERN.test(scope.requestId)
      || !APPROVAL_TOKEN_HASH_PATTERN.test(scope.pollTokenHash)
      || !scope.tenantId || !scope.environment || !scope.requesterKeyId) {
    throw new Error('approval_token_scope_invalid');
  }
  return Buffer.from(JSON.stringify([
    'EP-APPROVAL-v1',
    scope.requestId,
    scope.tenantId,
    scope.environment,
    scope.requesterKeyId,
    scope.pollTokenHash,
  ]), 'utf8');
}

export function generateApprovalRequestId(): string {
  return `apr_${crypto.randomBytes(16).toString('hex')}`;
}

export function generateApprovalPollToken(): string {
  return `apt_${crypto.randomBytes(24).toString('hex')}`;
}

export function hashPollToken(token: string): string {
  if (!APPROVAL_POLL_TOKEN_PATTERN.test(token)) throw new Error('approval_poll_token_invalid');
  return `sha256:${crypto.createHash('sha256').update(token, 'utf8').digest('hex')}`;
}

export function encryptPollToken(token: string, scope: ApprovalTokenScope): SealedPollToken {
  if (!APPROVAL_POLL_TOKEN_PATTERN.test(token)) throw new Error('approval_poll_token_invalid');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  cipher.setAAD(aad(scope));
  const ciphertext = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  return {
    ciphertext: ciphertext.toString('base64url'),
    iv: iv.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
  };
}

export function decryptPollToken(sealed: SealedPollToken, scope: ApprovalTokenScope): string {
  const iv = Buffer.from(sealed.iv || '', 'base64url');
  const ciphertext = Buffer.from(sealed.ciphertext || '', 'base64url');
  const tag = Buffer.from(sealed.tag || '', 'base64url');
  if (iv.length !== 12 || tag.length !== 16 || ciphertext.length < 16 || ciphertext.length > 256) {
    throw new Error('approval_poll_token_ciphertext_invalid');
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), iv);
  decipher.setAAD(aad(scope));
  decipher.setAuthTag(tag);
  const token = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  if (!APPROVAL_POLL_TOKEN_PATTERN.test(token)
      || !crypto.timingSafeEqual(Buffer.from(hashPollToken(token)), Buffer.from(scope.pollTokenHash))) {
    throw new Error('approval_poll_token_ciphertext_invalid');
  }
  return token;
}
