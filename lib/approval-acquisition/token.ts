// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { getApprovalAcquisitionConfig } from '@/lib/env.js';

export const APPROVAL_REQUEST_ID_PATTERN = /^apr_[a-f0-9]{32}$/;
export const APPROVAL_POLL_TOKEN_PATTERN = /^apt_[a-f0-9]{48}$/;
export const APPROVAL_TOKEN_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const APPROVAL_TOKEN_ENVELOPE_VERSION = 'epat1';
const APPROVAL_TOKEN_KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const MAX_KEYRING_KEYS = 32;

export type ApprovalTokenScope = {
  requestId: string;
  tenantId: string;
  environment: string;
  requesterKeyId: string;
  pollTokenHash: string;
};

export type SealedPollToken = {
  keyId: string;
  ciphertext: string;
  iv: string;
  tag: string;
};

type EncryptionKeyring = {
  activeKeyId: string;
  keys: Map<string, Buffer>;
};

export class ApprovalTokenKeyUnavailableError extends Error {
  code: string;

  constructor(code = 'approval_token_encryption_key_unknown') {
    super(code);
    this.name = 'ApprovalTokenKeyUnavailableError';
    this.code = code;
  }
}

function decodeEncryptionKey(raw: unknown): Buffer | null {
  if (typeof raw !== 'string' || raw.length < 40 || raw.length > 48
      || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(raw)) {
    return null;
  }
  try {
    const key = Buffer.from(raw, raw.includes('-') || raw.includes('_') ? 'base64url' : 'base64');
    return key.length === 32 ? key : null;
  } catch {
    return null;
  }
}

function encryptionKeyring(): EncryptionKeyring {
  const config = getApprovalAcquisitionConfig();
  const serialized = config.tokenEncryptionKeyring;
  if (serialized === null) {
    const legacyKey = decodeEncryptionKey(config.tokenEncryptionKey);
    if (!legacyKey) throw new Error('approval_token_encryption_key_unavailable');
    return { activeKeyId: 'legacy-v1', keys: new Map([['legacy-v1', legacyKey]]) };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new Error('approval_token_encryption_key_unavailable');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
      || Object.getPrototypeOf(parsed) !== Object.prototype) {
    throw new Error('approval_token_encryption_key_unavailable');
  }
  const entries = Object.entries(parsed as Record<string, unknown>);
  if (entries.length === 0 || entries.length > MAX_KEYRING_KEYS) {
    throw new Error('approval_token_encryption_key_unavailable');
  }
  const keys = new Map<string, Buffer>();
  for (const [keyId, raw] of entries) {
    const key = decodeEncryptionKey(raw);
    if (!APPROVAL_TOKEN_KEY_ID_PATTERN.test(keyId) || !key) {
      throw new Error('approval_token_encryption_key_unavailable');
    }
    keys.set(keyId, key);
  }
  const activeKeyId = config.tokenEncryptionActiveKeyId || '';
  if (!APPROVAL_TOKEN_KEY_ID_PATTERN.test(activeKeyId) || !keys.has(activeKeyId)) {
    throw new Error('approval_token_encryption_key_unavailable');
  }
  return { activeKeyId, keys };
}

function encryptionKey(keyId: string): Buffer {
  const key = encryptionKeyring().keys.get(keyId);
  if (!key) throw new ApprovalTokenKeyUnavailableError();
  return key;
}

function validateScope(scope: ApprovalTokenScope): void {
  if (!APPROVAL_REQUEST_ID_PATTERN.test(scope.requestId)
      || !APPROVAL_TOKEN_HASH_PATTERN.test(scope.pollTokenHash)
      || !scope.tenantId || !scope.environment || !scope.requesterKeyId) {
    throw new Error('approval_token_scope_invalid');
  }
}

function aad(scope: ApprovalTokenScope, keyId: string): Buffer {
  validateScope(scope);
  if (!APPROVAL_TOKEN_KEY_ID_PATTERN.test(keyId)) throw new Error('approval_token_scope_invalid');
  return Buffer.from(JSON.stringify([
    'EP-APPROVAL-v1',
    APPROVAL_TOKEN_ENVELOPE_VERSION,
    keyId,
    scope.requestId,
    scope.tenantId,
    scope.environment,
    scope.requesterKeyId,
    scope.pollTokenHash,
  ]), 'utf8');
}

function legacyAad(scope: ApprovalTokenScope): Buffer {
  validateScope(scope);
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
  const { activeKeyId, keys } = encryptionKeyring();
  const key = keys.get(activeKeyId);
  if (!key) throw new Error('approval_token_encryption_key_unavailable');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad(scope, activeKeyId));
  const ciphertext = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  return {
    keyId: activeKeyId,
    ciphertext: `${APPROVAL_TOKEN_ENVELOPE_VERSION}.${Buffer.from(activeKeyId, 'utf8').toString('base64url')}.${ciphertext.toString('base64url')}`,
    iv: iv.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
  };
}

export function decryptPollToken(sealed: SealedPollToken, scope: ApprovalTokenScope): string {
  const parts = typeof sealed.ciphertext === 'string' ? sealed.ciphertext.split('.') : [];
  if (!APPROVAL_TOKEN_KEY_ID_PATTERN.test(sealed.keyId || '')) {
    throw new Error('approval_poll_token_ciphertext_invalid');
  }
  let embeddedKeyId = sealed.keyId;
  let encodedCiphertext = sealed.ciphertext;
  let authenticatedData: Buffer;
  if (parts.length === 3 && parts[0] === APPROVAL_TOKEN_ENVELOPE_VERSION) {
    embeddedKeyId = Buffer.from(parts[1], 'base64url').toString('utf8');
    if (Buffer.from(embeddedKeyId, 'utf8').toString('base64url') !== parts[1]
        || embeddedKeyId !== sealed.keyId) {
      throw new Error('approval_poll_token_ciphertext_invalid');
    }
    encodedCiphertext = parts[2];
    authenticatedData = aad(scope, embeddedKeyId);
  } else {
    // Rows created by the committed migration predate versioned envelopes.
    // They remain decryptable only under the explicitly named legacy key;
    // unknown/retired keys take the authenticated recovery path in service.ts.
    if (parts.length !== 1 || sealed.keyId !== 'legacy-v1'
        || !/^[A-Za-z0-9_-]+$/.test(sealed.ciphertext || '')) {
      throw new Error('approval_poll_token_ciphertext_invalid');
    }
    authenticatedData = legacyAad(scope);
  }
  const iv = Buffer.from(sealed.iv || '', 'base64url');
  const ciphertext = Buffer.from(encodedCiphertext || '', 'base64url');
  const tag = Buffer.from(sealed.tag || '', 'base64url');
  if (iv.length !== 12 || tag.length !== 16 || ciphertext.length < 16 || ciphertext.length > 256) {
    throw new Error('approval_poll_token_ciphertext_invalid');
  }
  const key = encryptionKey(embeddedKeyId);
  let token: string;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(authenticatedData);
    decipher.setAuthTag(tag);
    token = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    throw new Error('approval_poll_token_ciphertext_invalid');
  }
  if (!APPROVAL_POLL_TOKEN_PATTERN.test(token)
      || !crypto.timingSafeEqual(Buffer.from(hashPollToken(token)), Buffer.from(scope.pollTokenHash))) {
    throw new Error('approval_poll_token_ciphertext_invalid');
  }
  return token;
}
