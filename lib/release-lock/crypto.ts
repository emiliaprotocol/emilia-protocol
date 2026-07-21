// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { canonicalize, isCanonicalizable } from '../../packages/verify/index.js';
import {
  RELEASE_LOCK_DIGEST_PATTERN,
  RELEASE_LOCK_HMAC_PATTERN,
  RELEASE_LOCK_TOKEN_BYTES,
} from './constants.js';
import { releaseLockRefusal } from './errors.js';

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const DOMAIN_INVITATION = 'EP-RELEASE-LOCK-INVITATION-v1\0';
const DOMAIN_PAIRING = 'EP-RELEASE-LOCK-PAIRING-v1\0';
const DOMAIN_SESSION = 'EP-RELEASE-LOCK-SESSION-v1\0';
const DOMAIN_CONTACT = 'EP-RELEASE-LOCK-CONTACT-v1\0';
const DOMAIN_CONTACT_PROOF = 'EP-RELEASE-LOCK-CONTACT-PROOF-v1\0';
const DOMAIN_AUTHORITY_ASSERTION = 'EP-RELEASE-LOCK-AUTHORITY-ASSERTION-v1\0';
const AUTHORITY_PROVIDER_PATTERN = /^[a-z0-9][a-z0-9._-]{1,127}$/;
const AUTHORITY_KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const AUTHORITY_SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;

interface AuthorityAssertion {
  provider?: string;
  key_id?: string;
  [key: string]: unknown;
}

export interface ReleaseLockCryptoSuite {
  invitation(): { token: string; digest: string };
  pairing(): { token: string; digest: string };
  session(): { token: string; digest: string };
  invitationDigest(token: string): string;
  pairingDigest(token: string): string;
  sessionDigest(token: string): string;
  contactDigest(normalizedChannel: string, normalizedIdentifier: string): string;
  contactProofDigest(proofBody: unknown): string;
  verifyAuthorityAssertion(assertion: AuthorityAssertion | null | undefined, signature: string | null | undefined): boolean;
}

export interface CreateReleaseLockCryptoOptions {
  tokenKey?: unknown;
  contactKey?: unknown;
  authorityKeys?: unknown;
  randomBytes?: (size: number) => Buffer;
}

function keyBytes(value: unknown, name: string): Buffer {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const bytes = Buffer.from(value);
    if (bytes.length >= 32) return bytes;
  }
  if (typeof value === 'string') {
    if (/^[0-9a-fA-F]{64,}$/.test(value) && value.length % 2 === 0) {
      const bytes = Buffer.from(value, 'hex');
      if (bytes.length >= 32) return bytes;
    }
    if (/^[A-Za-z0-9_-]{43,}$/.test(value)) {
      const bytes = Buffer.from(value, 'base64url');
      if (bytes.length >= 32 && bytes.toString('base64url') === value) return bytes;
    }
  }
  throw releaseLockRefusal(
    503,
    'release_lock_crypto_unconfigured',
    `${name} must be configured with at least 32 bytes of key material.`,
  );
}

function hmac(key: Buffer, domain: string, value: string): string {
  return `hmac-sha256:${crypto.createHmac('sha256', key)
    .update(domain, 'utf8')
    .update(value, 'utf8')
    .digest('hex')}`;
}

function authorityKeyMap(value: unknown): Map<string, crypto.KeyObject> {
  // Authority key configuration is parsed from an environment-provided JSON
  // blob (genuinely dynamic external data); `any` here matches that, with
  // every field independently validated below before it is trusted.
  let source: any = value;
  if (source === undefined) source = process.env.RELEASE_LOCK_AUTHORITY_KEYS_JSON || '{}';
  if (typeof source === 'string') {
    try {
      source = JSON.parse(source);
    } catch {
      throw releaseLockRefusal(
        503,
        'release_lock_crypto_unconfigured',
        'RELEASE_LOCK_AUTHORITY_KEYS_JSON must be valid JSON.',
      );
    }
  }
  if (source === null || typeof source !== 'object' || Array.isArray(source)) {
    throw releaseLockRefusal(
      503,
      'release_lock_crypto_unconfigured',
      'Release Lock authority keys must be a provider-keyed object.',
    );
  }
  const keys = new Map<string, crypto.KeyObject>();
  try {
    for (const [provider, providerKeys] of Object.entries(source)) {
      if (!AUTHORITY_PROVIDER_PATTERN.test(provider)
          || providerKeys === null
          || typeof providerKeys !== 'object'
          || Array.isArray(providerKeys)) {
        throw new TypeError('authority provider key set is invalid');
      }
      for (const [keyId, profile] of Object.entries(providerKeys)) {
        if (!AUTHORITY_KEY_ID_PATTERN.test(keyId)
            || profile === null
            || typeof profile !== 'object'
            || Array.isArray(profile)
            || profile.algorithm !== 'Ed25519'
            || typeof profile.public_key !== 'string') {
          throw new TypeError('authority key profile is invalid');
        }
        const der = Buffer.from(profile.public_key, 'base64url');
        if (der.length === 0 || der.toString('base64url') !== profile.public_key) {
          throw new TypeError('authority public key encoding is invalid');
        }
        const publicKey = crypto.createPublicKey({
          key: der,
          format: 'der',
          type: 'spki',
        });
        if (publicKey.asymmetricKeyType !== 'ed25519') {
          throw new TypeError('authority public key must be Ed25519');
        }
        keys.set(`${provider}\0${keyId}`, publicKey);
      }
    }
  } catch {
    throw releaseLockRefusal(
      503,
      'release_lock_crypto_unconfigured',
      'Release Lock authority key configuration is invalid.',
    );
  }
  return keys;
}

export function authorityAssertionBytes(assertion: AuthorityAssertion | null | undefined): Buffer {
  if (!isCanonicalizable(assertion)) {
    throw releaseLockRefusal(
      400,
      'authority_verification_invalid',
      'External authority assertion is malformed.',
    );
  }
  return Buffer.from(`${DOMAIN_AUTHORITY_ASSERTION}${canonicalize(assertion)}`, 'utf8');
}

export function canonicalDigest(value: unknown): string {
  if (!isCanonicalizable(value)) {
    throw releaseLockRefusal(400, 'non_canonical_value', 'Value is outside the canonical JSON profile.');
  }
  return `sha256:${crypto.createHash('sha256')
    .update(canonicalize(value), 'utf8')
    .digest('hex')}`;
}

export function bytesDigest(value: Buffer | Uint8Array | ArrayLike<number> | null | undefined): string {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value || []);
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

export function randomReleaseLockId(randomBytes: (size: number) => Buffer = crypto.randomBytes): string {
  return `rlk_${randomBytes(16).toString('hex')}`;
}

export function randomOpaqueId(
  prefix: string,
  randomBytes: (size: number) => Buffer = crypto.randomBytes,
): string {
  if (typeof prefix !== 'string' || !/^[a-z][a-z0-9_]{1,20}$/.test(prefix)) {
    throw new TypeError('opaque id prefix is invalid');
  }
  return `${prefix}_${randomBytes(16).toString('hex')}`;
}

export function randomToken(randomBytes: (size: number) => Buffer = crypto.randomBytes): string {
  const raw = randomBytes(RELEASE_LOCK_TOKEN_BYTES);
  if (!Buffer.isBuffer(raw) || raw.length !== RELEASE_LOCK_TOKEN_BYTES) {
    throw new Error('secure random source returned an invalid token');
  }
  return raw.toString('base64url');
}

export function validRawToken(value: unknown): boolean {
  if (typeof value !== 'string' || !TOKEN_PATTERN.test(value)) return false;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length === RELEASE_LOCK_TOKEN_BYTES
    && bytes.toString('base64url') === value;
}

export function timingSafeTextEqual(left: unknown, right: unknown): boolean {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function createReleaseLockCrypto({
  tokenKey,
  contactKey,
  authorityKeys,
  randomBytes = crypto.randomBytes,
}: CreateReleaseLockCryptoOptions = {}): ReleaseLockCryptoSuite {
  const tokenHmacKey = keyBytes(
    tokenKey ?? process.env.RELEASE_LOCK_TOKEN_HMAC_KEY,
    'RELEASE_LOCK_TOKEN_HMAC_KEY',
  );
  const contactHmacKey = keyBytes(
    contactKey ?? process.env.RELEASE_LOCK_CONTACT_HMAC_KEY,
    'RELEASE_LOCK_CONTACT_HMAC_KEY',
  );
  const pinnedAuthorityKeys = authorityKeyMap(authorityKeys);
  if (typeof randomBytes !== 'function') throw new TypeError('randomBytes must be a function');

  return Object.freeze({
    invitation() {
      const token = randomToken(randomBytes);
      return {
        token,
        digest: hmac(tokenHmacKey, DOMAIN_INVITATION, token),
      };
    },
    pairing() {
      const token = randomToken(randomBytes);
      return {
        token,
        digest: hmac(tokenHmacKey, DOMAIN_PAIRING, token),
      };
    },
    session() {
      const token = randomToken(randomBytes);
      return {
        token,
        digest: hmac(tokenHmacKey, DOMAIN_SESSION, token),
      };
    },
    invitationDigest(token: string): string {
      if (!validRawToken(token)) {
        throw releaseLockRefusal(401, 'invitation_invalid', 'Invitation capability is invalid.');
      }
      return hmac(tokenHmacKey, DOMAIN_INVITATION, token);
    },
    pairingDigest(token: string): string {
      if (!validRawToken(token)) {
        throw releaseLockRefusal(401, 'pairing_invalid', 'Action Mirror pairing is invalid.');
      }
      return hmac(tokenHmacKey, DOMAIN_PAIRING, token);
    },
    sessionDigest(token: string): string {
      if (!validRawToken(token)) {
        throw releaseLockRefusal(401, 'session_invalid', 'Release Lock session is invalid.');
      }
      return hmac(tokenHmacKey, DOMAIN_SESSION, token);
    },
    contactDigest(normalizedChannel: string, normalizedIdentifier: string): string {
      return hmac(contactHmacKey, DOMAIN_CONTACT, `${normalizedChannel}\0${normalizedIdentifier}`);
    },
    contactProofDigest(proofBody: unknown): string {
      if (!isCanonicalizable(proofBody)) {
        throw releaseLockRefusal(400, 'contact_verification_invalid', 'Contact verification is malformed.');
      }
      return hmac(contactHmacKey, DOMAIN_CONTACT_PROOF, canonicalize(proofBody));
    },
    verifyAuthorityAssertion(
      assertion: AuthorityAssertion | null | undefined,
      signature: string | null | undefined,
    ): boolean {
      if (!AUTHORITY_PROVIDER_PATTERN.test(assertion?.provider || '')
          || !AUTHORITY_KEY_ID_PATTERN.test(assertion?.key_id || '')
          || !AUTHORITY_SIGNATURE_PATTERN.test(signature || '')) {
        return false;
      }
      const signatureBytes = Buffer.from(signature as string, 'base64url');
      if (signatureBytes.length !== 64
          || signatureBytes.toString('base64url') !== signature) {
        return false;
      }
      const publicKey = pinnedAuthorityKeys.get(
        `${assertion!.provider}\0${assertion!.key_id}`,
      );
      if (!publicKey) return false;
      try {
        return crypto.verify(
          null,
          authorityAssertionBytes(assertion),
          publicKey,
          signatureBytes,
        );
      } catch {
        return false;
      }
    },
  });
}

export function isDigest(value: unknown): boolean {
  return typeof value === 'string' && RELEASE_LOCK_DIGEST_PATTERN.test(value);
}

export function isHmacDigest(value: unknown): boolean {
  return typeof value === 'string' && RELEASE_LOCK_HMAC_PATTERN.test(value);
}
