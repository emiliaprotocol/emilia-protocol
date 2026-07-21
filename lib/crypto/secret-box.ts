/**
 * Secret box — AES-256-GCM encryption-at-rest for stored credentials.
 *
 * Used for values EP must be able to read back (e.g. a tenant's OIDC client
 * secret, which is replayed to the IdP's token endpoint) — hashing is not an
 * option, so they are sealed with a server-side key instead of stored
 * plaintext.
 *
 * Key resolution: EP_SECRET_KEY (64 hex chars = 32 bytes) when set; otherwise
 * derived from the service-role key so every deployment has a stable key with
 * zero new configuration. Moving the key into a dedicated KMS is the named
 * next step for a paying SSO customer; the storage format already carries a
 * version tag (`epenc:v1:`) so re-encryption under a KMS key is a rolling
 * upgrade, not a migration.
 *
 * Format: epenc:v1:<base64url(iv[12] || ciphertext || authTag[16])>
 * open() passes through values without the prefix unchanged, so rows written
 * before encryption keep working (read-compatible rollout).
 *
 * @license Apache-2.0
 */

import crypto from 'node:crypto';
import { getSecretBoxKey } from '@/lib/env';

const PREFIX = 'epenc:v1:';
const IV_LEN = 12;
const TAG_LEN = 16;

function keyBytes(): Buffer {
  const explicit = getSecretBoxKey();
  if (explicit) return Buffer.from(explicit, 'hex');
  if (process.env.NODE_ENV === 'production') {
    throw new Error('secret-box: EP_SECRET_KEY (64 hex) is required in production — refusing the shared service-role-derived fallback key');
  }
  const base = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY || 'ep-dev-secret-box';
  return crypto.createHash('sha256').update(`ep-secret-box:${base}`, 'utf8').digest();
}

/** Encrypt a secret for storage. null/empty passes through unchanged. */
export function seal(plaintext: any): string | null {
  if (plaintext == null || plaintext === '') return plaintext;
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBytes(), iv, { authTagLength: TAG_LEN });
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return PREFIX + Buffer.concat([iv, ciphertext, tag]).toString('base64url');
}

/**
 * Decrypt a stored secret. Values without the epenc prefix are returned as-is
 * (pre-encryption rows). A sealed value that fails authentication throws —
 * a tampered ciphertext must never decrypt to something plausible.
 */
export function open(stored: any): string {
  if (stored == null || stored === '' || !String(stored).startsWith(PREFIX)) return stored;
  const raw = Buffer.from(String(stored).slice(PREFIX.length), 'base64url');
  if (raw.length < IV_LEN + TAG_LEN + 1) throw new Error('secret-box: ciphertext too short');
  const iv = raw.subarray(0, IV_LEN);
  const tag = raw.subarray(raw.length - TAG_LEN);
  const ciphertext = raw.subarray(IV_LEN, raw.length - TAG_LEN);
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBytes(), iv, { authTagLength: TAG_LEN });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

/** True if the stored value is sealed (vs a pre-encryption plaintext row). */
export function isSealed(stored: any): boolean {
  return typeof stored === 'string' && stored.startsWith(PREFIX);
}
