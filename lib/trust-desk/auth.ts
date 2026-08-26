// SPDX-License-Identifier: Apache-2.0
// Stateless Trust Desk reviewer session.
//
// The bootstrap token is accepted only from the bounded POST body at the
// exchange endpoint. It is never accepted from a URL or copied into a browser
// cookie; the cookie is a short-lived, HMAC-protected session envelope with a
// fresh nonce and an explicit expiry.

import crypto from 'node:crypto';
import { getServiceClient } from '@/lib/supabase';
import { getTrustDeskAuthConfig } from '@/lib/env';

export const TRUST_DESK_SESSION_COOKIE = 'td_internal';
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const MAX_SESSION_CHARS = 4096;

function sessionSecret(): string | null {
  const value = getTrustDeskAuthConfig().sessionSecret;
  return typeof value === 'string' && Buffer.byteLength(value, 'utf8') >= 32 ? value : null;
}

function bootstrapToken(): string | null {
  const value = getTrustDeskAuthConfig().bootstrapToken;
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function configuredReviewerId(): string | null {
  const value = getTrustDeskAuthConfig().reviewerId;
  if (typeof value !== 'string') return null;
  const reviewerId = value.trim();
  if (reviewerId.length < 3 || reviewerId.length > 200 || /[\u0000-\u001f\u007f]/.test(reviewerId)) {
    return null;
  }
  return reviewerId;
}

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

/** Parses the base64url session payload. Genuinely dynamic — this is
 * untrusted client-supplied data until every field below is validated. */
function decode(value: string): any {
  try {
    const raw = Buffer.from(value, 'base64url');
    if (!raw.length || raw.toString('base64url') !== value) return null;
    return JSON.parse(raw.toString('utf8'));
  } catch {
    return null;
  }
}

export function issueTrustDeskSession(): string | null {
  const key = sessionSecret();
  const reviewerId = configuredReviewerId();
  if (!key || !reviewerId) return null;
  const now = Math.floor(Date.now() / 1000);
  const payload = encode({
    purpose: 'trust-desk-reviewer',
    iat: now,
    exp: now + SESSION_TTL_SECONDS,
    nonce: crypto.randomBytes(24).toString('base64url'),
    reviewer_id: reviewerId,
  });
  const mac = crypto.createHmac('sha256', key).update(payload).digest('base64url');
  return `tds1.${payload}.${mac}`;
}

export interface TrustDeskReviewerSession {
  reviewerId: string;
}

export function authenticateTrustDeskReviewer(
  token: string | null | undefined,
): TrustDeskReviewerSession | null {
  const key = sessionSecret();
  if (!key || typeof token !== 'string' || token.length > MAX_SESSION_CHARS) return null;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'tds1') return null;
  const [, payload, suppliedMac] = parts;
  if (!/^[A-Za-z0-9_-]+$/.test(payload) || !/^[A-Za-z0-9_-]+$/.test(suppliedMac)) return null;
  const expectedMac = crypto.createHmac('sha256', key).update(payload).digest();
  let actualMac: Buffer;
  try { actualMac = Buffer.from(suppliedMac, 'base64url'); } catch { return null; }
  if (actualMac.length !== expectedMac.length || !crypto.timingSafeEqual(actualMac, expectedMac)) return null;
  const data = decode(payload);
  const now = Math.floor(Date.now() / 1000);
  if (!data
    || data.purpose !== 'trust-desk-reviewer'
    || typeof data.nonce !== 'string'
    || data.nonce.length < 16
    || typeof data.reviewer_id !== 'string'
    || data.reviewer_id.trim() !== data.reviewer_id
    || data.reviewer_id.length < 3
    || data.reviewer_id.length > 200
    || /[\u0000-\u001f\u007f]/.test(data.reviewer_id)
    || !Number.isSafeInteger(data.iat)
    || !Number.isSafeInteger(data.exp)
    || data.exp < now
    || data.iat > now + 60) {
    return null;
  }
  return { reviewerId: data.reviewer_id };
}

export interface ConsumeTrustDeskBootstrapResult {
  ok: boolean;
  reason: string | null;
  error?: unknown;
}

/**
 * Consume the configured bootstrap bearer exactly once. The database stores
 * only a hash, and the atomic RPC makes replay fail across instances rather
 * than relying on a process-local memory map.
 */
export async function consumeTrustDeskBootstrap(token: string): Promise<ConsumeTrustDeskBootstrapResult> {
  const key = bootstrapToken();
  if (!key || typeof token !== 'string' || token.length === 0) {
    return { ok: false, reason: 'bootstrap_not_configured' };
  }
  const tokenHash = crypto.createHash('sha256').update(token, 'utf8').digest('hex');
  try {
    const { data, error } = await getServiceClient().rpc(
      'consume_trust_desk_bootstrap_atomic',
      { p_token_hash: tokenHash },
    );
    if (error) return { ok: false, reason: 'bootstrap_store_unavailable', error };
    return { ok: data?.consumed === true, reason: data?.consumed === true ? null : 'bootstrap_replayed' };
  } catch (error) {
    return { ok: false, reason: 'bootstrap_store_unavailable', error };
  }
}

export function verifyTrustDeskSession(token: string | null | undefined): boolean {
  return authenticateTrustDeskReviewer(token) !== null;
}
