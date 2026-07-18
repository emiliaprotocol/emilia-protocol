// Stateless Trust Desk reviewer session.
//
// The bootstrap token is accepted only at the exchange endpoint. It is never
// copied into a browser cookie; the cookie is a short-lived, HMAC-protected
// session envelope with a fresh nonce and an explicit expiry.

import crypto from 'node:crypto';
import { getServiceClient } from '@/lib/supabase';

export const TRUST_DESK_SESSION_COOKIE = 'td_internal';
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const MAX_SESSION_CHARS = 4096;

function secret() {
  const value = process.env.TRUST_DESK_INTERNAL_TOKEN;
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function encode(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function decode(value) {
  try {
    const raw = Buffer.from(value, 'base64url');
    if (!raw.length || raw.toString('base64url') !== value) return null;
    return JSON.parse(raw.toString('utf8'));
  } catch {
    return null;
  }
}

export function issueTrustDeskSession() {
  const key = secret();
  if (!key) return null;
  const now = Math.floor(Date.now() / 1000);
  const payload = encode({
    purpose: 'trust-desk-reviewer',
    iat: now,
    exp: now + SESSION_TTL_SECONDS,
    nonce: crypto.randomBytes(24).toString('base64url'),
  });
  const mac = crypto.createHmac('sha256', key).update(payload).digest('base64url');
  return `tds1.${payload}.${mac}`;
}

/**
 * Consume the configured bootstrap bearer exactly once. The database stores
 * only a hash, and the atomic RPC makes replay fail across instances rather
 * than relying on a process-local memory map.
 */
export async function consumeTrustDeskBootstrap(token) {
  const key = secret();
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

export function verifyTrustDeskSession(token) {
  const key = secret();
  if (!key || typeof token !== 'string' || token.length > MAX_SESSION_CHARS) return false;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'tds1') return false;
  const [, payload, suppliedMac] = parts;
  if (!/^[A-Za-z0-9_-]+$/.test(payload) || !/^[A-Za-z0-9_-]+$/.test(suppliedMac)) return false;
  const expectedMac = crypto.createHmac('sha256', key).update(payload).digest();
  let actualMac;
  try { actualMac = Buffer.from(suppliedMac, 'base64url'); } catch { return false; }
  if (actualMac.length !== expectedMac.length || !crypto.timingSafeEqual(actualMac, expectedMac)) return false;
  const data = decode(payload);
  const now = Math.floor(Date.now() / 1000);
  return !!data
    && data.purpose === 'trust-desk-reviewer'
    && typeof data.nonce === 'string'
    && data.nonce.length >= 16
    && Number.isSafeInteger(data.iat)
    && Number.isSafeInteger(data.exp)
    && data.exp >= now
    && data.iat <= now + 60;
}
