// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';

import { createSupabaseWorksAccountStore } from './account-store.js';
import type { WorksAccountStore, WorksSessionActor } from './account-service.js';

export const WORKS_SESSION_COOKIE_NAME = '__Host-emilia_works_session';
const SESSION_TOKEN = /^wss1_[a-f0-9]{64}$/;

export class WorksSessionUnavailableError extends Error {
  constructor() {
    super('Works account sessions are unavailable.');
    this.name = 'WorksSessionUnavailableError';
  }
}

function configuredOrigin(): string | null {
  const candidate = process.env.WORKS_PUBLIC_ORIGIN
    || process.env.NEXT_PUBLIC_APP_URL
    || process.env.NEXT_PUBLIC_SITE_URL
    || 'https://www.emiliaprotocol.ai';
  try {
    const url = new URL(candidate);
    const loopbackHttp = url.protocol === 'http:'
      && (url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]');
    if ((url.protocol !== 'https:' && !loopbackHttp)
      || url.username || url.password || url.pathname !== '/' || url.search || url.hash) return null;
    return url.origin;
  } catch {
    return null;
  }
}

/** Browser account mutations must originate at the server-pinned public origin. */
export function assertWorksSameOrigin(request: Pick<Request, 'headers'>): boolean {
  const expected = configuredOrigin();
  const supplied = request.headers.get('origin');
  const fetchSite = request.headers.get('sec-fetch-site');
  if (!expected || !supplied || fetchSite === 'cross-site') return false;
  try {
    return new URL(supplied).origin === expected && supplied === new URL(supplied).origin;
  } catch {
    return false;
  }
}

function tokenFromRequest(request: Pick<Request, 'headers'>): string | null {
  const cookie = request.headers.get('cookie') || '';
  const values: string[] = [];
  for (const part of cookie.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0 || part.slice(0, separator).trim() !== WORKS_SESSION_COOKIE_NAME) continue;
    values.push(part.slice(separator + 1).trim());
  }
  return values.length === 1 && SESSION_TOKEN.test(values[0]) ? values[0] : null;
}

function digest(token: string): string {
  return `sha256:${crypto.createHash('sha256').update(token, 'utf8').digest('hex')}`;
}

export async function getWorksSessionActor(
  request: Pick<Request, 'headers'>,
  store?: WorksAccountStore,
): Promise<WorksSessionActor | null> {
  const token = tokenFromRequest(request);
  if (!token) return null;
  let result;
  try {
    result = await (store || createSupabaseWorksAccountStore()).readSession(digest(token));
  } catch {
    throw new WorksSessionUnavailableError();
  }
  if (!result.ok) throw new WorksSessionUnavailableError();
  return result.actor;
}

export async function revokeWorksSession(
  request: Pick<Request, 'headers'>,
  store?: WorksAccountStore,
): Promise<boolean> {
  const token = tokenFromRequest(request);
  if (!token) return false;
  let result;
  try {
    result = await (store || createSupabaseWorksAccountStore()).revokeSession(digest(token));
  } catch {
    throw new WorksSessionUnavailableError();
  }
  if (!result.ok) throw new WorksSessionUnavailableError();
  return result.revoked;
}

export function serializeWorksSessionCookie(token: string, expires: Date): string {
  if (!SESSION_TOKEN.test(token) || !Number.isFinite(expires.getTime())) {
    throw new WorksSessionUnavailableError();
  }
  return `${WORKS_SESSION_COOKIE_NAME}=${token}; Path=/; Expires=${expires.toUTCString()}; HttpOnly; Secure; SameSite=Strict; Priority=High`;
}

export function clearWorksSessionCookieHeader(): string {
  return `${WORKS_SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict; Priority=High`;
}
