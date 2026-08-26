/**
 * EP Secure App — hosted mobile API client.
 *
 * The only credential path is a server-minted paired session acquired at
 * runtime from a one-time admin-created pairing code. No bearer credential is
 * accepted from Expo public environment variables or another bundled source.
 *
 * @license Apache-2.0
 */

import type { PairedSession } from './session';
import {
  authorizationHeadersForSession,
  validatePairedSession,
} from './security-boundary.mjs';

export const MOBILE_API_ORIGIN = 'https://www.emiliaprotocol.ai';
const APP_ID = /^[A-Za-z0-9:_.@-]{3,256}$/;
const PAIRING_CODE = /^[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$/;
const MAX_JSON_CHARS = 128 * 1024;

type FetchImpl = typeof fetch;

function endpoint(path: string): string {
  if (!path.startsWith('/api/v1/mobile/')) throw new Error('mobile_endpoint_required');
  return `${MOBILE_API_ORIGIN}${path}`;
}

async function readBoundedJson(response: Response, label: string): Promise<any> {
  const contentType = response.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/json' && contentType !== 'application/problem+json') {
    throw new Error(`${label}: server did not return JSON`);
  }
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_JSON_CHARS) {
    throw new Error(`${label}: response too large`);
  }
  const text = await response.text();
  if (text.length > MAX_JSON_CHARS) throw new Error(`${label}: response too large`);
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`${label}: malformed JSON response`);
  }
  if (!response.ok) throw new Error(`${label}: HTTP ${response.status}`);
  return value;
}

function pairedHeaders(session: PairedSession): Record<string, string> {
  return authorizationHeadersForSession(session) as Record<string, string>;
}

export async function exchangeMobilePairing({
  pairingCode,
  platform,
  appId,
  identityAssertion,
  fetchImpl = fetch,
}: {
  pairingCode: string;
  platform: 'ios' | 'android';
  appId: string;
  identityAssertion: Record<string, unknown>;
  fetchImpl?: FetchImpl;
}): Promise<PairedSession> {
  const normalizedCode = pairingCode.trim().toUpperCase();
  if (!PAIRING_CODE.test(normalizedCode) || !['ios', 'android'].includes(platform) || !APP_ID.test(appId)) {
    throw new Error('invalid_pairing_input');
  }
  if (!identityAssertion || typeof identityAssertion !== 'object' || Array.isArray(identityAssertion)
      || typeof identityAssertion.id !== 'string' || !identityAssertion.id) {
    throw new Error('pairing_identity_assertion_required');
  }
  const response = await fetchImpl(endpoint('/api/v1/mobile/pairings/exchange'), {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      pairing_code: normalizedCode,
      platform,
      app_id: appId,
      identity_assertion: identityAssertion,
    }),
    redirect: 'error',
    credentials: 'omit',
  });
  const body = await readBoundedJson(response, 'pairing exchange');
  const session = validatePairedSession({
    accessToken: body?.access_token,
    expiresAt: body?.expires_at,
    approverId: body?.approver_id,
    profileId: body?.profile_id,
    platform,
    appId,
  });
  if (!session || body?.token_type !== 'Bearer') throw new Error('pairing exchange: invalid session response');
  return session as PairedSession;
}

export async function fetchMobileInbox({
  session,
  fetchImpl = fetch,
}: {
  session: PairedSession;
  fetchImpl?: FetchImpl;
}): Promise<{ approver_id: string; actions: any[] }> {
  const response = await fetchImpl(endpoint('/api/v1/mobile/inbox'), {
    method: 'GET',
    headers: { accept: 'application/json', ...pairedHeaders(session) },
    redirect: 'error',
    credentials: 'omit',
  });
  const body = await readBoundedJson(response, 'mobile inbox');
  if (body?.approver_id !== session.approverId || !Array.isArray(body?.actions)) {
    throw new Error('mobile inbox: response is not bound to the paired approver');
  }
  return body;
}

/**
 * Begin the server-authorized enrollment ceremony for a future native signer.
 * This Expo build intentionally does not implement completion because its
 * dependencies cannot produce platform WebAuthn plus App Attest/Play evidence.
 */
export async function requestTrustedEnrollmentChallenge({
  session,
  fetchImpl = fetch,
}: {
  session: PairedSession;
  fetchImpl?: FetchImpl;
}): Promise<any> {
  const response = await fetchImpl(endpoint('/api/v1/mobile/enrollments/challenges'), {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      ...pairedHeaders(session),
    },
    body: JSON.stringify({
      approver_id: session.approverId,
      platform: session.platform,
      app_id: session.appId,
    }),
    redirect: 'error',
    credentials: 'omit',
  });
  return readBoundedJson(response, 'enrollment challenge');
}

export async function revokeMobileSession({
  session,
  fetchImpl = fetch,
}: {
  session: PairedSession;
  fetchImpl?: FetchImpl;
}): Promise<void> {
  const response = await fetchImpl(endpoint('/api/v1/mobile/session'), {
    method: 'DELETE',
    headers: { accept: 'application/json', ...pairedHeaders(session) },
    redirect: 'error',
    credentials: 'omit',
  });
  if (!response.ok) throw new Error(`session revocation: HTTP ${response.status}`);
}
