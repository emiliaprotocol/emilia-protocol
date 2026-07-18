// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  protectReleaseLockResponse,
  releaseLockCookieName,
  releaseLockJson,
  releaseLockSessionCookie,
  requireReleaseLockSameOrigin,
  setReleaseLockSessionCookie,
} from './http.js';
import { createReleaseLockCrypto } from './crypto.js';

const LOCK_A = `rlk_${'a'.repeat(32)}`;
const LOCK_B = `rlk_${'b'.repeat(32)}`;

function suite() {
  return createReleaseLockCrypto({
    tokenKey: Buffer.alloc(32, 1),
    contactKey: Buffer.alloc(32, 2),
  });
}

describe('Release Lock HTTP capability boundary', () => {
  it('requires exactly one valid scoped session cookie', () => {
    const session = suite().session();
    const cookieName = releaseLockCookieName(LOCK_A);
    const request = new Request('https://example.com', {
      headers: {
        cookie: `${cookieName}=${session.token}`,
      },
    });
    expect(releaseLockSessionCookie(request, LOCK_A)).toBe(session.token);

    const duplicate = new Request('https://example.com', {
      headers: {
        cookie: `${cookieName}=${session.token}; ${cookieName}=${session.token}`,
      },
    });
    expect(() => releaseLockSessionCookie(duplicate, LOCK_A)).toThrowError(
      expect.objectContaining({ status: 401, code: 'session_invalid' }),
    );
  });

  it('isolates sessions for multiple locks in one browser', () => {
    const first = suite().session();
    const second = suite().session();
    const cookies = [
      `${releaseLockCookieName(LOCK_A)}=${first.token}`,
      `${releaseLockCookieName(LOCK_B)}=${second.token}`,
    ].join('; ');
    const request = new Request('https://example.com', {
      headers: { cookie: cookies },
    });

    expect(releaseLockSessionCookie(request, LOCK_A)).toBe(first.token);
    expect(releaseLockSessionCookie(request, LOCK_B)).toBe(second.token);
  });

  it('refuses cross-origin cookie-authenticated mutations', () => {
    const session = suite().session();
    const request = new Request('https://www.emiliaprotocol.ai/api/v1/release-locks/x', {
      method: 'POST',
      headers: {
        cookie: `${releaseLockCookieName(LOCK_A)}=${session.token}`,
        origin: 'https://attacker.emiliaprotocol.ai',
        'sec-fetch-site': 'same-site',
      },
    });

    expect(() => releaseLockSessionCookie(request, LOCK_A)).toThrowError(
      expect.objectContaining({
        status: 403,
        code: 'release_lock_origin_denied',
      }),
    );
    expect(() => requireReleaseLockSameOrigin(request)).toThrowError(
      expect.objectContaining({ code: 'release_lock_origin_denied' }),
    );
  });

  it('sets HttpOnly Secure SameSite=Strict and privacy headers', () => {
    const session = suite().session();
    const response = setReleaseLockSessionCookie(
      releaseLockJson({ ok: true }),
      session.token,
      '2030-01-01T00:00:00.000Z',
      LOCK_A,
    );
    const cookie = response.headers.get('set-cookie');
    expect(cookie).toContain(`${releaseLockCookieName(LOCK_A)}=`);
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('SameSite=strict');
    expect(cookie).toContain('Path=/');
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
  });

  it('protects refusal responses identically', () => {
    const response = protectReleaseLockResponse(
      new Response('{}', { status: 409 }),
    );
    expect(response.status).toBe(409);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
  });
});
