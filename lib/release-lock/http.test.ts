// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  protectReleaseLockResponse,
  releaseLockCookieName,
  releaseLockId,
  releaseLockJson,
  releaseLockProblem,
  releaseLockRound,
  releaseLockSessionCookie,
  readReleaseLockJson,
  requireReleaseLockSameOrigin,
  setReleaseLockSessionCookie,
} from './http.js';
import { createReleaseLockCrypto } from './crypto.js';
import { releaseLockRefusal } from './errors.js';

const LOCK_A = `rlk_${'a'.repeat(32)}`;
const LOCK_B = `rlk_${'b'.repeat(32)}`;

function suite() {
  return createReleaseLockCrypto({
    tokenKey: Buffer.alloc(32, 1),
    contactKey: Buffer.alloc(32, 2),
    authorityKeys: {},
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

  it('accepts exact same-origin mutations and skips Origin only for safe methods', () => {
    const session = suite().session();
    const cookie = `${releaseLockCookieName(LOCK_A)}=${session.token}`;
    const mutation = new Request('https://www.emiliaprotocol.ai/api/v1/release-locks/x', {
      method: 'POST',
      headers: {
        cookie,
        origin: 'https://www.emiliaprotocol.ai',
        'sec-fetch-site': 'same-origin',
      },
    });
    expect(requireReleaseLockSameOrigin(mutation)).toBeUndefined();
    expect(releaseLockSessionCookie(mutation, LOCK_A)).toBe(session.token);

    const safe = new Request('https://www.emiliaprotocol.ai/api/v1/release-locks/x', {
      method: 'GET',
      headers: { cookie },
    });
    expect(releaseLockSessionCookie(safe, LOCK_A)).toBe(session.token);
  });

  it('refuses missing, malformed, or fetch-site-confused origins', () => {
    for (const headers of [
      {},
      { origin: 'not a URL' },
      {
        origin: 'https://www.emiliaprotocol.ai',
        'sec-fetch-site': 'cross-site',
      },
    ]) {
      const request = new Request(
        'https://www.emiliaprotocol.ai/api/v1/release-locks/x',
        { method: 'POST', headers },
      );
      expect(() => requireReleaseLockSameOrigin(request)).toThrow(
        expect.objectContaining({ status: 403, code: 'release_lock_origin_denied' }),
      );
    }
  });

  it('refuses missing, malformed, and ambiguously parsed session cookies', () => {
    const cookieName = releaseLockCookieName(LOCK_A);
    for (const cookie of [
      '',
      `${cookieName}=invalid`,
      `no-separator; ${cookieName}`,
      `${cookieName}=invalid; ${cookieName}=invalid`,
    ]) {
      const request = new Request('https://example.com', {
        headers: cookie ? { cookie } : {},
      });
      expect(() => releaseLockSessionCookie(request, LOCK_A)).toThrow(
        expect.objectContaining({ status: 401, code: 'session_invalid' }),
      );
    }
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

  it('types identifiers and both round spellings at the HTTP boundary', () => {
    expect(releaseLockId(LOCK_A)).toBe(LOCK_A);
    for (const invalid of [null, '', 'rlk_bad', `rlk_${'A'.repeat(32)}`]) {
      expect(() => releaseLockId(invalid)).toThrow(
        expect.objectContaining({ code: 'invalid_release_lock_id' }),
      );
    }
    expect(releaseLockRound('co-accepted')).toBe('CO_ACCEPTED');
    expect(releaseLockRound('CO_ACCEPTED')).toBe('CO_ACCEPTED');
    expect(releaseLockRound('draw-release')).toBe('DRAW_RELEASE');
    expect(releaseLockRound('DRAW_RELEASE')).toBe('DRAW_RELEASE');
    expect(() => releaseLockRound('pay-now')).toThrow(
      expect.objectContaining({ code: 'invalid_release_lock_round' }),
    );
  });

  it('never sets an invalid raw session capability', () => {
    expect(() => setReleaseLockSessionCookie(
      releaseLockJson({ ok: true }),
      'invalid',
      '2030-01-01T00:00:00.000Z',
      LOCK_A,
    )).toThrow('Release Lock session token is invalid');
  });

  it('accepts only JSON objects under the common body limit', async () => {
    await expect(readReleaseLockJson(new Request('https://example.com', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ lock_id: LOCK_A }),
    }))).resolves.toEqual({ lock_id: LOCK_A });

    await expect(readReleaseLockJson(new Request('https://example.com', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '[]',
    }))).rejects.toMatchObject({ status: 400, code: 'invalid_request' });

    await expect(readReleaseLockJson(new Request('https://example.com', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{',
    }))).rejects.toMatchObject({ status: 400 });
  });

  it('redacts internal Release Lock failures and normalizes unknown errors', async () => {
    const hidden = releaseLockProblem(releaseLockRefusal(
      503,
      'release_lock_storage_unavailable',
      'database host secret',
      { expose: false },
    ));
    expect(hidden.status).toBe(503);
    await expect(hidden.json()).resolves.toMatchObject({
      detail: 'The Release Lock service is temporarily unavailable.',
    });

    const unknown = releaseLockProblem(new Error('secret stack detail'));
    expect(unknown.status).toBe(500);
    await expect(unknown.json()).resolves.toMatchObject({
      type: 'https://emiliaprotocol.ai/errors/release_lock_internal_error',
      detail: 'The Release Lock request failed due to a server-side error.',
    });
  });
});
