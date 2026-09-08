// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from 'vitest';

const rpc = vi.hoisted(() => vi.fn());
vi.mock('@/lib/supabase', () => ({ getServiceClient: () => ({ rpc }) }));

const {
  WORKS_SESSION_COOKIE_NAME,
  WorksSessionUnavailableError,
  assertWorksSameOrigin,
  clearWorksSessionCookieHeader,
  getWorksSessionActor,
  revokeWorksSession,
  serializeWorksSessionCookie,
} = await import('../lib/works/session.ts');

afterEach(() => {
  vi.unstubAllEnvs();
  rpc.mockReset();
});

describe('Works account session boundary', () => {
  it('uses one host-only secure HttpOnly strict cookie and emits a deletion with the same scope', () => {
    expect(WORKS_SESSION_COOKIE_NAME).toBe('__Host-emilia_works_session');
    const set = serializeWorksSessionCookie(`wss1_${'a'.repeat(64)}`, new Date('2026-09-08T00:00:00Z'));
    expect(set).toContain(`${WORKS_SESSION_COOKIE_NAME}=wss1_`);
    expect(set).toContain('Path=/');
    expect(set).toContain('HttpOnly');
    expect(set).toContain('Secure');
    expect(set).toContain('SameSite=Strict');
    expect(set).not.toMatch(/Domain=/i);
    expect(clearWorksSessionCookieHeader()).toContain('Max-Age=0');
  });

  it('pins mutation origin to configuration and never trusts Host or request URL', () => {
    vi.stubEnv('WORKS_PUBLIC_ORIGIN', 'https://works.emiliaprotocol.ai');
    const headers = new Headers({ origin: 'https://works.emiliaprotocol.ai', 'sec-fetch-site': 'same-origin', host: 'attacker.example' });
    expect(assertWorksSameOrigin(new Request('https://attacker.example/api/works/account/start', { method: 'POST', headers }))).toBe(true);
    headers.set('origin', 'https://attacker.example');
    expect(assertWorksSameOrigin(new Request('https://works.emiliaprotocol.ai/api/works/account/start', { method: 'POST', headers }))).toBe(false);
    headers.set('origin', 'https://works.emiliaprotocol.ai');
    headers.set('sec-fetch-site', 'cross-site');
    expect(assertWorksSameOrigin(new Request('https://works.emiliaprotocol.ai/api/works/account/start', { method: 'POST', headers }))).toBe(false);
    vi.stubEnv('WORKS_PUBLIC_ORIGIN', 'ftp://localhost');
    headers.set('origin', 'ftp://localhost');
    headers.set('sec-fetch-site', 'same-origin');
    expect(assertWorksSameOrigin(new Request('https://works.emiliaprotocol.ai/api/works/account/start', { method: 'POST', headers }))).toBe(false);
    headers.delete('origin');
    headers.delete('sec-fetch-site');
    expect(assertWorksSameOrigin(new Request('https://works.emiliaprotocol.ai/api/works/account/start', { method: 'POST', headers }))).toBe(false);
  });

  it('rejects malformed, duplicate and bearer-only cookies before storage', async () => {
    for (const cookie of [
      '',
      `${WORKS_SESSION_COOKIE_NAME}=not-a-token`,
      `${WORKS_SESSION_COOKIE_NAME}=wss1_${'a'.repeat(64)}; ${WORKS_SESSION_COOKIE_NAME}=wss1_${'b'.repeat(64)}`,
      `other=wss1_${'a'.repeat(64)}`,
    ]) {
      await expect(getWorksSessionActor({ headers: new Headers({ cookie, authorization: 'Bearer ep_live_not_a_session' }) })).resolves.toBeNull();
    }
    expect(rpc).not.toHaveBeenCalled();
  });

  it('hashes the cookie before an exact server-side active-session lookup', async () => {
    rpc.mockResolvedValueOnce({ data: {
      account_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      owner_entity_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      display_name: 'Avery Chen', email_notifications: false,
    }, error: null });
    const token = `wss1_${'a'.repeat(64)}`;
    await expect(getWorksSessionActor({ headers: new Headers({ cookie: `${WORKS_SESSION_COOKIE_NAME}=${token}` }) })).resolves.toMatchObject({
      displayName: 'Avery Chen', emailVerified: true, claimsVerified: false, authMethod: 'email_code',
    });
    expect(rpc).toHaveBeenCalledWith('read_works_account_session', {
      p_session_token_digest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
    });
    expect(JSON.stringify(rpc.mock.calls)).not.toContain(token);
  });

  it('distinguishes an invalid session from unavailable storage without leaking its error', async () => {
    rpc.mockResolvedValueOnce({ data: null, error: null });
    const request = { headers: new Headers({ cookie: `${WORKS_SESSION_COOKIE_NAME}=wss1_${'a'.repeat(64)}` }) };
    await expect(getWorksSessionActor(request)).resolves.toBeNull();
    rpc.mockRejectedValueOnce(new Error('PRIVATE_DATABASE_DETAIL'));
    await expect(getWorksSessionActor(request)).rejects.toBeInstanceOf(WorksSessionUnavailableError);
  });

  it('revokes only one well-formed cookie and sends storage only its digest', async () => {
    const token = `wss1_${'a'.repeat(64)}`;
    const request = { headers: new Headers({ cookie: `${WORKS_SESSION_COOKIE_NAME}=${token}` }) };
    const revokeSession = vi.fn(async () => ({ ok: true as const, revoked: true }));
    await expect(revokeWorksSession(request, {
      readSession: vi.fn(), beginChallenge: vi.fn(), markDelivery: vi.fn(), exchangeChallenge: vi.fn(), revokeSession,
    } as any)).resolves.toBe(true);
    expect(revokeSession).toHaveBeenCalledWith(expect.stringMatching(/^sha256:[a-f0-9]{64}$/));
    expect(JSON.stringify(revokeSession.mock.calls)).not.toContain(token);

    revokeSession.mockClear();
    await expect(revokeWorksSession({ headers: new Headers() }, { revokeSession } as any)).resolves.toBe(false);
    expect(revokeSession).not.toHaveBeenCalled();
  });

  it('fails closed when session revocation storage throws or returns an error', async () => {
    const request = { headers: new Headers({
      cookie: `${WORKS_SESSION_COOKIE_NAME}=wss1_${'a'.repeat(64)}`,
    }) };
    await expect(revokeWorksSession(request, {
      revokeSession: vi.fn(async () => { throw new Error('private transport detail'); }),
    } as any)).rejects.toBeInstanceOf(WorksSessionUnavailableError);
    await expect(revokeWorksSession(request, {
      revokeSession: vi.fn(async () => ({ ok: false as const, code: 'store_unavailable' })),
    } as any)).rejects.toBeInstanceOf(WorksSessionUnavailableError);
  });

  it('refuses malformed cookie serialization inputs', () => {
    expect(() => serializeWorksSessionCookie('not-a-session', new Date('2026-09-08T00:00:00Z')))
      .toThrow(WorksSessionUnavailableError);
    expect(() => serializeWorksSessionCookie(`wss1_${'a'.repeat(64)}`, new Date('invalid')))
      .toThrow(WorksSessionUnavailableError);
  });

  it('accepts only exact HTTPS origins or HTTP loopback development origins', () => {
    for (const origin of ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://[::1]:3000']) {
      vi.stubEnv('WORKS_PUBLIC_ORIGIN', origin);
      expect(assertWorksSameOrigin({ headers: new Headers({ origin }) })).toBe(true);
    }
    vi.stubEnv('WORKS_PUBLIC_ORIGIN', 'https://works.emiliaprotocol.ai/path');
    expect(assertWorksSameOrigin({ headers: new Headers({ origin: 'https://works.emiliaprotocol.ai' }) })).toBe(false);
    vi.stubEnv('WORKS_PUBLIC_ORIGIN', 'not-a-url');
    expect(assertWorksSameOrigin({ headers: new Headers({ origin: 'https://works.emiliaprotocol.ai' }) })).toBe(false);
    vi.stubEnv('WORKS_PUBLIC_ORIGIN', 'https://works.emiliaprotocol.ai');
    expect(assertWorksSameOrigin({ headers: new Headers({ origin: 'not a URL' }) })).toBe(false);
  });

  it('turns an injected session-store exception into the public unavailable error', async () => {
    const request = { headers: new Headers({
      cookie: `${WORKS_SESSION_COOKIE_NAME}=wss1_${'a'.repeat(64)}`,
    }) };
    await expect(getWorksSessionActor(request, {
      readSession: vi.fn(async () => { throw new Error('private database detail'); }),
    } as any)).rejects.toBeInstanceOf(WorksSessionUnavailableError);
  });
});
