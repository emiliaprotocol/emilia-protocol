// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  start: vi.fn(), verify: vi.fn(), getActor: vi.fn(), revoke: vi.fn(), email: vi.fn(),
}));

vi.mock('@/lib/works/account-store', () => ({ createSupabaseWorksAccountStore: () => ({ store: true }) }));
vi.mock('@/lib/works/account-email', () => ({ sendWorksAccountCodeEmail: mocks.email }));
vi.mock('@/lib/works/account-service', async original => {
  const actual = await original<typeof import('../lib/works/account-service.ts')>();
  return { ...actual, startWorksAccountChallenge: mocks.start, verifyWorksAccountChallenge: mocks.verify };
});
vi.mock('@/lib/works/session', async original => {
  const actual = await original<typeof import('../lib/works/session.ts')>();
  return { ...actual, getWorksSessionActor: mocks.getActor, revokeWorksSession: mocks.revoke };
});
vi.mock('@/lib/rate-limit', async original => {
  const actual = await original<typeof import('../lib/rate-limit.ts')>();
  return { ...actual, getClientIP: () => '203.0.113.9' };
});

const startRoute = await import('../app/api/works/account/start/route.ts');
const verifyRoute = await import('../app/api/works/account/verify/route.ts');
const sessionRoute = await import('../app/api/works/account/session/route.ts');
const logoutRoute = await import('../app/api/works/account/logout/route.ts');

const ORIGIN = 'https://works.emiliaprotocol.ai';
const ACTOR = {
  accountId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  ownerEntityId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  displayName: 'Avery Chen', emailVerified: true as const, emailNotifications: false,
  claimsVerified: false as const, authMethod: 'email_code' as const,
};

function post(url: string, body: unknown, origin = ORIGIN) {
  return new Request(`${ORIGIN}${url}`, {
    method: 'POST', body: JSON.stringify(body),
    headers: { 'content-type': 'application/json', origin, 'sec-fetch-site': 'same-origin' },
  });
}

beforeEach(() => {
  vi.stubEnv('WORKS_V0', '1');
  vi.stubEnv('WORKS_PUBLIC_ORIGIN', ORIGIN);
  vi.stubEnv('WORKS_ACCOUNT_HMAC_SECRET', 's'.repeat(64));
  for (const mock of Object.values(mocks)) mock.mockReset();
  mocks.start.mockResolvedValue({ accepted: true, challengeId: '11111111-1111-4111-8111-111111111111' });
  mocks.verify.mockResolvedValue({ actor: ACTOR, sessionToken: `wss1_${'a'.repeat(64)}`, sessionExpiresAt: new Date('2026-09-14T00:00:00Z') });
  mocks.getActor.mockResolvedValue(ACTOR);
  mocks.revoke.mockResolvedValue(true);
});

describe('Works account routes', () => {
  it('checks the feature flag and pinned origin before accepting account input', async () => {
    vi.stubEnv('WORKS_V0', '0');
    expect((await startRoute.POST(post('/api/works/account/start', { email: 'a@example.com' }) as any)).status).toBe(404);
    vi.stubEnv('WORKS_V0', '1');
    const hostile = await startRoute.POST(post('/api/works/account/start', { email: 'a@example.com' }, 'https://attacker.example') as any);
    expect(hostile.status).toBe(403);
    expect(mocks.start).not.toHaveBeenCalled();
  });

  it('starts signup without echoing email, code or delivery state', async () => {
    const response = await startRoute.POST(post('/api/works/account/start', {
      email: 'avery@example.com', name: 'Avery Chen', consent: true,
    }) as any);
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ accepted: true, challengeId: '11111111-1111-4111-8111-111111111111' });
    expect(mocks.start).toHaveBeenCalledWith(expect.objectContaining({
      input: { email: 'avery@example.com', name: 'Avery Chen', consent: true, emailNotifications: undefined },
      clientAddress: '203.0.113.9', secret: 's'.repeat(64), sendEmail: mocks.email,
    }));
  });

  it('rejects valid JSON that is not one account request object without calling storage', async () => {
    const response = await startRoute.POST(post('/api/works/account/start', null) as any);
    expect(response.status).toBe(400);
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(mocks.start).not.toHaveBeenCalled();
  });

  it('atomically verifies a typed code and sets only the hardened session cookie', async () => {
    const response = await verifyRoute.POST(post('/api/works/account/verify', {
      email: 'avery@example.com', challengeId: '11111111-1111-4111-8111-111111111111', code: '123456',
    }) as any);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ authenticated: true, account: {
      displayName: 'Avery Chen', claimsVerified: false, emailNotifications: false,
    } });
    const cookie = response.headers.get('set-cookie') || '';
    expect(cookie).toContain('__Host-emilia_works_session=wss1_');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('SameSite=Strict');
    expect(JSON.stringify(await Promise.resolve(response.headers))).not.toContain(ACTOR.ownerEntityId);
  });

  it('returns a least-disclosure session view and never exposes account identity or email', async () => {
    const response = await sessionRoute.GET(new Request(`${ORIGIN}/api/works/account/session`) as any);
    expect(await response.json()).toEqual({ authenticated: true, account: {
      displayName: 'Avery Chen', claimsVerified: false, emailNotifications: false,
    } });
    const text = await (await sessionRoute.GET(new Request(`${ORIGIN}/api/works/account/session`) as any)).text();
    expect(text).not.toContain(ACTOR.accountId);
    expect(text).not.toContain(ACTOR.ownerEntityId);
    expect(text).not.toContain('@');
  });

  it('revokes server-side before expiring the browser cookie', async () => {
    const response = await logoutRoute.POST(post('/api/works/account/logout', {}) as any);
    expect(response.status).toBe(204);
    expect(mocks.revoke).toHaveBeenCalledOnce();
    expect(response.headers.get('set-cookie')).toContain('Max-Age=0');
  });
});
