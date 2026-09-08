// SPDX-License-Identifier: Apache-2.0
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import AccountRoute, { metadata } from '../app/works/account/page';
import AccountPage, { requestWorksLogout, projectAccountIdentity } from '../app/works/account/AccountPage';

vi.mock('next/navigation', () => ({ notFound: () => { throw new Error('WORKS_NOT_FOUND'); } }));
afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); });

describe('Works account landing route', () => {
  it('registers a real gated route with no private SSR and no indexing', () => {
    vi.stubEnv('WORKS_V0', '0'); expect(() => AccountRoute()).toThrow('WORKS_NOT_FOUND');
    vi.stubEnv('WORKS_V0', '1'); vi.stubEnv('RESEND_API_KEY', '');
    const html = renderToStaticMarkup(AccountRoute());
    expect(metadata.robots).toEqual({ index: false, follow: false });
    expect(html).toContain('main-content'); expect(html).toContain('Your Works account.');
    expect(html).toContain('/works/workspace'); expect(html).toContain('/legal/privacy'); expect(html).toContain('/legal/terms');
    expect(html).not.toMatch(/RESEND_API_KEY|WORKS_ACCOUNT_HMAC_SECRET|SUPABASE_SERVICE_ROLE_KEY|type="password"/);
  });
  it('does not advertise a working email form when the provider is not configured', () => {
    const html = renderToStaticMarkup(createElement(AccountPage, { signInAvailable: false }));
    expect(html).toContain('Email sign-in is temporarily unavailable.');
    expect(html).toContain('/works/join'); expect(html).not.toContain('Email me a code');
  });
  it('enables email sign-in from server configuration without exposing private values', () => {
    vi.stubEnv('WORKS_V0', '1'); vi.stubEnv('RESEND_API_KEY', 'test-provider-key');
    vi.stubEnv('WORKS_ACCOUNT_HMAC_SECRET', 'x'.repeat(32));
    vi.stubEnv('NEXT_PUBLIC_SUPABASE_URL', 'https://database.example'); vi.stubEnv('SUPABASE_SERVICE_ROLE_KEY', 'test-service-key');
    const configured = renderToStaticMarkup(AccountRoute());
    expect(configured).not.toContain('Email sign-in is temporarily unavailable.');
    expect(configured).not.toMatch(/test-provider-key|test-service-key|database\.example/);
    vi.stubEnv('WORKS_ACCOUNT_HMAC_SECRET', 'too-short');
    expect(renderToStaticMarkup(AccountRoute())).toContain('Email sign-in is temporarily unavailable.');
  });
  it('checks the session before displaying an identity and clears private form state in the background', () => {
    const html = renderToStaticMarkup(createElement(AccountPage, { signInAvailable: true }));
    expect(html).toContain('Checking your account'); expect(html).not.toContain('Signed in as');
    const source = readFileSync(new URL('../app/works/account/AccountPage.tsx', import.meta.url), 'utf8');
    expect(source).toContain('useWorksAccount()'); expect(source).toContain('AccountForm');
    expect(source).toContain("document.visibilityState === 'hidden'");
    expect(source).toContain("window.addEventListener('pagehide'"); expect(source).toContain("window.addEventListener('pageshow'");
    expect(source).not.toMatch(/localStorage|sessionStorage|URLSearchParams|console\./);
    const form = readFileSync(new URL('../app/works/account/AccountForm.tsx', import.meta.url), 'utf8');
    expect(form).toContain('useEffect(() => () => { active.current?.abort(); }, [])');
    expect(form).toContain("account.claimsVerified !== false || typeof account.emailNotifications !== 'boolean'");
  });
});

describe('exact session actions', () => {
  it('accepts only a bounded public account without claiming verified agent capabilities', () => {
    expect(projectAccountIdentity({ displayName: 'A builder', claimsVerified: false, emailNotifications: false, secret: 'not-public' }))
      .toEqual({ displayName: 'A builder', claimsVerified: false, emailNotifications: false });
    for (const value of [null, {}, { displayName: 'A builder', claimsVerified: true, emailNotifications: false },
      { displayName: '', claimsVerified: false, emailNotifications: false }]) expect(() => projectAccountIdentity(value)).toThrow();
  });
  it('uses a session-only JSON POST and requires the exact 204 logout response', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(null, { status: 204 })); vi.stubGlobal('fetch', fetcher);
    await requestWorksLogout(new AbortController().signal);
    expect(fetcher).toHaveBeenCalledWith('/api/works/account/logout', expect.objectContaining({ method: 'POST', body: '{}',
      headers: { 'content-type': 'application/json' }, credentials: 'same-origin', redirect: 'error', cache: 'no-store' }));
  });
  it.each([200, 202, 400, 401, 403, 503])('does not treat HTTP %i as a confirmed logout', async status => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status })));
    await expect(requestWorksLogout(new AbortController().signal)).rejects.toThrow('account_logout_unconfirmed');
  });
  it('does not confirm an aborted logout after headers arrive', async () => {
    const controller = new AbortController();
    vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => { controller.abort(); return new Response(null, { status: 204 }); }));
    await expect(requestWorksLogout(controller.signal)).rejects.toThrow();
  });
});
