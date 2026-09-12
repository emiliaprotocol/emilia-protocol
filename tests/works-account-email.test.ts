// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe('Works account email delivery', () => {
  it('fails closed without a server-side provider key and does not call the network', async () => {
    vi.stubEnv('RESEND_API_KEY', '');
    const fetcher = vi.fn();
    vi.stubGlobal('fetch', fetcher);
    const { sendWorksAccountCodeEmail } = await import('../lib/works/account-email.ts');
    await expect(sendWorksAccountCodeEmail({ to: 'avery@example.com', code: '123456' }))
      .resolves.toEqual({ delivered: false });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('sends only the typed one-time code through the configured Resend sender', async () => {
    vi.stubEnv('RESEND_API_KEY', 're_test_secret');
    vi.stubEnv('WORKS_FROM_EMAIL', 'EMILIA Works <accounts@example.com>');
    const fetcher = vi.fn(async () => new Response(null, { status: 202 }));
    vi.stubGlobal('fetch', fetcher);
    const { sendWorksAccountCodeEmail } = await import('../lib/works/account-email.ts');
    await expect(sendWorksAccountCodeEmail({ to: 'avery@example.com', code: '123456' }))
      .resolves.toEqual({ delivered: true });

    expect(fetcher).toHaveBeenCalledOnce();
    const [url, options] = fetcher.mock.calls[0];
    expect(url).toBe('https://api.resend.com/emails');
    expect(options).toMatchObject({
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer re_test_secret' },
    });
    const body = JSON.parse(String(options.body));
    expect(body).toEqual(expect.objectContaining({
      from: 'EMILIA Works <accounts@example.com>',
      to: 'avery@example.com',
      subject: 'Your EMILIA Works sign-in code',
    }));
    expect(body.text).toContain('123456');
    expect(body.text).toContain('expires in 10 minutes');
  });

  it('reports unavailable delivery for provider refusal or a timed-out request', async () => {
    vi.stubEnv('RESEND_API_KEY', 're_test_secret');
    const fetcher = vi.fn()
      .mockResolvedValueOnce(new Response(null, { status: 429 }))
      .mockRejectedValueOnce(new DOMException('timed out', 'TimeoutError'));
    vi.stubGlobal('fetch', fetcher);
    const { sendWorksAccountCodeEmail } = await import('../lib/works/account-email.ts');
    await expect(sendWorksAccountCodeEmail({ to: 'avery@example.com', code: '123456' }))
      .resolves.toEqual({ delivered: false });
    await expect(sendWorksAccountCodeEmail({ to: 'avery@example.com', code: '654321' }))
      .resolves.toEqual({ delivered: false });
  });
});
