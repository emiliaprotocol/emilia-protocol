// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from 'vitest';
import { POST } from '../app/api/checkout/route.js';

afterEach(() => {
  vi.unstubAllEnvs();
});

function req(url, body = { plan: 'team' }) {
  return new Request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('POST /api/checkout — host-header hardening', () => {
  it('fails closed in production when canonical origin is not configured', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('STRIPE_SECRET_KEY', 'sk_test_fake');
    vi.stubEnv('STRIPE_PRICE_CLOUD_TEAM', 'price_fake');
    vi.stubEnv('NEXT_PUBLIC_APP_URL', '');
    vi.stubEnv('NEXT_PUBLIC_SITE_URL', '');

    const res = await POST(req('https://attacker.example/api/checkout'));
    const body = await res.json();

    expect(res.status).toBe(503);
    expect(body.type).toContain('checkout_origin_unconfigured');
  });

  it('rejects non-HTTPS canonical checkout origins in production', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('STRIPE_SECRET_KEY', 'sk_test_fake');
    vi.stubEnv('STRIPE_PRICE_CLOUD_TEAM', 'price_fake');
    vi.stubEnv('NEXT_PUBLIC_APP_URL', 'http://www.emiliaprotocol.ai');
    vi.stubEnv('NEXT_PUBLIC_SITE_URL', '');

    const res = await POST(req('https://www.emiliaprotocol.ai/api/checkout'));
    const body = await res.json();

    expect(res.status).toBe(503);
    expect(body.type).toContain('checkout_origin_unconfigured');
  });
});
