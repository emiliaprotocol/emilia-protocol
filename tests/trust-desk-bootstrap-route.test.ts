// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';

const mockRpc = vi.fn();

vi.mock('@/lib/supabase', () => ({
  getServiceClient: () => ({ rpc: (...args: unknown[]) => mockRpc(...args) }),
}));

import * as bootstrapRoute from '../app/internal/trust-desk/auth/route.js';

describe('STRIX-18 Trust Desk bootstrap transport', () => {
  beforeEach(() => {
    mockRpc.mockReset();
    vi.stubEnv('TRUST_DESK_INTERNAL_TOKEN', 'bootstrap-secret');
    vi.stubEnv('TRUST_DESK_SESSION_SECRET', 'independent-session-signing-secret');
    vi.stubEnv('TRUST_DESK_REVIEWER_ID', 'Iman Schrock <team@emiliaprotocol.ai>');
  });

  afterEach(() => vi.unstubAllEnvs());

  it('never accepts a bootstrap bearer from the URL query', async () => {
    mockRpc.mockResolvedValue({ data: { consumed: true }, error: null });
    const request = new NextRequest(
      'https://www.emiliaprotocol.ai/internal/trust-desk/auth?token=bootstrap-secret',
    );

    const response = await bootstrapRoute.GET(request);

    expect(response.status).toBe(303);
    expect(response.headers.get('location')).toBe(
      'https://www.emiliaprotocol.ai/internal/trust-desk/auth',
    );
    expect(response.headers.get('set-cookie')).toBeNull();
    expect(mockRpc).not.toHaveBeenCalled();
  });

  it('renders a no-store sign-in form at the clean URL', async () => {
    const response = await bootstrapRoute.GET(new NextRequest(
      'https://www.emiliaprotocol.ai/internal/trust-desk/auth',
    ));

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    const html = await response.text();
    expect(html).toContain('method="post"');
    expect(html).toContain('name="bootstrap_token"');
    expect(html).not.toContain('bootstrap-secret');
    expect(html).not.toContain('?token=');
  });

  it('exchanges a bounded same-origin POST body for the reviewer session', async () => {
    expect(typeof (bootstrapRoute as any).POST).toBe('function');
    mockRpc.mockResolvedValue({ data: { consumed: true }, error: null });
    const request = new NextRequest(
      'https://www.emiliaprotocol.ai/internal/trust-desk/auth',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          origin: 'https://www.emiliaprotocol.ai',
        },
        body: new URLSearchParams({ bootstrap_token: 'bootstrap-secret' }).toString(),
      },
    );

    const response = await (bootstrapRoute as any).POST(request);

    expect(response.status).toBe(303);
    expect(response.headers.get('location')).toBe(
      'https://www.emiliaprotocol.ai/internal/trust-desk',
    );
    const setCookie = response.headers.get('set-cookie') || '';
    expect(setCookie).toContain('td_internal=tds1.');
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie.toLowerCase()).toContain('samesite=strict');
    expect(setCookie).not.toContain('bootstrap-secret');
    expect(mockRpc).toHaveBeenCalledWith(
      'consume_trust_desk_bootstrap_atomic',
      {
        p_token_hash: crypto
          .createHash('sha256')
          .update('bootstrap-secret', 'utf8')
          .digest('hex'),
      },
    );
  });

  it('rejects cross-origin bootstrap submissions before token comparison or consumption', async () => {
    expect(typeof (bootstrapRoute as any).POST).toBe('function');
    const request = new NextRequest(
      'https://www.emiliaprotocol.ai/internal/trust-desk/auth',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          origin: 'https://attacker.example',
        },
        body: new URLSearchParams({ bootstrap_token: 'bootstrap-secret' }).toString(),
      },
    );

    const response = await (bootstrapRoute as any).POST(request);

    expect(response.status).toBe(403);
    expect(response.headers.get('set-cookie')).toBeNull();
    expect(mockRpc).not.toHaveBeenCalled();
  });

  it('rejects oversized form bodies before token comparison or consumption', async () => {
    expect(typeof (bootstrapRoute as any).POST).toBe('function');
    const request = new NextRequest(
      'https://www.emiliaprotocol.ai/internal/trust-desk/auth',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          origin: 'https://www.emiliaprotocol.ai',
        },
        body: new URLSearchParams({ bootstrap_token: 'x'.repeat(5000) }).toString(),
      },
    );

    const response = await (bootstrapRoute as any).POST(request);

    expect(response.status).toBe(413);
    expect(response.headers.get('set-cookie')).toBeNull();
    expect(mockRpc).not.toHaveBeenCalled();
  });
});
