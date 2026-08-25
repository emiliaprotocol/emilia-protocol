// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockCheckRateLimit = vi.fn();

vi.mock('@/lib/rate-limit', () => ({
  checkRateLimit: (...args) => mockCheckRateLimit(...args),
  getClientIP: () => '203.0.113.9',
  RATE_LIMITS: {
    submit: { max: 60, window: 60 },
    read: { max: 120, window: 60 },
    register: { max: 10, window: 60 },
    cloud_read: { max: 120, window: 60 },
  },
}));

vi.mock('@/lib/siem', () => ({
  siemEvent: vi.fn(),
}));

const { middleware } = await import('../middleware.ts');
const middlewareSource = readFileSync(new URL('../middleware.ts', import.meta.url), 'utf8');

function req(path, { method = 'POST', headers = {}, bodyBytes = null } = {}) {
  const url = `https://www.emiliaprotocol.ai${path}`;
  const base = {
    method,
    nextUrl: new URL(url),
    headers: new Headers(headers),
    body: null,
  };
  if (bodyBytes != null) {
    // A one-shot ReadableStream that emits `bodyBytes` in ~16KB chunks, mirroring
    // a chunked upload with no (or an understated) Content-Length. clone() returns
    // an independent stream over the same bytes so the middleware can byte-count
    // it without disturbing the (mock) original.
    const makeStream = () => new ReadableStream({
      start(controller) {
        let sent = 0;
        const CHUNK = 16 * 1024;
        while (sent < bodyBytes) {
          const size = Math.min(CHUNK, bodyBytes - sent);
          controller.enqueue(new Uint8Array(size));
          sent += size;
        }
        controller.close();
      },
    });
    base.body = makeStream();
    base.clone = () => ({ body: makeStream() });
  }
  return base;
}

describe('middleware API body-size tripwire', () => {
  beforeEach(() => {
    mockCheckRateLimit.mockReset();
    mockCheckRateLimit.mockResolvedValue({ allowed: true, remaining: 59, reset: 60 });
  });

  it('meters declared oversized JSON API bodies before rejecting them', async () => {
    const res = await middleware(req('/api/receipt', {
      headers: {
        'content-type': 'application/json',
        'content-length': String(1024 * 1024 + 1),
      },
    }));

    expect(res.status).toBe(413);
    expect(mockCheckRateLimit).toHaveBeenCalledWith('203.0.113.9', 'submit');
    expect(await res.json()).toMatchObject({ code: 'payload_too_large', max_bytes: 1024 * 1024 });
  });

  it('keeps multipart upload envelope separate from JSON/API body cap', async () => {
    const allowed = await middleware(req('/api/trust-desk/intake', {
      headers: {
        'content-type': 'multipart/form-data; boundary=x',
        'content-length': String(2 * 1024 * 1024),
      },
    }));
    expect(allowed.status).not.toBe(413);
    expect(mockCheckRateLimit).toHaveBeenCalledOnce();

    mockCheckRateLimit.mockClear();
    const denied = await middleware(req('/api/trust-desk/intake', {
      headers: {
        'content-type': 'multipart/form-data; boundary=x',
        'content-length': String(26 * 1024 * 1024 + 1),
      },
    }));

    expect(denied.status).toBe(413);
    expect(mockCheckRateLimit).toHaveBeenCalledWith('203.0.113.9', 'register');
  });

  it('rejects a chunked oversized body with NO Content-Length (stream cap)', async () => {
    const res = await middleware(req('/api/receipt', {
      headers: { 'content-type': 'application/json' }, // no content-length → bypasses layer 1
      bodyBytes: 1024 * 1024 + 4096, // over the 1 MB JSON cap
    }));

    expect(res.status).toBe(413);
    expect(mockCheckRateLimit).toHaveBeenCalledWith('203.0.113.9', 'submit');
    expect(await res.json()).toMatchObject({ code: 'payload_too_large', max_bytes: 1024 * 1024 });
  });

  it('allows a chunked under-cap body with no Content-Length', async () => {
    const res = await middleware(req('/api/receipt', {
      headers: { 'content-type': 'application/json' },
      bodyBytes: 32 * 1024, // well under 1 MB
    }));

    expect(res.status).not.toBe(413);
    expect(mockCheckRateLimit).toHaveBeenCalledOnce();
  });

  it('rejects when Content-Length understates a chunked oversized body', async () => {
    const res = await middleware(req('/api/receipt', {
      headers: {
        'content-type': 'application/json',
        'content-length': '10', // lies — real body is over the cap
      },
      bodyBytes: 1024 * 1024 + 4096,
    }));

    expect(res.status).toBe(413);
    expect(mockCheckRateLimit).toHaveBeenCalledWith('203.0.113.9', 'submit');
  });

  it('fails closed when a request body cannot be cloned for byte counting', async () => {
    const request = req('/api/receipt', {
      headers: { 'content-type': 'application/json' },
      bodyBytes: 32,
    });
    request.clone = () => { throw new Error('clone unavailable'); };

    const res = await middleware(request);

    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ code: 'invalid_body' });
  });

  it('does not let a forged Host header make an attacker Origin same-origin', async () => {
    vi.stubEnv('NODE_ENV', 'development');
    vi.stubEnv('ALLOWED_ORIGINS', '');
    vi.stubEnv('NEXT_PUBLIC_APP_URL', 'https://www.emiliaprotocol.ai');
    const res = await middleware(req('/api/cloud/approvals', {
      method: 'GET',
      headers: { origin: 'https://attacker.example', host: 'attacker.example' },
    }));

    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ code: 'cors_denied' });
  });

  it('does not trust a poisoned request URL as the application origin', async () => {
    vi.stubEnv('ALLOWED_ORIGINS', '');
    vi.stubEnv('NEXT_PUBLIC_APP_URL', 'https://www.emiliaprotocol.ai');
    const request = req('/api/cloud/approvals', {
      method: 'GET',
      headers: { origin: 'https://attacker.example', host: 'attacker.example' },
    });
    request.nextUrl = new URL('https://attacker.example/api/cloud/approvals');

    const res = await middleware(request);

    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ code: 'cors_denied' });
  });

  it('denies cross-origin cloud requests with no allowlist in development too', async () => {
    vi.stubEnv('NODE_ENV', 'development');
    vi.stubEnv('ALLOWED_ORIGINS', '');
    vi.stubEnv('NEXT_PUBLIC_APP_URL', 'https://www.emiliaprotocol.ai');
    const res = await middleware(req('/api/cloud/approvals', {
      method: 'GET',
      headers: { origin: 'https://attacker.example' },
    }));

    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ code: 'cors_denied' });
  });

  it('pins API matcher and mutating-method body-cap coverage', () => {
    expect(middlewareSource).toContain("'/api/:path*'");
    expect(middlewareSource).toContain("new Set(['POST', 'PUT', 'PATCH', 'DELETE'])");
  });
});
