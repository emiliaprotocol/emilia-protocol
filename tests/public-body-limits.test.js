// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi, beforeEach } from 'vitest';

const mockGetGuardedClient = vi.fn();

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const Waitlist = await import('../app/api/waitlist/route.js');
const Inquiries = await import('../app/api/inquiries/route.js');
const Operators = await import('../app/api/operators/apply/route.js');
const PilotRequest = await import('../app/api/pilot/request/route.js');
const Checkout = await import('../app/api/checkout/route.js');
const Guarded = await import('../app/api/v1/guarded/route.js');
const DemoReceipt = await import('../app/api/demo/require-receipt/route.js');
const DemoX402 = await import('../app/api/demo/x402/route.js');
const Mcp = await import('../app/api/mcp/[transport]/route.js');
const SamlAcs = await import('../app/api/sso/saml/acs/route.js');

function oversizedReq(path, bytes, body = {}) {
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'content-length': String(bytes),
    },
    body: JSON.stringify(body),
  });
}

function oversizedUndeclaredReq(path, bodyText) {
  return new Request(`https://www.emiliaprotocol.ai${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: bodyText,
  });
}

describe('public POST body limits', () => {
  beforeEach(() => {
    mockGetGuardedClient.mockReset();
  });

  const cases = [
    ['waitlist', Waitlist.POST, '/api/waitlist', 5 * 1024],
    ['inquiries', Inquiries.POST, '/api/inquiries', 17 * 1024],
    ['operators/apply', Operators.POST, '/api/operators/apply', 17 * 1024],
    ['pilot/request', PilotRequest.POST, '/api/pilot/request', 17 * 1024],
    ['checkout', Checkout.POST, '/api/checkout', 3 * 1024],
    ['v1/guarded', Guarded.POST, '/api/v1/guarded?action=payment.release', 257 * 1024],
    ['demo/require-receipt', DemoReceipt.POST, '/api/demo/require-receipt', 257 * 1024],
    ['demo/x402', DemoX402.POST, '/api/demo/x402', 257 * 1024],
    ['mcp', Mcp.POST, '/api/mcp/mcp', 257 * 1024],
    ['sso/saml/acs', SamlAcs.POST, '/api/sso/saml/acs', 257 * 1024],
  ];

  for (const [name, handler, path, bytes] of cases) {
    it(`${name} returns 413 before parsing large anonymous bodies`, async () => {
      const res = await handler(oversizedReq(path, bytes, { ping: true }), {});

      expect(res.status).toBe(413);
      expect(mockGetGuardedClient).not.toHaveBeenCalled();
    });
  }

  it('enforces the cap even when Content-Length is absent', async () => {
    const hugeJson = JSON.stringify({ email: `${'a'.repeat(5 * 1024)}@example.com` });
    const res = await Waitlist.POST(oversizedUndeclaredReq('/api/waitlist', hugeJson));

    expect(res.status).toBe(413);
    expect(mockGetGuardedClient).not.toHaveBeenCalled();
  });

  it('strips HTML from inquiry fields before durable storage', async () => {
    let inserted;
    mockGetGuardedClient.mockReturnValue({
      from: () => ({
        insert: vi.fn(async (row) => {
          inserted = row;
          return { error: null };
        }),
      }),
    });

    const res = await Inquiries.POST(new Request('https://www.emiliaprotocol.ai/api/inquiries', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        type: 'partner',
        name: '<img src=x onerror=alert(1)>Alice',
        email: 'alice@example.com',
        org: '<script>alert(1)</script>Demo Agency',
        problem: 'Need review <svg onload=alert(1)>before launch</svg>',
        notes: '<iframe srcdoc="<script>alert(1)</script>"></iframe>internal note',
      }),
    }));

    expect(res.status).toBe(200);
    expect(inserted.name).toBe('Alice');
    expect(JSON.stringify(inserted)).not.toMatch(/<script|<img|<svg|<iframe|onerror|onload/i);
  });
});
