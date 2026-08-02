// SPDX-License-Identifier: Apache-2.0
//
// POST /api/cloud/webhooks — transport pre-check.
//
// Audit #12 finding 6 claimed http: webhooks were an open SSRF vector, citing
// the route's protocol allowlist. SSRF was never open: validateWebhookUrl
// (lib/cloud/webhooks.ts) is https-only, blocks localhost / *.internal /
// IP-literal hosts, and resolves the hostname to reject private and link-local
// answers including the IPv4-mapped form of 169.254.169.254 — and
// registerEndpoint calls it before any row is written. Both of the audit's
// example URLs were already refused. tests/cloud-webhook-route-ssrf.test.ts is
// the existing guard for that.
//
// What WAS wrong is smaller and real: the route's own pre-check accepted http:
// and told the caller "Webhook URL must use HTTPS or HTTP", so the API
// advertised a protocol the delivery path has never used, and an http URL got a
// confusing 422 from two layers down instead of a plain 400. These cases pin
// the refusal at the boundary that states the rule.

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockAuthenticateCloudRequest = vi.fn();
const mockRequirePermission = vi.fn();
const mockGetGuardedClient = vi.fn();
const mockRegisterEndpoint = vi.fn();

vi.mock('@/lib/cloud/auth', () => ({
  authenticateCloudRequest: (...args: unknown[]) => mockAuthenticateCloudRequest(...args),
}));

vi.mock('@/lib/cloud/authorize', () => ({
  requirePermission: (...args: unknown[]) => mockRequirePermission(...args),
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args: unknown[]) => mockGetGuardedClient(...args),
}));

vi.mock('@/lib/supabase', () => ({ getServiceClient: vi.fn() }));

vi.mock('@/lib/cloud/webhooks', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/cloud/webhooks.js')>();
  return { ...actual, registerEndpoint: (...args: unknown[]) => mockRegisterEndpoint(...args) };
});

vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const { POST } = await import('../app/api/cloud/webhooks/route.js');

function req(url: string): Request {
  return new Request('https://cloud.example/api/cloud/webhooks', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url, events: ['receipt.created'] }),
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockAuthenticateCloudRequest.mockResolvedValue({ tenantId: 'tenant-1', permissions: ['write'] });
  mockRegisterEndpoint.mockResolvedValue({
    endpoint: { endpoint_id: 'ep-1' },
    secret: 'whsec_test',
  });
});

describe('POST /api/cloud/webhooks — transport', () => {
  it('refuses an http:// endpoint at the route, before registration runs', async () => {
    const res = await POST(req('http://hooks.example.com/ep') as never);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(JSON.stringify(body)).toMatch(/HTTPS/);
    // The refusal is the route's, so nothing reached the registration path.
    expect(mockRegisterEndpoint).not.toHaveBeenCalled();
  });

  it('does not offer http as an acceptable protocol in the error text', async () => {
    const res = await POST(req('ftp://hooks.example.com/ep') as never);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(JSON.stringify(body)).not.toMatch(/or HTTP\b/i);
  });

  it('still accepts an https:// endpoint', async () => {
    const res = await POST(req('https://hooks.example.com/ep') as never);

    expect(res.status).toBe(201);
    expect(mockRegisterEndpoint).toHaveBeenCalledTimes(1);
  });
});
