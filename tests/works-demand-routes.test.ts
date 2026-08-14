// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  create: vi.fn(),
  verify: vi.fn(),
  counts: vi.fn(),
  email: vi.fn(),
}));

vi.mock('@/lib/works/demand-store', () => ({
  createSupabaseAuthorityDemandStore: () => ({ mocked: true }),
}));
vi.mock('@/lib/works/demand-service', async (original) => {
  const actual = await original<typeof import('../lib/works/demand-service.ts')>();
  return {
    ...actual,
    createAuthorityRecordDemandRequest: mocks.create,
    verifyAuthorityRecordDemandRequest: mocks.verify,
    readAuthorityRecordDemandCounts: mocks.counts,
  };
});
vi.mock('@/lib/works/demand-email', () => ({ sendAuthorityDemandVerificationEmail: mocks.email }));

const requestRoute = await import('../app/api/works/authority-records/[recordId]/requests/route.ts');
const verifyRoute = await import('../app/api/works/authority-records/requests/verify/route.ts');

const RECORD_ID = 'authority-record-acme-agent';
const context = { params: Promise.resolve({ recordId: RECORD_ID }) };

beforeEach(() => {
  process.env.WORKS_V0 = '1';
  process.env.WORKS_DEMAND_HMAC_KEY = 'd'.repeat(64);
  for (const mock of Object.values(mocks)) mock.mockReset();
  mocks.create.mockResolvedValue({ accepted: true, verification_sent: true });
  mocks.verify.mockResolvedValue({
    record_id: RECORD_ID, verified_requesters: 1, verified_organizations: 1,
  });
  mocks.counts.mockResolvedValue({ verified_requesters: 1, verified_organizations: 1 });
});

describe('Authority Record verified-request routes', () => {
  it('is completely hidden when Works is disabled', async () => {
    delete process.env.WORKS_V0;
    const response = await requestRoute.POST(new Request('https://www.emiliaprotocol.ai/x', {
      method: 'POST', body: JSON.stringify({ email: 'person@one.example' }),
      headers: { 'content-type': 'application/json' },
    }) as any, context);
    expect(response.status).toBe(404);
    expect(mocks.create).not.toHaveBeenCalled();
  });

  it('accepts an email request generically without echoing contact or delivery state', async () => {
    const response = await requestRoute.POST(new Request('https://www.emiliaprotocol.ai/x', {
      method: 'POST', body: JSON.stringify({ email: 'person@one.example' }),
      headers: { 'content-type': 'application/json' },
    }) as any, context);
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ accepted: true });
    expect(mocks.create).toHaveBeenCalledWith(expect.objectContaining({
      input: { record_id: RECORD_ID, email: 'person@one.example' },
      hmacKey: 'd'.repeat(64),
      sendEmail: mocks.email,
    }));
  });

  it('verifies only a fragment-delivered token from the body and returns exact request counts', async () => {
    const token = `ardv1_${'a'.repeat(64)}`;
    const response = await verifyRoute.POST(new Request('https://www.emiliaprotocol.ai/x', {
      method: 'POST', body: JSON.stringify({ token }),
      headers: { 'content-type': 'application/json' },
    }) as any);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      record_id: RECORD_ID, verified_requesters: 1, verified_organizations: 1,
    });
    expect(response.headers.get('cache-control')).toContain('no-store');
  });

  it('serves exact counts without buyer or purchase language', async () => {
    const response = await requestRoute.GET(new Request('https://www.emiliaprotocol.ai/x') as any, context);
    expect(response.status).toBe(200);
    const text = JSON.stringify(await response.json());
    expect(text).toContain('verified_requesters');
    expect(text).not.toMatch(/buyer|purchas/i);
  });
});
