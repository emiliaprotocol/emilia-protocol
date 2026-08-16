// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  checkout: vi.fn(),
  apply: vi.fn(),
  reconcile: vi.fn(),
  createStripeCheckout: vi.fn(),
  retrieveSubscription: vi.fn(),
  constructEvent: vi.fn(),
}));

vi.mock('@/lib/works/authority-record-store', () => ({
  createSupabaseAuthorityRecordStore: () => ({ authority: true }),
}));
vi.mock('@/lib/works/billing-store', () => ({
  createSupabaseAuthorityBillingStore: () => ({ billing: true }),
}));
vi.mock('@/lib/works/billing-service', async (original) => {
  const actual = await original<typeof import('../lib/works/billing-service.ts')>();
  return {
    ...actual,
    createAuthorityMonitoringCheckout: mocks.checkout,
    applyAuthorityStripeEvent: mocks.apply,
    reconcileAuthorityMonitoring: mocks.reconcile,
  };
});
vi.mock('@/lib/works/stripe-gateway', () => ({
  createStripeCheckout: mocks.createStripeCheckout,
  retrieveStripeSubscription: mocks.retrieveSubscription,
  constructStripeWebhookEvent: mocks.constructEvent,
}));

const checkoutRoute = await import('../app/api/works/authority-records/[recordId]/billing/checkout/route.ts');
const reconcileRoute = await import('../app/api/works/authority-records/[recordId]/billing/reconcile/route.ts');
const webhookRoute = await import('../app/api/works/billing/webhook/route.ts');

const RECORD_ID = 'authority-record-acme-agent';
const OWNER_TOKEN = `aro1_${'b'.repeat(64)}`;
const context = { params: Promise.resolve({ recordId: RECORD_ID }) };

function request(url: string, init: RequestInit = {}) {
  return new Request(url, init);
}

beforeEach(() => {
  process.env.WORKS_V0 = '1';
  process.env.STRIPE_SECRET_KEY = 'sk_test_secret';
  process.env.STRIPE_PRICE_AUTHORITY_RECORD_MONITOR = 'price_12345678';
  process.env.STRIPE_WORKS_WEBHOOK_SECRET = 'whsec_12345678';
  process.env.NEXT_PUBLIC_APP_URL = 'https://www.emiliaprotocol.ai';
  for (const mock of Object.values(mocks)) mock.mockReset();
  mocks.checkout.mockResolvedValue({ url: 'https://checkout.stripe.com/c/pay/1' });
  mocks.reconcile.mockResolvedValue({ status: 'ACTIVE' });
  mocks.constructEvent.mockReturnValue({ id: 'evt_12345678', type: 'customer.subscription.updated' });
  mocks.apply.mockResolvedValue({ status: 'ACTIVE' });
});

describe('Authority Record billing route boundary', () => {
  it('hides billing when Works is disabled', async () => {
    delete process.env.WORKS_V0;
    const response = await checkoutRoute.POST(request('https://www.emiliaprotocol.ai/x', {
      method: 'POST', headers: { authorization: `Bearer ${OWNER_TOKEN}` },
    }) as any, context);
    expect(response.status).toBe(404);
    expect(mocks.checkout).not.toHaveBeenCalled();
  });

  it('creates checkout only with an owner bearer and canonical configured origin', async () => {
    expect((await checkoutRoute.POST(request('https://attacker.example/x', { method: 'POST' }) as any, context)).status).toBe(404);
    const response = await checkoutRoute.POST(request('https://attacker.example/x', {
      method: 'POST', headers: { authorization: `Bearer ${OWNER_TOKEN}` },
    }) as any, context);
    expect(response.status).toBe(200);
    expect(mocks.checkout).toHaveBeenCalledWith(expect.objectContaining({
      recordId: RECORD_ID,
      ownerToken: OWNER_TOKEN,
      priceId: 'price_12345678',
      siteOrigin: 'https://www.emiliaprotocol.ai',
      createCheckout: mocks.createStripeCheckout,
    }));
  });

  it('verifies the exact raw webhook body before applying an event', async () => {
    const raw = '{"id":"evt_12345678"}';
    const response = await webhookRoute.POST(request('https://www.emiliaprotocol.ai/x', {
      method: 'POST', body: raw, headers: { 'stripe-signature': 't=1,v1=abc' },
    }) as any);
    expect(response.status).toBe(200);
    expect(mocks.constructEvent).toHaveBeenCalledWith(raw, 't=1,v1=abc', 'whsec_12345678');
    expect(mocks.apply).toHaveBeenCalledWith(expect.objectContaining({
      retrieveSubscription: mocks.retrieveSubscription,
    }));
  });

  it('rejects unsigned and oversized webhook bodies before applying state', async () => {
    expect((await webhookRoute.POST(request('https://www.emiliaprotocol.ai/x', {
      method: 'POST', body: '{}',
    }) as any)).status).toBe(400);
    expect((await webhookRoute.POST(request('https://www.emiliaprotocol.ai/x', {
      method: 'POST', body: 'x'.repeat(262145), headers: { 'stripe-signature': 'x' },
    }) as any)).status).toBe(413);
    expect(mocks.apply).not.toHaveBeenCalled();
  });

  it('reconciles current Stripe state only for the record owner', async () => {
    const response = await reconcileRoute.POST(request('https://www.emiliaprotocol.ai/x', {
      method: 'POST', headers: { authorization: `Bearer ${OWNER_TOKEN}` },
    }) as any, context);
    expect(response.status).toBe(200);
    expect(mocks.reconcile).toHaveBeenCalledWith(expect.objectContaining({
      recordId: RECORD_ID, ownerToken: OWNER_TOKEN,
      retrieveSubscription: mocks.retrieveSubscription,
    }));
  });
});
