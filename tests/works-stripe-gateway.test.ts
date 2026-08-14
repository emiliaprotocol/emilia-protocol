// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const stripeMocks = vi.hoisted(() => ({
  retrievePrice: vi.fn(),
  createCheckout: vi.fn(),
  retrieveSubscription: vi.fn(),
  constructEvent: vi.fn(),
}));

vi.mock('stripe', () => ({
  default: class Stripe {
    prices = { retrieve: stripeMocks.retrievePrice };
    checkout = { sessions: { create: stripeMocks.createCheckout } };
    subscriptions = { retrieve: stripeMocks.retrieveSubscription };
    webhooks = { constructEvent: stripeMocks.constructEvent };
  },
}));

import {
  assertMonitoringPrice,
  constructStripeWebhookEvent,
  createStripeCheckout,
  retrieveStripeSubscription,
} from '../lib/works/stripe-gateway.ts';

beforeEach(() => {
  process.env.STRIPE_SECRET_KEY = 'sk_test_authority_records';
  for (const mock of Object.values(stripeMocks)) mock.mockReset();
});

afterEach(() => {
  delete process.env.STRIPE_SECRET_KEY;
});

describe('Authority Record Stripe gateway', () => {
  it('accepts only the advertised active USD 29 monthly recurring price', () => {
    expect(() => assertMonitoringPrice({
      active: true,
      currency: 'usd',
      unit_amount: 2900,
      type: 'recurring',
      recurring: { interval: 'month', interval_count: 1 },
    })).not.toThrow();

    for (const price of [
      { active: false, currency: 'usd', unit_amount: 2900, type: 'recurring', recurring: { interval: 'month', interval_count: 1 } },
      { active: true, currency: 'usd', unit_amount: 9900, type: 'recurring', recurring: { interval: 'month', interval_count: 1 } },
      { active: true, currency: 'eur', unit_amount: 2900, type: 'recurring', recurring: { interval: 'month', interval_count: 1 } },
      { active: true, currency: 'usd', unit_amount: 2900, type: 'recurring', recurring: { interval: 'year', interval_count: 1 } },
      { active: true, currency: 'usd', unit_amount: 2900, type: 'one_time', recurring: null },
    ]) expect(() => assertMonitoringPrice(price)).toThrow('monitoring price mismatch');
  });

  it('refuses to call Stripe when the account secret is absent', async () => {
    delete process.env.STRIPE_SECRET_KEY;
    await expect(createStripeCheckout({
      mode: 'subscription',
      priceId: 'price_12345678',
      recordId: 'authority-record-acme-agent',
      successUrl: 'https://www.emiliaprotocol.ai/success',
      cancelUrl: 'https://www.emiliaprotocol.ai/cancel',
      metadata: {
        record_id: 'authority-record-acme-agent',
        purchase_scope: 'monitoring_freshness_and_presentation',
      },
    })).rejects.toThrow('Stripe is not configured');
    expect(stripeMocks.retrievePrice).not.toHaveBeenCalled();
  });

  it('pins the live Stripe price before creating the monitoring checkout', async () => {
    stripeMocks.retrievePrice.mockResolvedValue({
      active: true,
      currency: 'usd',
      unit_amount: 2900,
      type: 'recurring',
      recurring: { interval: 'month', interval_count: 1 },
    });
    stripeMocks.createCheckout.mockResolvedValue({
      url: 'https://checkout.stripe.com/c/pay/cs_test_authority',
    });
    const metadata = {
      record_id: 'authority-record-acme-agent' as const,
      purchase_scope: 'monitoring_freshness_and_presentation' as const,
    };

    await expect(createStripeCheckout({
      mode: 'subscription',
      priceId: 'price_12345678',
      recordId: metadata.record_id,
      successUrl: 'https://www.emiliaprotocol.ai/success',
      cancelUrl: 'https://www.emiliaprotocol.ai/cancel',
      metadata,
    })).resolves.toEqual({ url: 'https://checkout.stripe.com/c/pay/cs_test_authority' });

    expect(stripeMocks.retrievePrice).toHaveBeenCalledWith('price_12345678');
    expect(stripeMocks.createCheckout).toHaveBeenCalledWith(expect.objectContaining({
      mode: 'subscription',
      line_items: [{ price: 'price_12345678', quantity: 1 }],
      client_reference_id: metadata.record_id,
      metadata,
      subscription_data: { metadata },
    }));
  });

  it('normalizes subscription customer and period fields without inventing values', async () => {
    stripeMocks.retrieveSubscription
      .mockResolvedValueOnce({
        id: 'sub_string_customer', status: 'active', customer: 'cus_12345678',
        current_period_end: 1789344000, metadata: { record_id: 'authority-record-acme-agent' },
      })
      .mockResolvedValueOnce({
        id: 'sub_object_customer', status: 'past_due', customer: { id: 'cus_87654321' },
        current_period_end: 1789344000.5,
      });

    await expect(retrieveStripeSubscription('sub_string_customer')).resolves.toEqual({
      id: 'sub_string_customer', status: 'active', customerId: 'cus_12345678',
      currentPeriodEnd: 1789344000, metadata: { record_id: 'authority-record-acme-agent' },
    });
    await expect(retrieveStripeSubscription('sub_object_customer')).resolves.toEqual({
      id: 'sub_object_customer', status: 'past_due', customerId: 'cus_87654321',
      currentPeriodEnd: null, metadata: {},
    });
  });

  it('delegates webhook verification to the configured Stripe client', async () => {
    const event = { id: 'evt_12345678', type: 'customer.subscription.updated' };
    stripeMocks.constructEvent.mockReturnValue(event);
    await expect(constructStripeWebhookEvent(
      '{"id":"evt_12345678"}', 'stripe-signature', 'whsec_authority_records',
    )).resolves.toBe(event);
    expect(stripeMocks.constructEvent).toHaveBeenCalledWith(
      '{"id":"evt_12345678"}', 'stripe-signature', 'whsec_authority_records',
    );
  });
});
