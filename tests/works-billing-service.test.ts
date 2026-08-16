// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';

import {
  applyAuthorityStripeEvent,
  BillingServiceError,
  createAuthorityMonitoringCheckout,
  reconcileAuthorityMonitoring,
  type AuthorityBillingStore,
} from '../lib/works/billing-service.ts';

const RECORD_ID = 'authority-record-acme-agent';
const OWNER_TOKEN = `aro1_${'b'.repeat(64)}`;

function ownerStore(status = 'PUBLISHED') {
  return {
    readOwnerState: vi.fn(async () => ({
      ok: true,
      state: {
        record_id: RECORD_ID, current_version: 1,
        current_digest: `sha256:${'a'.repeat(64)}`, current_projection: {},
        repository_url: 'https://github.com/acme/agent', status,
        approved_at: '2026-08-14T00:00:00.000Z', withdrawn_at: null,
      },
    })),
  } as any;
}

class BillingStore implements AuthorityBillingStore {
  applied: any[] = [];
  reconciled: any[] = [];
  entitlement: any = {
    record_id: RECORD_ID, tier: 'MONITORED', status: 'ACTIVE',
    stripe_customer_id: 'cus_12345678', stripe_subscription_id: 'sub_12345678',
    current_period_end: '2026-09-14T00:00:00.000Z',
  };
  async applyEvent(input: any) { this.applied.push(input); return { ok: true as const, entitlement: this.entitlement }; }
  async readEntitlement() { return { ok: true as const, entitlement: this.entitlement }; }
  async reconcile(input: any) { this.reconciled.push(input); return { ok: true as const, entitlement: this.entitlement }; }
}

describe('Authority Record monitoring billing', () => {
  it('creates an owner-authorized $29 monitoring checkout without putting owner credentials in Stripe', async () => {
    const createCheckout = vi.fn(async () => ({ url: 'https://checkout.stripe.com/c/pay/cs_test_123' }));
    const result = await createAuthorityMonitoringCheckout({
      recordId: RECORD_ID, ownerToken: OWNER_TOKEN, authorityStore: ownerStore(),
      priceId: 'price_12345678', siteOrigin: 'https://www.emiliaprotocol.ai', createCheckout,
    });
    expect(result).toEqual({ url: 'https://checkout.stripe.com/c/pay/cs_test_123' });
    const input = createCheckout.mock.calls[0][0];
    expect(input).toMatchObject({
      mode: 'subscription', priceId: 'price_12345678', recordId: RECORD_ID,
      successUrl: `https://www.emiliaprotocol.ai/works/records/${RECORD_ID}?billing=success`,
    });
    expect(JSON.stringify(input)).not.toContain(OWNER_TOKEN);
    expect(JSON.stringify(input)).not.toMatch(/safe|approved|certif/i);
  });

  it('refuses withdrawn records and non-HTTPS canonical origins before Stripe', async () => {
    for (const options of [
      { authorityStore: ownerStore('WITHDRAWN'), siteOrigin: 'https://www.emiliaprotocol.ai' },
      { authorityStore: ownerStore(), siteOrigin: 'http://www.emiliaprotocol.ai' },
    ]) {
      await expect(createAuthorityMonitoringCheckout({
        recordId: RECORD_ID, ownerToken: OWNER_TOKEN, priceId: 'price_12345678',
        createCheckout: vi.fn(), ...options,
      })).rejects.toBeInstanceOf(BillingServiceError);
    }
  });

  it('fails closed on invalid configuration and untrusted checkout responses', async () => {
    await expect(createAuthorityMonitoringCheckout({
      recordId: RECORD_ID, ownerToken: OWNER_TOKEN, authorityStore: ownerStore(),
      priceId: 'bad', siteOrigin: 'https://www.emiliaprotocol.ai', createCheckout: vi.fn(),
    })).rejects.toMatchObject({ status: 503, code: 'authority_billing_unconfigured' });

    for (const createCheckout of [
      vi.fn(async () => { throw new Error('Stripe unavailable'); }),
      vi.fn(async () => ({ url: null })),
      vi.fn(async () => ({ url: 'https://evil.example/checkout' })),
    ]) {
      await expect(createAuthorityMonitoringCheckout({
        recordId: RECORD_ID, ownerToken: OWNER_TOKEN, authorityStore: ownerStore(),
        priceId: 'price_12345678', siteOrigin: 'https://www.emiliaprotocol.ai', createCheckout,
      })).rejects.toMatchObject({ status: 503, code: 'authority_billing_unavailable' });
    }
  });

  it('retrieves current subscription state before applying delayed signed webhook events', async () => {
    const billingStore = new BillingStore();
    const retrieveSubscription = vi.fn(async () => ({
      id: 'sub_12345678', status: 'active', customerId: 'cus_12345678',
      currentPeriodEnd: 1789344000, metadata: { record_id: RECORD_ID },
    }));
    await applyAuthorityStripeEvent({
      event: {
        id: 'evt_12345678', type: 'customer.subscription.updated', created: 1786665600,
        data: { object: { id: 'sub_12345678', metadata: { record_id: RECORD_ID } } },
      },
      retrieveSubscription, store: billingStore,
    });
    expect(retrieveSubscription).toHaveBeenCalledWith('sub_12345678');
    expect(billingStore.applied[0]).toMatchObject({
      stripe_event_id: 'evt_12345678', record_id: RECORD_ID,
      subscription_status: 'active', stripe_subscription_id: 'sub_12345678',
    });
  });

  it('applies deletion as inactive without pretending a failed retrieval is current', async () => {
    const store = new BillingStore();
    await applyAuthorityStripeEvent({
      event: {
        id: 'evt_87654321', type: 'customer.subscription.deleted', created: 1786665600,
        data: { object: {
          id: 'sub_12345678', status: 'canceled', customer: 'cus_12345678',
          metadata: { record_id: RECORD_ID }, current_period_end: 1789344000,
        } },
      }, retrieveSubscription: vi.fn(), store,
    });
    expect(store.applied[0].subscription_status).toBe('canceled');
  });

  it('refuses unknown event types and missing record binding without touching entitlements', async () => {
    const store = new BillingStore();
    for (const event of [
      { id: 'evt_12345678', type: 'invoice.paid', created: 1, data: { object: {} } },
      { id: 'evt_12345678', type: 'customer.subscription.updated', created: 1,
        data: { object: { id: 'sub_12345678', metadata: {} } } },
    ]) {
      await expect(applyAuthorityStripeEvent({
        event, retrieveSubscription: vi.fn(), store,
      })).rejects.toBeInstanceOf(BillingServiceError);
    }
    expect(store.applied).toHaveLength(0);
  });

  it('refuses malformed event objects, subscription references, and stale Stripe state', async () => {
    const store = new BillingStore();
    for (const event of [
      { id: 'evt_12345678', type: 'customer.subscription.updated', created: 1, data: { object: [] } },
      {
        id: 'evt_12345678', type: 'checkout.session.completed', created: 1,
        data: { object: { metadata: { record_id: RECORD_ID }, subscription: null } },
      },
    ]) {
      await expect(applyAuthorityStripeEvent({
        event, retrieveSubscription: vi.fn(), store,
      })).rejects.toBeInstanceOf(BillingServiceError);
    }

    await expect(applyAuthorityStripeEvent({
      event: {
        id: 'evt_12345678', type: 'customer.subscription.updated', created: 1,
        data: { object: { id: 'sub_12345678', metadata: { record_id: RECORD_ID } } },
      },
      retrieveSubscription: vi.fn(async () => { throw new Error('Stripe unavailable'); }),
      store,
    })).rejects.toMatchObject({ status: 503, code: 'authority_billing_reconciliation_unavailable' });
  });

  it('rejects mismatched subscription state and storage failures', async () => {
    const event = {
      id: 'evt_12345678', type: 'customer.subscription.updated', created: 1,
      data: { object: { id: 'sub_12345678', metadata: { record_id: RECORD_ID } } },
    };
    for (const subscription of [
      {
        id: 'sub_12345678', status: 'active', customerId: 'cus_12345678',
        currentPeriodEnd: 1789344000, metadata: { record_id: 'authority-record-other-agent' },
      },
      {
        id: 'sub_12345678', status: 'active', customerId: 'cus_12345678',
        currentPeriodEnd: -1, metadata: { record_id: RECORD_ID },
      },
    ]) {
      await expect(applyAuthorityStripeEvent({
        event, retrieveSubscription: vi.fn(async () => subscription), store: new BillingStore(),
      })).rejects.toBeInstanceOf(BillingServiceError);
    }

    const failingStore = new BillingStore();
    failingStore.applyEvent = vi.fn(async () => ({
      ok: false as const, code: 'storage_offline', detail: 'private',
    }));
    await expect(applyAuthorityStripeEvent({
      event,
      retrieveSubscription: vi.fn(async () => ({
        id: 'sub_12345678', status: 'active', customerId: 'cus_12345678',
        currentPeriodEnd: 1789344000, metadata: { record_id: RECORD_ID },
      })),
      store: failingStore,
    })).rejects.toMatchObject({ status: 503, code: 'authority_billing_store_unavailable' });
  });

  it('reconciles from Stripe current state without fabricating a webhook event', async () => {
    const store = new BillingStore();
    const retrieveSubscription = vi.fn(async () => ({
      id: 'sub_12345678', status: 'past_due', customerId: 'cus_12345678',
      currentPeriodEnd: 1789344000, metadata: { record_id: RECORD_ID },
    }));
    await reconcileAuthorityMonitoring({
      recordId: RECORD_ID, ownerToken: OWNER_TOKEN, authorityStore: ownerStore(),
      store, retrieveSubscription,
    });
    expect(store.reconciled[0]).toMatchObject({
      record_id: RECORD_ID, subscription_status: 'past_due',
    });
    expect(store.reconciled[0]).not.toHaveProperty('stripe_event_id');
  });

  it('refuses reconciliation without an entitlement or current Stripe state', async () => {
    const missingStore = new BillingStore();
    missingStore.readEntitlement = vi.fn(async () => ({ ok: true as const, entitlement: null }));
    await expect(reconcileAuthorityMonitoring({
      recordId: RECORD_ID, ownerToken: OWNER_TOKEN, authorityStore: ownerStore(),
      store: missingStore, retrieveSubscription: vi.fn(),
    })).rejects.toMatchObject({ status: 404, code: 'authority_billing_subscription_not_found' });

    await expect(reconcileAuthorityMonitoring({
      recordId: RECORD_ID, ownerToken: OWNER_TOKEN, authorityStore: ownerStore(),
      store: new BillingStore(),
      retrieveSubscription: vi.fn(async () => { throw new Error('Stripe unavailable'); }),
    })).rejects.toMatchObject({ status: 503, code: 'authority_billing_reconciliation_unavailable' });
  });
});
