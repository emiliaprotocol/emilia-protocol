// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';

import { createSupabaseAuthorityBillingStore } from '../lib/works/billing-store.ts';

const RECORD_ID = 'authority-record-acme-agent';
const ENTITLEMENT = {
  record_id: RECORD_ID,
  tier: 'MONITORED',
  status: 'ACTIVE',
  stripe_customer_id: 'cus_12345678',
  stripe_subscription_id: 'sub_12345678',
  current_period_end: '2026-09-14T00:00:00+00:00',
};

describe('Supabase Authority Record billing store', () => {
  it('applies idempotent signed Stripe events through the event RPC', async () => {
    const rpc = vi.fn(async () => ({ data: ENTITLEMENT, error: null }));
    const store = createSupabaseAuthorityBillingStore({ rpc } as any);
    const result = await store.applyEvent({
      stripe_event_id: 'evt_12345678', event_type: 'customer.subscription.updated',
      record_id: RECORD_ID, subscription_status: 'active',
      stripe_customer_id: 'cus_12345678', stripe_subscription_id: 'sub_12345678',
      current_period_end: '2026-09-14T00:00:00.000Z',
      event_created_at: '2026-08-14T00:00:00.000Z',
    });
    expect(result).toEqual({ ok: true, entitlement: expect.objectContaining({ status: 'ACTIVE' }) });
    expect(rpc).toHaveBeenCalledWith('apply_works_authority_stripe_event', expect.objectContaining({
      p_stripe_event_id: 'evt_12345678', p_record_id: RECORD_ID,
    }));
  });

  it('reads and reconciles without creating a fake Stripe event', async () => {
    const rpc = vi.fn(async (name: string) => ({
      data: name === 'read_works_authority_entitlement' ? ENTITLEMENT : ENTITLEMENT,
      error: null,
    }));
    const store = createSupabaseAuthorityBillingStore({ rpc } as any);
    expect(await store.readEntitlement(RECORD_ID)).toEqual({
      ok: true, entitlement: expect.objectContaining({ record_id: RECORD_ID }),
    });
    await store.reconcile({
      record_id: RECORD_ID, subscription_status: 'past_due',
      stripe_customer_id: 'cus_12345678', stripe_subscription_id: 'sub_12345678',
      current_period_end: '2026-09-14T00:00:00.000Z',
    });
    expect(rpc).toHaveBeenLastCalledWith('reconcile_works_authority_entitlement', expect.not.objectContaining({
      p_stripe_event_id: expect.anything(),
    }));
  });

  it('rejects malformed entitlement rows from storage', async () => {
    const rpc = vi.fn(async () => ({ data: { ...ENTITLEMENT, tier: 'CERTIFIED' }, error: null }));
    const result = await createSupabaseAuthorityBillingStore({ rpc } as any).readEntitlement(RECORD_ID);
    expect(result).toEqual(expect.objectContaining({ ok: false, code: 'store_invalid' }));
  });
});
