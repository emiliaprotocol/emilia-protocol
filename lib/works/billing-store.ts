// SPDX-License-Identifier: Apache-2.0

import type { SupabaseClient } from '@supabase/supabase-js';

import { getServiceClient } from '../supabase.js';
import type {
  AuthorityBillingStore,
  AuthorityEntitlement,
} from './billing-service.js';

type RpcClient = Pick<SupabaseClient, 'rpc'>;

function failure(code = 'store_unavailable') {
  return { ok: false as const, code, detail: 'Authority billing storage is unavailable.' };
}

function isObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function entitlement(value: unknown): AuthorityEntitlement | null {
  if (!isObject(value)
      || typeof value.record_id !== 'string'
      || !['FREE', 'MONITORED'].includes(String(value.tier))
      || !['ACTIVE', 'TRIALING', 'PAST_DUE', 'INACTIVE'].includes(String(value.status))
      || (value.stripe_customer_id !== null && typeof value.stripe_customer_id !== 'string')
      || (value.stripe_subscription_id !== null && typeof value.stripe_subscription_id !== 'string')
      || (value.current_period_end !== null && typeof value.current_period_end !== 'string')) return null;
  return {
    record_id: value.record_id,
    tier: value.tier as AuthorityEntitlement['tier'],
    status: value.status as AuthorityEntitlement['status'],
    stripe_customer_id: value.stripe_customer_id as string | null,
    stripe_subscription_id: value.stripe_subscription_id as string | null,
    current_period_end: value.current_period_end as string | null,
  };
}

async function call(client: RpcClient, name: string, args: Record<string, unknown>) {
  try {
    const result = await client.rpc(name, args);
    return result?.error ? failure() : { ok: true as const, data: result?.data };
  } catch {
    return failure();
  }
}

function transitionArgs(input: {
  record_id: string;
  subscription_status: string;
  stripe_customer_id: string;
  stripe_subscription_id: string;
  current_period_end: string | null;
}) {
  return {
    p_record_id: input.record_id,
    p_subscription_status: input.subscription_status,
    p_stripe_customer_id: input.stripe_customer_id,
    p_stripe_subscription_id: input.stripe_subscription_id,
    p_current_period_end: input.current_period_end,
  };
}

export function createSupabaseAuthorityBillingStore(
  client: RpcClient = getServiceClient(),
): AuthorityBillingStore {
  return {
    async applyEvent(input) {
      const result = await call(client, 'apply_works_authority_stripe_event', {
        p_stripe_event_id: input.stripe_event_id,
        p_event_type: input.event_type,
        ...transitionArgs(input),
        p_event_created_at: input.event_created_at,
      });
      if (!result.ok) return result;
      const normalized = entitlement(result.data);
      return normalized ? { ok: true, entitlement: normalized } : failure('store_invalid');
    },

    async readEntitlement(recordId) {
      const result = await call(client, 'read_works_authority_entitlement', {
        p_record_id: recordId,
      });
      if (!result.ok) return result;
      if (result.data === null) return { ok: true, entitlement: null };
      const normalized = entitlement(result.data);
      return normalized ? { ok: true, entitlement: normalized } : failure('store_invalid');
    },

    async reconcile(input) {
      const result = await call(client, 'reconcile_works_authority_entitlement', transitionArgs(input));
      if (!result.ok) return result;
      const normalized = entitlement(result.data);
      return normalized ? { ok: true, entitlement: normalized } : failure('store_invalid');
    },
  };
}
