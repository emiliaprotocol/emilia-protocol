// SPDX-License-Identifier: Apache-2.0
//
// Monitoring purchases freshness and presentation depth. It never purchases a
// favorable Authority Record conclusion. Stripe owns payment state; the local
// entitlement is a reconciled projection of Stripe's current subscription.

import type { AuthorityRecordStore } from './authority-record-service.js';
import { getOwnerAuthorityRecord } from './authority-record-service.js';

const RECORD_ID = /^authority-record-[a-z0-9][a-z0-9-]{2,63}$/;
const PRICE_ID = /^price_[A-Za-z0-9_]{8,255}$/;
const EVENT_ID = /^evt_[A-Za-z0-9_]{8,255}$/;
const SUBSCRIPTION_ID = /^sub_[A-Za-z0-9_]{8,255}$/;
const CUSTOMER_ID = /^cus_[A-Za-z0-9_]{8,255}$/;
const EVENT_TYPES = new Set([
  'checkout.session.completed',
  'customer.subscription.created',
  'customer.subscription.updated',
  'customer.subscription.deleted',
]);
const SUBSCRIPTION_STATUSES = new Set([
  'active', 'trialing', 'past_due', 'unpaid', 'canceled', 'incomplete', 'incomplete_expired',
]);

type BillingFailure = Readonly<{ ok: false; code: string; detail: string }>;
type BillingSuccess<T extends object> = Readonly<{ ok: true } & T>;
type BillingResult<T extends object> = BillingSuccess<T> | BillingFailure;

export type AuthorityEntitlement = Readonly<{
  record_id: string;
  tier: 'FREE' | 'MONITORED';
  status: 'ACTIVE' | 'TRIALING' | 'PAST_DUE' | 'INACTIVE';
  stripe_customer_id: string | null;
  stripe_subscription_id: string | null;
  current_period_end: string | null;
}>;

export type NormalizedSubscription = Readonly<{
  id: string;
  status: string;
  customerId: string;
  currentPeriodEnd: number | null;
  metadata: Record<string, string>;
}>;

type EntitlementTransition = {
  record_id: string;
  subscription_status: string;
  stripe_customer_id: string;
  stripe_subscription_id: string;
  current_period_end: string | null;
};

export interface AuthorityBillingStore {
  applyEvent(input: EntitlementTransition & {
    stripe_event_id: string;
    event_type: string;
    event_created_at: string;
  }): Promise<BillingResult<{ entitlement: AuthorityEntitlement }>>;
  readEntitlement(recordId: string): Promise<BillingResult<{ entitlement: AuthorityEntitlement | null }>>;
  reconcile(input: EntitlementTransition): Promise<BillingResult<{ entitlement: AuthorityEntitlement }>>;
}

export class BillingServiceError extends Error {
  constructor(public status: number, public code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'BillingServiceError';
  }
}

function fail(status: number, code: string, message: string, cause?: unknown): never {
  throw new BillingServiceError(status, code, message,
    cause === undefined ? undefined : { cause });
}

function canonicalOrigin(value: string): string {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password
        || parsed.pathname !== '/' || parsed.search || parsed.hash) throw new Error('invalid');
    return parsed.origin;
  } catch {
    fail(503, 'authority_billing_origin_unavailable', 'Canonical HTTPS origin is unavailable.');
  }
}

function requireStore<T extends object>(result: BillingResult<T>): BillingSuccess<T> {
  if (result.ok === true) return result as BillingSuccess<T>;
  fail(503, 'authority_billing_store_unavailable', 'Monitoring entitlement storage is unavailable.');
}

function subscriptionTransition(subscription: NormalizedSubscription, recordId: string): EntitlementTransition {
  if (!SUBSCRIPTION_ID.test(subscription.id)
      || !CUSTOMER_ID.test(subscription.customerId)
      || !SUBSCRIPTION_STATUSES.has(subscription.status)
      || subscription.metadata?.record_id !== recordId
      || !RECORD_ID.test(recordId)) {
    fail(422, 'authority_billing_binding_invalid', 'Stripe subscription is not bound to this Authority Record.');
  }
  let currentPeriodEnd: string | null = null;
  if (subscription.currentPeriodEnd !== null) {
    if (!Number.isInteger(subscription.currentPeriodEnd) || subscription.currentPeriodEnd <= 0) {
      fail(422, 'authority_billing_period_invalid', 'Stripe subscription period is invalid.');
    }
    currentPeriodEnd = new Date(subscription.currentPeriodEnd * 1000).toISOString();
  }
  return {
    record_id: recordId,
    subscription_status: subscription.status,
    stripe_customer_id: subscription.customerId,
    stripe_subscription_id: subscription.id,
    current_period_end: currentPeriodEnd,
  };
}

export async function createAuthorityMonitoringCheckout({
  recordId,
  ownerToken,
  authorityStore,
  priceId,
  siteOrigin = '',
  createCheckout,
}: {
  recordId: string;
  ownerToken: string;
  authorityStore: AuthorityRecordStore;
  priceId: string;
  siteOrigin?: string;
  createCheckout: (input: {
    mode: 'subscription';
    priceId: string;
    recordId: string;
    successUrl: string;
    cancelUrl: string;
    metadata: { record_id: string; purchase_scope: 'monitoring_freshness_and_presentation' };
  }) => Promise<{ url: string | null }>;
}) {
  if (!RECORD_ID.test(recordId) || !PRICE_ID.test(priceId)) {
    fail(503, 'authority_billing_unconfigured', 'Monitoring checkout is unavailable.');
  }
  const owner = await getOwnerAuthorityRecord({ recordId, ownerToken, store: authorityStore });
  if (owner.status === 'WITHDRAWN') {
    fail(409, 'authority_record_withdrawn', 'Republish the Authority Record before enabling monitoring.');
  }
  const origin = canonicalOrigin(siteOrigin);
  const metadata = {
    record_id: recordId,
    purchase_scope: 'monitoring_freshness_and_presentation' as const,
  };
  let session: { url: string | null };
  try {
    session = await createCheckout({
      mode: 'subscription', priceId, recordId,
      successUrl: `${origin}/works/records/${recordId}?billing=success`,
      cancelUrl: `${origin}/works/records/${recordId}?billing=cancelled`,
      metadata,
    });
  } catch (cause) {
    fail(503, 'authority_billing_unavailable', 'Monitoring checkout is unavailable.', cause);
  }
  let url: URL;
  try {
    url = new URL(session.url || '');
  } catch {
    fail(503, 'authority_billing_unavailable', 'Monitoring checkout is unavailable.');
  }
  if (url.protocol !== 'https:' || !(url.hostname === 'stripe.com' || url.hostname.endsWith('.stripe.com'))) {
    fail(503, 'authority_billing_unavailable', 'Monitoring checkout is unavailable.');
  }
  return Object.freeze({ url: url.toString() });
}

function eventObject(event: any): Record<string, any> {
  const value = event?.data?.object;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(400, 'authority_billing_event_invalid', 'Stripe event is invalid.');
  }
  return value;
}

export async function applyAuthorityStripeEvent({
  event,
  retrieveSubscription,
  store,
}: {
  event: any;
  retrieveSubscription: (subscriptionId: string) => Promise<NormalizedSubscription>;
  store: AuthorityBillingStore;
}) {
  if (!EVENT_ID.test(event?.id || '') || !EVENT_TYPES.has(event?.type)
      || !Number.isInteger(event?.created) || event.created <= 0) {
    fail(400, 'authority_billing_event_invalid', 'Stripe event is invalid.');
  }
  const object = eventObject(event);
  const recordId = object.metadata?.record_id;
  if (typeof recordId !== 'string' || !RECORD_ID.test(recordId)) {
    fail(422, 'authority_billing_binding_invalid', 'Stripe event has no Authority Record binding.');
  }
  let subscription: NormalizedSubscription;
  if (event.type === 'customer.subscription.deleted') {
    subscription = {
      id: object.id,
      status: object.status,
      customerId: typeof object.customer === 'string' ? object.customer : object.customer?.id,
      currentPeriodEnd: Number.isInteger(object.current_period_end) ? object.current_period_end : null,
      metadata: object.metadata,
    };
  } else {
    const subscriptionId = event.type === 'checkout.session.completed'
      ? (typeof object.subscription === 'string' ? object.subscription : object.subscription?.id)
      : object.id;
    if (typeof subscriptionId !== 'string' || !SUBSCRIPTION_ID.test(subscriptionId)) {
      fail(422, 'authority_billing_subscription_invalid', 'Stripe subscription reference is invalid.');
    }
    try {
      subscription = await retrieveSubscription(subscriptionId);
    } catch (cause) {
      fail(503, 'authority_billing_reconciliation_unavailable', 'Current Stripe state is unavailable.', cause);
    }
  }
  const transition = subscriptionTransition(subscription, recordId);
  return requireStore(await store.applyEvent({
    ...transition,
    stripe_event_id: event.id,
    event_type: event.type,
    event_created_at: new Date(event.created * 1000).toISOString(),
  })).entitlement;
}

export async function reconcileAuthorityMonitoring({
  recordId,
  ownerToken,
  authorityStore,
  store,
  retrieveSubscription,
}: {
  recordId: string;
  ownerToken: string;
  authorityStore: AuthorityRecordStore;
  store: AuthorityBillingStore;
  retrieveSubscription: (subscriptionId: string) => Promise<NormalizedSubscription>;
}) {
  await getOwnerAuthorityRecord({ recordId, ownerToken, store: authorityStore });
  const loaded = requireStore(await store.readEntitlement(recordId)).entitlement;
  if (!loaded?.stripe_subscription_id) {
    fail(404, 'authority_billing_subscription_not_found', 'Monitoring subscription not found.');
  }
  let subscription: NormalizedSubscription;
  try {
    subscription = await retrieveSubscription(loaded.stripe_subscription_id);
  } catch (cause) {
    fail(503, 'authority_billing_reconciliation_unavailable', 'Current Stripe state is unavailable.', cause);
  }
  return requireStore(await store.reconcile(subscriptionTransition(subscription, recordId))).entitlement;
}
