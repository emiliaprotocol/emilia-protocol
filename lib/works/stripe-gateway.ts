// SPDX-License-Identifier: Apache-2.0

import type { NormalizedSubscription } from './billing-service.js';

async function client() {
  const secret = process.env.STRIPE_SECRET_KEY;
  if (!secret) throw new Error('Stripe is not configured');
  const { default: Stripe } = await import('stripe');
  return new Stripe(secret);
}

export function assertMonitoringPrice(price: any): void {
  if (price?.active !== true
      || price.currency !== 'usd'
      || price.unit_amount !== 2900
      || price.type !== 'recurring'
      || price.recurring?.interval !== 'month'
      || price.recurring?.interval_count !== 1) {
    throw new Error('monitoring price mismatch');
  }
}

export async function createStripeCheckout(input: {
  mode: 'subscription';
  priceId: string;
  recordId: string;
  successUrl: string;
  cancelUrl: string;
  metadata: { record_id: string; purchase_scope: 'monitoring_freshness_and_presentation' };
}) {
  const stripe = await client();
  const price = await stripe.prices.retrieve(input.priceId);
  assertMonitoringPrice(price);
  const session = await stripe.checkout.sessions.create({
    mode: input.mode,
    line_items: [{ price: input.priceId, quantity: 1 }],
    success_url: input.successUrl,
    cancel_url: input.cancelUrl,
    client_reference_id: input.recordId,
    allow_promotion_codes: true,
    billing_address_collection: 'auto',
    metadata: input.metadata,
    subscription_data: { metadata: input.metadata },
  });
  return { url: session.url };
}

export async function retrieveStripeSubscription(subscriptionId: string): Promise<NormalizedSubscription> {
  const stripe = await client();
  const subscription: any = await stripe.subscriptions.retrieve(subscriptionId);
  return {
    id: subscription.id,
    status: subscription.status,
    customerId: typeof subscription.customer === 'string'
      ? subscription.customer : subscription.customer?.id,
    currentPeriodEnd: Number.isInteger(subscription.current_period_end)
      ? subscription.current_period_end : null,
    metadata: subscription.metadata || {},
  };
}

export async function constructStripeWebhookEvent(
  rawBody: string,
  signature: string,
  webhookSecret: string,
) {
  const stripe = await client();
  return stripe.webhooks.constructEvent(rawBody, signature, webhookSecret);
}
