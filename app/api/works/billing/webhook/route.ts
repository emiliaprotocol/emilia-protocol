// SPDX-License-Identifier: Apache-2.0

import type { NextRequest } from 'next/server';

import { epProblem } from '@/lib/errors';
import { createSupabaseAuthorityBillingStore } from '@/lib/works/billing-store';
import { applyAuthorityStripeEvent, BillingServiceError } from '@/lib/works/billing-service';
import { isWorksV0Enabled } from '@/lib/works/env';
import {
  constructStripeWebhookEvent,
  retrieveStripeSubscription,
} from '@/lib/works/stripe-gateway';

export const runtime = 'nodejs';
const MAX_WEBHOOK_BYTES = 256 * 1024;
const APPLIED_TYPES = new Set([
  'checkout.session.completed',
  'customer.subscription.created',
  'customer.subscription.updated',
  'customer.subscription.deleted',
]);

export async function POST(request: NextRequest) {
  if (!isWorksV0Enabled()) return epProblem(404, 'not_found', 'Not found');
  const signature = request.headers.get('stripe-signature');
  const secret = process.env.STRIPE_WORKS_WEBHOOK_SECRET;
  if (!signature) return epProblem(400, 'stripe_signature_missing', 'Stripe signature is required.');
  if (!secret || !process.env.STRIPE_SECRET_KEY) {
    return epProblem(503, 'authority_billing_unconfigured', 'Monitoring billing is unavailable.');
  }
  const declared = Number(request.headers.get('content-length') || '0');
  if (Number.isFinite(declared) && declared > MAX_WEBHOOK_BYTES) {
    return epProblem(413, 'payload_too_large', 'Webhook body is too large.');
  }
  const rawBody = await request.text();
  if (Buffer.byteLength(rawBody, 'utf8') > MAX_WEBHOOK_BYTES) {
    return epProblem(413, 'payload_too_large', 'Webhook body is too large.');
  }
  try {
    const event: any = await constructStripeWebhookEvent(rawBody, signature, secret);
    if (!APPLIED_TYPES.has(event.type)) {
      return Response.json({ received: true, applied: false });
    }
    await applyAuthorityStripeEvent({
      event,
      retrieveSubscription: retrieveStripeSubscription,
      store: createSupabaseAuthorityBillingStore(),
    });
    return Response.json({ received: true, applied: true });
  } catch (error) {
    if (error instanceof BillingServiceError) {
      return epProblem(error.status, error.code, error.message);
    }
    return epProblem(400, 'stripe_signature_invalid', 'Stripe webhook signature is invalid.');
  }
}
