import { NextResponse } from 'next/server';
import { epProblem } from '@/lib/errors';
import { logger } from '../../../lib/logger.js';
import { readLimitedJson } from '@/lib/http/body-limit';

export const runtime = 'nodejs';

/**
 * POST /api/checkout
 *
 * Creates a Stripe Checkout Session for an EP Cloud plan and returns its URL.
 *
 * The secret key and Price IDs are read from server-side env — never from the
 * client, never hardcoded. Run `scripts/stripe-setup.mjs` (with your own
 * rotated key) to create the prices, then set:
 *   STRIPE_SECRET_KEY, STRIPE_PRICE_CLOUD_TEAM, STRIPE_PRICE_CLOUD_BUSINESS
 *
 * If those are unset, this returns 503 and the /pricing page falls back to the
 * "request early access" flow — so the site never breaks before billing is wired.
 *
 * Body: { plan: "team" | "business" }
 * Returns: { url } | RFC-7807 problem
 */
const PRICE_ENV = {
  team: 'STRIPE_PRICE_CLOUD_TEAM',
  business: 'STRIPE_PRICE_CLOUD_BUSINESS',
};
const MAX_CHECKOUT_BYTES = 2 * 1024;

function siteOrigin(request) {
  const configured = process.env.NEXT_PUBLIC_APP_URL || process.env.NEXT_PUBLIC_SITE_URL || '';
  if (configured) {
    const parsed = new URL(configured);
    if (process.env.NODE_ENV === 'production' && parsed.protocol !== 'https:') {
      throw new Error('checkout origin must be HTTPS in production');
    }
    return parsed.origin;
  }
  if (process.env.NODE_ENV === 'production') {
    throw new Error('checkout origin is not configured');
  }
  return new URL(request.url).origin;
}

export async function POST(request) {
  try {
    const parsed = await readLimitedJson(request, MAX_CHECKOUT_BYTES, { invalidValue: {} });
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    const plan = typeof body.plan === 'string' ? body.plan : '';
    const priceEnv = PRICE_ENV[plan];
    if (!priceEnv) {
      return epProblem(400, 'invalid_plan', 'Unknown plan. Expected one of: team, business.');
    }

    const secret = process.env.STRIPE_SECRET_KEY;
    const priceId = process.env[priceEnv];
    if (!secret || !priceId) {
      return epProblem(503, 'checkout_unconfigured', 'Stripe checkout is not configured yet.');
    }

    const { default: Stripe } = await import('stripe');
    const stripe = new Stripe(secret);
    let origin;
    try {
      origin = siteOrigin(request);
    } catch (err) {
      logger.error?.('checkout: canonical origin unavailable', { error: err.message });
      return epProblem(503, 'checkout_origin_unconfigured', 'Checkout canonical origin is not configured.');
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      allow_promotion_codes: true,
      billing_address_collection: 'auto',
      success_url: `${origin}/pricing?status=success&plan=${encodeURIComponent(plan)}`,
      cancel_url: `${origin}/pricing?status=cancelled`,
    });

    return NextResponse.json({ url: session.url });
  } catch (err) {
    logger.error?.('checkout: failed to create session', { error: err.message });
    return epProblem(500, 'checkout_failed', 'Could not create a checkout session.');
  }
}
