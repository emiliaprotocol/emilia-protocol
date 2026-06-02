/* eslint-disable no-console */
/**
 * EMILIA Protocol — Stripe pricing setup.
 * @license Apache-2.0
 *
 * Run ONCE with YOUR OWN (rotated) secret key to create the EP Cloud products,
 * monthly prices, and payment links in Stripe — then it prints the IDs/URLs and
 * the exact `vercel env add` commands to wire them.
 *
 *   STRIPE_SECRET_KEY=sk_live_xxx node scripts/stripe-setup.mjs
 *
 * The key is read from your shell environment and is NEVER written to disk or
 * echoed. Edit the PLANS amounts below to your real prices before running.
 *
 * Re-running creates NEW products/prices each time (Stripe has no upsert on
 * name) — run once, or archive duplicates in the dashboard afterward.
 */
import process from 'node:process';

// ── EDIT THESE: your real EP Cloud prices (USD cents, billed monthly) ──────
const PLANS = [
  {
    key: 'team',
    name: 'EP Cloud — Team',
    amount: 9900,
    description: 'Hosted control plane: managed policy registry, signoff orchestration, audit exports.',
  },
  {
    key: 'business',
    name: 'EP Cloud — Business',
    amount: 49900,
    description: 'Higher limits, webhooks, multi-tenant isolation, and priority support.',
  },
];
// ───────────────────────────────────────────────────────────────────────────

const key = process.env.STRIPE_SECRET_KEY;
if (!key) {
  console.error('✗ Set STRIPE_SECRET_KEY in your shell (use your ROTATED key). Aborting.');
  process.exit(2);
}
if (!key.startsWith('sk_')) {
  console.error('✗ STRIPE_SECRET_KEY does not look like a Stripe secret key. Aborting.');
  process.exit(2);
}
if (key.startsWith('sk_live_')) {
  console.log('⚠  Using a LIVE key — this creates real, chargeable products.\n');
}

const { default: Stripe } = await import('stripe');
const stripe = new Stripe(key);

const out = {};
for (const plan of PLANS) {
  const product = await stripe.products.create({ name: plan.name, description: plan.description });
  const price = await stripe.prices.create({
    product: product.id,
    currency: 'usd',
    unit_amount: plan.amount,
    recurring: { interval: 'month' },
  });
  const link = await stripe.paymentLinks.create({ line_items: [{ price: price.id, quantity: 1 }] });
  out[plan.key] = { price: price.id, url: link.url };
  console.log(`\n${plan.name}`);
  console.log(`  product: ${product.id}`);
  console.log(`  price:   ${price.id}  ($${(plan.amount / 100).toFixed(2)}/mo)`);
  console.log(`  link:    ${link.url}`);
}

console.log('\n──────── wire these env vars (Vercel) ────────');
console.log('# Embedded checkout (/api/checkout):');
console.log(`STRIPE_PRICE_CLOUD_TEAM=${out.team?.price ?? ''}`);
console.log(`STRIPE_PRICE_CLOUD_BUSINESS=${out.business?.price ?? ''}`);
console.log('# Payment-link fallback (no secret key needed, public URLs):');
console.log(`NEXT_PUBLIC_STRIPE_CLOUD_TEAM=${out.team?.url ?? ''}`);
console.log(`NEXT_PUBLIC_STRIPE_CLOUD_BUSINESS=${out.business?.url ?? ''}`);
console.log('\nSet the secret too (for embedded checkout):  vercel env add STRIPE_SECRET_KEY production');
console.log('Then redeploy — /pricing goes live.\n');
