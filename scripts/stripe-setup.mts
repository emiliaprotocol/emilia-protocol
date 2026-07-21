/* eslint-disable no-console */
/**
 * EMILIA Protocol — full Stripe pricing setup.
 * @license Apache-2.0
 *
 * Creates EVERY priced product across the project (AI Trust Desk + EMILIA Gate Cloud) as
 * Stripe products + prices + payment links, then writes the resulting public
 * env values to `.stripe-vars.json` (price IDs + payment links — NO secrets).
 *
 *   node scripts/stripe-setup.mts
 *
 * Reads STRIPE_SECRET_KEY from your shell, or from .env.local / .env (non-blank).
 * Because Vercel marks the key "Sensitive", `vercel env pull` writes it BLANK —
 * so paste your rotated key into .env.local manually (see the error below).
 *
 * IDEMPOTENT: products are tagged with metadata.ep_key and reused on re-run, so
 * running this twice will NOT create duplicates. Edit an amount and re-run to add
 * a new price + payment link for the changed tier.
 */
import process from 'node:process';
import { readFileSync, existsSync, writeFileSync } from 'node:fs';

interface ProductDefinition {
  key: string;
  name: string;
  amount: number;
  interval: string | null;
  desc: string;
  priceEnv?: string;
  linkEnv: string;
}

// ── Load STRIPE_SECRET_KEY from .env.local / .env (ignoring blank values) ──────
if (!process.env.STRIPE_SECRET_KEY) {
  for (const f of ['.env.local', '.env']) {
    if (!existsSync(f)) continue;
    for (const line of readFileSync(f, 'utf8').split('\n')) {
      const m: RegExpMatchArray | null = line.match(/^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
      if (!m) continue;
      const val: string = m[2].replace(/^["']|["']$/g, '');
      if (val && !(m[1] in process.env)) process.env[m[1]] = val; // skip blanks
    }
  }
}

const key: string | undefined = process.env.STRIPE_SECRET_KEY;
if (!key) {
  console.error(`
✗ STRIPE_SECRET_KEY not found.

  Vercel marks it "Sensitive", so \`vercel env pull\` writes it BLANK — that's why
  it can't be read automatically. Fix in 10 seconds:

    1. open .env.local
    2. set:   STRIPE_SECRET_KEY=sk_live_your_rotated_key   (replace the blank line)
    3. re-run: node scripts/stripe-setup.mjs
`);
  process.exit(2);
}
if (!key.startsWith('sk_')) {
  console.error('✗ STRIPE_SECRET_KEY is not a Stripe secret key (must start with sk_).');
  process.exit(2);
}
if (key.startsWith('sk_live_')) console.log('⚠  LIVE key — creating real, chargeable products.\n');

// ── The full project price book ───────────────────────────────────────────────
// amount = USD cents. interval = 'month' for recurring, null for one-time.
// Trust Desk amounts mirror the live /trust-desk page. EDIT only the EMILIA Gate Cloud ones.
const PRODUCTS: ProductDefinition[] = [
  // AI Trust Desk — fixed-scope engagements (prices already published on /trust-desk)
  { key: 'td_emergency', name: 'AI Trust Desk — Emergency Review', amount: 350000, interval: null, desc: 'Fixed-scope emergency questionnaire review.', linkEnv: 'NEXT_PUBLIC_STRIPE_EMERGENCY' },
  { key: 'td_full', name: 'AI Trust Desk — Full Completion', amount: 950000, interval: null, desc: 'Full questionnaire completion.', linkEnv: 'NEXT_PUBLIC_STRIPE_FULL' },
  { key: 'td_packet', name: 'AI Trust Desk — AI Trust Packet', amount: 2450000, interval: null, desc: 'Full AI Trust Packet engagement.', linkEnv: 'NEXT_PUBLIC_STRIPE_PACKET' },
  { key: 'td_retainer', name: 'AI Trust Desk — Retainer', amount: 1200000, interval: 'month', desc: 'Ongoing retainer, 3-month minimum.', linkEnv: 'NEXT_PUBLIC_STRIPE_RETAINER' },

  // EMILIA Gate Cloud — monthly subscriptions.  ◀── EDIT THESE TWO AMOUNTS to your real prices
  { key: 'cloud_team', name: 'EMILIA Gate Cloud — Team', amount: 49900, interval: 'month', desc: 'Hosted control plane: managed policies, signoff orchestration, audit exports.', priceEnv: 'STRIPE_PRICE_CLOUD_TEAM', linkEnv: 'NEXT_PUBLIC_STRIPE_CLOUD_TEAM' },
  { key: 'cloud_business', name: 'EMILIA Gate Cloud — Business', amount: 250000, interval: 'month', desc: 'Higher limits, webhooks, multi-tenant isolation, priority support.', priceEnv: 'STRIPE_PRICE_CLOUD_BUSINESS', linkEnv: 'NEXT_PUBLIC_STRIPE_CLOUD_BUSINESS' },
];

const { default: Stripe } = await import('stripe');
const stripe: any = new Stripe(key);

async function findOrCreateProduct(p: ProductDefinition): Promise<any> {
  const list: any = await stripe.products.list({ limit: 100, active: true });
  const found: any = list.data.find((x: any) => x.metadata?.ep_key === p.key);
  if (found) return found;
  return stripe.products.create({ name: p.name, description: p.desc, metadata: { ep_key: p.key, ep_setup: 'v1' } });
}

async function findOrCreatePrice(product: any, p: ProductDefinition): Promise<any> {
  const prices: any = await stripe.prices.list({ product: product.id, active: true, limit: 100 });
  const match: any = prices.data.find(
    (pr: any) => pr.unit_amount === p.amount
      && (p.interval ? pr.recurring?.interval === p.interval : !pr.recurring),
  );
  if (match) return match;
  return stripe.prices.create({
    product: product.id,
    currency: 'usd',
    unit_amount: p.amount,
    ...(p.interval ? { recurring: { interval: p.interval } } : {}),
  });
}

async function findOrCreateLink(product: any, price: any): Promise<any> {
  const existingId: string | undefined = product.metadata?.ep_link_id;
  if (existingId) {
    try {
      const l: any = await stripe.paymentLinks.retrieve(existingId);
      if (l?.active) return l;
    } catch { /* fall through and recreate */ }
  }
  const link: any = await stripe.paymentLinks.create({ line_items: [{ price: price.id, quantity: 1 }] });
  await stripe.products.update(product.id, { metadata: { ...product.metadata, ep_link_id: link.id } });
  return link;
}

const env: Record<string, string> = {};
for (const p of PRODUCTS) {
  const product: any = await findOrCreateProduct(p);
  const price: any = await findOrCreatePrice(product, p);
  const link: any = await findOrCreateLink(product, price);
  if (p.priceEnv) env[p.priceEnv] = price.id;
  if (p.linkEnv) env[p.linkEnv] = link.url;
  const money = `$${(p.amount / 100).toLocaleString('en-US')}${p.interval ? '/mo' : ''}`;
  console.log(`✓ ${p.name.padEnd(38)} ${money}`);
  if (p.priceEnv) console.log(`    ${p.priceEnv}=${price.id}`);
  console.log(`    ${p.linkEnv}=${link.url}`);
}

writeFileSync('.stripe-vars.json', `${JSON.stringify(env, null, 2)}\n`);
console.log(`\nWrote .stripe-vars.json — ${Object.keys(env).length} public vars (price IDs + payment links, no secrets).`);
console.log('Next: tell your assistant "done" and it will wire these into Vercel + redeploy.');
console.log('(Or set them yourself; the file is gitignored.)');
