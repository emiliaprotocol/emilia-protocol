# Legacy Stripe / EMILIA Gate Cloud billing — inactive runbook

> **Not the current public Gate offer.** The public pricing path is the fixed
> $25,000 managed pilot followed by a production contract scoped by protected
> workflow, deployment boundary, retention, integrations, and service level.
> `/pricing` does not link to these historical Team or Business subscriptions.
> Do not activate them for new customers without an approved offer change.

The site is wired for two billing paths. Pick one (or both). **Neither requires
pasting a secret key into a chat or a file you commit.**

---

## 0. Rotate the leaked key first (required)

A `sk_live_…` secret key was exposed. Before anything else:

1. Stripe Dashboard → **Developers → API keys**
2. **Roll** the leaked secret key (this invalidates it everywhere immediately)
3. Check **Developers → Events / Logs** for any unexpected activity

A leaked live secret key can create charges, refunds, and payouts. Rotation is
not optional.

---

## Path A — Payment Links (simplest, no secret key in the app)

Stripe Payment Links are public `https://buy.stripe.com/…` URLs. They are safe to
expose and need no secret key in the app.

1. Run the setup script with your **rotated** key (key stays in your shell):
   ```bash
   STRIPE_SECRET_KEY=sk_live_your_ROTATED_key node scripts/stripe-setup.mjs
   ```
   It creates the EMILIA Gate Cloud products + prices + payment links and prints the URLs.
   (Edit the `PLANS` amounts in the script first — those are your real prices.)

2. Set the public link URLs in Vercel:
   ```bash
   vercel env add NEXT_PUBLIC_STRIPE_CLOUD_TEAM production       # https://buy.stripe.com/...
   vercel env add NEXT_PUBLIC_STRIPE_CLOUD_BUSINESS production   # https://buy.stripe.com/...
   ```

3. A redeploy only makes the historical link available to code that explicitly
   uses the environment variable. The current `/pricing` page does not use it.

---

## Path B — Embedded Checkout Sessions (`/api/checkout`)

Use this if you want the checkout to launch from your own button/flow.

1. Run `scripts/stripe-setup.mjs` (as above) to get the **Price IDs**.

2. Set server-side env in Vercel (the secret stays in Vercel, never in the repo):
   ```bash
   vercel env add STRIPE_SECRET_KEY production            # your ROTATED key
   vercel env add STRIPE_PRICE_CLOUD_TEAM production       # price_...
   vercel env add STRIPE_PRICE_CLOUD_BUSINESS production   # price_...
   ```

3. `POST /api/checkout { "plan": "team" }` returns `{ url }`; until the env is
   set it returns `503 checkout_unconfigured`. This endpoint is retained for
   historical integrations and is not linked from the current pricing page.

---

## Env var reference

| Var | Path | Secret? | Purpose |
|-----|------|---------|---------|
| `STRIPE_SECRET_KEY` | B | **yes** | Server-side Stripe API key (set in Vercel only) |
| `STRIPE_PRICE_CLOUD_TEAM` | B | no | Price ID for the Team plan |
| `STRIPE_PRICE_CLOUD_BUSINESS` | B | no | Price ID for the Business plan |
| `NEXT_PUBLIC_STRIPE_CLOUD_TEAM` | A | no | Public payment-link URL (Team) |
| `NEXT_PUBLIC_STRIPE_CLOUD_BUSINESS` | A | no | Public payment-link URL (Business) |

> The existing AI Trust Desk uses the same pattern with
> `NEXT_PUBLIC_STRIPE_PACKET / RETAINER / FULL / EMERGENCY` payment links.

---

## EMILIA Works Authority Record monitoring

This is a separate, active private-beta flow. It sells recurring watched-ref
monitoring, freshness history, and presentation depth for an owner-claimed
Authority Record. It never sells a favorable conclusion, certification, trust
score, or safety label.

Create a recurring USD Price for **$29/month** in the EMILIA Stripe account,
then configure these server-only values:

```bash
vercel env add STRIPE_PRICE_AUTHORITY_RECORD_MONITOR production  # price_...
vercel env add STRIPE_WORKS_WEBHOOK_SECRET production             # whsec_...
```

`STRIPE_SECRET_KEY` is shared with the existing server-side Stripe client. The
canonical `NEXT_PUBLIC_APP_URL` must be HTTPS in the deployed environment.

Configure the dedicated webhook endpoint:

`POST https://www.emiliaprotocol.ai/api/works/billing/webhook`

Subscribe it only to:

- `checkout.session.completed`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`

The endpoint verifies the exact raw body with `STRIPE_WORKS_WEBHOOK_SECRET`,
deduplicates Stripe event IDs in PostgreSQL, and retrieves current subscription
state before applying non-deletion events. An owner can invoke the separate
reconciliation route when a webhook outcome is uncertain. Reconciliation does
not manufacture a Stripe event.

Required non-Stripe Works settings:

```bash
vercel env add WORKS_DEMAND_HMAC_KEY production  # at least 32 random bytes
vercel env add WORKS_FROM_EMAIL production       # verified Resend sender
vercel env add WORKS_V0 production               # 1 only when private beta gates pass
```

Before enabling `WORKS_V0`, verify one real test-mode payment end to end: owner
checkout, signed webhook, entitlement projection, cancellation, and owner-led
reconciliation. A configured Price ID is not evidence that payment works.
