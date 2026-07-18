# Stripe / EMILIA Gate Cloud billing — setup runbook

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

3. Redeploy. The `/pricing` "EMILIA Gate Cloud" CTA now links straight to checkout.

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

3. Redeploy. `POST /api/checkout { "plan": "team" }` returns `{ url }`; until the
   env is set it returns `503 checkout_unconfigured` and the page falls back to
   "request early access" — so nothing breaks before billing is live.

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
