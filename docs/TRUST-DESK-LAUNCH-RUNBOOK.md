# AI Trust Desk — Launch Runbook

**Goal:** go from "engine works" to "first paid customer" with nothing missed.
**Status of the product:** the full pipeline is LIVE and verified in production
(intake → Claude-assisted answers → signed page → buyer verification). What
remains below is business plumbing, not engineering.

Legend: **[YOU]** = you must do it (account/payment/legal). **[ME]** = Claude can
do it once you provide the value (set env vars, wire, test). **[SHARED]** = we do
it together.

---

## PHASE 0 — Already done ✅ (no action)

- Pipeline: extract → classify → answer → verify → sign → publish (verified in prod)
- Supabase backend live (tables `trust_desk_engagements`, `trust_desk_pages`)
- Env set on Vercel: `ANTHROPIC_API_KEY`, `ATD_SIGNING_KEY`, `TRUST_DESK_STORE=supabase`, `TRUST_DESK_INTERNAL_TOKEN`
- Reviewer dashboard: `/internal/trust-desk` (login via `/internal/trust-desk/auth?token=…`)
- Buyer verify endpoint: `/api/trust-desk/verify/<slug>`
- Daily expiry-monitor cron wired (`/api/cron/trust-desk-monitor`)

---

## PHASE 1 — Money: Stripe (≈45 min)  ← biggest blocker

Without this, the "Buy" buttons fall back to a `mailto:` — you can still invoice
manually, but no self-serve checkout.

### 1.1 [YOU] Create / log into Stripe
- https://stripe.com → sign up (or log in) as **EMILIA Protocol, Inc.** (Delaware C-Corp).
- Complete **business profile**: legal entity, EIN, address, support email
  (`team@emiliaprotocol.ai`), statement descriptor ("EMILIA TRUST DESK").
- Add a **bank account** for payouts (requires the business bank account — see Phase 4).
- Stripe will run identity verification; can take 1–2 days to fully activate
  payouts, but you can create payment links immediately in test then live.

### 1.2 [YOU] Create 4 Payment Links (Stripe Dashboard → Payment Links → New)
Create one **Product + Price** per tier, then a Payment Link for each:

| Tier | Price | Type | Env var the site reads |
|------|-------|------|------------------------|
| Emergency Review | $3,500 | one-time | `NEXT_PUBLIC_STRIPE_EMERGENCY` |
| Full Completion | $9,500 | one-time | `NEXT_PUBLIC_STRIPE_FULL` |
| AI Trust Packet | $24,500 | one-time | `NEXT_PUBLIC_STRIPE_PACKET` |
| Retainer | $12,000/mo | recurring monthly | `NEXT_PUBLIC_STRIPE_RETAINER` |

For each link, in **Advanced options**:
- Turn ON **"Collect customer email"** (you need it to match the intake).
- (Optional) Add a field "Engagement reference" so you can tie payment ↔ engagement.
- Set **after-payment**: redirect to `https://www.emiliaprotocol.ai/trust-desk/upload`
  (so paid customers land on the intake form).
- Copy the resulting URL (looks like `https://buy.stripe.com/xxxx`).

### 1.3 [ME] Set the 4 URLs on Vercel
Send me the 4 `https://buy.stripe.com/...` links and I'll run:
```
vercel env add NEXT_PUBLIC_STRIPE_EMERGENCY production   # (repeat per tier)
```
then redeploy. The "Buy" buttons go live immediately.

### 1.4 [SHARED] (Recommended, later) Stripe webhook → auto-mark paid
Right now the form runs the pipeline on submit regardless of payment. For
launch that's fine (you collect payment via the link, then they fill the form).
To enforce "pay first, then pipeline runs," we add a Stripe webhook
(`checkout.session.completed`) → flips an engagement to `paid`. ~2h of work —
do it after first revenue, not before.

### 1.5 [YOU] Decide: test mode first?
Recommend doing ONE end-to-end purchase in **Stripe test mode** (test card
`4242 4242 4242 4242`) before flipping live. I can point the env vars at test
links first, then swap to live.

---

## PHASE 2 — Email: Resend + domain (≈30 min + DNS propagation)

Without this, customers don't get the "your trust page is live" email (the page
still publishes; you'd just notify manually).

### 2.1 [YOU] Create Resend account
- https://resend.com → sign up.
- **Add domain** `emiliaprotocol.ai`.

### 2.2 [SHARED] Add DNS records to verify the domain
Resend shows 3 records (SPF, DKIM, DMARC). The domain's DNS is on **Vercel**
(or your registrar). Add the records there:
- `MX` / `TXT` (SPF): `send.emiliaprotocol.ai` ...
- `TXT` (DKIM): `resend._domainkey` ...
- `TXT` (DMARC): `_dmarc` ...
I can add these via the Vercel DNS CLI if the domain's nameservers are Vercel —
paste me the exact records Resend gives you. Propagation: minutes to ~1 hour.

### 2.3 [YOU] Generate API key + [ME] set it
- Resend → API Keys → create (name "trust-desk-prod"). Copy `re_...`.
- Send it to me; I set:
```
vercel env add RESEND_API_KEY production
vercel env add TRUST_DESK_FROM_EMAIL production   # value: AI Trust Desk <trust@emiliaprotocol.ai>
```
(⚠️ as with the Claude key — once you paste it here, rotate it after if you want;
or set it yourself in the Vercel dashboard and just tell me it's done.)

### 2.4 [ME] Test a real send
I'll run an intake through prod and confirm the customer email actually delivers.

### 2.5 [YOU] Inbox for `team@emiliaprotocol.ai`
The site uses `team@emiliaprotocol.ai` for contact + the Stripe descriptor.
Make sure that inbox exists and you monitor it:
- Google Workspace on emiliaprotocol.ai (recommended), or
- An email-forwarding rule to your personal inbox.

---

## PHASE 3 — Legal & trust basics (≈2–4 h, can parallel Phases 1–2)

The FAQ on the landing page promises an MSA on intake and makes liability
claims — you need the docs to back them.

### 3.1 [YOU] Master Services Agreement (MSA)
- The thing you send a customer on intake. Covers scope, your liability for
  analysis/platform vs. their liability for claim accuracy, payment terms,
  confidentiality.
- Fastest path: a template from Stripe Atlas / Clerky / a startup-lawyer
  (Cooley GO has free templates), then a 1-hour lawyer review. Budget $500–1,500.

### 3.2 [YOU] Terms of Service + Privacy Policy
- You already have `/legal/terms`, `/legal/privacy`, `/legal/acceptable-use`,
  `/legal/sub-processors` on the site — **review them** and make sure they cover
  the Trust Desk service specifically (you're processing customers' security
  questionnaires + product info). Add the AI subprocessors you actually use
  (OpenAI, Anthropic) to `/legal/sub-processors`.

### 3.3 [YOU] Confidentiality / data handling
- You're handling customers' internal security details. State retention +
  deletion in the MSA. Offer NDA-on-request (the FAQ says this).

### 3.4 [SHARED] Honesty pass on claims
- Marketing now says "drafted automatically, source-cited, human signs off on
  escalations." Make sure your actual operating procedure matches (you DO review
  escalations). Don't claim a SOC 2 you don't have, etc.

---

## PHASE 4 — Entity & banking (do first if not already done)

Stripe payouts need a business bank account.

### 4.1 [YOU] Business entity
- Formed: **EMILIA Protocol, Inc.** — Delaware C-Corp, incorporated 2026-06-03 via
  Stripe Atlas (entity + EIN + bank intro in one flow).

### 4.2 [YOU] EIN + business bank account
- EIN from IRS (free, instant online) → business bank (Mercury / Brex are fast,
  startup-friendly) → connect to Stripe for payouts.

---

## PHASE 5 — Operational readiness (≈1 h)

### 5.1 [ME, then YOU] Reviewer workflow
- Dashboard: `https://www.emiliaprotocol.ai/internal/trust-desk/auth?token=<YOUR_TOKEN>`
  (your token is in your password manager — I generated it earlier).
- When an engagement **escalates**, it shows in the "Escalations" queue. Your job:
  open it, finish the flagged questions by hand, re-publish. (We can add an
  "edit + republish" UI later; for now escalations are handled by you editing
  the answers + re-running.)

### 5.2 [YOU] Slack (optional but recommended)
- Create an incoming webhook in your Slack → send me the URL → I set
  `TRUST_DESK_SLACK_WEBHOOK`. Then you get a ping on every publish + escalation.

### 5.3 [SHARED] First-response SLA
- Decide your real SLA. The site says "minutes for most; up to 4h if escalated."
  Make sure you can actually hit 4h during business hours before you promise it.

---

## PHASE 6 — Pre-launch QA checklist (≈30 min, mostly [ME])

- [ ] [ME] End-to-end with Stripe test link → form → published page → customer email received
- [ ] [ME] Buyer verify endpoint returns `verified: true` for a fresh page
- [ ] [YOU] Click every "Buy" button on `/trust-desk` → lands on correct Stripe checkout
- [ ] [YOU] Submit the intake form yourself with a real `.xlsx` and a `.pdf` → confirms binary parsing
- [ ] [YOU] Open a published page as if you were the buyer → does it look credible?
- [ ] [YOU] Confirm `team@emiliaprotocol.ai` receives a test email
- [ ] [ME] Confirm `/internal/trust-desk` is gated (no token = no access)
- [ ] [YOU] Read the MSA one more time

---

## PHASE 7 — Go-to-market: first 5 customers (the real work)

The product is for **AI vendors selling into financial services** who have a
**stuck enterprise security review**. That's your ICP.

### 7.1 Find them
- LinkedIn / Crunchbase: AI startups (seed–Series B) selling to banks, fintechs,
  insurers, credit unions. Titles: founder, head of security, head of sales.
- Signals they're stuck: hiring a "security/compliance" person, recent SOC 2
  announcement, case studies with financial logos.
- The repo already has 3 cold-email buckets drafted:
  `content/trust-desk/emails/bucket-1-agent-platforms.md`,
  `bucket-2-fraud-aml.md`, `bucket-3-neobanks.md`.

### 7.2 The offer that converts
- Lead with the pain: "Enterprise buyer sent you a 60-question AI security
  review? We answer it + publish a verifiable trust page in minutes, not weeks."
- First-customer tactic: offer the **first 3 design partners** a steep discount
  (or free Emergency tier) in exchange for a logo + testimonial. This seeds the
  case studies you need for the strategy brief's acquisition story.

### 7.3 Channels
- Direct outreach (the 3 email buckets) — highest signal for B2B at this price.
- Post the "what changes Aug 2 (EU AI Act)" angle — you already have `/eu-ai-act`.
- Founder network / warm intros to AI startups with financial customers.

---

## PHASE 8 — Launch day

1. [ME] Flip Stripe env vars from test → live links; redeploy.
2. [YOU] Do ONE real $3,500 purchase yourself (or a friendly design partner) to
   confirm live payments + payout.
3. [YOU] Send the first batch of cold emails (start with 10, not 100 — learn first).
4. [ME] Watch logs/Sentry for the first real intakes; I'll triage any errors.
5. [YOU] Be on call for the 4h SLA the first week.

---

## PHASE 9 — Week 1–4 after launch

- [ ] Add the Stripe webhook (Phase 1.4) so payment → pipeline is enforced.
- [ ] Build the "edit escalated answer + republish" reviewer UI.
- [ ] First Shadow Mode Report from a real design partner (see strategy supplement).
- [ ] Rotate the API keys that were pasted in chat (Anthropic + Resend).
- [ ] Add Sentry alerting on pipeline failures.
- [ ] Collect 1 logo + 1 testimonial → put on `/trust-desk`.

---

## The critical path (if you only do the minimum to take a dollar)

1. **Stripe**: 4 payment links → I set 4 env vars. (Phase 1)
2. **Bank/entity** so Stripe can pay out. (Phase 4)
3. **MSA** to send on intake. (Phase 3.1)
4. **`team@` inbox** + **Resend** so customers hear from you. (Phase 2)
5. **10 cold emails** to the ICP. (Phase 7)

Everything else is optimization. The engine already runs.

---

## What I (Claude) can knock out the moment you send me values

- Set all Stripe + Resend + Slack env vars and redeploy.
- Add Resend DNS records via Vercel CLI (if domain is on Vercel nameservers).
- Run end-to-end QA with real test purchases + confirm email delivery.
- Build the Stripe webhook + the reviewer republish UI.
- Add the OpenAI/Anthropic entries to `/legal/sub-processors`.
