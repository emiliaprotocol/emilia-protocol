# Founder TODO — EMILIA Protocol

Working checklist of things **only Iman** can do (anything code-shaped is
already done or claimable in a session). Ordered by **time-to-first-revenue
and revenue-multiplier-per-hour**, not by technical importance.

Update this file as you go — check items off, add notes inline, move
deferred items to the bottom.

> **Status refresh 2026-06-18:** The grant tranche below is largely SENT
> (OpenAI Cybersecurity, Anthropic Research, NSF SBIR pitch, NIST AISIC all
> submitted; AWS Activate applied; SAM.gov registration underway). The
> **highest-EV live thread is now California CDT** — its GenAI program invited
> a vendor submittal and CDT's Office of Information Security has been pitched
> on the human-oversight control. See `~/Documents/emilia-sizzle/EXECUTION-NOW.md`
> and `CALIFORNIA-REFERENCED-CONTROL-STRATEGY.md` (local) for the active plan.
> Remaining founder-only items here: Stripe/pricing, C-corp, advisors, SEO
> submission, and the GovGuard/CDT outbound follow-through.

## Current north star

Read first: [`docs/strategy/FUTURE_OF_TRUST_ADOPTION_PLAN.md`](docs/strategy/FUTURE_OF_TRUST_ADOPTION_PLAN.md)

The operating thesis is:

> EMILIA builds toward the open standard for authorization receipts for irreversible actions.

Decision logs prove it to you. A receipt proves it to everyone else -
auditors, regulators, acquirers - without trusting your logs, your vendor, or
EMILIA.

Use two lanes:

| Lane | This means | Immediate win |
|---|---|---|
| Commercial proof | Spend 80% of founder time on GovGuard observe-mode pilots | About 10 government first-calls held in 90 days |
| Protocol adoption | Spend 20% of founder time making receipts easy to issue, verify, and standardize | Publish `@emilia-protocol/issue` v0.1 and keep one IETF night/week |

---

## ⚡ Today (1–3 hours total — these unlock everything else)

| ☐ | Time | Action | Why it matters |
|---|---|---|---|
| ☐ | 5 min | Create a Stripe account at https://dashboard.stripe.com/register. Share the **test publishable key** + **test secret key** with me in the next session. | Unlocks: I can wire up `/pricing`, Stripe Checkout, customer portal, and the tenant-plan webhook in ~3 hours of one session. Without this, no self-serve revenue. |
| ☐ | 10 min | Decide pricing on Pro / Team / Enterprise tiers. My recommendation: **Free / Pro $299/mo / Team $999/mo / Enterprise custom**. Confirm or counter. | Unlocks the same Stripe wire-up. Pricing is a one-time decision; can be A/B-tested later. |
| ☐ | 5 min | Decide Compliance Pack price (NIST AI RMF + EU AI Act mappings + 30-min consult). My recommendation: **$5K each, $7.5K combined**. Confirm or counter. | Unlocks the highest-margin product (zero engineering, pure asset assembly). |
| ✅ | 5 min | Apply to **AWS Activate Builders** at https://aws.amazon.com/activate/. No proposal needed. | DONE — applied 2026-06-15, credits processing. |
| ☐ | 15 min | Put **AAIF v3** on hold or use informal technical outreach only. Archived reference: [`docs/archive/grants-and-applications-2026-06-29/grant-applications/aaif/cover-email.md`](docs/archive/grants-and-applications-2026-06-29/grant-applications/aaif/cover-email.md). Do **not** submit EMILIA as an AAIF project proposal unless counsel approves the asset/trademark transfer terms. | AAIF project acceptance requires transfer of project trademarks/assets to LF. Keep EMILIA's brand, repo, packages, and commercial products unless there is a deliberate carve-out. |

## 🚀 This week (3–6 hours total)

| ☐ | Time | Action | Why it matters |
|---|---|---|---|
| ✅ | 30 min | Submit **OpenAI Cybersecurity Grant** at https://openai.com/index/cybersecurity-grant-program/. Archived reference: [`docs/archive/grants-and-applications-2026-06-29/grant-applications/openai-cybersecurity/application.md`](docs/archive/grants-and-applications-2026-06-29/grant-applications/openai-cybersecurity/application.md). | DONE — submitted at $250K (credits-weighted). Revision playbook prepped. |
| ✅ | 30 min | Send **Anthropic Research** direct outreach. Archived reference: [`docs/archive/grants-and-applications-2026-06-29/grant-applications/anthropic-research/`](docs/archive/grants-and-applications-2026-06-29/grant-applications/anthropic-research/) for the email and target inboxes. | DONE — External Researcher Access submitted ($10K credits, crumple-zone angle). |
| ◐ | 15 min | Email **NIST AISIC** at aiconsortium@nist.gov using archived reference [`docs/archive/grants-and-applications-2026-06-29/grant-applications/nist-aisic/application.md`](docs/archive/grants-and-applications-2026-06-29/grant-applications/nist-aisic/application.md). | Emailed + they replied: consortium relaunched, now requires the official LOI form (FRN 2026-10779). Form-ready LOI built (`~/Documents/emilia-sizzle/NIST-LOI-FORM-READY.md`) — only the business mailing address left to fill + submit. |
| ◐ | 1 hr | Register at **SAM.gov** (https://sam.gov/) + **research.gov** for NSF SBIR. Takes 1–2 weeks for SAM approval — start in parallel. | In progress — SAM.gov registration underway (incident open at GSA FSD); research.gov/NSF account created. Use ORCID 0009-0004-0290-5433. |
| ✅ | 2 hrs | Submit **NSF SBIR Project Pitch** at https://seedfund.nsf.gov/applications/. Archived reference: [`docs/archive/grants-and-applications-2026-06-29/grant-applications/nsf-sbir-phase-1/application.md`](docs/archive/grants-and-applications-2026-06-29/grant-applications/nsf-sbir-phase-1/application.md). | DONE — Project Pitch submitted (topic AI7 Trustworthy AI, NSF 26-510). |
| ☐ | 30 min | Flip the GitHub org-level setting **"Allow GitHub Actions to create and approve pull requests"** at https://github.com/organizations/futureenterprises/settings/actions (or wherever your org settings live). Also bump default workflow permissions to "Read and write." | Unlocks fully-silent dependabot auto-merge. Without it, the workflow merges but can't approve, and you may need to click approve once per PR. |

## 📈 This week — GovGuard outbound (the critical one)

| ☐ | Time | Action | Why it matters |
|---|---|---|---|
| ☐ | 30 min | Start with **Robin** and the highest-warmth government path. Ask for one intro close to county treasury, procurement finance, benefits, program integrity, or county finance. | Warm government trust beats a polished cold funnel this week. |
| ☐ | 45 min | Send tranche 1 of the GovGuard drafts. Point links at `/govguard`, not `/r/example`. | The page now needs to convert treasurer traffic into a first call, not show a generic demo receipt. |
| ☐ | 30 min | Reply to any ops immediately: calendar holds, forwarded intros, procurement questions, and "what would a pilot look like?" | Momentum dies fastest in government when the next step is fuzzy. |
| ☐ | 30 min | Draft the one-page pilot scope: **60 days, observe mode, one workflow, $25K**. | Gives a buyer something specific enough to forward internally. |
| ☐ | 30 min | Do one standards night: outline "What an authorization receipt proves and what it does not." | Keeps the open-standard story defensible without stealing the week from sales. |

## 🏛️ This month

| ☐ | Time | Action | Why it matters |
|---|---|---|---|
| ☐ | varies | Decide on **Delaware C-corp formation**. Stripe Atlas ($500), Clerky ($300), or attorney ($1.5K). | Required for NIST CRADA, preferred by VCs, makes most grant submissions cleaner. Can wait until first paid pilot, but no later. |
| ☐ | 1 hr | Identify **1–3 advisors** for credibility on grant applications: NIST AISI contact, AAIF reviewer, AI safety academic, formal-methods researcher. A 30-min "would you let me name you as advisor?" ask in your network. | Lifts conversion rate dramatically on every grant, every cold email, every investor pitch. |
| ☐ | varies | Watch https://sam.gov/ + https://www.darpa.mil/work-with-us/ weekly for **DARPA SAFE-AI BAAs**. Archived white paper template: [`docs/archive/grants-and-applications-2026-06-29/grant-applications/darpa-safe-ai/white-paper.md`](docs/archive/grants-and-applications-2026-06-29/grant-applications/darpa-safe-ai/white-paper.md) — rewrite against current positioning before use. | $0.5M–$5M Phase 1; longest cycle but biggest individual award if it lands. |

## 🔍 SEO submission (5–10 min total — do once, never again)

| ☐ | Time | Action | Why it matters |
|---|---|---|---|
| ☐ | 5 min | **Submit sitemap to Google Search Console** at https://search.google.com/search-console. Add `https://www.emiliaprotocol.ai`, verify via HTML tag, then Sitemaps → enter `sitemap.xml`. Walkthrough in [`docs/seo/STRATEGY.md`](docs/seo/STRATEGY.md). | Without this, Google waits to discover the site organically — weeks vs hours. |
| ☐ | 5 min | **Submit sitemap to Bing Webmaster Tools** at https://www.bing.com/webmasters. Easiest: "Import from Google Search Console" once Google is verified. Otherwise add manually + verify same way. | Bing + IndexNow indexes within 24–72h. ChatGPT search uses Bing's index. |
| ☐ | 1 min | After Google verifies, copy the verification meta tag value into `app/layout.js` under `metadata.verification.google` so the verification persists across redeploys. | Otherwise every deploy can theoretically un-verify the site. |
| ☐ | 30 min | Use **URL Inspection → Request Indexing** on the 8 highest-value pages: `/`, `/protocol`, `/govguard`, `/finguard`, `/use-cases/ai-agent`, `/compare/oauth`, `/compare/mcp-auth-alone`, `/blog/mcp-authorization-best-practices`. | Forces a crawl in hours, not days, on the pages most likely to rank. |

## 🐛 Operational debt (do anytime, no urgency)

| ☐ | Time | Action | Notes |
|---|---|---|---|
| ☐ | 30 min | Delete `perf-test-probe-noop` entity from prod Supabase via Studio SQL editor. | Benign artifact from an earlier schema probe; no DELETE API exists for entities so this is the only way. |
| ✅ | 1 hr | Investigate origin of `policy_versions` table referenced in migration 072 — is it from an old removed migration, or should it be created? Decide and either add a fresh migration or remove the reference. | Resolved: `policy_versions` was redundant with `handshake_policies` (versioned by `policy_key` + `version`). The three cloud routes that read it (`/api/cloud/policies/[policyId]/{versions,diff,rollout}`) were repointed at `handshake_policies`; no table was created. The guarded `policy_versions` ALTER branches in 072/087 remain as harmless no-ops. |
| ☐ | 2 hrs | Audit which RLS policies from migration 076 actually exist on prod via Studio. The defensive 088 made it idempotent, but ground-truth verification is worth doing once. | Service role bypasses RLS anyway, so this is defense-in-depth not runtime risk. |
| ☐ | 1 hr | When prod p95 server-time stays below 600ms for a full week, tighten the k6 thresholds in `tests/k6/baseline.js` from 900ms back toward 400–500ms. | The ratchet history is in the file's threshold comment block. |

## 🎯 Stretch goals (only after first revenue)

| ☐ | Notes |
|---|---|
| ☐ Hit **$10K MRR** from self-serve Pro/Team plans | Validates the SaaS funnel exists |
| ☐ Hold **10 government first calls** | The 90-day metric that validates or falsifies the GovGuard wedge |
| ☐ Land **first paid pilot** ($25K+) | Validates the GovGuard observe-mode wedge |
| ☐ Submit **EP Core v1.0 to IETF** as Internet Draft | Standards-body citation surface; not for adoption — for legitimacy |
| ☐ Get **EP cited in one external academic paper or NIST publication** | Same purpose; harder; opens partnership paths |
| ☐ Open **Series A pitch** with $1M+ ARR + 3 named customers | The fundraising story only writes itself when these three numbers are real |

---

## How to use this file

- Check items off as you do them (`☐` → `☑`)
- If something blocks you, add a one-line note inline and move it down
- New action items: add them at the appropriate urgency tier; don't let them rot in your head
- Re-read top-to-bottom every Monday morning. The order is opinionated and may need to shift as reality changes.

The single highest-EV item right now is the **outbound-sales section** — getting one named customer logo unblocks every other lever on this list.
