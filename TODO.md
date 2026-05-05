# Founder TODO — EMILIA Protocol

Working checklist of things **only Iman** can do (anything code-shaped is
already done or claimable in a session). Ordered by **time-to-first-revenue
and revenue-multiplier-per-hour**, not by technical importance.

Update this file as you go — check items off, add notes inline, move
deferred items to the bottom.

---

## ⚡ Today (1–3 hours total — these unlock everything else)

| ☐ | Time | Action | Why it matters |
|---|---|---|---|
| ☐ | 5 min | Create a Stripe account at https://dashboard.stripe.com/register. Share the **test publishable key** + **test secret key** with me in the next session. | Unlocks: I can wire up `/pricing`, Stripe Checkout, customer portal, and the tenant-plan webhook in ~3 hours of one session. Without this, no self-serve revenue. |
| ☐ | 10 min | Decide pricing on Pro / Team / Enterprise tiers. My recommendation: **Free / Pro $299/mo / Team $999/mo / Enterprise custom**. Confirm or counter. | Unlocks the same Stripe wire-up. Pricing is a one-time decision; can be A/B-tested later. |
| ☐ | 5 min | Decide Compliance Pack price (NIST AI RMF + EU AI Act mappings + 30-min consult). My recommendation: **$5K each, $7.5K combined**. Confirm or counter. | Unlocks the highest-margin product (zero engineering, pure asset assembly). |
| ☐ | 5 min | Apply to **AWS Activate Builders** at https://aws.amazon.com/activate/. No proposal needed. | $5K AWS credits in 24h. Free. Lowest-friction grant on the list. |
| ☐ | 10 min | Send the **AAIF v3** proposal. See [`docs/grant-applications/aaif/cover-email.md`](docs/grant-applications/aaif/cover-email.md) for the email body. Attach `docs/AAIF-PROPOSAL-v3.md` (pandoc to PDF if they want PDF). | Already drafted; literally one paste-and-send. |

## 🚀 This week (3–6 hours total)

| ☐ | Time | Action | Why it matters |
|---|---|---|---|
| ☐ | 30 min | Submit **OpenAI Cybersecurity Grant** at https://openai.com/index/cybersecurity-grant-program/. Content drafted at [`docs/grant-applications/openai-cybersecurity/application.md`](docs/grant-applications/openai-cybersecurity/application.md). | $10K–$1M cash + API credits, quarterly review. Real money. |
| ☐ | 30 min | Send **Anthropic Research** direct outreach. See [`docs/grant-applications/anthropic-research/`](docs/grant-applications/anthropic-research/) for the email and target inboxes. | Even without grants, gets EP onto the radar of Anthropic's safety team — unlocks every future engagement. |
| ☐ | 15 min | Email **NIST AISIC** at aiconsortium@nist.gov using [`docs/grant-applications/nist-aisic/application.md`](docs/grant-applications/nist-aisic/application.md). | Free; non-monetary; **credibility multiplier for every other grant on this list**. |
| ☐ | 1 hr | Register at **SAM.gov** (https://sam.gov/) + **research.gov** for NSF SBIR. Takes 1–2 weeks for SAM approval — start in parallel. | Required for NSF SBIR full Phase I. Does not block the Project Pitch step below. |
| ☐ | 2 hrs | Submit **NSF SBIR Project Pitch** at https://seedfund.nsf.gov/applications/. Content drafted at [`docs/grant-applications/nsf-sbir-phase-1/application.md`](docs/grant-applications/nsf-sbir-phase-1/application.md). | $305K Phase I award. Highest-dollar program on the list. Pitch is 3 pages, free, fast review. |
| ☐ | 30 min | Flip the GitHub org-level setting **"Allow GitHub Actions to create and approve pull requests"** at https://github.com/organizations/futureenterprises/settings/actions (or wherever your org settings live). Also bump default workflow permissions to "Read and write." | Unlocks fully-silent dependabot auto-merge. Without it, the workflow merges but can't approve, and you may need to click approve once per PR. |

## 📈 This week — outbound sales (the critical one)

| ☐ | Time | Action | Why it matters |
|---|---|---|---|
| ☐ | 1 hr | Build a list of **20 named AI agent platforms** to email. Crunchbase filter: "AI agents" + Series A–C + USA. Get founder + Head-of-Trust emails. Tool: Apollo.io ($79/mo) or LinkedIn Sales Navigator ($99/mo). | These are the fastest-cycle ICP. 4–8 week sales, $20K–$80K ARR per close. |
| ☐ | 1 hr | Personalize the cold-email template (in my last monetization summary) for the top 10. First sentence references something specific they shipped this month. | 1–3% reply rate × 50% call rate × 10% close = 1 deal per 100 sends. |
| ☐ | 30 min | Send the first 50 cold emails. | 0 → 1 named customer is the only thing that compounds. Until you have one logo, every other lever is theater. |

## 🏛️ This month

| ☐ | Time | Action | Why it matters |
|---|---|---|---|
| ☐ | varies | Decide on **Delaware C-corp formation**. Stripe Atlas ($500), Clerky ($300), or attorney ($1.5K). | Required for NIST CRADA, preferred by VCs, makes most grant submissions cleaner. Can wait until first paid pilot, but no later. |
| ☐ | 1 hr | Identify **1–3 advisors** for credibility on grant applications: NIST AISI contact, AAIF reviewer, AI safety academic, formal-methods researcher. A 30-min "would you let me name you as advisor?" ask in your network. | Lifts conversion rate dramatically on every grant, every cold email, every investor pitch. |
| ☐ | varies | Watch https://sam.gov/ + https://www.darpa.mil/work-with-us/ weekly for **DARPA SAFE-AI BAAs**. White paper template ready at [`docs/grant-applications/darpa-safe-ai/white-paper.md`](docs/grant-applications/darpa-safe-ai/white-paper.md) — customize against the BAA when one drops. | $0.5M–$5M Phase 1; longest cycle but biggest individual award if it lands. |

## 🐛 Operational debt (do anytime, no urgency)

| ☐ | Time | Action | Notes |
|---|---|---|---|
| ☐ | 30 min | Delete `perf-test-probe-noop` entity from prod Supabase via Studio SQL editor. | Benign artifact from an earlier schema probe; no DELETE API exists for entities so this is the only way. |
| ☐ | 1 hr | Investigate origin of `policy_versions` table referenced in migration 072 — is it from an old removed migration, or should it be created? Decide and either add a fresh migration or remove the reference. | Currently no-op via the defensive guard in 087, but this is real schema drift to clean up. |
| ☐ | 2 hrs | Audit which RLS policies from migration 076 actually exist on prod via Studio. The defensive 088 made it idempotent, but ground-truth verification is worth doing once. | Service role bypasses RLS anyway, so this is defense-in-depth not runtime risk. |
| ☐ | 1 hr | When prod p95 server-time stays below 600ms for a full week, tighten the k6 thresholds in `tests/k6/baseline.js` from 900ms back toward 400–500ms. | The ratchet history is in the file's threshold comment block. |

## 🎯 Stretch goals (only after first revenue)

| ☐ | Notes |
|---|---|
| ☐ Hit **$10K MRR** from self-serve Pro/Team plans | Validates the SaaS funnel exists |
| ☐ Land **first paid pilot** ($35K+) | Validates the GovGuard/FinGuard wedge |
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
