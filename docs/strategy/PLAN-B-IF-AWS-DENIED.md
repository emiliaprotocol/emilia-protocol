# Plan B — If the AWS Open Source Grant is Denied

**Date:** 2026-04-28
**Trigger:** AWS notifies that the $150K grant request is denied or
delayed past Q3 2026.
**Owner:** Iman Schrock

---

## Why this exists

The AWS grant ($150K over 12 months) is currently the only material
runway line item in EMILIA Protocol's 2026 plan. If denied, default
behavior is panic + ad-hoc cuts. This document pre-commits the
response so the decision is mechanical, not emotional.

---

## Decision tree on day 0

```
AWS grant decision arrives
    │
    ├── Approved ─────────→ execute as planned
    │
    ├── Denied (clean no) ─→ Path A
    │
    ├── Denied with feedback "resubmit Q4" ──→ Path B
    │
    └── Delayed past Q3 ──→ Path C (treat as denied for cash purposes)
```

---

## Path A — Clean denial

### Day 0–7: cut burn to a 12-month runway

1. **Pause SOC 2 auditor engagement.** Quotes received but no contracts
   signed yet (per the cold-emails file's §A/B/C). Signal "deferred"
   to Schellman / A-LIGN / Prescient — defer 6 months minimum.
2. **Pause native-PDF tooling spend.** basictex install requires sudo;
   keep using Chrome headless for the few PDFs the year needs.
3. **Pause infrastructure expansion.** Single Vercel project, single
   Supabase project, single Base L2 anchor key. No second-operator
   federation deploy. Federation reference implementation deferred
   until pilot revenue covers it.

### Day 8–30: tighten the wedge

4. **Drop FinGuard and AgentGuard from public surfaces.** Keep them
   internally. Homepage + /protocol + /partners reference GovGuard
   only. Reduces support surface, narrows the buyer pitch, eliminates
   "what about my use case" distraction.
5. **Drop the rules-engine v0 shadow signal back to dormant.** Remove
   `EP_RULES_ENGINE_V0` from production env. Keep code on disk; turn
   off the per-receipt parallel evaluation cost (small but real).
6. **Withdraw from AAIF working-group activities that require travel
   or billable hours.** Maintain the proposal + asynchronous
   participation only.

### Day 31–90: revenue-first or shutdown decision

7. **Send 50 additional Tier-1+2 cold emails over 30 days.** Same
   list pattern as `outreach/cold-emails-tier1-tier2.md` but expand
   to TX, FL, NY, MA welfare/payment-integrity units. Goal: any
   reply that opens a conversation.
8. **Trade a 30-day free shadow pilot for a logo + case-study right.**
   Anywhere. Government, fintech, regulated-industry. The first
   logo is worth more than the first $25K.
9. **Decide at day 90:** if a logo conversation is real and budgeted,
   continue another 90 days. If not, formally pause active development
   and shift to maintenance mode.

### Maintenance-mode definition

- Repository public, license unchanged, all artifacts preserved.
- No new features.
- Security patches only, applied within 30 days of disclosure.
- 1-line README at top: "EMILIA Protocol is in maintenance mode as of
  YYYY-MM-DD pending revenue. Contact iman@emiliaprotocol.ai for
  pilot inquiries."

---

## Path B — "Resubmit Q4"

If AWS denies but invites resubmission:

1. Address every gap they cite.
2. Resubmit with at least 1 named pilot or design partner logo if
   possible (this is the difference between "interesting research" and
   "fundable open-source ecosystem play").
3. Bridge the cash gap (Q3 → Q4) with the same Path-A burn cuts but
   without committing to maintenance mode.
4. If the resubmission is approved at 50%+ of original ask, execute as
   planned. If denied a second time, default to Path A.

---

## Path C — Delayed past Q3

Treat as denial for cash-flow purposes. Cut burn now (Path A steps 1–6)
even while the application is technically pending. If approval arrives
later, restore the cuts incrementally — but don't carry the spend
assuming approval will land in time.

---

## What does NOT change in any path

- The protocol remains Apache 2.0. No closed-sourcing under cash
  pressure.
- The receipt schema and EP-RECEIPT-v1 format remain frozen. No
  schema changes to chase a pivot.
- DCO + SBOM + provenance commitments remain.
- Compliance mapping documents remain published.

---

## Bridge funding options (last resort)

If active conversations exist at day 90 of Path A but cash runs out:

1. **Ask each prospective customer for an advance against pilot fee.**
   $5K–$15K committed before contract signature, applied as credit.
2. **Founder loan from personal savings, formally documented.** Up to
   $25K. Above that, the math doesn't work.
3. **AAIF / NIST grant or research contract.** Slower than AWS but
   non-dilutive.
4. **Friends-and-family SAFE up to $50K at $5M cap.** Document
   carefully; this is a real obligation.

What is NOT on this list:
- Institutional VC (you're too early, dilution will be brutal)
- Crypto / token raise (the protocol is explicitly NOT a token; staying
  consistent is worth more than the cash)
- Selling the protocol IP (it's open-source; there's nothing to sell)

---

## Decision-maker shortlist

When the email arrives:
1. Read it once, fully, before reacting.
2. Wait 24 hours before any public statement.
3. Open this document.
4. Pick the path mechanically.
5. Tell anyone who needs to know what was decided and why.

Do NOT:
- Send a public "still building, undeterred" tweet within 24 hours
  (looks performative)
- Ask AWS for reconsideration on the same day
- Pivot the protocol thesis to chase a perceived signal in the rejection
  letter
