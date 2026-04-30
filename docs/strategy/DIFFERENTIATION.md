# EMILIA Protocol — Differentiation Position

**Date:** 2026-04-28
**Question this answers:** Why does a CFO buy EMILIA GovGuard instead
of Trustpair, Eftsure, Validis, Onyxia, or Creditsafe?

---

## The honest competitive landscape

Vendor-bank-account-change validation is a CROWDED B2B fraud category.
Every one of these vendors has paying customers, case studies, and 7+
figure ARR:

| Vendor | Focus | Coverage | Differentiation |
|---|---|---|---|
| **Trustpair** | Vendor data validation | Bank-account verification, compliance screening | Mid-market AP automation integrations, named logos |
| **Eftsure** | AU/UK payment-controls | Real-time payee verification | Established AU/UK presence, partnerships with NetSuite/Xero |
| **Validis** | Vendor onboarding intelligence | Bank verification + identity checks | UK-rooted, accounting-firm channel |
| **Onyxia** | Payment integrity for SMB | Bank-account verification | SMB-focused, simpler integration |
| **Creditsafe** | Vendor risk + KYC | Credit checks + bank verification | Massive credit-data moat, global coverage |

**Each has what EMILIA does not have today:** customer logos, case
studies, recurring revenue, enterprise integrations, and a track record
that procurement teams can reference.

EMILIA must win on a SHARP, NARROW edge — not by claiming feature
parity, which would be a lie.

---

## Where EMILIA wins (and where it doesn't)

### Wins

1. **Cryptographic evidence that survives the vendor.**
   Trustpair / Eftsure / Validis store decisions in their own database
   under their own audit. If the vendor is acquired, sunset, or
   subpoenaed, the auditability of past decisions depends on the
   vendor's continued cooperation. EMILIA's trust receipts are
   Ed25519-signed and Merkle-anchored — verifiable forever, by anyone,
   without EMILIA's continued cooperation. **For agencies subject to
   12-year retention requirements, this is not equivalent to "we have
   a database log."**

2. **Open standard, no lock-in.**
   Apache 2.0 protocol. Self-hostable reference runtime. The agency
   can run EP entirely on its own infrastructure if procurement
   policy demands it (some federal contexts effectively require
   this). Trustpair / Eftsure are SaaS-only. **For FedRAMP-adjacent
   agencies, this is not equivalent to "they have SOC 2."**

3. **Pre-action enforcement, not post-hoc verification.**
   The competitors largely SCREEN vendor data on submission and
   periodically re-validate. EMILIA gates THE EXECUTION of a payment
   change before it reaches the disbursement pipeline, with a
   one-time-use authorization token. Different control surface.
   **For BEC scenarios where an attacker has already passed the
   onboarding screen, this matters.**

4. **Formal verification.**
   26 TLA+ theorems verified, 35 Alloy facts + 15 assertions. No
   competitor publishes formal models. **For agencies that have to
   defend control choices to internal/external auditors with state-
   machine reasoning, this is novel.**

5. **AI-agent execution governance** (forward-looking).
   Trustpair was designed for human-initiated payment changes. As
   public-sector AI-agent automation grows, the control surface
   shifts to "did THIS specific agent action authorize THIS specific
   payment under THIS policy?" — which is exactly EMILIA Handshake's
   primitive. No competitor is positioned for the AI-agent execution
   wave. **This is not a 2026 buyer concern, but it's a 2027–2028
   one, and the procurement teams thinking ahead want a vendor with
   a coherent answer.**

### Where EMILIA does NOT win (and don't pretend otherwise)

- **Logos.** They have them. EMILIA does not. This is a real gap.
- **Mid-market AP-automation integrations.** Trustpair has Coupa,
  SAP Ariba, NetSuite, Sage Intacct integrations in production.
  EMILIA has API + 5 demo adapters.
- **Global vendor data.** Creditsafe's data moat is years deep.
  EMILIA's data moat is zero.
- **Time-to-value for a small-business buyer.** Onyxia gets a 50-
  person company to "first protected payment" in <1 week. EMILIA
  requires more integration work.
- **Mid-market sales motion.** They have inside sales, marketing
  teams, and channel partnerships. EMILIA has one founder.

---

## The narrow positioning that wins

> **EMILIA GovGuard is the first pre-execution payment integrity layer
> that produces cryptographically verifiable evidence that survives
> auditor turnover, vendor acquisition, and SaaS sunset.**
>
> If your audit retention is 7+ years, your procurement policy
> requires self-hostable infrastructure, or you need to defend control
> choices in a formal proceeding, EMILIA is the differentiated answer.
> For everything else, Trustpair, Eftsure, and Validis are excellent
> mature products that probably fit your needs better today.

That positioning is honest. It cedes the easy wins to competitors and
claims a narrow, defensible category for which EMILIA is genuinely
the first-and-only answer. **Government and federal-adjacent fintech
is exactly the segment where this positioning resonates.**

---

## What this means for the cold emails

The current `outreach/cold-emails-tier1-tier2.md` pitches EMILIA as
"a pre-execution control layer" — which is accurate but
non-differentiated. Trustpair and Eftsure can claim the same
language. The next email-iteration pass should foreground the
sustained-evidence and open-protocol angles:

> "Most vendor-payment-integrity tools store their audit log in
> their own SaaS database. If the vendor is acquired or sunset,
> your evidence depends on their continued cooperation. EMILIA
> produces cryptographically signed receipts that any third party
> can verify offline forever — even if EMILIA shuts down tomorrow.
> For agencies subject to 7+ year retention, this is the difference
> between 'we hope the vendor still exists in 2033' and 'we have
> the math.'"

That's the pitch a CDSS Program Integrity Bureau Chief or a State
Controller's audit-evidence lead actually responds to.

---

## What this means for the website

`/govguard` should foreground:
1. The sustained-evidence claim (with a worked example: "verify a
   2026 receipt in 2033 without contacting EMILIA").
2. The self-hostable-protocol claim (with a link to the reference
   runtime).
3. The formal-verification claim (with a link to the TLA+ theorems).
4. The AI-agent-readiness claim (forward-looking, low priority for
   today's buyer, but a moat against next-cycle vendors).

What it should NOT do:
- Claim to be a Trustpair replacement
- Claim mid-market AP-integration coverage we don't have
- Claim global vendor-data we don't have
- Claim customer logos we don't have

The honest framing is that EMILIA is a NICHE first-and-only product,
not a mass-market alternative. Niche-first beats mass-market-also-ran
in regulated-industry sales every time.

---

## Pricing implications

Trustpair / Eftsure pricing for an enterprise/government deployment
is roughly $50K–$300K/year depending on scale. EMILIA's $150K–$500K
annual band from §5.2 of the audit is comparable.

But the SUSTAINED-EVIDENCE and SELF-HOSTABLE differentiators justify
a premium, not a discount, for the narrow segment that values them.
**Pitch in the upper half of the range ($300K–$500K annual)** for
agencies that explicitly call out cryptographic evidence retention or
self-hostable infrastructure in their RFP. **Pitch lower ($150K–$250K)
for agencies that don't — and accept that those agencies might choose
a competitor and that's okay.**

---

## What kills this positioning

Two things, watch for both:

1. **A competitor (most likely Trustpair) ships a "blockchain-
   anchored receipt" feature.** Their existing logos + integrations
   + sustained-evidence claim collapses EMILIA's narrow edge.
   Mitigation: ship the federation reference deployment ASAP after
   first pilot — multi-operator cross-verification is a layer above
   single-vendor blockchain anchoring that's much harder to copy.

2. **A regulated-industry buyer asks "does EFAS / Plaid / Stripe do
   this?" and the answer is yes.** Plaid has signal-grade
   verification primitives. Stripe Identity has crypto-signed
   attestations. If either ships pre-execution payment-change gating
   inside their existing pipeline, EMILIA's distribution is
   structurally weaker.
   Mitigation: focus on government and self-hostable-only segments
   where Plaid/Stripe SaaS distribution is a non-starter for
   procurement reasons.
