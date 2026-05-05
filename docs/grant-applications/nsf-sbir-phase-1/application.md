# NSF SBIR Phase I — Project Pitch

**Topic:** CT — Cybersecurity & Authentication
**Applicant:** Iman Schrock / EMILIA Protocol (US-owned small business)
**Award sought:** $305,000 / 12 months (Phase I)
**Submission portal:** https://seedfund.nsf.gov/applications/
**Format:** Project Pitch (~3 pages, plain text in NSF's web form)

> NSF SBIR Phase I is a two-step process: the **Project Pitch** is short
> and free; if NSF invites you, you write the full Phase I proposal
> (~50 pages) for the actual award. This document is the Project Pitch.
> Each section corresponds to a required field in the NSF Project Pitch
> web form.

---

## 1. Briefly Describe the Technology Innovation
*(NSF asks: ~500 words. What is the technology? Why is it new?)*

EMILIA Protocol (EP) is an open standard and reference implementation for
**verifiable pre-action authorization in AI agent systems**. EP gates every
high-stakes action an AI agent or human takes — payment redirection,
benefit-account changes, infrastructure mutations, autonomous tool use —
behind a cryptographic ceremony that binds, in one tamper-evident receipt:

1. **Who** — the entity initiating the action, attested via an authority chain
2. **Under what policy** — the exact policy version and rule set, hash-pinned
3. **For what** — the action's canonical hash and parameters
4. **With what evidence** — verifiable claims, optional named human signoff
5. **At what time and with what nonce** — replay-resistant and one-time-consumable

The technical innovation is not any single primitive — it is the **canonical
binding between identity, authority, policy, and action**, formally proven
to maintain seven safety properties under arbitrary adversarial scheduling.
EP is to AI-agent action authorization what TLS is to web security: a
common protocol that lets independent operators interoperate without
trusting each other.

The protocol is implemented in 3,483 automated tests across 132 files,
with 26 TLA+ safety properties (T1–T26) verified by TLC across 413,137
states, 0 errors. 35 Alloy relational facts and 15 assertions are
verified by Alloy 6.0.0, 0 counterexamples. All verification runs in CI
on every commit. The runtime ships under Apache 2.0; the protocol
specification is open and intended for standards-body adoption.

What is genuinely novel:

- **Self-verifying trust receipts**: receipts are Ed25519-signed and
  Merkle-anchored, verifiable offline by anyone with the public key, with
  no dependency on the operator's infrastructure (similar to how a Bitcoin
  transaction is verifiable without trusting Coinbase).
- **Policy-hash pinning at initiation, re-checked at consumption**:
  closes the silent-upgrade window where a policy is mutated between
  authorization and execution.
- **Privacy-preserving trust proofs**: an entity can prove "my trust
  score in domain X exceeds threshold T" without revealing receipts,
  counterparties, or interaction history.
- **Federation via cross-operator verification**: receipts are
  trans-operator-verifiable, enabling multi-operator deployments
  without a central authority.

## 2. Technical Objectives and Challenges
*(NSF asks: ~500 words. What R&D risk are you tackling?)*

Phase I R&D objectives:

**Objective 1 — Cross-language verification library.**
Today the Apache-2.0 verification library exists only for JavaScript
(`@emilia-protocol/verify` on npm). Phase I delivers Python, Go, and Rust
ports — each with a third-party crypto audit. The technical challenge is
ensuring binary-identical canonicalization across language ecosystems
(JSON serialization, UTF-8 normalization, integer ordering all interact
with cryptographic determinism).

**Objective 2 — Federation protocol formalization.**
The federation specification (`docs/FEDERATION-SPEC.md`) describes
cross-operator receipt verification, but its safety properties are not
yet in the formal model. Phase I extends the TLA+ specification to
include federation primitives (operator registry, trust delegation,
cross-receipt consumption) and proves that a malicious operator cannot
forge receipts that another operator's verifier accepts.

**Objective 3 — Threat model for compositional AI agent stacks.**
When an AI agent calls another AI agent, EP's existing single-actor model
is insufficient. Phase I formalizes the multi-hop authorization chain
(principal → primary agent → tool agent) with delegation acyclicity proven
under bounded depth. The technical challenge is keeping the verification
cheap enough to run in the request hot path (~50ms p95).

**Objective 4 — Reference operator on AWS GovCloud.**
The conformance test suite passes 7/7 on the primary operator. Phase I
deploys a second reference operator on AWS GovCloud (CloudFormation
template exists at `infrastructure/aws/template.yaml`) to validate that
operator implementations are interchangeable, completing the federation
loop end-to-end.

**Risk and feasibility.**
The protocol is already running in production on Vercel + Supabase with
real handshake creation, signoff issuance, consumption, and audit-event
emission. The R&D risk is in formalizing federation safety, not in the
single-operator base case (which is already shipped). 26 TLA+ properties
verified, 35 Alloy facts verified, and 7/7 conformance tests passing
mitigate the technical risk substantially.

## 3. Market Opportunity
*(NSF asks: ~500 words. Who pays, why, how big is the market?)*

EP serves three distinct markets, all expanding rapidly:

**1. AI agent platforms** ($45B forecasted 2027 — Gartner): Cognition,
Sierra, Adept, Lindy, and dozens of smaller agent platforms are shipping
agents that take real actions (payments, code deploys, customer
communications). Their enterprise customers — banks, insurers,
healthcare — are demanding action-binding controls before signing.
EP is the missing layer. Pricing: $20K–$80K ARR per platform,
self-serve via SaaS tiers.

**2. Financial fraud defense** ($87M+ annual losses to vendor-bank-change
and beneficiary-swap fraud at US community banks alone — ABA 2024
report; AI-voice-cloned wire fraud losses growing >300% YoY): EP
FinGuard productizes the core protocol for this domain. Channel
partners are core banking platforms (Jack Henry, Fiserv, Q2). Pricing:
$50K–$500K per pilot, $500K–$5M for at-scale enterprise contracts.

**3. Government benefit integrity** ($5B+ annual benefit-redirection
fraud — GAO Fraud Risk Framework 2024): SNAP, Medicaid, unemployment
insurance, and federal payment systems all face redirection fraud
where a legitimate session is exploited to redirect funds.
EP GovGuard binds the caseworker identity, policy authority, and
action context before any payment direction can change.
Compliance-mapped to NIST AI RMF (38 subcategories) and EU AI Act
(Articles 9–15, 26).

The protocol itself remains free and open under Apache 2.0. Revenue
comes from the managed cloud (EP Cloud — multi-tenant SaaS), from
domain-specific productized surfaces (EP GovGuard, EP FinGuard),
and from pilot engagements that include compliance certification
support. The protocol-vs-product separation is intentional: it
mirrors successful precedents (Apache HTTP server / nginx vs F5,
PostgreSQL vs Snowflake) and avoids the open-core bait-and-switch
that has poisoned recent OSS commercial efforts.

## 4. Company and Team
*(NSF asks: ~250 words. Who is doing the work?)*

**EMILIA Protocol** is a US-owned small business (sole proprietor;
Delaware C-corp formation in progress). Place of business: California.
Eligibility for SBIR: yes — single-founder US small businesses are
explicitly eligible per NSF SBIR Phase I solicitation.

**Iman Schrock** — Principal Investigator, Founder.
Designed and authored the full EP protocol stack including the
TLA+ formal specification, Alloy relational model, Apache-2.0
reference runtime (Next.js + Supabase), MCP server integration
(34 EP-prefixed tools), TypeScript and Python SDKs, and the
GovGuard / FinGuard productized surfaces. Background in trust
systems, cryptographic protocols, and regulated-industry software.
Active engagement: NIST AI Safety Working Groups (in progress),
AAIF (proposal v3 submitted).

**Phase I personnel plan**: PI commits 50% time. One contracted
cryptographic auditor (Cure53 or equivalent) for crypto-implementation
review of cross-language ports. One part-time formal-methods
collaborator for the federation TLA+ extension. All work performed
in the United States by US persons.

---

## Submission notes (delete before pasting into NSF form)

- The NSF Project Pitch web form has separate fields per section above.
  Paste each section into its corresponding field; the headings are for
  this document's clarity only.
- The 500-word / 250-word counts are approximate NSF guidance; current
  text is within budget.
- After submission, NSF response time is ~3 weeks: either (a) "do not
  encourage to submit a Phase I proposal" with feedback, or (b) "encourage
  to submit" with a Phase I solicitation invitation.
- If invited, the full Phase I proposal is due within ~30 days and is
  ~50 pages; reuse `docs/AWS-GRANT-APPLICATION.md` heavily for content.
