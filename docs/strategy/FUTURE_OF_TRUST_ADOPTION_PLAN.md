# EMILIA Protocol - Authorization Receipt Adoption Plan

**Date:** 2026-06-12
**Audience:** Founder, maintainers, advisors
**Purpose:** Turn EMILIA from a correct protocol into a protocol people can actually adopt.

## The blunt read

EMILIA has the right primitive, but the first adoption plan had one disqualifying flaw:

> The flywheel had no crank.

"Require a receipt" is not a developer motion unless a developer can mint a receipt without asking EMILIA for an account, backend, or private API. Verification alone proves the math. Issuance makes the ecosystem possible.

The immediate fix is now in the repo:

- `@emilia-protocol/issue` v0.1
- `ep-issue` CLI
- local key generation
- local authorization receipt issuance
- verifier-compatible `EP-RECEIPT-v1` output
- no EMILIA backend, no account, no API key

That should become the protocol adoption front door:

> Mint one authorization receipt locally. Verify it offline. Then require it where the action matters.

## The category

Use this everywhere:

> **EMILIA builds toward the open standard for authorization receipts.**

Short version:

> **Authorization receipts for irreversible actions.**

Expanded:

> EMILIA defines portable, cryptographically verifiable receipts that prove who authorized an irreversible action, under which policy, for which exact parameters, before execution.

Do not say "the open receipt layer" as if the category is empty. It is not. Agent authorization, notarized agent actions, human approval tools, policy engines, vendor-risk controls, and AI governance platforms are all converging toward the same gap. The opportunity is to make EMILIA the clearest open standard for the receipt artifact itself.

## The language lock

Use these rules in homepage, docs, outbound, and investor language:

- Say **irreversible**, not "consequential," in primary positioning.
- Say **authorization receipt**, not "Trust Receipt," in buyer-facing language.
- Keep the wire vocabulary as `EP-RECEIPT-v1`.
- In government copy, use concrete nouns: disbursements, vendor bank-account changes, benefit changes, payment-destination changes, caseworker overrides.
- EMILIA does not "prove." A receipt proves. The protocol defines. EMILIA builds products and reference implementations.

Preferred line:

> Decision logs prove it to you. A receipt proves it to everyone else - auditors, regulators, acquirers - without trusting your logs, your vendor, or us.

Short line:

> Decision logs are testimony. Receipts are evidence.

## What the repo already has

The foundation is unusually strong for this stage:

- Open protocol framing in `README.md`
- Self-verifying receipt library in `@emilia-protocol/verify`
- Signing-side issuer library in `@emilia-protocol/issue`
- `ep-issue` CLI for local receipt minting
- JavaScript, Python, and Go verifier story
- Conformance suite and live operator checks
- PIP process and core freeze direction
- MCP server, SDKs, GitHub Action, embed badge, explorer, playground, and `/adopt`
- GovGuard, FinGuard, Agent Guard, Trust Desk, vertical packs, compliance mappings, and launch docs
- Formal evidence: TLA+, Alloy, red-team cases, CI gates, performance proof

The remaining problem is focus. The repo can explain ten futures. The company can only sell one next step.

## The strategic split

Run two lanes, but do not give them equal time.

| Lane | Founder time | Goal | Audience | Primary offer | Success metric |
|---|---:|---|---|---|---|
| Commercial proof | 80% | One credible paid pilot | County treasurers, program integrity, procurement finance | GovGuard observe-mode pilot | About 10 government first-calls held in 90 days |
| Protocol adoption | 20% | Make the standard impossible to dismiss | Developers, standards people, auditors | Local issue + offline verify + IETF draft | External issuance/verifier usage and standards conversations |

Government proof buys credibility. Protocol adoption buys category legitimacy. The mistake would be treating developer adoption as the revenue motion this quarter.

## Why now

The market is moving toward EMILIA's shape:

- Agent systems are getting real tools and need action-level controls.
- MCP authorization is growing, but its own security guidance still points implementers toward consent, confirmation, logging, access controls, and audit.
- Modern authorization work such as AuthZEN, OPA, Cerbos, Permit, and related policy engines handles access decisions, but not portable proof that a specific irreversible action had accountable signoff before execution.
- Human approval products and agent governance tools are normalizing the buying language.
- Research and standards work around notarized agents, agent identity, delegated authorization, and secure unified delegation is moving quickly.
- The EU AI Act requires high-risk systems to support human oversight and logging.
- NIST AI RMF centers trustworthiness, governance, mapping, measurement, and management, which creates procurement language EMILIA can map to.

The wedge is not "we are another policy engine." The wedge is:

> After your policy engine says yes, an authorization receipt proves that this exact yes happened.

## What will make people adopt it

Mass adoption requires EMILIA to be useful before anyone trusts EMILIA.

The adoption ladder should be:

1. **Issue a receipt** locally with `@emilia-protocol/issue` or `ep-issue`.
2. **Verify the receipt** offline with `@emilia-protocol/verify`.
3. **Publish one receipt** from a real workflow.
4. **Require a receipt** in CI, an MCP tool, or a high-risk API endpoint.
5. **Display a badge** that links to verification.
6. **Run conformance** against an implementation.
7. **Operate a node** or join federation.

The first mass-adoption tool is:

> **Issue + Verify** - a local, copy-paste path that produces a receipt anyone can check.

Then the developer campaign can become:

> Show us one irreversible action your system should never take without an authorization receipt.

## Product priorities

### 1. Keep GovGuard as the buyer-facing wedge

Do not swap the homepage hero this week. The fastest revenue path is county treasurer and government payment-integrity traffic, not a broad category relaunch.

Tune `/govguard` around:

- vendor bank-account changes
- disbursement releases
- benefit bank-account changes
- benefit changes
- caseworker overrides
- observe mode first
- 60-day pilot
- $25k scoped engagement

The buyer promise:

> We will not block anything at first. We will show which actions would have needed signoff, and we will give you an evidence packet your auditors can verify later.

### 2. Make issuance a public primitive

`@emilia-protocol/verify` proves EMILIA can check receipts. `@emilia-protocol/issue` proves outsiders can create them.

Near-term tasks:

- Publish `@emilia-protocol/issue` v0.1.
- Add a "Mint and verify a receipt in five minutes" guide.
- Add one government action example and one agent-tool example.
- Link `/adopt`, `/spec/trust-receipt`, `/mcp`, and `/govguard` to the issuer package.
- Use `authorization receipt` language while preserving `EP-RECEIPT-v1` in the spec.

### 3. Treat IETF as urgency, not ceremony

Category claims are vulnerable until the artifact has standards-body gravity.

Do one night per week:

- tighten the receipt draft
- define what an authorization receipt proves and does not prove
- separate receipt artifact from EMILIA product claims
- publish two-operator cross-verification
- prepare an Internet-Draft submission path

IETF will not create adoption by itself. It will make the standard defensible when adjacent players arrive.

## Next 7 days

### Robin first

Take the highest-warmth government path first. The goal is not a perfect funnel. The goal is a credible first call with someone close to treasury, procurement, benefits, program integrity, or county finance.

### Tune `/govguard`

Reframe the page for treasurer and government payment-integrity traffic:

- "Who approved the bank-account change before money moved?"
- "Observe mode first. No blocking."
- "60 days. One workflow. Audit evidence packet."
- "Disbursements, vendor bank-account changes, benefit changes, caseworker overrides."

### Send 74 drafts in three tranches

Point every live demo link to `/govguard`, not `/r/example`.

The call-to-action should be:

> Scope a 60-day observe-mode pilot.

### Reply ops

Do the unglamorous work immediately: replies, warm intros, calendar holds, follow-ups, and one-page pilot scoping.

### Publish the issuer

Ship:

- `@emilia-protocol/issue`
- `ep-issue`
- README
- test that round-trips through `@emilia-protocol/verify`

### One IETF night

Write a short standards note:

> What a receipt proves and what it does not.

### Publish two-operator cross-verification

Show one receipt minted by one operator and verified by another. This is the smallest credible "open standard" demonstration.

## Days 8-30

- Follow up on tranche one, send tranches two and three.
- Ask NASCIO and ACFE for webinar, standards, or practitioner intro paths.
- Draft a scoped GovGuard pilot doc: 60 days, observe mode, one workflow, $25k.
- Create the issue-receipt GitHub Action, but only if it can use GitHub Environments required-reviewer approvals cleanly.
- Do not spend time on GitHub Marketplace until the action lives at the root of a dedicated action repo; `actions/verify-receipt` inside this monorepo is not a clean marketplace path.
- Publish "What a receipt proves and what it does not."
- Publish "Why authorization is not proof."
- Review on day 30 against one metric: government first-calls held.

## 90-day metric

Use one metric:

> Government first-calls held.

Target:

> About 10 first calls in 90 days.

This is a better truth serum than npm downloads, website traffic, or abstract standards interest. If the government wedge cannot earn calls, the paid motion needs to be reworked before more engineering is added.

## The final operating principle

Make EMILIA easy to adopt at the smallest possible scale:

> One issuer. One receipt. One irreversible action. One verification anyone can run.

Then build up:

> Many receipts. Many operators. One conformance standard.

That is how EMILIA becomes the future of trust without needing the world to believe the whole story on day one.
