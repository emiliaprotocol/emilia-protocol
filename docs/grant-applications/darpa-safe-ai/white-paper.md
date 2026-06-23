# DARPA / DoD AI-Assurance — White Paper Template

> **Status note (refreshed 2026-06-12).** There is **no DARPA program named
> "SAFE-AI."** That label was a placeholder. The real, current DARPA
> high-assurance / trustworthy-AI program line is **CLARA** (Defense
> Sciences Office) plus the standing **I2O Office-Wide BAA** and emerging
> I2O agent-autonomy work (**DICE**). This template is now matched against
> those real solicitations. See `WATCH.md` in this folder for the live
> saved searches that detect the next fit.

**Program family (real, as of June 2026).** DARPA's trustworthy/assured-AI
line currently runs through:

- **CLARA** — Compositional Learning-And-Reasoning for AI Complex Systems
  Engineering. Office: **DSO**. Solicitation **DARPA-PA-25-07-02**. Wants
  "verifiability with strong explainability to humans, based on automated
  logical proofs." Up to **$2M / 24 months**. Apache-2.0 open-source
  *mandatory*. **Proposals closed ~Apr 2026** — watch for a follow-on /
  Phase-equivalent or CyPhER-Forge / MATHBAC adjacent calls.
- **I2O Office-Wide BAA** — Solicitation **HR001126S0001** (released
  2025-11-28; abstracts due **2026-11-01**, full proposals **2026-11-30**;
  awards **$0.5M–$5M**). Four thrust areas, incl. **"transformative AI —
  trustworthy, explainable, ethically-aligned systems"** and **"resilient
  and secure software."** **Temporarily PAUSED effective 2026-05-21** for
  an I2O office rename + strategic realignment — expected to reopen under a
  new office name; this is the most likely standing home for EP.
- **DICE** — Decentralized AI through Controlled Emergence. Office: **I2O**.
  Proposers Day held **2026-05-29**; BAA expected to follow. Wants
  "heterogeneous AI agents that can autonomously execute sustained
  long-time-horizon missions… **while remaining under our control**" —
  directly about multi-agent accountability and bounded autonomy.
- **BORDEAUX** — AI cyber-security performance. Office **I2O**, solicitation
  **DARPA-PS-26-20** (closed 2026-05-15). Adjacent, not a primary fit.

> **The old HR001125S0002 number is stale.** That was the prior-FY I2O
> office-wide BAA. The current standing I2O office-wide BAA number is
> **HR001126S0001** (paused 2026-05-21). Always re-confirm the live number
> on darpa.mil before submitting.

**Award**: $0.5M – $5M typical Phase 1 (I2O BAA); CLARA-class programs run
~$2M / 24 months; multi-phase programs run $10M+ over 3–5 years.

**Format**: BAA-specific. Abstract / white paper first (3–5 pages); if
encouraged, full proposal (~30 pages). This document is a *white-paper
template* — fill in BAA-specific framing once a target BAA is identified.

---

## How to use this template

When a fitting BAA is open (search keywords: `trustworthy AI`,
`verifiable AI`, `autonomy assurance`, `agent accountability`, `human
oversight autonomous`, `formal methods AI`, `controlled emergence`):

1. Read the BAA carefully. Identify which **Technical Area (TA) / thrust**
   EP fits. For the I2O BAA, EP maps to **Thrust 1 (transformative,
   trustworthy AI)** and **Thrust 2 (resilient/secure software)**.
2. Customize §2 (Technical Approach) and §4 (Technical Plan) with the
   BAA's specific language.
3. Submit at the BAA's specified portal (BAA tells you — typically the
   DARPA BAA submission site / ARI portal).

---

## §0 — Seed Abstract (150 words — drop into any candidate BAA)

EMILIA Protocol (EP) is an open standard and reference implementation for
**authorization receipts**: cryptographic, offline-verifiable proof that a
*named* human approved an *exact*, irreversible AI-agent action *before* it
executed. EP composes WebAuthn device-bound human signoff, hash-pinned
policy binding, and append-only Merkle-anchored logs into a self-verifying
trust receipt that any third party validates with only the operator's
public key — no trust in the operator's runtime, patterned on Bitcoin's
verification model. Safety is formally guaranteed: 26 TLA+ properties
machine-checked across 413,137 states and 22 Alloy assertions with zero
counterexamples, re-run in CI. The protocol is specified in an IETF
Internet-Draft (now at -01) with three independent language verifiers and
live npm packages. For assured autonomy, EP converts open-ended agent risk
into bounded, RFC-shaped authorization risk analyzable with the same rigor
as OAuth or Kerberos — including the agent's own signed escalation
decision.

---

## §1 — Title

Verified Pre-Action Authorization for Autonomous AI Agents:
A Formally-Proven Open Protocol for Accountable, Offline-Verifiable
Human-in-the-Loop Control

## §2 — Technical Approach (~1.5 pages)

EMILIA Protocol (EP) provides a **cryptographic, formally-verified
pre-action authorization layer** for autonomous AI agent systems.
The protocol composes four primitives:

1. **Eye** — graduated risk observation (OBSERVE → SHADOW → ENFORCE)
2. **Handshake** — multi-party identity exchange with hash-pinned policy
3. **Signoff** — named accountable human attestation (WebAuthn,
   device-bound), hash-bound to the exact action
4. **Commit** — atomic action seal, Merkle-anchored to a public chain

These compose into a single ceremony that produces a self-verifying
**authorization receipt**: an Ed25519-signed, Merkle-batched record that
any third party can verify offline given the operator's public key. The
cryptographic structure is independent of the operator's runtime —
deliberately patterned after Bitcoin's transaction model, where
verification does not trust the issuer.

**Formal verification status (current).** 26 TLA+ safety properties
verified by TLC across 413,137 distinct states (T1–T26 in
`formal/PROOF_STATUS.md`). 35 Alloy relational facts and 22 assertions
verified by Alloy 6.0.0 with 0 counterexamples. All re-run on every commit
in CI.

**Standardization status (current).** EP's authorization-receipt format is
published as an IETF Internet-Draft, now at revision **-01**
(`draft-schrock-ep-authorization-receipts-01`), with **three independent
verifier implementations** (TypeScript/JS, plus additional language ports)
and **live npm packages** (`@emilia-protocol/verify` and the SDK), so any
reviewer can `npm i` and verify a receipt today.

**Why the protocol matters for assured autonomy.** When an AI agent takes
an irreversible real-world action, current systems can audit *after* the
fact. EP verifies *before*: the action does not execute unless a valid
authorization receipt exists, is policy-bound, and the policy hash matches
the live policy. This is precisely the "remaining under our control"
property DARPA's DICE program calls for, expressed as a verifiable
cryptographic invariant rather than a runtime promise.

## §3 — Innovation Claims (~0.5 pages)

What is genuinely new (not in prior literature):

1. **Hash-pinned policy at handshake initiation.** OAuth-style protocols
   bind to a token; EP binds to a *policy version hash*. A policy mutation
   between authorization and execution causes verification to fail —
   closing a class of silent-upgrade attacks.

2. **Action-hash binding with replay resistance under a concurrent
   adversary.** Proven by formal model: an adversary running
   `consume_handshake` operations concurrently cannot achieve
   double-consumption. Verified by TLA+ T1–T13 across 413,137 states.

3. **Signed escalation attestation (PIP-007).** When an agent decides it
   must escalate to a human, *that decision itself* is captured as a
   signed, append-only attestation — the agent's own cryptographic record
   of "I judged this required human authorization." This gives an assured-
   autonomy regime a tamper-evident trail not just of approvals but of the
   *agent's own judgment about when approval was needed* — directly
   relevant to DARPA's interest in keeping autonomous collectives "under
   control" and accountable.

4. **Federation via cross-operator cryptographic verification.** EP's
   federation specification lets operator A verify a receipt issued by
   operator B without trusting B's runtime — only B's public key. This
   gives multi-operator / multi-agent safety regimes a primitive that does
   not require central trust.

5. **Signoff is to a named human, not a role.** Where most schemes treat
   "manager approval" as a token signed by anyone in the "manager" role,
   EP's signoff is a named-principal, device-bound (WebAuthn) attestation
   irrevocably bound to a specific human's verified identity claim. This
   converts compliance theater into accountable individual attestation.

## §4 — Technical Plan (~1.5 pages)

Customize against the BAA's TA structure. Generic Phase 1 plan:

| Task | Deliverable | Months |
|---|---|---|
| 1. Cross-language verify hardening | Python, Go, Rust verifiers brought to parity + external crypto audit | 1–4 |
| 2. Federation TLA+ extension | Verified federation spec: operator registry, trust delegation, cross-receipt consumption | 2–6 |
| 3. Escalation-attestation (PIP-007) formal model | TLA+/Alloy model proving escalation decisions are unforgeable and append-only | 3–7 |
| 4. Reference operator on government cloud | Second operator on AWS GovCloud (or on-prem if BAA requires); cross-verification proven end-to-end | 4–8 |
| 5. Compositional agent threat model | Multi-hop authorization chain (principal → primary agent → tool agent) formally verified under bounded depth | 8–12 |
| 6. Adversarial benchmark (EP Eval) | Open-source benchmark for trust-reasoning capability of frontier models | 6–10 |

**Phase 1 budget request**: $1.2M / 12 months (scale to BAA ceiling — I2O
BAA supports up to $5M). Justification per BAA-specific cost format.

## §5 — Personnel and Past Performance

**PI**: Iman Schrock, Founder, EMILIA Protocol.
- Authored the protocol stack including the formal model.
- 26 TLA+ theorems verified, 35 Alloy facts, 4,195 tests.
- IETF Internet-Draft author (`draft-schrock-ep-authorization-receipts-01`),
  submitted to IETF secdispatch.
- Apache 2.0 published code at github.com/emiliaprotocol/emilia-protocol.
- NIST AI Safety / AI-RMF engagement (in progress).

**Past performance**: EP is the PI's first DARPA engagement. For Phase 1 we
propose to add a named cryptographic-implementation auditor (Cure53 or NCC
Group) and one part-time formal-methods collaborator.

## §6 — Public artifacts

All technical claims are independently verifiable today:

- Repository: https://github.com/emiliaprotocol/emilia-protocol (Apache 2.0)
- Formal proofs: `formal/ep_handshake.tla`, `formal/ep_relations.als`,
  `formal/PROOF_STATUS.md`
- IETF I-D: `draft-schrock-ep-authorization-receipts-01`
- Live demo: https://www.emiliaprotocol.ai/protocol (and `/try` Face ID demo)
- Verify library: `@emilia-protocol/verify` on npm (live)
- Compliance mappings: `docs/compliance/NIST-AI-RMF-MAPPING.md`

DARPA reviewers can clone the repo, run `npm test` (4,195 tests pass), run
TLC against `formal/ep_handshake.tla` (T1–T26 verify), run Alloy against
`formal/ep_relations.als` (15/15 assertions hold), and `npm i
@emilia-protocol/verify` to verify a receipt offline — independently
confirming every technical claim in this white paper.

---

## Submission notes

- The Apache-2.0 open-source mandate now common to DARPA AI BAAs (CLARA
  requires it explicitly) is a *strength* for EP — the entire stack is
  already Apache 2.0 and independently runnable.
- Watch https://www.darpa.mil/work-with-us/opportunities and SAM.gov per
  `WATCH.md`. The paused I2O BAA (HR001126S0001) is the most likely
  standing home; DICE is the most likely *named-program* fit when its BAA
  drops.
- White papers / abstracts are typically due 30–60 days after publication
  (I2O BAA accepts abstracts on a rolling basis through 2026-11-01 when not
  paused).
- DARPA prefers concise, evidence-heavy white papers; EP's formal numbers,
  IETF I-D, and live runtime are this proposal's strongest assets.
- Full proposal is ~30 pages with budget detail, SOW, and TRL assessment.
  EP is at **TRL 6** (system/subsystem demonstrated in a relevant
  environment).
