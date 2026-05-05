# DARPA SAFE-AI — White Paper Template

**Program family**: DARPA's safety-and-verification-of-AI program line.
At any given time the program may be branded as SAFE-AI, Information
Innovation Office (I2O), Assured Neuro Symbolic Learning and Reasoning
(ANSR), Verifiable Autonomy, or a successor. Watch SAM.gov and
darpa.mil/work-with-us for active BAAs.

**Award**: $0.5M – $5M typical Phase 1; multi-phase programs run $10M+
over 3–5 years.

**Format**: BAA-specific. White paper first (3–5 pages); if encouraged,
full proposal (~30 pages). This document is a *white-paper template* —
fill in BAA-specific framing once a target BAA is identified.

---

## How to use this template

When DARPA opens a BAA where EP is a fit (search SAM.gov weekly with
keywords: `verifiable AI`, `autonomy assurance`, `safe autonomy`, `agent
verification`, `formal methods AI`):

1. Read the BAA carefully. Identify which **Technical Area (TA)** EP fits.
2. Customize §2 (Technical Approach) and §4 (Technical Plan) with the
   BAA's specific language.
3. Submit the white paper at the BAA's specified portal (usually
   ARO Whitepaper Portal or similar — BAA tells you).

---

## §1 — Title

Verified Pre-Action Authorization for Autonomous AI Agents:
A Formally-Proven Open Protocol with Federation Architecture

## §2 — Technical Approach (~1.5 pages)

EMILIA Protocol (EP) provides a **cryptographic, formally-verified
pre-action authorization layer** for autonomous AI agent systems.
The protocol composes four primitives:

1. **Eye** — graduated risk observation (OBSERVE → SHADOW → ENFORCE)
2. **Handshake** — multi-party identity exchange with hash-pinned policy
3. **Signoff** — named accountable human attestation, hash-bound to
   the action
4. **Commit** — atomic action seal, Merkle-anchored to a public chain

These compose into a single ceremony that produces a self-verifying
trust receipt: an Ed25519-signed, Merkle-batched record that any third
party can verify offline given the operator's public key. The
cryptographic structure is independent of the operator's runtime —
deliberately patterned after Bitcoin's transaction model, where
verification does not trust the issuer.

**Formal verification status**: 26 TLA+ safety properties verified by
TLC 2.19 across 413,137 distinct states (T1–T26 in `formal/PROOF_STATUS.md`).
35 Alloy relational facts and 15 assertions verified by Alloy 6.0.0
with 0 counterexamples. All re-run on every commit in CI.

**Why the protocol matters for autonomy assurance.** When an AI agent
takes an irreversible real-world action, current systems can audit
*after* the fact. EP provides verification *before*: the action will
not execute unless a trust receipt exists, the receipt is policy-bound,
and the policy hash matches the live policy. This converts open-ended
autonomy risk into bounded, RFC-shaped authorization risk that can
be analyzed with the same techniques used for OAuth or Kerberos.

## §3 — Innovation Claims (~0.5 pages)

What is genuinely new (not in prior literature):

1. **Hash-pinned policy at handshake initiation.** Existing OAuth-style
   protocols bind to a token; EP binds to a *policy version hash*. A
   policy mutation between authorization and execution causes
   verification to fail — closing a class of silent-upgrade attacks.

2. **Action-hash binding with replay resistance under concurrent
   adversary.** Proven by formal model: an adversary running
   `consume_handshake` operations concurrently cannot succeed in
   double-consumption. Verified by TLA+ T1–T13 across 413,137 states.

3. **Federation via cross-operator cryptographic verification.** EP's
   federation specification allows operator A to verify a receipt
   issued by operator B without trusting B's runtime — only B's public
   key. This gives multi-operator AI safety regimes a primitive that
   does not require central trust.

4. **Signoff is to a named human, not a role.** Where most authorization
   schemes treat "manager approval" as a token signed by anyone in the
   "manager" role, EP's signoff is a named-principal attestation that
   is irrevocably bound to a specific human's verified identity claim.
   This converts compliance theater (rubber-stamp roles) into
   accountable individual attestation.

## §4 — Technical Plan (~1.5 pages)

Customize against the BAA's TA structure. Generic Phase 1 plan:

| Task | Deliverable | Months |
|---|---|---|
| 1. Cross-language verify ports | Python, Go, Rust libs + crypto audit | 1–4 |
| 2. Federation TLA+ extension | Verified federation specification covering operator registry, trust delegation, and cross-receipt consumption | 2–6 |
| 3. Reference operator on government cloud | Second operator deployed on AWS GovCloud (or on-prem if BAA requires); cross-verification proven end-to-end | 4–8 |
| 4. Adversarial benchmark (EP Eval) | Open-source benchmark suite for measuring trust-reasoning capability of frontier models | 6–10 |
| 5. Compositional agent threat model | Multi-hop authorization chain (principal → primary agent → tool agent) formally verified under bounded depth | 8–12 |

**Phase 1 budget request**: $1.2M / 12 months. Justification per
BAA-specific cost format.

## §5 — Personnel and Past Performance

**PI**: Iman Schrock, Founder, EMILIA Protocol.
- Authored the protocol stack including the formal model.
- 26 TLA+ theorems verified, 35 Alloy facts, 3,483 tests.
- Apache 2.0 published code at github.com/emiliaprotocol.
- NIST AI Safety Working Group engagement (in progress).
- AAIF v3 proposal submitted.

**Past performance**: EMILIA Protocol is the PI's first DARPA
engagement. Prior work in trust systems and regulated-industry
software is documented in the public LinkedIn / repository history.
For Phase 1, we propose to add named cryptographic-implementation
auditor (Cure53 or NCC Group) and one part-time formal-methods
collaborator.

## §6 — Public artifacts

All technical claims are independently verifiable today:

- Repository: https://github.com/emiliaprotocol/emilia-protocol (Apache 2.0)
- Formal proofs: `formal/ep_handshake.tla`, `formal/ep_relations.als`
- Live demo: https://www.emiliaprotocol.ai/protocol
- Verify library: `@emilia-protocol/verify` on npm
- Compliance mappings: `docs/compliance/NIST-AI-RMF-MAPPING.md`

DARPA reviewers can clone the repository, run `npm test` (3,483 tests
pass), run TLC against `formal/ep_handshake.tla` (T1–T26 verify),
and run Alloy against `formal/ep_relations.als` (15/15 assertions
hold) to independently verify the technical claims of this white paper.

---

## Submission notes

- Watch https://sam.gov/ and https://www.darpa.mil/work-with-us/
  for AI-verification BAAs. Subscribe to the DARPA Information
  Innovation Office (I2O) email list at
  https://www.darpa.mil/about-us/offices/i2o
- White papers are typically due 30–60 days after BAA publication.
- DARPA prefers concise white papers heavy on evidence; the formal
  verification numbers and the live runtime are this proposal's
  strongest assets.
- If DARPA encourages, the full proposal is ~30 pages and includes
  budget detail, Statement of Work, and a Technology Readiness Level
  (TRL) assessment. EP is at TRL 6 (system/subsystem demonstrated
  in relevant environment) — a strong starting point.
