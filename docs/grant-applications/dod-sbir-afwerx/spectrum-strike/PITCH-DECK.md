# EMILIA Protocol — DIU Project Spectrum Strike Pitch Deck

> **Vehicle:** DIU Commercial Solutions Opening / Prize Challenge — Project Spectrum Strike.
> **Round:** Pitch (due 2026-06-15) → MVP (2026-07-10) → Live demo (2026-08-25).
> **Applicant:** EMILIA Protocol, Inc. — for-profit Delaware C-corp, founder/PI Iman Schrock (ORCID 0009-0004-0290-5433).
> **Posture:** EP is the **authorization & audit module** for autonomous spectrum coordination — best teamed under a spectrum-AI prime, or bid as a standalone governance/audit module. We do not claim to be the spectrum-parsing/triage engine.
>
> This file is the slide-by-slide copy. `deck.html` renders the same 10 slides for print-to-PDF.
> Requirement wording below is captured from the solicitation as recorded in
> `../application.md` §1/§4a and **must be re-confirmed on the live DIU portal before submitting**.

---

## Slide 1 — Title

**Headline:** EMILIA Protocol — Authorization & Audit Module for Autonomous Spectrum Coordination

**On-slide body:**
- A named human's signed "yes" before an AI agent does anything irreversible — with a receipt anyone verifies offline.
- For Spectrum Strike: the governance & audit layer under your triage agent.
- Open Apache-2.0 standard + reference implementation. IETF Internet-Draft live.
- EMILIA Protocol, Inc. · Iman Schrock, Founder/PI · team@emiliaprotocol.ai

**Visual:** EP wordmark on dark field; one line beneath: "agent → escalation decision → named-human signoff → offline-verifiable receipt." Gold rule under the title.

**Speaker notes:** Open by naming the seam honestly. Spectrum Strike wants AI agents to triage spectrum-coordination and authorization requests fast, but keep humans on the loop for high-risk packets and keep the whole thing auditable as policy changes. EP is the piece that makes that human control and that audit trail a verifiable cryptographic fact rather than a runtime promise. We are not the spectrum engine — we are the part that proves a named human authorized the irreversible releases, and proves it offline, forever.

---

## Slide 2 — The DIU Problem, in DIU's Words

**Headline:** What Spectrum Strike Is Asking For

**On-slide body:**
- Collapse spectrum-coordination & authorization from **90+ days → under 5 days** with AI agents.
- Triage **without persistent human-in-the-loop bottlenecking**, while providing **human-on-the-loop** for flagged high-risk packets.
- **Auditable governance as policies change** — the rules will move; the audit must hold.
- A hard **0% false-negative** safety bar on safety-critical packets.

**Visual:** Four-quadrant card — Speed (90d→<5d) · Human-on-the-loop · Auditable governance · 0% false-negative — with the last two highlighted in gold as EP's lane.

**Speaker notes:** These four asks are quoted from the solicitation as we captured it; we re-verify them on the portal before we submit. Two of the four are squarely EP's lane: human-on-the-loop authorization for high-risk packets, and auditable governance that survives policy changes. The 0%-false-negative bar is a safety requirement — and a safety requirement is only as good as the evidence that the safety control actually fired. That evidence is exactly what an authorization receipt is.

---

## Slide 3 — The Gap Today

**Headline:** Control and Accountability Are a Runtime Promise, Not a Verifiable Invariant

**On-slide body:**
- Today "a human approved this" lives in a log the operator controls — testimony, not evidence.
- Logs can be edited, reconstructed, or lost; you trust the system that produced them.
- When the policy changes mid-mission, nothing ties an old approval to the exact policy in force then.
- At a 0%-false-negative bar, "trust our logs" is not an audit posture.

**Visual:** Left: a generic "audit log" box with an editable-pencil icon and a dashed trust boundary around the operator. Right (gold): a self-contained receipt that verifies outside that boundary.

**Speaker notes:** The status quo for agent oversight is a database row that says "approved." That row is only as trustworthy as the operator who holds it — it is testimony. For a contested-spectrum decision that radiates and cannot be recalled, and under a 0%-false-negative mandate, testimony is not enough. You need an artifact that proves a named human approved that exact emission, under the exact policy in force, before it executed — and that a third party can check without trusting the operator's runtime at all.

---

## Slide 4 — EP in One Diagram

**Headline:** From Agent Judgment to Offline-Verifiable Proof

**On-slide body:**
- **1. Escalation decision (PIP-007):** the agent's own signed record — "I judged this packet required human authorization." A claim by a party EP **identifies but never trusts**.
- **2. Named-human signoff:** WebAuthn device-bound approval over the exact action hash + pinned policy. The operator never holds the key.
- **3. Authorization receipt:** signoff + hash-pinned policy + append-only Merkle-anchored log, composed into one self-verifying document.
- **4. Offline verification:** any third party validates with only the approver's public key — no network, no trust in the operator.

**Visual:** Left-to-right pipeline of four nodes (Escalation → Signoff → Receipt → Offline verify), gold connectors, a "no network required" tag under node 4.

**Speaker notes:** Walk the four boxes. The first is PIP-007, our escalation attestation — and be precise: it is the agent's *claim* that it escalated, bound into what the human signs, never a trust input and never model introspection. The second is the device-bound human signature over the exact action. The third composes those with the pinned policy and the append-only log into one receipt. The fourth is the payoff: anyone validates it offline with just a public key. That last property is what makes a receipt evidence instead of testimony.

---

## Slide 5 — Requirement → Primitive Map

**Headline:** Each Spectrum Strike Ask, Mapped to the Exact EP Primitive

**On-slide body (table):**

| DIU requirement (re-confirm on portal) | EP primitive that satisfies it | What the receipt proves |
|---|---|---|
| Human-on-the-loop for flagged high-risk packets | WebAuthn device-bound **named-human signoff** over the exact action hash | A *named* human approved this *exact* spectrum release *before* it executed |
| Auditable governance **as policies change** | **Hash-pinned policy** binding in every signoff | Each approval is bound to the exact policy version in force — tamper-evident, replay-proof |
| Audit teeth for the **0% false-negative** bar | **Offline-verifiable receipt** + append-only Merkle-anchored log | Any third party re-checks every release with only a public key, no operator trust |
| Why the agent asked for a human at all | **PIP-007 escalation attestation** (signed, never trusted) | The agent's stated escalation reason is bound into what the human signed |
| Disconnected / classified operation | **Air-gap installer** (`deploy/airgap/`) | Issue and verify with no network, forever |

**Visual:** The table itself, DIU-ask column in muted ink, EP-primitive column in gold.

**Speaker notes:** This is the heart of the pitch. Each row is a solicitation requirement on the left and the specific, shipped EP primitive on the right. Note we map to mechanisms that exist today — device-bound signoff, hash-pinned policy, Merkle-anchored logs, the air-gap installer, PIP-007 — not to a roadmap. The right-most column states exactly what the receipt proves, in the narrow language we hold ourselves to. We do not claim the receipt proves the decision was wise or that the triage was correct — only that the named human authorized that exact action under that exact policy.

---

## Slide 6 — Why This Is Decisive for DoD

**Headline:** Built for Disconnected, Contested, Accountable Operations

**On-slide body:**
- **Offline / air-gapped verification:** receipts verify with no network, forever — the air-gap installer ships today (`deploy/airgap/`).
- **Classified & disconnected ops:** no trust in, and no connection to, the operator's runtime; only the approver's public key is needed.
- **Tamper-evident governance-as-policy-changes:** hash-pinned policy means an old approval can't be silently re-attributed to a new rule.
- **Attributable accountability:** every release names the human and the agent's stated escalation reason — discoverable in an after-action review.

**Visual:** Three pillars — Disconnected · Tamper-evident · Attributable — over a faint "no network" globe.

**Speaker notes:** This is where EP separates from a SaaS audit dashboard. A contested-spectrum environment is exactly where you cannot assume connectivity to a vendor's servers, and exactly where the audit trail must survive scrutiny. EP's verification is offline by construction and the air-gap installer already exists. And because policy is hash-pinned into each signoff, "governance as policies change" stays honest — you can always show which rule authorized which release.

---

## Slide 7 — Proof It's Real

**Headline:** Formally Assured, Independently Verifiable, Installable Today

**On-slide body:**
- **26 TLA+** safety properties machine-checked across **413,137 states**.
- **22 Alloy** assertions (15 core + 7 federation), **0 counterexamples**, re-run in CI.
- **85 red-team** cases cataloged.
- **IETF Internet-Draft** `draft-schrock-ep-authorization-receipts` at **-01**, live on datatracker.
- Independent **JS, Python, Go** verifiers + conformance suite; `npm i @emilia-protocol/verify` and check a receipt today.

**Visual:** Five-stat strip (26 / 413,137 / 22 / 85 / -01) in gold, with npm + datatracker line beneath.

**Speaker notes:** Evaluators can check every number themselves. The TLA+ and Alloy work proves the safety of the authorization state machine — be careful to scope it: it proves the protocol's invariants, not an AI model's behavior or a host's integrity. The format is an IETF Internet-Draft at revision -01, and there are three independent verifiers in three languages that agree on the conformance vectors. An evaluator can install one npm package and verify a real receipt in under a minute. That is the IETF bar for a real standard: multiple independent interoperable implementations.

---

## Slide 8 — Live 60-Second Demo

**Headline:** Issue a Spectrum-Release Receipt. Mutate One Field. Watch It Fail.

**On-slide body:**
- **Issue:** `ep-issue` mints a receipt for a mock "spectrum release authorization" (freq 2401 MHz, AOR-7), with a PIP-007 escalation attestation. Verify → **7/7 checks pass**.
- **Mutate:** change one field — frequency 2401 → 2455 MHz (an adversary retargets the emission).
- **Verify:** `@emilia-protocol/verify` → **NOT VERIFIED**; `action_hash`, `context_commitments`, and `inclusion` fail. Exit code 0 → 1.
- The signature was over the *exact* action. Change the target, and the proof collapses.

**Visual:** Split terminal — left pane green "✅ VERIFIED — 7/7"; right pane red "⛔ NOT VERIFIED — ✕ action_hash". (Full script: `DEMO-SCRIPT.md`.)

**Speaker notes:** This is the moment that lands the argument. We issue a real receipt for a realistic irreversible spectrum release and it verifies seven of seven checks offline. Then we change a single number — the frequency — exactly the way an adversary or a bug would retarget an emission. Verification immediately fails on the action-hash and commitment checks, and the exit code flips. Nothing about this is mocked: it is the published packages running offline. The script is in DEMO-SCRIPT.md with a browser fallback at emiliaprotocol.ai/verify.

---

## Slide 9 — Honest Scope & Teaming

**Headline:** What EP Is — and What It Needs From a Prime

**On-slide body:**
- **EP is** the governance/authorization & audit layer: signed escalation, named-human signoff, hash-pinned policy, offline-verifiable receipts.
- **EP is not** the spectrum-parsing/triage engine, RF modeling, or the deconfliction logic.
- **Best fit:** teaming/subcontract as the "governance & audit module" under a spectrum-AI prime — or a standalone audit-module bid.
- **What EP needs from a prime:** the triage agent's escalation hook (call EP's MCP server before an irreversible release), the policy definitions to hash-pin, and the named approver enrollment.
- **What a receipt does NOT prove:** not that the decision was wise/lawful; not real-world biometric identity beyond key↔approver enrollment; not rendering faithfulness (crypto proves a key signed a hash — narrowed by structured rendering + signed display attestation, not eliminated).

**Visual:** Two stacked bands — top (gold) "EP: authorization & audit," bottom (muted) "Prime: spectrum triage / RF / deconfliction" — with an MCP arrow between them.

**Speaker notes:** State the seam plainly; it builds credibility. EP does not parse spectrum or decide what to triage. We are the layer that makes the human authorization and the audit trail provable. The clean integration is our MCP server: a spectrum-AI agent calls EP to obtain a verifiable human signoff before any irreversible release. We are explicitly seeking a spectrum-AI prime to team under, and we are equally clear about what a receipt does not prove — wisdom, lawfulness, biometric identity, or perfect rendering. Honesty about the boundary is the asset here.

---

## Slide 10 — Ask & Roadmap

**Headline:** The Ask, the Timeline, and How to Reach Us

**On-slide body:**
- **Ask:** advance EP as the governance/audit module for Spectrum Strike — as a sub to a spectrum-AI prime, or as a standalone audit-module evaluation.
- **Roadmap aligned to the rounds:**
  - **Pitch — 2026-06-15:** this deck + the 60-second offline demo.
  - **MVP — 2026-07-10:** EP wired to a reference triage agent via MCP; receipts for every simulated high-risk release; offline audit bundle.
  - **Live demo — 2026-08-25:** end-to-end run — agent escalates, named human signs off, receipts verify offline, a mutated release fails.
- **What we bring today:** TRL ~6 receipt/verify core, IETF I-D -01, 3-language verifiers, air-gap installer.
- **Contact:** Iman Schrock · team@emiliaprotocol.ai · emiliaprotocol.ai · github.com/emiliaprotocol/emilia-protocol

**Visual:** Three-stop timeline (06-15 → 07-10 → 08-25) in gold with the contact line beneath.

**Speaker notes:** Close on the concrete. The ask is to advance EP as the audit and authorization module, ideally teamed under a spectrum prime. The roadmap maps one-to-one to DIU's three rounds, and each milestone is a demonstrable artifact, not a slideware promise. We are pre-revenue with no customers and a solo founder — we say so — but the receipt/verify core is real and installable today. Contact is team@emiliaprotocol.ai.

---

### Honesty footer (carry verbally; not a slide)

EMILIA Protocol, Inc. is pre-revenue with **no customers** (pilots have been offered, none signed) and a **solo** founder/PI. Claims on these slides are scoped to what an authorization receipt proves per `docs/RECEIPT-CLAIMS.md`. Solicitation requirement wording is as captured in `../application.md` and must be re-confirmed on the live DIU portal before submission.
