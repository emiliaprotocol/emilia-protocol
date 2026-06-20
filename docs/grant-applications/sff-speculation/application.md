# Survival and Flourishing Fund — Speculation Grant Application

**Prepared:** 2026-06-20
**Applicant:** Iman Schrock (sole founder), EMILIA Protocol, Inc.
**Contact:** team@emiliaprotocol.ai
**Repo / artifacts:** open-source, Apache-2.0; live at https://www.emiliaprotocol.ai (`/quorum` page + live multi-party demo)
**Ask:** a **Speculation Grant of $10,000–$50,000** to fund continued development plus the multi-party formal-model extension
**Intent:** to apply to the **next full SFF S-Process round** (a Speculation Grant is the prerequisite for guaranteed eligibility)

> Framing for SFF: this is human-in-the-loop **control** for autonomous AI agents — a concrete, shippable safety mechanism, not a research agenda. The thesis below is written through the catastrophic-risk lens, and it is deliberately honest about what the mechanism does and does not prevent.

---

## The risk this addresses

AI agents are being given credentials sufficient to take irreversible, high-stakes actions: releasing payments, changing beneficiary records, rotating production credentials, deleting data, deploying code into critical systems. As capability and autonomy scale, so does the failure mode that matters most for catastrophic risk: **an agent that is misaligned, compromised, or prompt-injected executing a consequential action that no accountable human authorized — and that no one can prove was unauthorized after the fact.**

Existing controls don't close this. Identity and access management authorizes sessions and scopes, not individual actions. Human "approval" is usually a click in a workflow tool, recorded in a mutable database the operator controls — testimony, not evidence. There is no portable, verifiable artifact that binds a specific accountable human to a specific irreversible action *before* it runs.

EMILIA Protocol (EP) is the missing control: a **fail-closed, cryptographically-enforced gate** that an autonomous agent cannot pass on a high-risk action without a named human's device-bound signature over the *exact* action. Crucially, the signature happens on the human's own hardware (WebAuthn / ES256), **outside the model's context** — so prompt injection can change what the agent *proposes*, but cannot produce the approval. A subverted agent therefore yields one of two outcomes: the gated action is **blocked** for want of a valid signoff, or it ran and the receipt **names who approved it**. The absence of a receipt for a gated action is itself a forensic finding.

## Why the two-person rule matters for safety

A single human approver is itself a single point of failure: one compromised credential, one coerced individual, one careless rubber-stamp. The newest EP mechanism — **EP-QUORUM-v1**, now shipped and verified — ports the nuclear two-person rule to AI agents. A gated action requires a *quorum* of distinct human signatories (M-of-N or strictly ordered), enforced by a fail-closed predicate that checks: every signature valid and bound to the exact action, signers distinct humans (separation of duties), in admitted roles, threshold met, order respected, all inside a time window. The canonical roster is a government oversight chain — Program Officer → Authorizing Official → Inspector General. **Even one compromised approver is insufficient** to release a high-stakes action.

This is the control that lets organizations grant agents real authority without a single point of failure — the safety property that makes autonomy survivable as it scales.

## What this is honest about (per the draft's Security Considerations)

Trust infrastructure dies of overclaiming, so the boundaries are stated plainly:

- EP **does not** defeat **collusion** among distinct enrolled humans, one human controlling multiple enrolled identities, or a **coerced** approver. What it does is make such acts **attributable** — named, signed, evidenced — which raises the cost of insider fraud; it does not make it impossible.
- Cryptography proves a key signed a hash; it **does not** prove the human saw a faithful rendering of the action (presentation attacks are the gravest residual risk, mitigated by policy-committed render templates and an independent second rendering surface for high-value policies — not by mathematics).
- Enforcement strength depends on deployment topology, and EP labels it: **STRONG** (execution-side — the system of record verifies before acting, unbypassable by anyone not controlling it), **STANDARD** (middleware — strong against agent error and prompt injection, bypassable by an operator with code control), **BASIC** (evidence-only). Marketing MUST NOT claim a stronger class than deployed.
- Offline verification establishes authenticity at commit time, not current revocation status.

These are quoted from the protocol's own Security Considerations because calibrated honesty is what makes a control mechanism trustworthy to a safety funder.

## Why this is a control mechanism, not a research agenda

The distinguishing feature for SFF is that this already works:

- **Working code, in the live action-authorization path.** EP-QUORUM-v1's fail-closed gate (`lib/signoff/quorum-session.js`) is wired into the live Class-A path: the quorum policy is persisted at issuance, an early-reject runs at approval (`approve-webauthn`), and the consume gate blocks any action whose quorum isn't satisfied (`trust-receipts/[receiptId]/consume`).
- **Tri-language conformance.** Three independent verifiers (JavaScript, Python, Go) agree on canonical adversarial vectors — including **9 EP-QUORUM-v1 vectors that agree across all three languages** (`conformance/vectors/quorum.v1.json`, run via `node conformance/run.mjs`). Multiple interoperable implementations is the IETF standard bar.
- **Multi-device end-to-end verification.** A virtual-authenticator E2E test drives multiple devices through the ordered oversight chain and confirms duplicate / out-of-order / late signers are rejected and consume is blocked until the trail is satisfied (`e2e/multi-party-quorum.spec.js`, passing).
- **Formal models.** 26 machine-checked TLA+ theorems (0 counterexamples, re-run in CI) plus Alloy models prove safety of the authorization state machine: no replay, no self-approval, no bypass within the modeled system.
- **IETF engagement.** Posted Internet-Draft `draft-schrock-ep-authorization-receipts-01`.

This is a shippable, verifiable safety control today — exactly the kind of concrete intervention SFF's mandate values over open-ended research promises.

## What the Speculation Grant funds

A **$10k–$50k** grant covering a few months of solo-founder full-time work, focused on the two highest-leverage safety deliverables:

1. **Multi-party formal-model extension.** The current TLA+/Alloy models prove the single-signoff state machine; the draft's Security Considerations honestly note the m-of-n / quorum flow is *specified and tested but not yet formally proven*. This grant extends the machine-checked models to cover the EP-QUORUM-v1 predicate — distinctness, threshold, ordering, time-window, action-binding — so the two-person rule is *proven*, not only implemented, with counterexamples public and re-run in CI.
2. **Continued development of the control.** Harden the live quorum path, grow the adversarial conformance corpus across all three languages, and advance the IETF draft toward a quorum-bearing revision — keeping enforcement and offline verification provably in agreement.

No commercial-product work is funded here; the GovGuard/FinGuard pilots (an *offer*, not a completed engagement) are funded separately by the company.

## Track record and transparency

Solo founder shipping in public: an IETF Internet-Draft; EP-QUORUM-v1 built, wired into the live path, and verified by multi-device E2E and tri-language conformance; three interoperable verifiers; 26 TLA+ theorems at 0 counterexamples; a live site with a working multi-party demo — all Apache-2.0 and independently checkable, no claim resting on trusting the applicant. EMILIA Protocol, Inc. is a for-profit Delaware C-corp; pre-revenue, no production customers. SFF eligibility covers incorporated for-profit and nonprofit organizations globally. This grant funds the open public-good control mechanism; commercial activity is funded separately. We intend to apply to the next full S-Process round and treat this Speculation Grant as the on-ramp.
