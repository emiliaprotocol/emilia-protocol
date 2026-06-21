# Emergent Ventures (Mercatus, EV AI vertical) — Grant Application

**Prepared:** 2026-06-20
**Applicant:** Iman Schrock (sole founder), EMILIA Protocol, Inc.
**Contact:** team@emiliaprotocol.ai
**Site:** https://www.emiliaprotocol.ai (live `/quorum` product page + live multi-party demo)
**Ask:** a flexible grant in the **$25,000–$100,000** range to fund a design-partner pilot plus the standards and formal-verification work
**Vertical:** EV AI

> EV applications are short and unstructured by design. The sections below answer EV's actual prompts — who I am, what the project is, why it's ambitious and important, what I'd do with the money, why conventional funders won't fund it, and my track record — in plain founder voice.

---

## The one-line version

**The two-person rule for AI agents** — the control that lets an organization give an agent real authority without creating a single point of failure.

For sixty years, no one human has been able to launch a nuclear weapon alone; it takes two people, each turning their own key, neither able to act for the other. We are about to hand AI agents the authority to release wires, change beneficiaries, rotate production credentials, and deploy code — and we have no equivalent. EMILIA Protocol is that equivalent, built as open infrastructure: a cryptographically-enforced, offline-verifiable gate that binds a named, accountable human (or a quorum of them) to one exact high-risk action, before it runs.

## Who I am

I'm Iman Schrock, the sole founder of EMILIA Protocol, Inc. I work in public: I write the standard, the code, and the formal proofs myself, and everything I claim is checkable in the open-source repository under Apache-2.0. I'm not raising this on a deck of projections — the protocol already ships, the multi-party "two-person rule" extension is built and verified end-to-end, and the work is posted as an IETF Internet-Draft. I move fast and refuse to overclaim; the protocol's own documentation is stricter about what it *doesn't* prove than most vendors are about what they do.

## What the project is

When an AI agent takes an irreversible action and something goes wrong, two questions have no good answer today: *which named human authorized this exact action?* and *can a third party prove it later without trusting the operator's own logs?* Access-management tools authorize sessions and scopes, not individual actions. Approval clicks live in mutable databases controlled by the very party whose conduct is later in question. That's testimony, not evidence.

EMILIA closes the gap with a small primitive: an **authorization receipt**. Before a gated action runs, a named approver signs the exact action — its full parameters, hashed — using a device-bound key (WebAuthn / ES256) held on their own hardware. The operator orchestrates the request but **cannot forge the signature** and cannot replay it. The resulting receipt is Merkle-anchored and **verifiable fully offline, forever** — anyone can confirm that a specific enrolled human approved this exact action, exactly once, with separation of duties enforced, using only the receipt and the approver's public key.

The newest and most ambitious piece — now shipped and verified — is **EP-QUORUM-v1**, the multi-party two-person rule. A single approver is often a single point of failure: one compromised, coerced, or careless human. EP-QUORUM enforces a *trail of signatories* — M-of-N or strictly ordered — with a fail-closed predicate that requires every signature to be valid and action-bound, the signers to be distinct humans in admitted roles (separation of duties), the threshold and order to hold, and all of it inside a time window. The canonical example is a government oversight chain: Program Officer → Authorizing Official → Inspector General, each turning their own key.

Two products ride on the one protocol: **FinGuard** (treasury and finance — wire release, beneficiary change, dual-auth) and **GovGuard** (government and defense — the nuclear two-person rule ported to AI agents). Both support single-signoff and multi-party.

I'm deliberately honest about the boundary. EP makes a misaligned, compromised, or prompt-injected agent unable to *unilaterally* execute a gated action — the signature happens on a human's hardware, outside the model's reach. It does **not** defeat collusion among distinct humans or a coerced approver; what it does is make those acts **attributable** — named, signed, and evidenced — which is exactly the property accountability needs and the property the field currently lacks.

## Why it's important and ambitious

This is infrastructure for the moment agents stop recommending and start *doing*. The ambition is to establish a portable, neutral standard — the way TLS made "is this connection authentic?" a solved, verifiable question — for "which accountable human authorized this exact agent action?" If agents are going to be trusted with consequential authority across finance, government, and critical systems, someone has to build the control that makes that authority safe to grant. I want EP to be that control, and to be open enough that even a vendor's competitors and regulators can verify it. That's an unusually high-leverage bet: a small, sharp primitive that, if it becomes the default, changes how every high-stakes agent deployment is governed.

## What I'd use the money for

A flexible grant of **$25k–$100k** funds two things, both of which conventional product revenue won't cover at this stage:

1. **A design-partner pilot.** Stand up GovGuard (or FinGuard) with a real oversight chain in observe-mode against live workflows, so the two-person rule is proven on real high-risk actions rather than only in the demo. The pilot is currently an *offer*, not a completed engagement; this funds the founder time and the integration work to convert it.
2. **The standards and formal-verification work.** Advance the IETF Internet-Draft, and extend the machine-checked formal models (TLA+/Alloy — 26 theorems verified today) to cover the multi-party quorum flow specifically, so the EP-QUORUM predicate is proven, not just implemented and tested. This is the work that makes EP a credible neutral standard rather than one company's library.

## Why conventional funders won't fund this

Venture capital wants a SaaS revenue curve, not a neutral open standard whose entire value is that it's free, auditable, and not controlled by any one vendor — including me. The open layer is most valuable precisely when no one has to trust the company that wrote it, which is the opposite of a venture moat. Traditional federal grants exist for this, but they move on timelines of quarters to years and want a finished research agenda. EV is the right funder because it backs *bold, unconventional, early bets on talented people moving fast* — and this is exactly that: a solo founder shipping a public-good control mechanism for a risk the rest of the field hasn't built for yet. The flexible, fast, low-overhead structure of an EV grant is what lets me run the pilot and harden the standard in parallel without waiting on a committee.

## Track record (all independently checkable)

Working code, not slideware:

- **IETF Internet-Draft** — `draft-schrock-ep-authorization-receipts-01`, posted, with the device-bound single-signoff fully specified.
- **EP-QUORUM-v1 shipped and verified** — multi-party M-of-N and ordered modes, fail-closed gate (`lib/signoff/quorum-session.js`), wired into the live Class-A path, verified by a multi-device virtual-authenticator end-to-end test and by **cross-language conformance: 9 quorum vectors agree across JavaScript, Python, and Go**.
- **Three interoperable verifiers** (JS / Python / Go) — the IETF bar of multiple independent implementations — plus a public conformance suite (`node conformance/run.mjs`).
- **Formal evidence** — 26 machine-checked TLA+ theorems, 0 counterexamples, re-run in CI; Alloy models alongside.
- **Live and public** — https://www.emiliaprotocol.ai with a `/quorum` product page and a working multi-party demo; everything Apache-2.0.

I've already submitted to other venues (Manifund, LTFF, and several federal/lab programs); EV's AI vertical is the right home for the *ambitious-bet* framing because it's the only one that moves at the speed I do.
