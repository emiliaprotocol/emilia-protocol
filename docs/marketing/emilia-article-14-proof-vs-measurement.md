<!-- SPDX-License-Identifier: Apache-2.0 -->
# Proof, not measurement
### EMILIA and EU AI Act Article 14 — what counts as evidence of human oversight

> **Decision logs are testimony. Scores are opinion. Receipts are evidence.**

---

## The Article 14 question

EU AI Act **Article 14** requires high-risk AI systems to be subject to *effective* oversight by natural persons — a human must be able to understand the system, decide not to use its output, **override** it, and **intervene or stop** it. High-risk (Annex III) obligations apply from **2 August 2026**. Colorado's SB 24‑205 / SB 26‑189 ADMT regime follows (2027).

When a regulator, a court, or an insurer later asks the only question that matters —

> *"Show me that a specific authorized human actually approved **this** irreversible action **before** it ran."*

— what do you hand them? Most "human oversight" tooling produces one of three things, and **none of them answers that question**:

- **A decision log** — the system's own account of what happened. Self-reported, mutable, and exactly what's in dispute. Testimony, not evidence.
- **An oversight score / dashboard** — a heuristic rating of how attentive or "independent" the reviewer probably was, computed over self-reported telemetry. An *opinion about* the human, not a *binding of* the human to the act. Gameable, and nothing a court can verify deterministically.
- **A "human-in-the-loop" toggle** — proof a review *step existed*, not that a named person authorized *this* action.

Having a human in the loop is not the same as proving the human exercised authority over a specific irreversible act. Article 14 is about the latter.

## The bright line: measurement vs. proof

Evidence of human oversight has to do two things a score cannot:

1. **Bind** — tie a *named human* to an *exact action* (the specific payment, deletion, deployment), before it executed.
2. **Verify without trust** — let an outside party confirm it **offline, with a public key**, without trusting the vendor, the log, or the system under review.

A score does neither. It rates a process; it doesn't bind an identity to an act, and you have to trust whoever computed it.

| | Oversight score / dashboard / log | **EMILIA authorization receipt** |
|---|---|---|
| **Artifact** | A number or a narrative *about* the review | A cryptographic **proof** of the authorization itself |
| **Evidence type** | Statistical / behavioral — an indicator | **Mathematical** — Ed25519 over RFC 8785 canonical JSON |
| **What it binds** | How attentive the reviewer probably was | A **named human → an exact action**, pre-execution |
| **Verifiable by an outsider?** | Only by trusting the issuer | **Yes — offline, with a public key.** No backend, no vendor trust |
| **Tamper-evidence** | Log integrity (you still trust the log) | The action can't change without breaking the signature |
| **Enforcement** | Advisory — it scores after the fact | **Fail-closed — no receipt, no execution** |
| **Gameable?** | Yes — telemetry is self-reported | No — a forged or altered authorization fails verification |

**A score tells you the oversight was *probably* real. A receipt *proves* the authorization happened — and refuses to let the action run without it.** For irreversible-action accountability, the binding is load-bearing; the score is, at most, an annotation on top of it.

## What EMILIA provides for Article 14

EMILIA is the **authorization-receipt layer**: for each irreversible agent action, an offline-verifiable receipt that a named human authorized *that exact action*. Concretely it gives an Article 14 program:

- **The audit artifact regulators can actually check** — deterministic verification with a public key; the receipt *is* the evidence, reproducible by anyone, years later.
- **Override and intervention you can prove** — a human's decision to approve, decline, or stop is captured as signed, tamper-evident, per-action proof, not a log entry.
- **Enforcement, not exhortation** — `428 — no receipt, no execution`. Oversight that can be bypassed isn't oversight; EMILIA fails closed.
- **Two-person control where the stakes demand it** — quorum receipts (a cryptographic two-person rule) and scoped delegation with verify-time constraint enforcement.
- **Built on accepted standards** — Ed25519 (RFC 8032), JSON canonicalization (RFC 8785); receipts express as JWS (RFC 7515) or COSE for interop, and can be logged to a transparency service (SCITT) for append-only accountability. Open IETF Internet-Draft, Apache-2.0, reference verifiers in JavaScript, Python, and Go.

## Honest scope

A receipt is **necessary, not sufficient**. It proves a named human authorized the exact action; it does **not** prove the decision was wise, lawful, or that the person fully understood the system — and a quality signal (e.g. a third-party judgment score) can sit *inside* a receipt as one more claim. EMILIA supplies the load-bearing, verifiable binding that the rest of an oversight program builds on. This is engineering and standards material, not legal advice; Article 14 compliance is a program, and the receipt is its evidence backbone.

---

**EMILIA Protocol** · authorization receipts for irreversible AI-agent actions · `draft-schrock-ep-authorization-receipts` · Apache-2.0 · team@emiliaprotocol.ai
