# Verifiable Human-Authorization Evidence for Autonomous Action

**EMILIA Protocol — one-page brief for autonomy programs, primes, and oversight bodies**

> **The line that matters:** EP turns human oversight from a policy promise into a
> cryptographic artifact. It proves *authorization* — not wisdom, lawfulness, or
> proportionality. **No irreversible autonomous action without a verifiable human receipt.**

## The problem: everyone requires human control; no one can prove it

DoD Directive 3000.09 requires "appropriate levels of human judgment over the use of
force." EU AI Act Article 14 requires high-risk AI be "effectively overseen by natural
persons." NIST AI RMF and the UN CCW say the same. Every instrument *mandates* meaningful
human control — and none provides an artifact that **proves it after the fact**.

Today, the record that a named human authorized an autonomous action is a **log the
operator controls**. It can be backfilled, forged, or rubber-stamped. After an incident,
an inspector general, a court, a coalition partner, or a treaty-verification regime has
no way to confirm — without trusting the very operator under review — that a specific,
accountable human authorized *that exact* engagement, at the right scope, currently,
under the right authority. **That is the evidence gap.**

## What EMILIA provides

An **offline-verifiable authorization receipt**: a named human's device-bound signoff over
one exact action (or a bounded engagement envelope), checkable by any third party without
trusting the operator. Open standard (Apache-2.0, IETF Internet-Drafts), formally verified
core, cross-language verifiers (JS / Python / Go), with an air-gap installer for classified
enclaves. EMILIA is the **verifiable human-authorization evidence layer** for autonomous
action: it proves *who* authorized *what*, under *which* policy, at *which* assurance level,
before execution — checkable later without trusting the operator's logs.

## It already does what the mission needs

| Mission requirement | EMILIA mechanism (shipped) |
|---|---|
| A *named, accountable* human — not a shared console login | Device-bound signoff (WebAuthn + user verification) |
| Two-person rule / launch authority | Quorum (m-of-n distinct humans, ordered) |
| Authority bounded by rules of engagement | Monotonic delegation constraints + signed ROE/policy reference |
| The order was *current*, not a stale standing authorization | Validity window + observed-evidence freshness (fail-closed) |
| Revoke / halt an autonomous envelope | Revocation + continuous evaluation |
| Works in contested, disconnected, classified ops | Fully offline verification; air-gap deployment |
| No verified human authorization → no effect | Fail-closed enforcement ("no receipt, no execution") |

## Example: human-on-the-loop weapons-release authorization

A human authorizes a **bounded envelope** — effect class, target set, geofence, time
window — via a two-person quorum receipt. The autonomous system may act *only* inside that
envelope, *only* while the authorization is unrevoked and unexpired. Every action carries a
content-derived reference to the authorizing receipt. After the engagement, an auditor
verifies offline: *which* humans authorized, *what* envelope, *when*, under *which* ROE —
and that nothing was forged, replayed, or moved to an action outside the scope.

## What it proves — and what it does not

**Proves:** a specific, pinned human (or quorum) authorized this exact action / envelope,
at a stated scope, within a validity window, under a referenced authority; the record
cannot be forged, replayed, re-targeted, or repudiated; anyone can verify it offline.

**Does not prove:** that the human *understood* the action (a WYSIWYS / display concern),
that they were uncoerced, or that the action was lawful or wise. EMILIA is a **necessary,
not sufficient** condition for meaningful human control. We state this plainly because
serious programs will — and because over-claiming is how accountability tech loses trust.

## The defense-grade version

Autonomous systems are moving faster than human oversight can audit. EMILIA provides a
**fail-closed receipt layer that proves who authorized what, under which policy, with which
assurance level, before execution.** It works offline, supports two-person quorum, binds the
exact displayed action, and gives inspectors a tamper-evident artifact they can verify
without trusting the operator. Maps to DoD Directive 3000.09's "appropriate levels of human
judgment" and its responsible/traceable/governable-AI and auditable-system requirements.

*A note on scope: lead with **3000.09** in U.S. defense rooms. The **EU AI Act** is a
civilian-autonomy tailwind only — it excludes systems used exclusively for military,
defense, or national-security purposes.*

## The ask

A **lighthouse pilot** with one program or prime carrying a 3000.09 / RAI compliance
burden: deploy EMILIA in observe-mode on a single human-control boundary, produce the
verifiable evidence trail, and demonstrate the compliance artifact in a tabletop review.
No production change in observe mode; offline and air-gap ready.

*EMILIA Protocol, Inc. · open standard + managed assurance layer · team@emiliaprotocol.ai*
