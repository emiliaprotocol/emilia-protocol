<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA — AAIF pitch script (FINAL, record-ready 2026-07-03)

Audience: Manik Surtani (AAIF CTO) + Technical Committee. Target ~4:30.
Tone: calm, technical, no hype. A primitive, not a company pitch.
Every number verified against the repo. Keep the honesty caveats verbatim.

---

## HERO

> "Hey Manik — thanks for the time. Straight to it. The agent stack is
> filling in fast: identity, tools, execution, transparency logs. One
> primitive nobody produces — **portable proof a named human authorized
> this exact, irreversible action, before it ran.** That's the whole of
> what EMILIA does."

- (the clip): "That animation is the shape of it — an action scanned,
  then authorized by a named human, or denied."
- (the pills): "A posted cluster of Internet-Drafts, Apache-2.0,
  JavaScript / Python / Go verifiers, verifies offline."

## 01 · THE LANDSCAPE GAP — the void map

> "Each ring is a real effort — tools, identity, attestation and logs,
> agent frameworks. None answers *who authorized this exact action*.
> Logs get close, but a log is the operator's own editable record."
>
> **"Logs are testimony. Receipts are evidence."**

## 02 · WHERE IT SITS — the stack

> "It sits above MCP, goose, AGENTS.md — a thin layer between intent and
> mutation. Composes with all of them, replaces none."
>
> **CORE SENTENCE (slow, every word):** "A named human — or a quorum —
> signs the exact canonical bytes of one irreversible action, before it
> runs. Offline-verifiable, bound to that action and no other, usable
> once."

## 03 · LIVE DEMO — try to break it

> "The part a CTO trusts. Four states: missing receipt → blocked, valid
> → runs once, replay → refused, forged signature → rejected.
> Deny-by-default, bound to the action hash, one-time. Real running code
> — I'll send you the receipt so you can verify it offline yourself."

- (optional: click into the live demo tab and run the attack sequence)

## 04 · SCITT COMPOSITION PROOF

> "Composition, not competition. The same canonical receipt rides as a
> **COSE_Sign1 Signed Statement**, registers through SCRAPI, inclusion
> verified in CI. SCITT proves a statement was *logged*; EMILIA proves
> *who authorized* the action — and rides on top of SCITT."

## 05 · HIGHER-STAKES SURFACES — the four cards (keep it short)

> "Same receipt spine, four surfaces: single approval; quorum, the
> two-person rule; the **Evidence Graph** — authorization, policy, and
> identity in one offline-verifiable graph, *who authorized, what ran,
> under which policy*; and a human-control profile for defense and
> public-sector oversight. The Evidence Graph is the draft we just filed
> — the composition point I most want your read on."

## BUILT, TESTED, LIGHTWEIGHT — the proof-stats grid

> "Small enough to try, serious enough to review: roughly **4,800
> automated tests, 26 machine-checked TLA+ safety properties, Alloy
> models, eight cross-language conformance suites** — and it runs in one
> line, `npx @emilia-protocol/issue demo`."

## REAL AND SMALL — the honesty bullets

> "Status, plainly: **not one draft but a posted cluster on the
> datatracker** — the receipt, quorum, the evidence graph that composes
> them, a challenge protocol, presentation binding, and trust
> establishment. Apache-2.0, verifiers in JavaScript, Python, and Go,
> thousands of tests, plus TLA+ and Alloy. Active *individual*
> Internet-Drafts — not an IETF endorsement. The three verifiers share
> one repository and agree byte-for-byte on the same vectors; a second,
> independent reimplementation is already underway. No account, no
> backend for the demo."

## ECOSYSTEM PROOF — the fire-drill / RR-1 numbers

> "The adoption path is a badge, not a scold: we scanned the MCP
> ecosystem, and a real share advertise high-risk capability. The line
> we lead with — *your most dangerous action should be safer than the
> ecosystem default.*"

## OBJECTIONS, ANSWERED — the Q&A grid

> "The usual objections are answered right here — is it just SCITT, is
> it OAuth, latency, where it standardizes. One-liners on screen; happy
> to take any of them."

## 06 · THE ASK

> "That's it. Apache-2.0, composes with MCP, goose, and AGENTS.md. The
> ask is non-binding: **is this the missing human-authorization layer,
> and where should it belong** — and does AAIF see it composing with the
> surfaces you care about?"
>
> "One last thing — EMILIA is named after my daughter. This one matters
> to me. Thank you for the read."

---

## One-liners if he interrupts with an objection (don't volunteer)

- **Just SCITT?** → SCITT logs a statement; never asserts a named human
  authorized the action. EP is that assertion, riding *as* a SCITT
  Signed Statement.
- **OAuth / WIMSE?** → Those say which *machine* may act. EP says a
  *named human* authorized *this exact action*. Above identity, not
  instead of it.
- **Latency of per-action sign-off?** → Only irreversible actions gate.
  Pre-auth + scoped delegation + quorum carry throughput.
- **Where does it standardize?** → An individual IETF I-D cluster —
  receipts, quorum, the evidence graph, a challenge protocol, and more —
  composing with SCITT / RFC 9943.

---

## Verified facts (do not drift on camera)

- Tests: 4,855 as of 2026-07-03 → say "roughly 4,800." OK.
- TLA+: exactly 26 safety properties in `formal/`. OK.
- Conformance: **eight** cross-language suites (`node conformance/run.mjs`
  runs 8). Do NOT say nine.
- Verifiers: **three cross-language** (JS/Python/Go), one repository —
  NOT "independent." The independent one is COSA's clean-room
  reimplementation, in progress. Never call the three "independent."
- Drafts: a posted cluster of INDIVIDUAL Internet-Drafts. Never "IETF
  standard," "adopted," or "endorsed."
- SCITT: EP–SCITT profile + reproducible mock-transparency verification
  in CI — not official SCITT WG conformance.
- `npx @emilia-protocol/issue demo` — real (README line 57).
