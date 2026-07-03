<!-- SPDX-License-Identifier: Apache-2.0 -->
# AAIF pitch — section-by-section script (for Manik, CTO, AAIF)

**Present off the LIVE page, scrolling top to bottom, one clean pass:**
https://www.emiliaprotocol.ai/aaif-video-pitch
Every heading below matches a box on the page **in the order you'll scroll past it** —
so you always have a line, even on the boxes between §05 and the ask.

**Before you hit record:** quiet room, door shut, demo pre-opened in a 2nd tab.
**No bio open** — start on the hook. Say the **CORE SENTENCE** slowly; it's the one that must be perfect.

---

### HERO — "The missing human-proof layer for agent actions"
> "Hey Manik — thanks for the time. Straight to it. The agent stack is filling in fast: identity, tools, execution, transparency logs. One primitive nobody produces — **portable proof a named human authorized this exact, irreversible action, before it ran.** That's the whole of what EMILIA does."
- (the clip): "that animation is the shape of it — an action scanned, then authorized by a named human, or denied."
- (the pills): "active individual Internet-Draft, Apache-2.0, JS/Python/Go verifiers, verifies offline."

### 01 · THE LANDSCAPE GAP — the void map
> "Each ring is a real effort — tools, identity, attestation and logs, agent frameworks. None answers *who authorized this exact action*. Logs get close, but a log is the operator's own editable record."
> **"Logs are testimony. Receipts are evidence."**

### 02 · WHERE IT SITS — the stack
> "It sits above MCP, goose, AGENTS.md — a thin layer between intent and mutation. Composes with all of them, replaces none."
>
> **CORE SENTENCE (slow, every word):** "A named human — or a quorum — signs the exact canonical bytes of one irreversible action, before it runs. Offline-verifiable, bound to that action and no other, usable once."

### 03 · LIVE DEMO — try to break it
> "The part a CTO trusts. Four states: missing receipt → blocked, valid → runs once, replay → refused, forged signature → rejected. Deny-by-default, bound to the action hash, one-time. Real running code — I'll send you the receipt so you can verify it offline yourself."
- (optional: click into the live demo tab and run the attack sequence)

### 04 · SCITT COMPOSITION PROOF
> "Composition, not competition. The same canonical receipt rides as a **COSE_Sign1 Signed Statement**, registers through SCRAPI, inclusion verified in CI. SCITT proves a statement was *logged*; EMILIA proves *who authorized* the action — and rides on top of SCITT."

### 05 · HIGHER-STAKES SURFACES — the four cards  (keep it short)
> "Same receipt spine, four surfaces: single approval; quorum, the two-person rule; the **Evidence Graph** — authorization, policy, and identity in one offline-verifiable graph, *who authorized, what ran, under which policy*; and a human-control profile for defense and public-sector oversight. The Evidence Graph is the draft we just filed — the composition point I most want your read on."

### BUILT, TESTED, LIGHTWEIGHT — the proof-stats grid
> "Small enough to try, serious enough to review: roughly **4,800 automated tests, 26 machine-checked TLA+ safety properties, Alloy models, nine cross-language conformance suites** — and it runs in one line, `npx @emilia-protocol/issue demo`."

### REAL AND SMALL — the honesty bullets
> "Status, plainly: it's an *active individual* Internet-Draft, not an IETF endorsement. Three independent verifiers — JavaScript, Python, Go — agree on shared vectors. No account, no backend for the demo."

### ECOSYSTEM PROOF — the fire-drill / RR-1 numbers
> "The adoption path is a badge, not a scold: we scanned the MCP ecosystem, and a real share advertise high-risk capability. The line we lead with — *your most dangerous action should be safer than the ecosystem default.*"

### OBJECTIONS, ANSWERED — the Q&A grid
> "The usual objections are answered right here — is it just SCITT, is it OAuth, latency, where it standardizes. One-liners on screen; happy to take any of them."

### 06 · THE ASK
> "That's it. Apache-2.0, composes with MCP, goose, and AGENTS.md. The ask is non-binding: **is this the missing human-authorization layer, and where should it belong** — and does AAIF see it composing with the surfaces you care about?"
> "One last thing — EMILIA is named after my daughter. This one matters to me. Thank you for the read."

---

## One-liners if he interrupts with an objection (don't volunteer)
- **Just SCITT?** → SCITT logs a statement; never asserts a named human authorized the action. EP is that assertion, riding *as* a SCITT Signed Statement.
- **OAuth / WIMSE?** → Those say which *machine* may act. EP says a *named human* authorized *this exact action*. Above identity, not instead of it.
- **Latency of per-action sign-off?** → Only irreversible actions gate. Pre-auth + scoped delegation + quorum carry throughput.
- **Where does it standardize?** → Individual IETF I-D cluster — receipts + quorum + evidence graph — composing with SCITT / RFC 9943.
