<!-- SPDX-License-Identifier: Apache-2.0 -->
# AAIF pitch — TIGHT re-record script (for Manik, CTO, AAIF)

**Target: 2:30–3:00. One clean pass.** Present off the LIVE page:
https://www.emiliaprotocol.ai/aaif-video-pitch — scroll top-to-bottom.

**Record discipline (this is why take 1 didn't land):**
- Quiet room, door shut, no interruptions. Demo tab **pre-opened** in a second tab.
- **No bio open.** Do NOT lead with "Dr. …, my doctorate is in psychology, named after my daughter." Lead with the hook. (Save the daughter line for the very end — it's lovely there.)
- Say the **core sentence** slowly and exactly. It's the one thing that must be perfect.
- Register: **engineer-to-engineer.** You're showing a peer a primitive, not asking permission.
- Read the quoted lines close to verbatim. Everything else, riff freely.

---

## 0:00 — HOOK (≈20s)  [screen: hero]
> "Hey Manik — thanks for making time. Straight to it.
> The agent stack is filling in fast: identity, tools, execution, transparency logs. There's one primitive nobody produces — **portable proof that a named human authorized this exact, irreversible action, before it ran.** That's the gap. That's all EMILIA does."

## 0:20 — WHAT IT IS (≈25s)  [screen: §01 gap → §02 stack]
> "A log won't do it — a log is the operator's own editable record. **Logs are testimony; receipts are evidence.**
> So the primitive is one sentence:"

**CORE SENTENCE — say it slowly, get every word:**
> "**A named human — or a quorum — signs the exact canonical bytes of one irreversible action, before it runs. Offline-verifiable, bound to that action and no other, usable once.**"

> "It's a thin layer between intent and mutation. It sits above MCP, goose, AGENTS.md — composes with all of them, replaces none."

## 0:45 — DEMO — the part a CTO trusts (≈45s)  [screen: open the live demo tab]
> "Let me just try to break it. Four states."
- Missing receipt → **blocked (428)**
- Valid receipt → **runs once**
- Same receipt again → **replay refused**
- Forged signature → **rejected**
> "Deny-by-default. The receipt is bound to the hash of the *specific* action, and it's one-time — so replay is refused and a forged signature fails. It's real running code; I'll send you the exact receipt so you can verify it yourself offline."

## 1:30 — COMPOSITION — what matters most to you (≈50s)  [screen: §04 SCITT → Evidence graph card]
> "Here's the part I actually want your read on: it **composes, it doesn't compete.**
> The same canonical receipt rides as a **COSE_Sign1 Signed Statement** — registers through SCRAPI, inclusion verified in CI. SCITT proves a statement was *logged*; EMILIA proves *who authorized the action* — and rides on top of SCITT.
> And it composes one level up into an **Action Evidence Graph**: the authorization receipt, a policy permit, and workload identity, bound into one offline-verifiable graph — **who authorized, what ran, under which policy** — checkable without trusting any single operator. That's the individual Internet-Draft we just filed, and it's the reason I went quiet for a few days."

## 2:20 — THE ASK (≈20s)  [screen: §06 ask]
> "That's it. It's Apache-2.0, it composes with MCP, goose, and AGENTS.md. The ask is non-binding: **is this the missing human-authorization layer, and where should it belong?** — and does AAIF see it composing with the surfaces you care about?
> One last thing — EMILIA is named after my daughter. This one matters to me. Thanks for the read."

---

## If asked (one-breath answers — keep these ready, don't volunteer them)
- **"Isn't this just SCITT?"** → SCITT logs a statement; it never asserts a *named human authorized the action*. EP is that assertion, and rides *as* a SCITT Signed Statement.
- **"Isn't this OAuth / WIMSE?"** → Those say which *machine* may act. EP says a *named human* authorized *this exact action*. Above identity, not instead of it.
- **"Latency of per-action sign-off?"** → Only irreversible actions gate. Pre-auth + scoped delegation + quorum carry throughput; honest story is pre-auth + post-hoc proof, not real-time human-in-the-loop.
- **"Where does it standardize?"** → Individual IETF I-D cluster — receipts + quorum + evidence graph — composing with SCITT / RFC 9943. That's the open question I'm bringing you.

## Cut from take 1 (deliberately) — do NOT include
- The bio / doctorate / "honored to present in front of you" open.
- The ring-by-ring "void map" narration (let the screen carry it).
- The DoD / EU AI Act / NIST defense-surfaces deep-dive — one line max if at all; it's not AAIF's lane and it ate time.
