<!-- SPDX-License-Identifier: Apache-2.0 -->
# AAIF pitch — 3–4 min run-of-show (for Manik, CTO, AAIF)

**Format:** present live off the page — https://www.emiliaprotocol.ai/aaif-video-pitch — scroll top-to-bottom; the page order *is* the pitch order. Each section is badged **01–06** matching the headings below. The top nav (Gap · Demo · SCITT · Surfaces · Ask) jumps to §01/§03/§04/§05/§06.
**Register:** engineer-to-engineer. Claims are checkable — say so.
**Say once, out loud:** "It's an active *individual* Internet-Draft, not an IETF endorsement."
**Total:** ~3.5 min at a brisk pace. Times are ceilings — if you're at 4:00, skip to the Ask.

---

## Hook — hero + film  (the open, before §01 · 0:00–0:25)
- Let the film run ~8s silent, then: "Agent stack's filling in fast — identity, tools, execution, logs. One primitive nobody produces: portable proof a *named human* authorized *this exact irreversible action* before it ran."
- "Not a platform. A small artifact + a verifier. I want your read on whether it's real and where it belongs."

## §01 · The gap  ·  nav: Gap  (0:25–1:00)
- Point at the void map. "Each ring answers a different question — none answers *who authorized this*. Logs get close, but a log is the operator's own editable record."
- **Line:** "Logs are testimony. Receipts are evidence."

## §02 · Where it sits  (0:55–1:20)
- Stack: MCP → goose → AGENTS.md → EMILIA. "A thin layer between intent and mutation. Composes with what you run; replaces none of it."

## §03 · The demo  ·  nav: Demo  (1:20–2:05)  ← the part a CTO trusts
- Four states: missing → 428 · valid → runs once · replay → refused · forged → rejected.
- "Deny-by-default. The receipt is bound to the hash of the *specific* action — one-time. Replay refused, forged sig fails. Run it yourself: `npx @emilia-protocol/issue demo`."
- **Offer:** "Happy to have you try to break it live — fastest way to evaluate this."

## §04 · SCITT composition  ·  nav: SCITT  (2:05–2:45)  ← what matters most to you
- "Composition, not competition. Same canonical payload wraps as a COSE_Sign1 Signed Statement, registers via SCRAPI, inclusion verified in CI."
- **Line:** "SCITT proves the statement was logged. EMILIA proves *who authorized* the action — and it rides on SCITT."

## §05 · Higher-stakes surfaces  ·  nav: Surfaces  (2:45–3:05)
- "Same receipt spine scales up: M-of-N / ordered two-person rule; a human-control profile mapped to DoD 3000.09, EU AI Act Art. 14, NIST AI RMF — scoped as authorization proof, *not* proof of wisdom."

## §06 · The ask  ·  nav: Ask  (3:05–3:30)
- "That's it. Non-binding read: if this is the missing human-authorization layer, where should it belong — and does AAIF see it composing with the surfaces you care about? Apache-2.0; composes with MCP, goose, AGENTS.md."

---

## 5 questions to go through fast (rapid Q&A — one-breath answers)
1. **"Isn't this just SCITT?"** → SCITT gives transparency/inclusion of a statement; it never asserts a named human authorized the action. EP is that assertion — and rides *as* a SCITT Signed Statement. Complementary, shown in CI.
2. **"Isn't this OAuth / WIMSE / delegation?"** → Those say which machine/service may act. EP says a *named human* authorized *this exact action*. Above identity, not instead of it.
3. **"Why not just log the approval?"** → A log is operator-editable — trustworthy only if you trust the operator. An EP receipt verifies offline, bound to the action hash, one-time. Testimony vs evidence.
4. **"Human sign-off per action — latency / scale?"** → Only high-risk/irreversible actions, not every call. Pre-auth + scoped delegation + quorum cover throughput; honest story is pre-auth + post-hoc proof, not real-time human-in-loop.
5. **"Where should it be standardized?"** → Individual IETF I-D cluster today (receipts, quorum, evidence-chain); composes with SCITT / RFC 9943. That's exactly what I'm bringing to you.

## Repeat 3× (positioning)
> "Identity says which machine acts. Tool-auth says which tools it may call. **EMILIA is the proof a named human authorized this exact action** — verifiable offline, composes with everything, competes with nothing."
