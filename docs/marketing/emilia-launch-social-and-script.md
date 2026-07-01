<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA — launch social copy + AAIF talk-track

Assets:
- Hero film (16:9): `public/hero/emilia-sequence.mp4`
- Square (1:1): `public/hero/social/emilia-square.mp4`
- Vertical (9:16): `public/hero/social/emilia-vertical.mp4`
- Poster / OG: `public/hero/emilia-sequence-poster.jpg`, `public/og-sequence.jpg`

---

## Launch post — X / short

> AI agents are already moving money, shipping code, and commanding machines — with no one able to prove who approved it.
>
> EMILIA is passport control for agent actions: every high-risk action is scanned, and it runs **only** with a named human authorizer. No receipt, no execution.
>
> Open, offline-verifiable, Apache-2.0. → emiliaprotocol.ai

## Launch post — LinkedIn / long

> **The agent economy has an accountability gap.**
>
> Agents now take irreversible actions at machine speed — releasing payments, deploying code, curtailing datacenters, moving robots. When a regulator, insurer, or board asks "who authorized that, and can you prove it?", the honest answer today is: we can't. The proof lives in editable logs.
>
> **EMILIA closes that gap.** Think passport control for AI agents: before a high-risk action executes, EMILIA verifies there is a valid authorization tracing to a *named human* who approved that exact action. Authorized → it proceeds. No valid human authorizer → denied. The result is a portable, offline-verifiable receipt anyone can check — without trusting the operator or us.
>
> Open protocol, Apache-2.0, cross-language verifiers, IETF drafts. **No receipt, no execution.**
>
> → emiliaprotocol.ai

## One-liners (captions / thumbnails)
- No receipt, no execution.
- Passport control for AI-agent actions.
- A named human authorized this exact action — provably.
- Logs are testimony. Receipts are evidence.

---

## AAIF video — <5-min talk-track (film as cold-open)

**[0:00–0:12] — Cold open: play the hero film silent.** Agents scanned → AUTHORIZED with named human authorizer / DENIED (authorizer unavailable) → EMILIA.

**[0:12–0:45] — The gap.**
> The agent stack is filling in fast — identity, tool access, execution, transparency logs. But there's a hole in the middle. When an agent takes an irreversible action, nothing produces portable proof that a *named human* authorized *that exact action* before it ran. Decision logs are testimony. What oversight regimes actually need is evidence.

**[0:45–1:45] — What EMILIA is.**
> EMILIA is that evidence layer. Picture passport control. An agent approaches a high-risk action. It's scanned. EMILIA checks: is there a valid authorization signed by a named human, bound to this exact action, in scope, not replayed? If yes — authorized, it proceeds, and an execution receipt is emitted. If not — denied. The receipt is a self-contained cryptographic object: Ed25519 over canonical JSON, verifiable fully offline. No account, no server, no trust in the operator or in us. Change one byte and verification fails.

**[1:45–2:45] — Where it sits (show the diagram / passport-control graphic).**
> This is deliberately a small layer, and it composes with everything around it. Identity systems say which machine is acting — the passport. Tool-authorization says which tools it may call — the visa. EMILIA is passport control and the stamp: proof a named human authorized this specific action. It plugs into MCP, agent runtimes, SCITT, and systems of record. Complementary to all; competitive with none.

**[2:45–3:45] — Proof it's real.**
> This isn't a slide deck. There's a reference runtime, three independent verifiers — JavaScript, Python, Go — that agree byte-for-byte, machine-checked TLA+ and Alloy models, a public conformance suite, and thousands of automated tests. It's Apache-2.0, with active IETF Internet-Drafts for the receipt and the multi-party quorum, and a SCITT signed-statement profile. Try to break it: an action is blocked without a receipt, runs once with a valid one, and refuses replay or tampering.

**[3:45–4:30] — The ask / close.**
> If you're building or governing agents that take consequential actions, EMILIA gives you the one artifact the compliance conversation keeps coming back to — verifiable, human authorization. Wrap one dangerous action and watch it get blocked: `npx -y @emilia-protocol/crash-test`. Spec, demo, and verifier are at emiliaprotocol.ai. **No receipt, no execution.**

**Disclaimer to keep on screen/verbal:** active individual Internet-Draft, not an IETF endorsement.
