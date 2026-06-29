<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Protocol — Launch / outreach kit

Drafts for adoption-side outreach. **Timing rule:** the primary needle-movers are
the reliance event (an external party verifying a receipt and saying so) and the
30 Jun Dispatch/SecDispatch interim. **Fire the newsletter/forum blast AFTER the
interim and/or after the first external verification** — the same content lands as
"externally-checked, IETF-engaged protocol" instead of "2-star research repo."

Status legend: **[READY]** send/use anytime · **[STAGE]** hold until post-interim / post-reliance-event.

---

## 1. [STAGE] Launch post — lobste.rs / r/programming / dev.to

> ⚠️ You are shadowbanned on HN — a Show HN from your account will not surface.
> Use lobste.rs / r/programming / a dev.to writeup, or have a non-banned
> collaborator post to HN. Do NOT create a sockpuppet — it would taint the launch.

**Title:** `Show HN: An AI agent can't take an irreversible action without a named human's signoff — verify offline in 30s`

**Body:**

AI agents are starting to do irreversible things — move money, change records, delete data. "A human is in the loop" is the standard reassurance, but it's unfalsifiable: there's no artifact anyone can check afterward that a specific, accountable person approved *this exact action* before it happened.

EMILIA Protocol is an attempt to fix that. Before a high-risk action runs, a named human approves the exact action on their own device (WebAuthn / Face ID), and the system emits an **authorization receipt** — a signed evidence packet anyone can verify **offline, with no account and without trusting the issuer's servers**. Alter one byte and verification fails.

Try it in ~30 seconds, fully offline, no key:
- `npx @emilia-protocol/crash-test` — an agent proposes a $2.4M disbursement, self-approval is rejected, two humans sign, a receipt is issued, it verifies offline against nobody's server, and a forged copy is rejected. Emits an auditor workpaper.
- The demand side: clone the repo, then `FAST=1 node examples/mcp/payment-server.mjs` — a service answers `428 Receipt Required`, the agent obtains a receipt and retries, then replay and forgery are refused. The legacy 402 loop remains available for x402/AP2-style compatibility.
- Paste any receipt at emiliaprotocol.ai/verify; Face ID demo at /try.

Open standard (Apache-2.0), posted as IETF Internet-Drafts, with three independent verifiers (JS / Python / Go) that agree on a cross-language conformance suite, plus TLA+ and Alloy machine-checked models.

**Honest limitations** (these are in the spec, not buried): a receipt proves a named, enrolled approver authorized the exact action — it does **not** prove the decision was *correct*, does not by itself establish the real-world identity behind an enrolled approver (an enrollment/identity-proofing layer), and offline verification cannot prove the *absence* of a later revocation. There is **no production deployment yet** — that's the honest current state.

Repo + drafts: github.com/emiliaprotocol/emilia-protocol

---

## 2. [READY] IETF 5-minute statement — 30 Jun interim AOB / IETF 126

"I'm Iman Schrock; I maintain EMILIA Protocol. I've posted two individual drafts — `draft-schrock-ep-authorization-receipts` and `draft-schrock-ep-quorum` — and I'm here for dispatch guidance on where this work belongs.

The framing: several proposals on this agenda — AIIP, CIRP, AgentROA, and the delegation-receipt work — define machine-side, post-action or per-hop receipts of what an *agent* did under delegated authority. None binds a named, accountable **human** to the action before it executes. A newer individual effort — Permit Receipts (`draft-lee-orprg-permit-receipts`) — authorizes the *effect at the boundary by policy* before commit, and independently converges on the same evidence primitives (canonical action-digest binding, policy epoch, anti-replay, fail-closed) — which I take as a signal the shape is right; EP is precisely the human-authorization layer its own author notes can sit atop it. EP is that missing layer: an offline-verifiable, non-repudiable receipt that a named human — or a quorum of distinct humans, the two-person rule — authorized a specific high-risk action, with separation of duties and a cryptographic ordering chain. They compose into one accountability chain: who authorized it (EP) → that it was carried out (the agent-side drafts). I've been coordinating directly with the DRP author, and three of us published a joint survey mapping the efforts onto one verifier-side matrix.

On maturity: three independent, interoperable implementations — JavaScript, Python, Go — agree on a cross-language conformance suite spanning receipts, multi-party quorum, revocation, provenance, and long-term preservation, plus machine-checked TLA+ and Alloy models, in CI. And the demand-side mechanic is live and runnable today — a service that answers `428 Receipt Required`, an agent that obtains a receipt and retries, verified offline, then replay and forgery are refused. I can show it in two minutes.

The honest gap: no production deployment yet — that's the work in front of me. The ask: dispatch guidance on whether human-authorization receipts belong as a work item here, and the room's view on convergence with the delegation-receipt drafts."

---

## 3. [STAGE] Newsletter pitches — problem-discovery voice

Lead with the *problem discovery*, not the product. Best audience fit: AI-infra
newsletters. Send post-interim.

**Latent Space / Architecture Notes (AI infra):**

> Subject: agents are taking irreversible actions with no proof a human authorized them
>
> Hi — I ran into a gap building agent tooling: when an AI agent moves money or changes a record, "a human approved it" is an unfalsifiable claim. There's no artifact a court, auditor, or counterparty can check afterward. I ended up writing an IETF draft and building offline-verifiable "authorization receipts" — a named human signs the exact action on their device, and anyone can verify it offline, no server. Three independent implementations (JS/Python/Go) agree on a conformance suite; there's a 30-second offline demo (`npx @emilia-protocol/crash-test`) and a live `428 Receipt Required` loop. Thought it might fit your audience. Happy to send the one-pager or do a short writeup.

**Console.dev / TLDR (developer tools):**

> Tool tip: `@emilia-protocol/verify` (Apache-2.0) — offline, zero-dependency verification that a named human authorized an AI agent's irreversible action. `npx @emilia-protocol/crash-test` shows the whole loop in 30s, no account. IETF-drafted; JS/Python/Go verifiers agree on a cross-language conformance suite.

---

## 4. [READY] awesome-mcp-servers entry

EP ships an MCP server (36 tools) that gates agent actions behind verifiable
human authorization — a natural fit for "awesome-mcp-servers" lists. Submit a PR
to the relevant list(s) with:

> - **[EMILIA Protocol](https://github.com/emiliaprotocol/emilia-protocol)** — Gate irreversible MCP tool calls behind a named human's offline-verifiable authorization receipt (WebAuthn signoff, two-person rule). 36 tools; Receipt Required 428 rail with legacy 402 compatibility; IETF-drafted.

Target lists (verify each is active before submitting): `punkpeye/awesome-mcp-servers`, `wong2/awesome-mcp-servers`, and the modelcontextprotocol community list. Keep the entry one line, factual, no superlatives.

---

## 5. [READY] GitHub Action

`actions/verify-receipt/` is marketplace-ready (action.yml + README, inputs, exit
codes, honest "what it does not do"). To publish: tag a release and check
"Publish this Action to the GitHub Marketplace" in the release UI. The dev hook:
"add EP receipt verification to your CI in three lines."
