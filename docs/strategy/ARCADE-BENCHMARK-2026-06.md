# Arcade.dev vs EMILIA — benchmark & positioning (2026-06)

Arcade raised a **$60M Series A (SYN Ventures lead; Morgan Stanley + Wipro strategic; $72M total)** for "the secure action layer for enterprise AI agents." This is the closest-funded company to our category, so we position *precisely against it*. This is a market-validation event for us, not a threat — but only if we are crisp about the difference.

## What Arcade actually is (from their site/blog/docs, June 2026)
- **Access-control runtime + MCP gateway.** Agents act *as the user* via OAuth/scoped tokens — "the access the user has, only for the action they're taking; no standing permissions." "Enforce, execute, govern."
- **Integrations are the moat:** 8,000+ agent-optimized MCP tools; 25x tool-call growth in 6 months; production at large banks/industrials/pharma. They authored the MCP authorization spec.
- **Audit:** "every action leaves a record: which agent, on behalf of which user, against which resource" — **a record Arcade produces and stores in its control plane, exportable** to your SIEM.
- **No human-in-the-loop.** No per-action human approval/consent anywhere in their material.

## Where Arcade is ahead of us (be honest)
1. **Integrations / DX breadth** — 8,000+ prebuilt tools vs our handful of example guards. Biggest practical gap.
2. **Customers** — Fortune 500 in production vs our zero signed customers (open PRs only).
3. **Capital + enterprise GTM** — $72M, strategic banks, sales motion.
4. **One-line DX positioning** — "Ship agents, not auth infrastructure." Ours is more conceptual.
5. **Standards + impl + customers combined** — they wrote the MCP authz spec AND ship it AND have logos.

## Where EMILIA structurally wins (what Arcade cannot claim)
1. **Consent, not just access.** Arcade decides *can this agent (as this user) do this?* — machine access control. EMILIA proves *a named human deliberately authorized THIS exact irreversible action* — accountability/consent. Arcade has no human-in-the-loop; this is a category they don't occupy.
2. **Offline, operator-independent proof.** Arcade's audit is a log **Arcade produces and you trust**. EMILIA's receipt verifies **offline, by anyone, trusting no one — not even EMILIA**. When a regulator, court, insurer, or counterparty asks "prove a human authorized this without trusting the operator," an exported vendor log is the operator's word; an EMILIA receipt is not. Decisive in regulated/adversarial contexts.
3. **Open standard, not a runtime to adopt.** Arcade is a gateway you route traffic through (lock-in). EMILIA is an IETF Internet-Draft cluster + Apache-2.0 + offline verifiers — adoptable with no vendor dependency.
4. **Composes ON TOP of any runtime — including Arcade.** Our OpenAI-Agents-SDK adapter already proves portability. EMILIA can sit on top of Arcade's tool calls and add the human-consent receipt Arcade lacks. We complete Arcade; we don't replace it.
5. **Per-action binding + one-time consumption + replay/forgery refusal** (RR-1) — not surfaced in Arcade's model.

## The one-line rebuttal (for VCs / "isn't this just Arcade?")
> Arcade controls what an agent *can* do and keeps the log. EMILIA proves a *named human authorized this exact irreversible action* — verifiable offline by anyone, without trusting the agent, the app, or Arcade. Access control vs. portable accountability evidence. They even compose: EMILIA can ride on top of Arcade.

## Action items
1. **Investor framing (now):** in the Conviction/Lux emails, preempt "isn't this Arcade?" with the access-vs-consent + offline-verifiable + composes-on-top line, and cite SYN's $60M as proof the category is hot. (Done — drafts updated.)
2. **Build the Arcade adapter** (like the OpenAI one): an EMILIA receipt gate on top of an Arcade tool call — concrete "we complete their gap (human consent + offline proof)" demo. Do NOT disclose to SYN/Arcade; just build the integration. Highest-leverage product move.
3. **Sharpen the public one-liner** toward Arcade's clarity: "Proof a human authorized it — not just that an agent could."
4. **Close the credibility gap** that capital can't paper over: land the reliance event (a named auditor/insurer says they'd rely on a receipt) and one real pilot. That is the thing Arcade has (logos) and we don't.
5. **Don't try to out-integrate Arcade.** Lean on "add a human-consent receipt to any of Arcade's 8,000 tools" rather than rebuilding 8,000 tools.
