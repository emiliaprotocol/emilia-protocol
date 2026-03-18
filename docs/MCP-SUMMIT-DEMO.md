# MCP Dev Summit — 5-Minute Live Demo Script

**Title:** EP: Trust Evaluation and Appeals for MCP Servers and Software

**Goal:** Show EP working through MCP tools in Claude. Minimize terminal. Maximize the MCP-native experience.

---

## Setup (before you walk on stage)

- EP instance running at emiliaprotocol.ai
- Claude Desktop connected to EP MCP server
- Entity `mcp-server-ep-v1` registered with at least 2 receipts pre-seeded
- Auto-receipt enabled for the demo entity (run ep_configure_auto_receipt beforehand)
- One API key ready for terminal fallback only
- Claude window fills the screen. Terminal minimized as backup.
- Backup screenshots of each step in case Wi-Fi dies

---

## 0:00–0:30 — Opening

> MCP gives systems access to tools.
> EP gives them a way to evaluate whether a server or software component should be trusted enough to connect in this context.
> In five minutes, I'll query a trust profile, run install preflight, generate a zero-knowledge trust proof, and verify it — all through MCP tools in Claude.

---

## 0:30–1:30 — Query trust profile in Claude

**Prompt Claude:**
> Show me the trust profile for mcp-server-ep-v1.

**While Claude runs, say:**
> This is the canonical output in EP. Not a number — a trust profile: confidence level, behavioral outcomes, provenance composition, dispute history. The compatibility score exists for sorting, but agents make decisions against policies, not scores.

**Highlight in the output:**
- Confidence: provisional / emerging / confident (depending on evidence)
- Behavioral: completion rate, dispute rate
- Provenance: bilateral vs self-attested
- Disputes: 0

> This is the key shift. Trust profiles, not scores.

---

## 1:30–3:00 — Install preflight (the sharpest wedge)

> MCP tells you what a server can do. EP helps answer whether it should be trusted enough to connect in this environment.

**Prompt Claude:**
> Run install preflight for mcp-server-ep-v1 with policy mcp_server_safe_v1 in this context: host is mcp, data_sensitivity is private_workspace, tool_scope is repo_read.

**While Claude runs, say:**
> This is one of EP's most important use cases. Not "what is this server?" but "is it safe enough for this specific context and policy?"

**Highlight in the output:**
- Decision: allow / review / deny
- Policy used
- Reasons (publisher verification, permissions, provenance)
- Confidence level

> That's the future trust question for software: not "is this popular?" but "is this safe enough for this policy and scope?"

---

## 3:00–4:00 — Auto-Receipt + ZK Proof (the closing argument)

> Every MCP tool call we've run so far generated a behavioral receipt automatically — no developer instrumentation, no manual submission. That's the auto-receipt layer. Trust data accumulates passively as agents work.

**Prompt Claude:**
> Enable auto-receipt generation for mcp-server-ep-v1 in privacy mode.

**While Claude runs, say:**
> Opt-in, per entity. In privacy mode, counterparty identities are hashed — never stored in plaintext. The trust graph grows without exposing who is interacting with whom.

**Prompt Claude:**
> Generate a zero-knowledge proof that mcp-server-ep-v1 has a trust score above 0.80 in the financial domain.

**While Claude runs, say:**
> This is a commitment-based ZK proof — HMAC-SHA256 plus a Merkle tree over the entity's receipts. It proves the score threshold is met without revealing a single receipt, counterparty, or transaction detail.

**Highlight in the output:**
- proof_id
- domain: financial
- threshold: 0.80
- result: threshold met / not met

**Prompt Claude:**
> Verify that proof. Use only the proof_id.

**Highlight in the output:**
- Verification: valid
- No receipts, no counterparties, no history disclosed

> Healthcare, legal, and financial sector participants can now join the trust graph as full citizens — without revealing a single transaction.
> The proof_id is all you share. The graph does the rest.

---

## 4:00–4:30 — List available policies

**Prompt Claude:**
> List all available trust policies.

> Agents don't check raw numbers. They evaluate against structured policies. Strict for high-value. Standard for normal. Discovery for exploring new tools. Software-specific policies for GitHub Apps, npm packages, MCP servers, browser extensions.

---

## 4:30–5:00 — Closing

> Here is what EP is now.

> The trust graph is an immune system. When a receipt is disputed, the graph's own high-confidence vouchers vote on it. The accused cannot dominate their own adjudication. Upheld disputes collapse to zero weight. Dismissed disputes are fully restored. The graph corrects itself — without operators, without platform intervention.

> Humans have trust scores. For the first time, there is a verifiable record of how well a human delegates to AI agents — a delegation judgment grade derived from the Principal→Agent→Tool attribution chain embedded in every receipt. Excellent, good, fair, or poor. Auditable. Portable. Yours.

> And for regulated industries — healthcare, legal, finance — the ZK privacy guarantee means the trust layer is no longer opt-out because of confidentiality concerns. You prove what you need to prove. You reveal nothing else.

> MCP provides tool access. EP provides trust evaluation and appeals.
> Together, agents can make safer install decisions, route to trustworthy counterparties, and challenge trust when it's wrong — in private, when it needs to be.
> All of this is open source, Apache 2.0, and designed to be a neutral standard — not a platform.

---

## Prepared Claude prompts (copy these)

1. `Show me the trust profile for mcp-server-ep-v1.`
2. `Run install preflight for mcp-server-ep-v1 with policy mcp_server_safe_v1 in this context: host is mcp, data_sensitivity is private_workspace, tool_scope is repo_read.`
3. `Enable auto-receipt generation for mcp-server-ep-v1 in privacy mode.`
4. `Generate a zero-knowledge proof that mcp-server-ep-v1 has a trust score above 0.80 in the financial domain.`
5. `Verify that proof. Use only the proof_id.`
6. `List all available trust policies.`

## If something fails

Say: "That's exactly why appeals and operational trust matter — even the trust layer needs to handle failure gracefully."

## Do NOT say

- Blockchain, anchoring costs
- Compatibility score
- "Future of trust" grandiosity
- Old review-corruption framing
- Anything about funding or company
- "Merkle trees" (unless a technical audience asks directly)

## DO say

- Trust profiles, not scores
- Install preflight
- Policy evaluation
- Disputes and appeals
- Context-aware decisions
- Constitutional principle: trust must never be more powerful than appeal
- Auto-receipt: trust data accumulates passively
- Zero-knowledge proof: prove the threshold, reveal nothing
- Delegation judgment: humans have trust scores now
- The graph is an immune system
