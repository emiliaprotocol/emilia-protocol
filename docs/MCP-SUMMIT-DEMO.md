# MCP Dev Summit — 5-Minute Live Demo Script

**Title:** EP: Trust Evaluation and Appeals for MCP Servers and Software

**Goal:** Show EP working through MCP tools in Claude. Minimize terminal. Maximize the MCP-native experience.

---

## Setup (before you walk on stage)

- EP instance running at emiliaprotocol.ai
- Claude Desktop connected to EP MCP server
- Entity `mcp-server-ep-v1` registered with at least 2 receipts pre-seeded
- One API key ready for terminal fallback only
- Claude window fills the screen. Terminal minimized as backup.
- Backup screenshots of each step in case Wi-Fi dies

---

## 0:00–0:30 — Opening

> MCP gives systems access to tools.
> EP gives them a way to evaluate whether a server or software component should be trusted enough to connect in this context.
> In five minutes, I'll query a trust profile, run install preflight, and file a dispute — all through MCP tools in Claude.

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

## 3:00–4:00 — File a dispute

**Prompt Claude:**
> File a dispute against the latest receipt for mcp-server-ep-v1 with the reason: demo challenge — testing dispute lifecycle.

**While Claude runs, say:**
> A real trust layer can't only compute trust. It has to handle contested trust. Every negative trust effect in EP must be explainable, challengeable, and reversible. That's the constitutional principle.

**Highlight in the output:**
- Dispute created
- Status: open
- Receipt ID linked
- Trust remains auditable — nothing deleted

> EP is built so trust can be challenged and corrected without erasing what happened.

---

## 4:00–4:30 — List available policies

**Prompt Claude:**
> List all available trust policies.

> Agents don't check raw numbers. They evaluate against structured policies. Strict for high-value. Standard for normal. Discovery for exploring new tools. Software-specific policies for GitHub Apps, npm packages, MCP servers, browser extensions.

---

## 4:30–5:00 — Closing

> MCP provides tool access.
> EP provides trust evaluation and appeals.
> Together, agents can make safer install decisions, route to trustworthy counterparties, and challenge trust when it's wrong.
> All of this is open source, Apache 2.0, and designed to be a neutral standard — not a platform.

---

## Prepared Claude prompts (copy these)

1. `Show me the trust profile for mcp-server-ep-v1.`
2. `Run install preflight for mcp-server-ep-v1 with policy mcp_server_safe_v1 in this context: host is mcp, data_sensitivity is private_workspace, tool_scope is repo_read.`
3. `File a dispute against the latest receipt for mcp-server-ep-v1 with the reason: demo challenge — testing dispute lifecycle.`
4. `List all available trust policies.`

## If something fails

Say: "That's exactly why appeals and operational trust matter — even the trust layer needs to handle failure gracefully."

## Do NOT say

- Blockchain, Merkle trees, anchoring costs
- Compatibility score
- "Future of trust" grandiosity
- Old review-corruption framing
- Anything about funding or company

## DO say

- Trust profiles, not scores
- Install preflight
- Policy evaluation
- Disputes and appeals
- Context-aware decisions
- Constitutional principle: trust must never be more powerful than appeal
