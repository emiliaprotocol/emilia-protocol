# EMILIA Protocol — AAIF Project Proposal

**Proposed Project:** EMILIA Protocol (EP) — Trust & Reputation Layer for Agentic Commerce
**Submitted to:** Agentic AI Foundation (AAIF) / Linux Foundation
**Date:** March 2026
**Contact:** hello@emiliaprotocol.ai
**License:** Apache-2.0
**Repository:** https://github.com/emiliaprotocol/emilia-protocol

---

## 1. Executive Summary

EMILIA Protocol (EP) is an open-source reputation scoring protocol for the agent economy. It provides the trust layer that is currently missing from the agentic commerce stack.

The AAIF currently governs three foundational projects: MCP (tool connectivity), goose (agent framework), and AGENTS.md (agent instructions). These address *how agents connect*, *how agents execute*, and *how agents are guided*. None of them address the fundamental question: **should you trust this agent?**

EP answers that question through cryptographically verified transaction receipts — objective, auditable, and unpurchasable reputation scoring.

We propose EP as an AAIF project to provide the trust and reputation layer that completes the agent interoperability stack.

---

## 2. Problem Statement

As AI agents increasingly handle discovery, negotiation, checkout, and fulfillment on behalf of humans and organizations, no standardized system exists for measuring whether an agent, merchant, or service provider should be trusted.

Existing reputation systems (Amazon reviews, Yelp ratings, Uber stars) are fundamentally compromised: the platform hosting the reviews profits from the businesses being reviewed, creating inevitable conflicts of interest.

In the agent economy, this problem is more acute:
- Agents transact autonomously without human oversight of every decision
- Agents need machine-readable trust signals, not human-readable star ratings
- Transaction volume will exceed human review capacity by orders of magnitude
- No human is present to "read the reviews" before every purchase

Without a trust layer, the agent economy will either: (a) centralize trust into platform gatekeepers (recreating the review problem), or (b) operate without trust signals (enabling fraud at scale).

---

## 3. Proposed Solution

EP defines:
- **Receipt Schema**: Cryptographically hashed, chain-linked transaction records
- **Scoring Algorithm**: Open-source, weighted across 6 objective signals (delivery accuracy 30%, product accuracy 25%, price integrity 15%, return processing 15%, agent satisfaction 10%, consistency 5%)
- **Score Lookup API**: Public, no-auth score queries for any entity
- **Verification Flow**: Merkle tree batching + blockchain anchoring for independent verification
- **Sybil Resistance**: Graph analysis, rate limiting, behavioral signals

Key properties:
- **Open source** (Apache-2.0) — the algorithm is public and auditable
- **Receipts, not reviews** — objective transaction data, not opinions
- **Unpurchasable** — no payment, partnership, or API tier affects scoring
- **Bidirectional** — both parties in a transaction can score each other
- **MCP-native** — EP MCP server ships with 6 tools for any MCP client

---

## 4. Relationship to Existing AAIF Projects

| AAIF Project | What It Does | EP Integration |
|-------------|-------------|----------------|
| **MCP** | Agents connect to tools | EP MCP server provides trust tools (`ep_score_lookup`, `ep_submit_receipt`, `ep_verify_receipt`) |
| **goose** | Agent execution framework | Goose agents can query EP scores before executing transactions |
| **AGENTS.md** | Agent instructions | AGENTS.md can specify minimum EP score thresholds for counterparties |

EP does not overlap with any existing AAIF project. It occupies a distinct layer (trust) that the current stack does not address.

### MCP Integration (Shipping)

```json
{
  "mcpServers": {
    "emilia": {
      "command": "npx",
      "args": ["@emilia-protocol/mcp-server"],
      "env": { "EP_BASE_URL": "https://emiliaprotocol.ai" }
    }
  }
}
```

### A2A Agent Card Integration (Proposed)

```json
{
  "name": "Shopping Agent",
  "emilia": {
    "entity_id": "shopping-agent-v1",
    "score_url": "https://emiliaprotocol.ai/api/score/shopping-agent-v1",
    "min_counterparty_score": 70
  }
}
```

---

## 5. Technical Maturity

| Component | Status |
|-----------|--------|
| Protocol specification (EP Spec v1.0) | Complete |
| Canonical implementation (14 API endpoints) | Deployed |
| Scoring algorithm (6 signals, rolling window, dampening) | Complete, tested |
| MCP server (6 tools) | Complete |
| TypeScript SDK | Complete |
| Python SDK | Complete |
| Blockchain verification (Merkle + Base L2) | Complete |
| Sybil resistance (graph analysis, rate limiting) | Complete |
| Database schema + migrations (4 migrations) | Complete |
| Test suite | Scoring tests complete |

Total: 40+ files, 14 API endpoints, 4 database migrations, 2 SDKs, 1 MCP server.

---

## 6. Community & Governance

EP is currently maintained by EMILIA Inc. The governance roadmap:
1. **Phase 1 (Current)**: EMILIA Inc. maintains spec + canonical implementation
2. **Phase 2**: Advisory Board of early adopters and protocol contributors
3. **Phase 3**: Transition to AAIF governance (this proposal)

We are open to AAIF's governance model and welcome community contributions under the foundation's established processes.

---

## 7. Why AAIF

The AAIF's mission is to ensure agentic AI evolves transparently and collaboratively. Trust and reputation are critical infrastructure for this mission:

- **Trust enables interoperability**: Agents won't transact with unknown counterparties without trust signals
- **Neutrality is essential**: A trust layer controlled by any single platform (Google, Amazon, OpenAI) would be inherently conflicted — they are merchants themselves
- **Open governance prevents capture**: Under AAIF, no single company can manipulate the scoring to favor their own products

EP under AAIF governance would signal to the ecosystem that agent reputation is a public good, not a proprietary advantage.

---

## 8. Immediate Next Steps

If accepted:
1. Transfer `emiliaprotocol/emilia-protocol` repository to AAIF GitHub org
2. Publish `@emilia-protocol/mcp-server` and SDKs under AAIF npm scope
3. Present EP at MCP Dev Summit NA (April 2-3, NYC)
4. Submit EP spec as AAIF working group deliverable
5. Integrate EP score field into MCP tool responses and A2A Agent Cards

---

## 9. Resources

- **Website**: https://emiliaprotocol.ai
- **GitHub**: https://github.com/emiliaprotocol/emilia-protocol
- **Spec**: EP-SPEC-v1.md (in repo)
- **MCP Server**: `npx @emilia-protocol/mcp-server`
- **Business Plan**: Available upon request

---

*EMILIA Protocol — Receipts, not reviews. The trust layer for agentic commerce.*
