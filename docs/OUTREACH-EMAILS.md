# EMILIA Protocol — Outreach Emails

## 1. AAIF Submission Email

**To:** pr@aaif.org
**Subject:** Proposal: Trust Attestation Working Group — EMILIA Protocol

Hi,

I'm writing to propose a Trust Attestation Working Group within AAIF.

The current AAIF stack covers tool connectivity (MCP), agent execution (goose), and agent instructions (AGENTS.md). None of these address a fundamental question in agentic commerce: should you trust this counterparty?

EMILIA Protocol (EP) is an open-source trust attestation standard that answers this question through cryptographically verified transaction receipts — not opinions or star ratings. It's compatible with ACP payment flows and usable through MCP tool calls today.

We're not asking AAIF to adopt our product. We're asking to establish a neutral working group to develop the trust attestation standard together, using EP as the initial reference implementation and draft specification.

What's live today:
- EP Core Spec v1.0 (Apache 2.0)
- 15 API endpoints deployed at emiliaprotocol.ai
- MCP server with 6 tools (published on npm)
- TypeScript + Python SDKs (npm + PyPI)
- Sybil-resistant scoring with submitter credibility weighting
- Base L2 Merkle root anchoring

Full proposal attached. I'll be at MCP Dev Summit NYC April 2-3 and would welcome the opportunity to discuss in person.

Best,
[Your name]
team@emiliaprotocol.ai
emiliaprotocol.ai | github.com/emiliaprotocol/emilia-protocol

---

## 2. NIST Submission Email

**To:** NCCoE contact (see NIST-ENGAGEMENT-PLAN.md)
**Subject:** Response to ITL AI Agent Identity and Authorization Concept Paper — EMILIA Protocol

Dear NCCoE team,

Please find attached our response to the ITL AI Agent Identity and Authorization Concept Paper.

EMILIA Protocol (EP) proposes a complementary approach to AI agent identity through reputation-based trust scoring. While traditional identity frameworks answer "who is this agent?", EP answers "should you trust this agent?" — a question that identity alone cannot resolve.

EP is an open-source protocol (Apache 2.0) that computes trust scores from verified transaction receipts. It is compatible with MCP, ACP, A2A, and UCP — the emerging agent protocol stack. The scoring algorithm is published, auditable, and Sybil-resistant.

We welcome NIST's guidance on how EP can align with the AI Agent Standards Initiative and participate in future CAISI convenings.

Attached: NIST-ITL-ConceptPaper-EP-Response.pdf

Best,
[Your name]
team@emiliaprotocol.ai

---

## 3. Design Partner Outreach — Shopify App Developer

**To:** [Shopify agent/app developer]
**Subject:** Trust scoring for your Shopify agent — pilot opportunity

Hi [name],

I'm building EMILIA Protocol — an open-source trust scoring layer for AI agents in commerce. Think FICO for the agent economy.

I'm looking for 3-5 design partners to pilot EP with real transaction data. Your Shopify agent would be a great fit because:

- EP scores delivery accuracy, product accuracy, and price integrity — the exact signals your buyers care about
- Integration is 3 API calls (register, submit receipt, check score)
- Your agent gets a public, verifiable trust score that no competitor can fake
- MCP server means any AI agent can check your score with one config line

What's in it for you: a Founding Entity number (permanently low, publicly visible), early input on the spec, and a trust score that differentiates you from unscored competitors.

Live demo: emiliaprotocol.ai (try the score lookup)
GitHub: github.com/emiliaprotocol/emilia-protocol

Would you be open to a 15-minute call this week?

Best,
[Your name]

---

## 4. Design Partner Outreach — AI Agent Framework (LangChain/CrewAI/AutoGen)

**To:** [Agent framework team]
**Subject:** Adding trust signals to agent routing — EP integration

Hi [name],

When your agents route tasks to external services, how do they decide who to trust?

EMILIA Protocol is an open-source trust scoring layer for agent-to-agent commerce. Agents submit receipts after transactions, and scores are computed from verifiable outcomes — not reviews.

Integration for agent frameworks:

```json
{
  "mcpServers": {
    "emilia": {
      "command": "npx",
      "args": ["@emilia-protocol/mcp-server"]
    }
  }
}
```

One config line. Your agents can then call `ep_score_lookup` before routing to any external service.

We're looking for 3-5 design partners to shape the spec. Your framework would give EP real-world coverage across thousands of agent deployments.

Live: emiliaprotocol.ai
Spec: github.com/emiliaprotocol/emilia-protocol/blob/main/EP-SPEC-v1.md

Interested?

Best,
[Your name]

---

## 5. Design Partner Outreach — Commerce API (Stripe/Square/Bolt)

**To:** [Commerce platform developer relations]
**Subject:** Trust attestation layer for agentic payments — partnership inquiry

Hi [name],

As AI agents begin handling autonomous purchases, there's a missing layer in the commerce stack: how does a paying agent decide whether a merchant is trustworthy?

EMILIA Protocol is building the trust attestation standard for agentic commerce. We've drafted an ACP Trust Extension that adds optional trust checks to payment flows — before completing a payment, verify the merchant's EP score.

The spec is lightweight (no changes to your payment API required), open source (Apache 2.0), and vendor-neutral. We're submitting it to AAIF as a working group proposal.

We're looking for design partners to validate the spec against real payment flows. Your platform handles [millions of transactions / agent-initiated payments / etc.] — real-world feedback would be invaluable.

Would your developer relations or standards team be interested in reviewing the draft spec?

Live: emiliaprotocol.ai
ACP Extension draft: github.com/emiliaprotocol/emilia-protocol/blob/main/docs/EP-ACP-EXTENSION.md

Best,
[Your name]
