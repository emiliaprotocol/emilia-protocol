# EMILIA Protocol — Outreach Emails

## 1. AAIF Submission Email

**To:** pr@aaif.org
**Subject:** Proposal: Trust Attestation Working Group — EMILIA Protocol

Hi,

I'm writing to propose a Trust Attestation Working Group within AAIF.

The current AAIF stack covers tool connectivity (MCP), agent execution (goose), and agent instructions (AGENTS.md). None address a fundamental question in agentic commerce: should you trust this counterparty?

EMILIA Protocol (EP) is an open-source trust attestation standard that answers this through cryptographically verified transaction receipts. Unlike traditional review systems, EP outputs multi-dimensional trust profiles evaluated against configurable policies — not scalar scores.

We're not asking AAIF to adopt our product. We're proposing a neutral working group to develop the trust attestation standard together, using EP as the initial reference implementation.

What's deployed today:
- Trust profile endpoint (GET /api/trust/profile/:entityId) — behavioral rates, signal breakdowns, anomaly detection, confidence levels
- Policy evaluation (POST /api/trust/evaluate) — structured decision frameworks with 4 built-in + custom policies
- Behavioral-first scoring — completion/retry/abandon/dispute as primary signals (40% weight)
- 4-layer Sybil resistance — effective-evidence dampening, graph analysis in scoring, submitter credibility, Upstash Redis rate limiting
- Context keys on receipts — task_type, category, geo, modality for future contextual trust
- Canonical JSON hashing for cross-language verification
- Receipt immutability via DB triggers
- Unified receipt pipeline with canonical establishment stamped via SQL function
- Compatible with ACP payment flows, usable through MCP tools
- MCP server, TypeScript + Python SDKs published
- Two test suites (v1 scoring + v2 trust profiles/policies)

Full proposal attached. I'll be at MCP Dev Summit NYC April 2-3 and would welcome the opportunity to discuss in person.

Best,
[Your name]
team@emiliaprotocol.ai
https://emiliaprotocol.ai | https://github.com/emiliaprotocol/emilia-protocol

---

## 2. NIST Submission Email

**To:** NCCoE contact
**Subject:** Response to ITL AI Agent Identity and Authorization Concept Paper — EMILIA Protocol

Dear NCCoE team,

Please find attached our response to the ITL AI Agent Identity and Authorization Concept Paper.

EMILIA Protocol (EP) proposes a complementary approach to AI agent identity through reputation-based trust attestation. While traditional identity frameworks answer "who is this agent?", EP answers "should you trust this agent?" — through multi-dimensional trust profiles computed from verified transaction receipts, evaluated against configurable trust policies.

EP is an open-source protocol (Apache 2.0) that outputs trust profiles — not scalar scores. The protocol includes behavioral-first scoring, effective-evidence Sybil resistance, context-aware receipts, and policy evaluation as first-class primitives. It is compatible with MCP, ACP, A2A, and UCP.

We welcome NIST's guidance on how EP can align with the AI Agent Standards Initiative.

Attached: NIST-ITL-ConceptPaper-EP-Response.pdf

Best,
[Your name]
team@emiliaprotocol.ai

---

## 3. Design Partner Outreach — Shopify App Developer

**To:** [Shopify agent/app developer]
**Subject:** Trust profiles for your Shopify agent — pilot opportunity

Hi [name],

I'm building EMILIA Protocol — an open-source trust attestation standard for AI agents in commerce. Not another review score — EP outputs multi-dimensional trust profiles that agents evaluate against configurable policies.

I'm looking for 3-5 design partners to pilot EP with real transaction data. Your Shopify agent would be a great fit because:

- EP profiles measure delivery accuracy, product accuracy, price integrity, and behavioral outcomes — the exact signals your buyers care about
- Context keys let receipts specify category, geo, and value band — so trust is contextual, not generic
- Integration is 3 API calls: register, submit receipt, evaluate trust
- Your agent gets a verifiable trust profile that no competitor can fake
- MCP server means any AI agent can check your profile with one config line

What's deployed right now:
- GET /api/trust/profile/:entityId — full behavioral breakdown, anomaly detection, confidence
- POST /api/trust/evaluate — "does this merchant pass my strict policy for furniture?" → pass/fail with reasons
- 4-layer Sybil resistance so fake receipts can't game the system

What's in it for you: a Founding Entity number, early input on the spec, and a trust profile that differentiates you from unscored competitors.

Live: https://emiliaprotocol.ai
GitHub: https://github.com/emiliaprotocol/emilia-protocol

15-minute call this week?

Best,
[Your name]

---

## 4. Design Partner Outreach — AI Agent Framework (LangChain/CrewAI/AutoGen)

**To:** [Agent framework team]
**Subject:** Adding trust-aware routing to your agent framework

Hi [name],

When your agents route tasks to external services, how do they decide who to trust?

EMILIA Protocol is an open-source trust attestation standard for agent-to-agent commerce. Instead of opaque reputation scores, EP outputs trust profiles that agents evaluate against configurable policies.

Your agents can now do:

```
POST /api/trust/evaluate
{ "entity_id": "merchant-xyz", "policy": "strict" }
→ { "pass": true, "confidence": "confident", "completion_rate": 94.3%, "dispute_rate": 0.7% }
```

Or via MCP:
```json
{ "mcpServers": { "emilia": { "command": "npx", "args": ["@emilia-protocol/mcp-server"] } } }
```

One config line. Your agents can then evaluate any counterparty against trust policies before routing.

What makes EP different from reputation scores:
- Trust profiles, not scalar scores — behavioral rates, signal breakdowns, anomaly alerts
- Trust policies, not thresholds — structured decision frameworks with pass/fail/reasons
- Context keys — trust is contextual (a merchant good for beauty products may be bad for furniture)
- 4-layer Sybil resistance — fake receipts from throwaway entities carry 0.1x weight
- Effective-evidence dampening — 5 perfect receipts from nobody produces score ~55, not 100

We're looking for 3-5 design partners to shape the spec. Your framework would give EP coverage across thousands of agent deployments.

Interested?

Best,
[Your name]

---

## 5. Design Partner Outreach — Commerce API (Stripe/Square/Bolt)

**To:** [Commerce platform developer relations]
**Subject:** Trust attestation layer for agentic payments — partnership inquiry

Hi [name],

As AI agents begin handling autonomous purchases, there's a missing layer in the commerce stack: how does a paying agent decide whether a merchant is trustworthy?

EMILIA Protocol is building the trust attestation standard for agentic commerce. We've drafted an ACP Trust Extension that adds optional trust evaluation to payment flows:

```
Before completing payment:
POST /api/trust/evaluate
{ "entity_id": "merchant-xyz", "policy": "standard" }
→ { "pass": true, "completion_rate": 94.3%, "dispute_rate": 0.7% }
```

The agent sees a multi-dimensional trust profile — not just a number. It evaluates against a configurable policy. If the merchant doesn't pass, the agent can decline or warn before money moves.

Key properties:
- No changes to your payment API required — purely additive
- Open source (Apache 2.0), vendor-neutral
- Behavioral-first scoring — completion/retry/abandon/dispute as primary signals
- Context-aware — receipts carry task_type, category, geo, value_band
- Sybil-resistant — 4-layer defense, effective-evidence dampening

We're submitting this to AAIF as a working group proposal. Would your developer relations or standards team be interested in reviewing the draft spec?

ACP Extension draft: https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/EP-ACP-EXTENSION.md

Best,
[Your name]
