# EMILIA Protocol — Outreach Emails

## 1. AAIF Submission Email

**To:** pr@aaif.org
**Subject:** Proposal: Trust Attestation Working Group — EMILIA Protocol

Hi,

I'm writing to propose a Trust Attestation Working Group within AAIF.

The current AAIF stack covers tool connectivity (MCP), agent execution (goose), and agent instructions (AGENTS.md). None address a fundamental question in agentic commerce: should you trust this counterparty?

EMILIA Protocol (EP) is an open-source trust attestation standard that answers this through cryptographically verified transaction receipts. Unlike traditional review systems, EP outputs multi-dimensional trust profiles evaluated against configurable policies — not scalar scores.

EP operates under one constitutional principle: **trust must never be more powerful than appeal.** Every negative trust effect must be explainable, challengeable, and reversible. The v4 roadmap includes provenance tiers, due-process lifecycle (challenged → under review → resolved/reversed → superseded), relationship trust, and context-aware evaluation.

We're not asking AAIF to adopt our product. We're proposing a neutral working group to develop the trust attestation standard together, using EP as the initial reference implementation.

What's deployed today:
- Trust profile endpoint (GET /api/trust/profile/:entityId) — behavioral rates, signal breakdowns, anomaly detection, confidence levels
- Context-aware policy evaluation (POST /api/trust/evaluate) — 4 built-in + custom JSONB policies, filters receipts by context with global fallback
- Behavioral-first scoring — behavioral 40%, consistency 25%, weights sum to 1.00
- 4-layer Sybil resistance — effective-evidence dampening, graph analysis, submitter credibility, identity-aware rate limiting
- Policy-native needs — needs accept JSONB trust policies, claim evaluation enforces them
- Confidence-aware search and leaderboard — rank by score, confidence, or evidence depth
- Context keys on receipts — task_type, category, geo, modality, value_band, risk_class
- Three-factor receipt weighting: submitter credibility × time decay × graph health
- Current vs historical confidence as separate protocol objects across all surfaces
- Identity-aware write throttling — API key prefix + IP on authenticated writes
- Server-derived owner identity — not caller-supplied
- MCP server (8 tools, trust-profile-first, context-aware), TypeScript + Python SDKs
- 3 test suites, ~65 tests (scoring, trust profiles, protocol surface contracts, hash determinism)
- Shopify DTC integration spec (webhook → event ledger → EP receipts)

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

## 5. Design Partner Outreach — DTC Merchant on Shopify

**To:** [DTC brand founder / head of ecommerce]
**Subject:** Make your store machine-trustable before AI agents become a sales channel

Hi [name],

AI shopping agents are coming. When they do, they'll need to decide which merchants to trust — before checkout, without a human reading reviews.

EMILIA Protocol lets your Shopify store generate a machine-readable trust profile from your own operational data. No surveys, no badges, no reviews. Just your actual delivery performance, pricing accuracy, and return handling — computed from Shopify webhooks into a verifiable trust profile.

How it works:
1. Shopify app subscribes to orders/paid, fulfillments, refunds, returns
2. Events are normalized into a merchant transaction ledger
3. Canonical EP receipts are generated with structured claims and evidence
4. Your store gets a public trust profile any AI agent can evaluate

What agents see:
```
GET /api/trust/profile/yourstore.com
→ { completion_rate: 93.8%, delivery_accuracy: 91.6%, 
    dispute_rate: 0.4%, confidence: "confident" }
```

What agents do:
```
POST /api/trust/evaluate
{ "entity_id": "yourstore.com", "policy": "strict" }
→ { "pass": true }
```

Your store becomes agent-readable. Competitors without EP trust profiles become invisible to routing agents.

We're building the Shopify integration now and looking for 3 founding DTC merchants. You'd get a permanent Founding Entity number, early input on the spec, and a trust profile that compounds with every order you fulfill well.

The pitch is simple: **make your store machine-trustable before AI agents become a major sales channel.**

15-minute call this week?

Best,
[Your name]

---

## 6. Design Partner Outreach — Commerce Platform (Stripe/Square/Bolt)

**To:** [Commerce platform developer relations]
**Subject:** Trust evaluation layer for agentic payments — partnership inquiry

Hi [name],

As AI agents begin handling autonomous purchases, there's a missing layer: how does a paying agent decide whether a merchant is trustworthy?

EMILIA Protocol adds optional trust evaluation to payment flows. Before completing a payment, the agent evaluates the merchant against a configurable trust policy:

```
POST /api/trust/evaluate
{ "entity_id": "merchant-xyz", "policy": "standard" }
→ { "pass": true, "completion_rate": 94.3%, "dispute_rate": 0.7% }
```

Key properties:
- No changes to your payment API — purely additive
- Open source (Apache 2.0), vendor-neutral, submitting to AAIF
- Behavioral-first: completion/retry/abandon/dispute as primary signals
- Context-aware: receipts carry task_type, category, geo, value_band
- Sybil-resistant: 4-layer defense including effective-evidence dampening
- Constitutional principle: trust must never be more powerful than appeal

We have a Shopify DTC integration spec ready and are looking for commerce platform partners to validate the ACP trust extension.

ACP Extension: https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/EP-ACP-EXTENSION.md
Shopify Spec: available on request

Best,
[Your name]
