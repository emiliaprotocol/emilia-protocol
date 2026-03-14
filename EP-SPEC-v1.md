# EP (EMILIA Protocol) Specification v1.0

> **⚠️ DEPRECATED:** This document describes the v1.0 scoring-first design. The canonical specification is now [EP Core RFC v1.1](docs/EP-CORE-RFC.md), which reflects the current runtime: behavioral-first scoring, trust profiles as the primary output, policy evaluation, effective-evidence dampening, and graph-weight integration. Please refer to the RFC for all new implementations.

**Entity Measurement Infrastructure for Ledgered Interaction Accountability**

*A vendor-neutral trust attestation standard for agentic commerce.*

---

## Abstract

EP is a formal protocol specification for reputation scoring in the agent economy. It defines the receipt schema, scoring algorithm interface, score lookup API, and cryptographic verification flow. EP sits alongside MCP (tools), A2A (communication), UCP (commerce), and ACP (payments) as the trust layer in the agentic commerce stack.

Any entity that transacts — agents, merchants, service providers — can be scored through EP. Scores are computed from verified transaction receipts, not opinions. The algorithm is open source. The receipts are immutable.

**Status:** Draft Specification v1.0
**License:** Apache-2.0
**Canonical Implementation:** https://emiliaprotocol.ai
**GitHub:** https://github.com/emiliaprotocol/emilia-protocol

---

## 1. Terminology

| Term | Definition |
|------|-----------|
| **Entity** | Any commercial actor — an AI agent, a merchant, a service provider |
| **Receipt** | A cryptographically hashed record of a transaction outcome |
| **EMILIA Score** | A 0-100 trust score computed from an entity's receipt history |
| **Signal** | A specific measurement within a receipt (e.g., delivery_accuracy) |
| **Merkle Batch** | A set of receipt hashes compiled into a Merkle tree |
| **Anchor** | Publishing a Merkle root to a blockchain for independent verification |
| **EP Implementation** | Any system that implements this specification |

---

## 2. Protocol Stack Position

```
┌─────────────────────────────────────────┐
│  TRUST        EP (EMILIA Protocol)      │  ← This specification
├─────────────────────────────────────────┤
│  PAYMENTS     AP2 / ACP                 │  Google / OpenAI + Stripe
├─────────────────────────────────────────┤
│  COMMERCE     UCP                       │  Google + Shopify
├─────────────────────────────────────────┤
│  COMMUNICATION  A2A                     │  Google
├─────────────────────────────────────────┤
│  TOOLS        MCP                       │  Anthropic
└─────────────────────────────────────────┘
```

EP is the only layer that answers: **"Should you trust this entity?"**

---

## 3. Entity Model

### 3.1 Entity Registration

Every entity in the EP network has:

```json
{
  "entity_id": "string",          // Human-readable slug: "rex-booking-v1"
  "display_name": "string",       // "Rex — Inbound AI Receptionist"
  "entity_type": "enum",          // "agent" | "merchant" | "service_provider"
  "description": "string",        // What this entity does
  "capabilities": ["string"],     // ["inbound_booking", "sentiment_analysis"]
  "category": "string",           // "salon", "legal", "furniture"
  "service_area": "string",       // Geographic or "global"
  
  // Interoperability
  "a2a_endpoint": "string",       // A2A Agent Card URL
  "ucp_profile_url": "string",    // UCP merchant profile URL
  
  // Computed (NEVER self-reported)
  "emilia_score": "number",       // 0-100
  "total_receipts": "integer",
  "verified": "boolean"
}
```

### 3.2 Entity Types

- **Agent**: An AI system that acts on behalf of a user (shopping agent, booking agent, research agent)
- **Merchant**: A business that sells goods or services (online store, SaaS provider, marketplace seller)
- **Service Provider**: An entity that provides capabilities to other entities (payment processor, shipping provider, data service)

### 3.3 Entity Numbers

Entities receive a sequential number upon registration (Entity #1, #2, #3...). This number is permanent and cannot be reassigned.

---

## 4. Receipt Schema

Receipts are the core data structure in EP. They record **what happened**, not opinions.

### 4.1 Receipt Structure

```json
{
  "receipt_id": "string",                // Unique: "ep_rcpt_{random_hex}"
  "entity_id": "uuid",                   // Entity being scored
  "submitted_by": "uuid",                // Entity submitting the receipt
  "transaction_ref": "string",           // External ref (UCP order, A2A task)
  "transaction_type": "enum",            // See 4.2
  
  // Signals (all 0-100, all optional — at least one required)
  "delivery_accuracy": "number | null",  // Promised vs actual timing
  "product_accuracy": "number | null",   // Listing vs reality
  "price_integrity": "number | null",    // Quoted vs charged
  "return_processing": "number | null",  // Return policy honored?
  "agent_satisfaction": "number | null",  // Purchasing agent signal
  
  // Evidence (structured, not opinions)
  "evidence": {
    "promised_delivery": "string",
    "actual_delivery": "string",
    "price_quoted": "integer",           // Cents
    "price_charged": "integer"           // Cents
  },
  
  // Computed at write time
  "composite_score": "number",           // Weighted average of signals
  "receipt_hash": "string",              // SHA-256
  "previous_hash": "string | null",      // Chain link
  "created_at": "datetime"
}
```

### 4.2 Transaction Types

| Type | Description |
|------|-------------|
| `purchase` | Goods or services bought |
| `service` | Service rendered |
| `task_completion` | Agent task completed |
| `delivery` | Physical or digital delivery |
| `return` | Return or refund processed |

### 4.3 Receipt Rules

1. **Append-only**: Receipts cannot be modified or deleted after creation.
2. **Chain-linked**: Each receipt includes the SHA-256 hash of the previous receipt for the same entity, forming a tamper-evident chain.
3. **No self-scoring**: An entity cannot submit receipts for itself.
4. **Bidirectional**: Both parties in a transaction can score each other.
5. **Evidence-based**: Signals should be supported by structured evidence, not subjective opinions.

### 4.4 Receipt Hash Computation

```
receipt_hash = SHA-256(JSON.stringify({
  entity_id,
  submitted_by,
  transaction_ref,
  transaction_type,
  delivery_accuracy,
  product_accuracy,
  price_integrity,
  return_processing,
  agent_satisfaction,
  evidence,
  previous_hash
}))
```

The hash is deterministic. Anyone with the receipt data can recompute it.

---

## 5. Scoring Algorithm

### 5.1 Signal Weights

| Signal | Weight | What It Measures |
|--------|--------|------------------|
| `delivery_accuracy` | 30% | Promised vs actual timing |
| `product_accuracy` | 25% | Listing vs reality |
| `price_integrity` | 15% | Quoted vs charged |
| `return_processing` | 15% | Return policy honored |
| `agent_satisfaction` | 10% | Purchasing agent signal |
| `consistency` | 5% | Low variance over time |

### 5.2 Receipt Composite Score

For a single receipt, the composite score is the weighted average of all present signals. Missing signals are excluded (not penalized).

```
composite = Σ(signal_value × weight) / Σ(weights of present signals)
```

### 5.3 Entity Score

The EMILIA Score is computed from the rolling window of the last 200 receipts:

1. Compute the mean of each signal across the window
2. Compute consistency: `max(0, 100 - stddev(composite_scores) × 2)`
3. Weighted average of all signals + consistency
4. For new entities (< 5 receipts): dampen toward 50
   - `score = 50 + (raw_score - 50) × (receipt_count / 5)`
5. Clamp to [0, 100], round to 1 decimal

### 5.4 Behavioral Agent Satisfaction

The `agent_satisfaction` signal (10% weight) is measured through observable agent behavior, not subjective ratings. When a receipt includes `agent_behavior`, the satisfaction score is computed automatically:

| Behavior | Score | What It Means |
|----------|-------|---------------|
| `completed` | 95 | Transaction completed without retry |
| `retried_same` | 75 | Agent retried with the same entity (minor issue resolved) |
| `retried_different` | 40 | Agent switched to a different entity |
| `abandoned` | 15 | Agent abandoned the transaction entirely |
| `disputed` | 5 | Agent filed a dispute |

Submitters MAY provide a raw `agent_satisfaction` score (0-100) instead. If both `agent_behavior` and `agent_satisfaction` are provided, the behavioral signal takes precedence.

### 5.5 Score Properties

- **Deterministic**: Same receipts always produce the same score.
- **Public**: Any entity's score can be looked up without authentication.
- **Auditable**: The algorithm is open source (Apache-2.0).
- **Unpurchasable**: No payment, partnership, or API tier affects scoring.

---

## 6. API Surface

An EP implementation MUST expose these endpoints:

### 6.1 Core Endpoints (Required)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/entities/register` | API Key | Register a new entity |
| `POST` | `/api/receipts/submit` | API Key | Submit a transaction receipt |
| `GET` | `/api/score/{entityId}` | None | Look up an entity's EMILIA Score |

### 6.2 Discovery Endpoints (Recommended)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/entities/search?q=...` | None | Search entities |
| `GET` | `/api/score/{entityId}/history` | None | Score change history |
| `GET` | `/api/leaderboard` | None | Top-scored entities |
| `GET` | `/api/feed` | None | SSE feed of network activity |

### 6.3 Verification Endpoints (Recommended)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/verify/{receiptId}` | None | Merkle proof for a receipt |
| `POST` | `/api/blockchain/anchor` | CRON_SECRET | Batch and anchor receipts |

### 6.4 Needs Marketplace (Optional)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/needs/broadcast` | API Key | Broadcast a need |
| `POST` | `/api/needs/{id}/claim` | API Key | Claim a need |
| `POST` | `/api/needs/{id}/complete` | API Key | Complete a need |
| `POST` | `/api/needs/{id}/rate` | API Key | Rate completion |

### 6.5 Authentication

Write operations require an EP API key:
```
Authorization: Bearer ep_live_{64_hex_chars}
```

Read operations (score lookup, search, verify) require no authentication.

---

## 7. Blockchain Verification

### 7.1 Overview

EP receipts are stored in a database and cryptographically anchored on-chain. This is NOT a crypto product — no tokens, no DeFi, no wallets. It's a verification mechanism.

### 7.2 Verification Flow

```
Receipt Submitted → SHA-256 Hash → Merkle Tree Batch → Base L2 Anchor → Anyone Can Verify
```

### 7.3 Merkle Tree Construction

1. Collect unanchored receipt hashes
2. Build a binary Merkle tree (sorted pair hashing)
3. If odd number of leaves, promote the last leaf
4. Store the tree layers for proof generation
5. Publish the root to Base L2

### 7.4 Merkle Proof Verification

To verify any receipt:

1. Recompute `receipt_hash` from raw receipt data
2. Obtain the Merkle proof from `/api/verify/{receiptId}`
3. Walk the proof: for each step, `hash(sorted(current, sibling))`
4. Compare the resulting root to the on-chain value
5. Look up the transaction on Base L2 (basescan.org) to confirm

### 7.5 On-Chain Format

Transaction calldata: `EP:v1:{batchId}:{merkleRoot}`

This is a data-only transaction on Base L2 (Coinbase Layer 2). Cost: ~$0.60/month at launch scale, ~$600/month at 2M receipts/day.

---

## 8. Integrations

### 8.1 MCP Integration

EP provides an MCP server that gives any AI agent access to trust data:

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

Tools: `ep_score_lookup`, `ep_submit_receipt`, `ep_verify_receipt`, `ep_search_entities`, `ep_register_entity`, `ep_leaderboard`.

### 8.2 A2A Integration

EP scores can be included in A2A Agent Cards:

```json
{
  "name": "Rex Booking Agent",
  "url": "https://rex.example.com/.well-known/agent.json",
  "emilia": {
    "entity_id": "rex-booking-v1",
    "score_url": "https://emiliaprotocol.ai/api/score/rex-booking-v1",
    "min_counterparty_score": 70
  }
}
```

### 8.3 UCP Integration

EP receipts map to UCP transaction outcomes:

| UCP Event | EP Signal |
|-----------|-----------|
| `order.delivered` | `delivery_accuracy` |
| `order.returned` | `return_processing` |
| `payment.completed` | `price_integrity` |
| `product.received` | `product_accuracy` |

### 8.4 SDK Usage

**TypeScript:**
```typescript
import { EmiliaClient } from '@emilia-protocol/sdk';

const ep = new EmiliaClient({
  baseUrl: 'https://emiliaprotocol.ai',
  apiKey: 'ep_live_...',
});

const score = await ep.getScore('rex-booking-v1');
if (score.emilia_score >= 80) {
  // Trust this entity
}
```

**Python:**
```python
from emilia_protocol import EmiliaClient

ep = EmiliaClient(
    base_url="https://emiliaprotocol.ai",
    api_key="ep_live_...",
)

score = ep.get_score("rex-booking-v1")
if score.emilia_score >= 80:
    # Trust this entity
    pass
```

---

## 9. Security Considerations

### 9.1 Receipt Integrity

Each receipt is SHA-256 hashed and chain-linked. Tampering with any receipt breaks the chain. On-chain Merkle anchoring provides an independent verification path that does not require trusting the EP implementation.

### 9.2 API Key Security

Keys are hashed (SHA-256) before storage. Only the hash is persisted. Keys are prefixed with `ep_live_` for identification.

### 9.3 Sybil Resistance

EP defends against fake entities and synthetic transactions at three layers:

**Layer 1: Registration Friction**

- Rate-limited registration: max 5 entities per owner per day, max 50 total
- Entity owners are identified by API key lineage
- Future: email/domain verification, optional refundable micro-deposit staking ($10-50)

**Layer 2: Receipt Graph Analysis**

The canonical implementation monitors the receipt graph for collusion patterns:

| Pattern | Detection | Action |
|---------|-----------|--------|
| **Closed loop** | A scores B AND B scores A | Warning flag (bidirectional scoring is sometimes legitimate) |
| **Thin graph** | 5+ receipts but < 3 unique submitters | Entity marked "unestablished" regardless of receipt count |
| **Single source** | 3+ receipts all from one submitter | Flag + entity not eligible for "established" status |
| **Velocity spike** | 100+ receipts from one submitter in 1 hour | Receipt blocked |
| **Cluster** | Small group of entities that only score each other | Flag for review |

All fraud flags are logged permanently in the `fraud_flags` table for audit.

**Layer 3: Protocol Design**

- **No self-scoring**: Entities cannot submit receipts for themselves
- **Rolling window of 200**: Flooding with old receipts doesn't help — only the last 200 count
- **New entity dampening**: Scores start at 50 and require 5+ receipts to move significantly
- **Establishment requires diversity**: An entity needs both 5+ receipts AND 3+ unique submitters to be considered "established"
- **Bidirectional scoring**: Creating a fake buyer to inflate a merchant's score leaves a permanent, auditable trail on the fake buyer
- **Append-only ledger**: Every fake receipt is recorded forever — you cannot clean up after a Sybil attack

**Economic cost of a Sybil attack**: To meaningfully inflate a score, an attacker must create multiple fake entities (rate-limited), register API keys for each, submit 5+ receipts per entity from 3+ unique submitters to escape dampening, and maintain consistent scoring across 200+ receipts — all while leaving a permanent, auditable, on-chain-anchored trail.

---

## 10. Governance Path

1. **Phase 1 (Current)**: EMILIA Inc. maintains the specification and canonical implementation.
2. **Phase 2**: Advisory Board of early adopters and protocol contributors.
3. **Phase 3**: EMILIA Foundation (independent governance body).

The specification is Apache-2.0 licensed. Anyone can implement EP. The canonical implementation is a reference, not a requirement.

---

## 11. Quick Start

### For Developers (Agent Builders)

```bash
# 1. Register your agent
curl -X POST https://emiliaprotocol.ai/api/entities/register \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "my-agent-v1",
    "display_name": "My Shopping Agent",
    "entity_type": "agent",
    "description": "AI agent that finds the best deals"
  }'

# 2. Check a score before transacting
curl https://emiliaprotocol.ai/api/score/some-merchant-v1

# 3. Submit a receipt after the transaction
curl -X POST https://emiliaprotocol.ai/api/receipts/submit \
  -H "Authorization: Bearer ep_live_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "merchant-uuid-here",
    "transaction_type": "purchase",
    "delivery_accuracy": 95,
    "product_accuracy": 88,
    "price_integrity": 100,
    "evidence": {
      "promised_delivery": "2 business days",
      "actual_delivery": "2 business days"
    }
  }'

# 4. Verify any receipt
curl https://emiliaprotocol.ai/api/verify/ep_rcpt_abc123
```

### For MCP Users (Claude, etc.)

```json
{
  "mcpServers": {
    "emilia": {
      "command": "npx",
      "args": ["@emilia-protocol/mcp-server"],
      "env": {
        "EP_BASE_URL": "https://emiliaprotocol.ai",
        "EP_API_KEY": "ep_live_your_key"
      }
    }
  }
}
```

Then ask your agent: *"Check the EMILIA Score for rex-booking-v1."*

---

## Appendix A: Analogies

| Protocol | Physical World Analogy |
|----------|----------------------|
| MCP | USB-C (universal connectivity) |
| A2A | TCP/IP (communication) |
| UCP | HTTP (commerce) |
| EP | FICO Score / SSL Certificates (trust) |

---

*EP Specification v1.0 — March 2026*
*EMILIA Protocol — Receipts, not reviews.*
