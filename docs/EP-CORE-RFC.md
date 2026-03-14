# EP Trust Attestation — Core Specification

**Version:** 1.0-draft
**Status:** Working Draft
**License:** Apache-2.0
**Authors:** EMILIA Protocol Contributors

---

## 1. Purpose

This specification defines a portable, vendor-neutral format for trust attestations between transacting entities in agent-to-agent commerce. It is designed to be consumed through MCP tool calls, attached to ACP payment flows, and embedded in A2A Agent Cards.

EP does not handle transactions, payments, or communication. It answers one question: **should you trust this counterparty?**

---

## 2. Trust Receipt

A Trust Receipt is a cryptographic record of a transaction outcome. It is submitted by the purchasing party after a transaction completes.

### 2.1 Required Fields

```json
{
  "receipt_id": "ep_rcpt_{hex}",
  "entity_id": "scored-entity-slug",
  "submitted_by": "submitter-uuid",
  "transaction_type": "purchase | service | delivery | return",
  "agent_behavior": "completed | retried_same | retried_different | abandoned | disputed",
  "created_at": "ISO-8601"
}
```

### 2.2 Signal Fields (all optional, 0-100)

| Signal | Weight | Description |
|--------|--------|-------------|
| `delivery_accuracy` | 30% | Promised vs actual delivery |
| `product_accuracy` | 25% | Listing vs reality |
| `price_integrity` | 15% | Quoted vs charged |
| `return_processing` | 15% | Return policy honored |
| `agent_satisfaction` | 10% | Behavioral (see §2.3) |
| `consistency` | 5% | Entity-level, computed |

### 2.3 Agent Satisfaction (Behavioral)

Not a rating. An observable action by the purchasing agent:

| Behavior | Score | Definition |
|----------|-------|-----------|
| `completed` | 95 | Transaction finished, no retry |
| `retried_same` | 75 | Same counterparty, new attempt |
| `retried_different` | 40 | Switched counterparty for same task |
| `abandoned` | 15 | Stopped pursuing task category |
| `disputed` | 5 | Formal dispute filed |

### 2.4 Evidence-Backed Claims (v2)

Implementations MAY accept structured claims instead of numeric signals:

```json
{
  "claims": {
    "delivered": true,
    "on_time": { "promised": "ISO-8601", "actual": "ISO-8601" },
    "price_honored": { "quoted_cents": 4990, "charged_cents": 4990 },
    "as_described": false
  },
  "evidence": {
    "tracking_id": "FDX-123456",
    "payment_ref": "stripe_pi_abc"
  }
}
```

The implementation computes signal scores from claims. Claims-computed signals override manual signals when both are present.

---

## 3. Score Computation

### 3.1 Formula

```
signal_average = weighted_average(receipts, weights=[0.30, 0.25, 0.15, 0.15, 0.10, 0.05])
```

Each receipt is weighted by two factors:
- **Submitter credibility:** Established submitter = `score/100`. Unestablished = `0.1`.
- **Time decay:** `max(0.05, 0.5^(age_days/90))`

Combined: `receipt_weight = submitter_weight × time_weight`

### 3.2 Establishment

An entity is established when it has **5+ receipts** from **3+ unique submitters** where those submitters are themselves established.

### 3.3 Dampening

Score is dampened toward 50 based on **effective receipt count** (sum of all receipt weights), not raw count:

```
if effective_count < 5:
  score = 50 + (raw_score - 50) × (effective_count / 5)
```

### 3.4 Score Confidence

| Level | Condition | Breakdown Shown |
|-------|-----------|----------------|
| `pending` | 0 receipts | No |
| `insufficient` | Score ≤55, receipts ≤10 | No |
| `provisional` | <5 effective receipts | No |
| `emerging` | 5+ effective, established | Yes |
| `confident` | 20+ receipts, multiple submitters | Yes |

---

## 4. Score Proof Format

An EP Score Proof is a portable attestation that can be attached to ACP payments, MCP tool responses, or A2A Agent Cards.

```json
{
  "ep_proof": {
    "entity_id": "merchant-xyz",
    "score": 87.3,
    "confidence": "confident",
    "total_receipts": 142,
    "established": true,
    "proof_timestamp": "ISO-8601",
    "merkle_root": "sha256:abc...",
    "anchor_tx": "0x...",
    "verify_url": "https://emiliaprotocol.ai/api/score/merchant-xyz"
  }
}
```

Any party can independently verify by:
1. Querying the score API
2. Checking the Merkle root against the on-chain anchor
3. Recomputing the score from raw receipts (algorithm is open source)

---

## 5. Cryptographic Integrity

- Each receipt is **SHA-256 hashed**
- Each receipt includes the **previous receipt's hash** (chain linking)
- Batches of receipt hashes form a **Merkle tree**
- Merkle roots are **anchored on-chain** (Base L2 reference implementation, chain-agnostic spec)
- Anyone can verify any receipt against the on-chain root

---

## 6. Sybil Resistance

Four layers:
1. **Registration friction:** Rate limiting (5 entities/day/owner)
2. **Graph analysis:** Closed-loop detection, thin-graph flagging, velocity monitoring, cluster detection
3. **Submitter credibility:** Unestablished entities = 0.1x receipt weight
4. **Protocol design:** No self-scoring, rolling 200-receipt window, effective-count dampening

---

## 7. Interoperability

### MCP Tool
```json
{ "tool": "ep_score_lookup", "input": { "entity_id": "merchant-xyz" } }
```

### ACP Trust Extension
```json
{
  "acp_payment": { ... },
  "ep_trust_check": {
    "entity_id": "merchant-xyz",
    "min_score": 70,
    "min_confidence": "emerging"
  }
}
```

### A2A Agent Card
```json
{
  "name": "Shopping Agent",
  "ep": { "entity_id": "agent-123", "min_counterparty_score": 70 }
}
```

---

*EP Trust Attestation Core Specification v1.0-draft*
*Apache-2.0 · Compatible with ACP, MCP, A2A*
