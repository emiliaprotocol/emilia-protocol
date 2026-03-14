# EP Trust Attestation — Core Specification

**Version:** 1.1
**Status:** Working Draft
**License:** Apache-2.0
**Authors:** EMILIA Protocol Contributors

---

## 1. Purpose

EP defines a portable, vendor-neutral format for trust attestations between transacting entities in agent-to-agent commerce. It is consumable through MCP tool calls, attachable to ACP payment flows, and embeddable in A2A Agent Cards.

EP answers one question: **should you trust this counterparty?**

The primary protocol output is a **trust profile**, not a score. A compatibility score is provided for sorting and backward compatibility but is not the canonical truth object.

---

## 2. Trust Receipt

A Trust Receipt is a cryptographic record of a transaction outcome, submitted by the purchasing party.

### 2.1 Required Fields

```json
{
  "receipt_id": "ep_rcpt_{hex}",
  "entity_id": "scored-entity-slug",
  "submitted_by": "submitter-uuid",
  "transaction_ref": "external-txn-id",
  "transaction_type": "purchase | service | task_completion | delivery | return",
  "created_at": "ISO-8601"
}
```

`transaction_ref` is **mandatory**. Every receipt must reference an external transaction. Enforced at both API and database level (NOT NULL + unique index on `entity_id, submitted_by, transaction_ref`).

### 2.2 Signal Fields (optional, 0-100)

| Signal | v1 Weight | v2 Weight | Description |
|--------|-----------|-----------|-------------|
| `delivery_accuracy` | 30% | 12% | Promised vs actual delivery |
| `product_accuracy` | 25% | 10% | Listing vs reality |
| `price_integrity` | 15% | 8% | Quoted vs charged |
| `return_processing` | 15% | 5% | Return policy honored |
| `agent_satisfaction` | 10% | — | Replaced by behavioral in v2 |
| `behavioral` | — | 40% | Observable agent action (v2 primary) |
| `consistency` | 5% | 25% | Low variance over time |

v2 behavioral-first weights are the canonical runtime model. v1 weights are used by the legacy `compute_emilia_score()` SQL function for the compatibility score.

### 2.3 Agent Behavior (Behavioral Signal)

Not a rating. An observable action by the purchasing agent:

| Behavior | Score | Definition |
|----------|-------|-----------|
| `completed` | 95 | Transaction finished, no retry |
| `retried_same` | 75 | Same counterparty, new attempt |
| `retried_different` | 40 | Switched counterparty for same task |
| `abandoned` | 15 | Stopped pursuing task category |
| `disputed` | 5 | Formal dispute filed |

Behavioral signals are the strongest Phase 1 signal because they are harder to fake credibly and more aligned with real routing outcomes. They are not unfakeable — that requires bilateral attestations (Phase 2) and oracle verification (Phase 3).

### 2.4 Evidence-Backed Claims (v2)

```json
{
  "claims": {
    "delivered": true,
    "on_time": { "promised": "ISO-8601", "actual": "ISO-8601" },
    "price_honored": { "quoted_cents": 4990, "charged_cents": 4990 },
    "as_described": true
  },
  "evidence": {
    "tracking_id": "FDX-123456",
    "payment_ref": "stripe_pi_abc"
  }
}
```

Claims must produce at least one recognized derived signal. Junk claims with unknown keys are rejected.

---

## 3. Receipt Weighting

Each receipt carries a three-factor weight:

```
receipt_weight = submitter_weight × time_weight × graph_weight
```

| Factor | Formula | Purpose |
|--------|---------|---------|
| Submitter weight | Established: `score/100`. Unestablished: `0.1` | Sybil resistance |
| Time weight | `max(0.05, 0.5^(age_days/90))` | Recent receipts matter more |
| Graph weight | `0.1` to `1.0` from fraud graph analysis | Penalize suspicious patterns |

Graph weight penalties:
- Closed-loop (A↔B mutual scoring): `0.4x`
- Thin graph (few unique submitters): `0.5x`
- Single source: `0.3x`
- Cluster detected: `0.1x` + receipt blocked

---

## 4. Effective Evidence

**Effective evidence** = sum of all receipt weights in the scoring window.

All dampening, establishment, and confidence use effective evidence, **not** raw receipt count.

```
if effective_evidence < 5.0:
  score = 50 + (raw_score - 50) × (effective_evidence / 5.0)
```

Example: 5 receipts from unestablished submitters (0.1x each) = 0.5 effective evidence → score dampened to ~55 regardless of signal values.

---

## 5. Establishment and Confidence

### 5.1 Historical Establishment

Computed by `is_entity_established()` over **all** receipts:
- Effective evidence ≥ 5.0
- 3+ unique submitters

Establishment is permanent once achieved. It answers: "Has this entity ever built enough credible history?"

### 5.2 Current Confidence

Computed from effective evidence in the current scoring window:

| Level | Effective Evidence | Meaning |
|-------|-------------------|---------|
| `pending` | 0 | No data |
| `insufficient` | < 1.0 | Receipts exist but carry very low weight |
| `provisional` | 1.0 – 4.9 | Building credible history |
| `emerging` | 5.0 – 19.9 | Score is meaningful |
| `confident` | ≥ 20.0 | High confidence, broad evidence |

An entity can be historically established but have low current confidence (declining recent performance).

---

## 6. Trust Profile

The **primary protocol output**. Replaces the single 0-100 score.

```json
{
  "profile": {
    "behavioral": {
      "score": 91.2,
      "completion_rate": 94.3,
      "retry_rate": 3.2,
      "abandon_rate": 1.1,
      "dispute_rate": 0.7
    },
    "signals": {
      "delivery_accuracy": 89.1,
      "product_accuracy": 92.4,
      "price_integrity": 99.1,
      "return_processing": 84.2
    },
    "consistency": 93.4
  },
  "anomaly": null,
  "confidence": "confident",
  "effective_evidence": 37.6,
  "established": true,
  "compat_score": 86.9
}
```

`compat_score` (the legacy EMILIA Score) is for sorting and backward compatibility only.

---

## 7. Trust Policies

Agents evaluate counterparties against structured policies, not raw score thresholds.

```json
{
  "min_score": 75,
  "min_confidence": "confident",
  "max_dispute_rate": 0.03,
  "min_completion_rate": 0.85,
  "reject_anomaly": true,
  "signal_minimums": { "delivery_accuracy": 80, "price_integrity": 90 }
}
```

Built-in policies: `strict`, `standard`, `permissive`, `discovery`.

Evaluation returns pass/fail with specific failure reasons.

---

## 8. Anomaly Detection

Score velocity matters more than absolute score. EP computes 7-day vs 30-day average delta:

| Alert Level | Delta | Meaning |
|-------------|-------|---------|
| moderate | 10–19 points | Notable change |
| severe | ≥ 20 points | Agents may auto-reject |

---

## 9. Sybil Resistance (4 layers)

1. **Registration friction** — IP-based rate limiting (Upstash Redis in production, in-memory fallback)
2. **Graph analysis** — closed-loop detection, thin-graph flagging, cluster detection → `graph_weight` penalty
3. **Submitter credibility** — unestablished submitters = 0.1x receipt weight
4. **Effective evidence dampening** — score pulled toward 50 until weighted evidence ≥ 5.0

---

## 10. Cryptographic Integrity

- Canonical JSON serialization with sorted keys (cross-language deterministic)
- SHA-256 hash of full receipt envelope (all truth-bearing fields)
- Chain linking (each receipt includes previous hash)
- Merkle tree batching + blockchain anchoring (optional extension)
- DB triggers reject UPDATE on receipt content and DELETE on receipts

---

## 11. APIs

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/entities/register` | Register entity, get API key |
| POST | `/api/receipts/submit` | Submit receipt (requires `transaction_ref`) |
| GET | `/api/score/:entityId` | Compatibility score + establishment + confidence |
| GET | `/api/trust/profile/:entityId` | **Primary**: full trust profile |
| POST | `/api/trust/evaluate` | Evaluate entity against trust policy |
| GET | `/api/leaderboard` | Ranked entities by compatibility score |
| GET | `/api/verify/:receiptId` | Verify receipt hash and chain |

---

## 12. Interoperability

### MCP Tools
```json
{ "tool": "ep_trust_profile", "input": { "entity_id": "merchant-xyz" } }
{ "tool": "ep_trust_evaluate", "input": { "entity_id": "merchant-xyz", "policy": "strict" } }
```

### ACP Trust Extension
```json
{
  "acp_payment": { "..." },
  "ep_trust_check": {
    "entity_id": "merchant-xyz",
    "policy": "standard",
    "result": { "pass": true, "confidence": "confident" }
  }
}
```

### A2A Agent Card
```json
{
  "name": "Shopping Agent",
  "ep": { "entity_id": "agent-123", "trust_policy": "strict" }
}
```

---

*EP Trust Attestation Core Specification v1.1*
*Apache-2.0 · Compatible with ACP, MCP, A2A*
