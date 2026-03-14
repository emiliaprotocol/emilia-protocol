# EP-ACP Trust Extension — Draft Specification

**Version:** 0.1-draft
**Status:** Proposal
**Extends:** Agent Commerce Protocol (ACP) by OpenAI + Stripe
**License:** Apache-2.0

---

## 1. Purpose

ACP defines how AI agents discover, negotiate, and pay merchants autonomously. ACP does not define how an agent decides whether a merchant is **trustworthy** before initiating payment.

This extension adds an optional EP trust check to the ACP payment flow. Agents can set minimum trust thresholds before completing transactions.

---

## 2. Flow

```
Standard ACP:
  Agent discovers merchant → Negotiates → Pays via Stripe

ACP + EP Trust Extension:
  Agent discovers merchant → Checks EP score → If score ≥ threshold → Pays via Stripe
                                              → If score < threshold → Declines or warns
```

---

## 3. Trust Check Request

Before completing an ACP payment, the agent queries the merchant's EP score:

```json
POST /api/score/{merchant_entity_id}

Response:
{
  "entity_id": "merchant-xyz",
  "emilia_score": 87.3,
  "confidence": "confident",
  "total_receipts": 142,
  "established": true
}
```

---

## 4. ACP Payment with Trust Attestation

The ACP payment object includes an optional `ep_trust` field:

```json
{
  "acp_payment": {
    "merchant_id": "merchant-xyz",
    "amount_cents": 4990,
    "currency": "USD",
    "payment_method": "stripe"
  },
  "ep_trust": {
    "entity_id": "merchant-xyz",
    "score_at_payment": 87.3,
    "confidence": "confident",
    "min_score_required": 70,
    "check_timestamp": "2026-03-14T12:00:00Z",
    "verify_url": "https://emiliaprotocol.ai/api/score/merchant-xyz"
  }
}
```

---

## 5. Agent Configuration

Agents configure trust thresholds in their ACP settings:

```json
{
  "acp_config": {
    "ep_trust_policy": {
      "enabled": true,
      "min_score": 70,
      "min_confidence": "emerging",
      "on_fail": "decline",
      "on_no_score": "warn"
    }
  }
}
```

| `on_fail` | Behavior when score < threshold |
|-----------|--------------------------------|
| `decline` | Do not proceed with payment |
| `warn` | Proceed but flag to user |
| `allow` | Proceed regardless (log only) |

---

## 6. Post-Transaction Receipt

After an ACP transaction completes, the purchasing agent submits an EP receipt:

```json
POST /api/receipts/submit
Authorization: Bearer ep_live_...

{
  "entity_id": "merchant-xyz",
  "transaction_type": "purchase",
  "transaction_ref": "acp_txn_abc123",
  "delivery_accuracy": 92,
  "product_accuracy": 88,
  "price_integrity": 100,
  "agent_behavior": "completed",
  "evidence": {
    "acp_transaction_id": "acp_txn_abc123",
    "payment_ref": "stripe_pi_xyz",
    "amount_cents": 4990
  }
}
```

This closes the loop: ACP handles the payment, EP scores the outcome.

---

## 7. Benefits

| For Agents | For Merchants | For Platforms |
|-----------|--------------|--------------|
| Avoid bad merchants before paying | High scores = more transactions | Reduced fraud/chargebacks |
| Automated trust decisions | Reputation is portable across platforms | Lower dispute costs |
| No human review needed | Good performance compounds | Trust without gatekeeping |

---

## 8. Implementation

The EP MCP server already provides `ep_score_lookup` as a tool. Any ACP-compatible agent using MCP can check scores today:

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

No changes to ACP are required. This extension is purely additive — agents that don't use EP continue to work normally.

---

*EP-ACP Trust Extension v0.1-draft*
*A vendor-neutral trust layer for ACP payment flows.*
