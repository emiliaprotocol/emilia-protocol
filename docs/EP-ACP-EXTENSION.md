# EP-ACP Trust Extension — Draft Specification

**Version:** 0.2-draft
**Status:** Proposal
**Extends:** Agent Commerce Protocol (ACP) by OpenAI + Stripe
**License:** Apache-2.0

---

## 1. Purpose

ACP defines how AI agents discover, negotiate, and pay merchants. ACP does not define how an agent decides whether a merchant is **trustworthy** before initiating payment.

This extension adds optional EP trust evaluation to the ACP payment flow. Agents evaluate counterparties against trust policies before completing transactions.

---

## 2. Flow

```
Standard ACP:
  Agent discovers merchant → Negotiates → Pays via Stripe

ACP + EP Trust Extension:
  Agent discovers merchant → Evaluates trust profile against policy
    → If pass → Pays via Stripe
    → If fail → Declines, warns, or routes elsewhere
```

---

## 3. Trust Evaluation

Before completing an ACP payment, the agent evaluates the merchant:

```json
POST /api/trust/evaluate
{
  "entity_id": "merchant-xyz",
  "policy": "strict"
}

Response:
{
  "decision": "allow",
  "entity_id": "merchant-xyz",
  "policy_used": "strict",
  "confidence": "confident",
  "reasons": [],
  "warnings": [],
  "appeal_path": "https://emiliaprotocol.ai/appeal",
  "profile_summary": {
    "confidence": "confident",
    "evidence_level": 87.3,
    "dispute_rate": 0.7
  }
}
```

Or for the public capability projection:

```json
GET /api/trust/profile/merchant-xyz?view=capability

Response:
{
  "entity_id": "merchant-xyz",
  "capability": "authorization_receipts",
  "capability_on": true
}
```

---

## 4. ACP Payment with Trust Evaluation

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
    "policy_used": "strict",
    "decision": "allow",
    "confidence": "confident",
    "completion_rate": 94.3,
    "dispute_rate": 0.7,
    "context": {
      "task_type": "purchase",
      "category": "electronics",
      "geo": "US-CA"
    },
    "evaluated_at": "2026-03-14T12:00:00Z",
    "verify_url": "https://emiliaprotocol.ai/verify"
  }
}
```

---

## 5. Agent Configuration

Agents configure trust policies in their ACP settings:

```json
{
  "acp_config": {
    "ep_trust_policy": {
      "enabled": true,
      "policy": "standard",
      "on_fail": "decline",
      "on_no_profile": "warn"
    }
  }
}
```

| `on_fail` | Behavior when policy fails |
|-----------|---------------------------|
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
  "transaction_ref": "acp_txn_abc123",
  "transaction_type": "purchase",
  "agent_behavior": "completed",
  "delivery_accuracy": 92,
  "price_integrity": 100,
  "context": {
    "task_type": "purchase",
    "category": "electronics",
    "geo": "US-CA",
    "value_band": "100-500"
  },
  "evidence": {
    "acp_transaction_id": "acp_txn_abc123",
    "payment_ref": "stripe_pi_xyz"
  }
}
```

This closes the loop: ACP handles the payment, EP evaluates trust and records the outcome.

---

## 7. Benefits

| For Agents | For Merchants | For Platforms |
|-----------|--------------|--------------|
| Evaluate trust before paying | High trust profiles = more transactions | Reduced fraud/chargebacks |
| Policy-based decisions, not guesswork | Trust enforcement profiles across platforms | Lower dispute costs |
| Context-aware (category, geo, value) | Behavioral track record compounds | Trust without gatekeeping |

---

## 8. Implementation

The public EP MCP server exposes offline verification tools only. Rich trust-profile and policy-evaluation APIs are authenticated server APIs, not anonymous MCP tools:

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

No changes to ACP are required. This extension is purely additive.

---

*EP-ACP Trust Extension v0.2-draft*
*A vendor-neutral trust evaluation layer for ACP payment flows.*
