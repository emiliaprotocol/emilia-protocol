# EMILIA Protocol

**Evidence-based Mediation & Integrity Layer for Interactions and Appeals**

Portable trust for machine counterparties and third-party software.
Compatible with ACP. Usable through MCP. Apache 2.0.

---

## What is EP?

EP is an open protocol that computes trust profiles for principals in machine-mediated systems — merchants, agents, service providers, GitHub Apps, MCP servers, npm packages, Chrome extensions, marketplace plugins, and agent tools — from verified transaction and interaction receipts.

EP outputs **trust profiles**, not just scores. A trust profile includes behavioral rates (completion, retry, abandon, dispute), per-signal breakdowns, provenance composition, consistency, anomaly alerts, and confidence levels. Agents and systems evaluate counterparties against **trust policies** — configurable decision frameworks — not raw score thresholds.

For software entities, EP provides **install preflight** — "should I install this plugin?" — evaluating publisher verification, permission risk, provenance, and incident history against host-specific policies.

### Primary output: Trust Profile + Policy Evaluation

```
POST /api/trust/evaluate
{
  "entity_id": "merchant-xyz",
  "policy": "strict"
}

→ {
    "pass": true,
    "score": 87.3,
    "confidence": "confident",
    "profile": {
      "behavioral": { "completion_rate": 94.3, "dispute_rate": 0.7 },
      "signals": { "delivery_accuracy": 89.1, "price_integrity": 99.1 }
    }
  }
```

### Install Preflight (EP-SX: Software Trust)

```
POST /api/trust/install-preflight
{
  "entity_id": "mcp-server-ep-v1",
  "policy": "mcp_server_safe_v1",
  "context": { "host": "mcp", "permission_class": "bounded_external_access" }
}

→ {
    "decision": "allow",
    "reasons": [
      "✓ publisher_verified",
      "✓ provenance_verified",
      "✓ permission_class_acceptable"
    ]
  }
```

### Compatibility score (legacy)

EP also exposes a 0-100 compatibility score via `GET /api/score/:entityId` for sorting, leaderboards, and backward compatibility. This is a weighted composite, **not** the primary protocol output. The trust profile is the canonical truth.

### How trust is computed

Receipts are weighted by four factors:
- **Submitter credibility**: unestablished submitters = 0.1x, established = score/100
- **Time decay**: 90-day half-life, recent receipts matter more
- **Graph health**: thin graphs, closed loops, and clusters reduce weight
- **Provenance**: self_attested (0.3x) → bilateral (0.8x) → oracle_verified (1.0x)

Scores are dampened by **effective evidence** (sum of weighted receipts), not raw receipt count. A Sybil quality gate caps unestablished evidence at 2.0 for dampening — pure volume from fake identities cannot overcome the trust barrier.

### Trust policies

Agents don't check "score > 70." They evaluate against structured policies:

| Policy | Use case | Key gates |
|--------|----------|-----------|
| `strict` | High-value purchases | Score ≥75, confident, dispute rate ≤3%, completion ≥85% |
| `standard` | Normal commerce | Score ≥60, emerging, dispute rate ≤10% |
| `permissive` | Low-risk | Score ≥40, provisional |
| `discovery` | Browsing | Allow unscored |

Custom policies supported via JSON.

---

## Quick Start

```bash
git clone https://github.com/emiliaprotocol/emilia-protocol.git
cd emilia-protocol
npm install
cp .env.example .env
# Add Supabase, OpenAI, and optionally Upstash Redis credentials
npm run dev
```

## API

### Register an entity
```bash
curl -X POST https://emiliaprotocol.ai/api/entities/register \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "my-shopping-agent",
    "display_name": "My Shopping Agent",
    "entity_type": "agent",
    "description": "Finds the best deals on electronics"
  }'
```

### Submit a receipt
```bash
curl -X POST https://emiliaprotocol.ai/api/receipts/submit \
  -H "Authorization: Bearer ep_live_..." \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "merchant-xyz",
    "transaction_ref": "order_12345",
    "transaction_type": "purchase",
    "delivery_accuracy": 95,
    "product_accuracy": 88,
    "price_integrity": 100,
    "agent_behavior": "completed",
    "evidence": {
      "tracking_id": "FDX-789",
      "payment_ref": "stripe_pi_abc"
    }
  }'
```

`transaction_ref` is **required**. Every receipt must reference an external transaction. `agent_behavior` is the strongest Phase 1 signal.

### Look up a trust profile
```bash
curl https://emiliaprotocol.ai/api/trust/profile/merchant-xyz
```

### Look up compatibility score (legacy)
```bash
curl https://emiliaprotocol.ai/api/score/merchant-xyz
```

### Evaluate against a trust policy
```bash
curl -X POST https://emiliaprotocol.ai/api/trust/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "merchant-xyz",
    "policy": "standard"
  }'
```

### MCP Integration
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

## Architecture

```
Trust Profile + Policy Evaluation    ← Primary output
        ↑
Scoring Engine (behavioral-first, effective-evidence dampened)
        ↑
Receipt Ledger (append-only, SHA-256 chained, Merkle-anchored)
        ↑
Fraud Detection (graph analysis, velocity, closed-loop, cluster)
        ↑
Entity Registration (IP rate-limited, Upstash Redis in production)
```

### Sybil resistance (4 layers)
1. **Registration friction** — IP-based rate limiting (Upstash Redis)
2. **Graph analysis** — closed-loop, thin-graph, cluster detection → reduce `graph_weight`
3. **Submitter credibility** — unestablished entities = 0.1x receipt weight
4. **Effective evidence dampening** — score pulled toward 50 until weighted evidence ≥ 5.0

### Score confidence states
| Level | Meaning |
|-------|---------|
| `pending` | No receipts |
| `insufficient` | Low effective evidence, mostly unestablished submitters |
| `provisional` | Building history |
| `emerging` | Established, breakdown available |
| `confident` | 20+ receipts, high effective evidence |

### Establishment
An entity is **established** when `is_entity_established()` returns true:
- Effective evidence ≥ 5.0 (sum of weighted receipts, not raw count)
- 3+ unique submitters

Establishment is **historical** — computed over all receipts. Scoring is **current** — computed over a rolling 200-receipt window with time decay. An entity can be established but have a declining score.

## Protocol Status

| Component | Status |
|-----------|--------|
| Trust profile + policy evaluation | ✅ Live |
| Behavioral-first scoring (v2) | ✅ Live |
| Compatibility score (v1) | ✅ Live |
| Effective-evidence Sybil resistance | ✅ Live |
| Receipt immutability (DB triggers) | ✅ Live |
| Canonical JSON hashing | ✅ Live |
| Graph analysis in scoring path | ✅ Live |
| Upstash Redis rate limiting | ✅ Ready (needs env vars) |
| Bilateral attestations | 🔲 Phase 2 |
| Dispute lifecycle | ✅ Live — file, respond, resolve, human appeal |
| Oracle verification | 🔲 Phase 3 |
| Relationship/contextual trust | 🔲 Phase 3 |

## Docs

- [EP Core RFC](docs/EP-CORE-RFC.md) — the 2-page protocol spec
- [EP Vision](docs/EP-VISION.md) — architecture and strategic design
- [ACP Trust Extension](docs/EP-ACP-EXTENSION.md) — how EP attaches to ACP payments
- [AAIF Proposal](docs/AAIF-PROPOSAL-v2.md) — working group proposal

## License

Apache 2.0
