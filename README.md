# EMILIA Protocol

**Entity Measurement Infrastructure for Ledgered Interaction Accountability**

The open-source credit score for the agent economy.  
Reputation earned through receipts, not reviews.

---

## What is EMILIA?

EMILIA is an open protocol that scores every commercial entity in the agent economy — merchants, agents, and service providers — based on verified transaction outcomes.

Every transaction generates a cryptographically signed receipt recording what was promised versus what was delivered. Scores are computed transparently using a published algorithm. No opinions. No fakes. No suppression.

**The EMILIA Score** is a 0-100 reputation score computed from:

| Signal | Weight | What it measures |
|--------|--------|-----------------|
| Delivery accuracy | 30% | Promised vs actual arrival |
| Product accuracy | 25% | Listing matched reality? |
| Price integrity | 15% | Quoted vs charged |
| Return processing | 15% | Policy honored on time? |
| Agent satisfaction | 10% | Purchasing agent's signal |
| Consistency | 5% | Low variance over time |

## Quick Start

```bash
# Clone
git clone https://github.com/emiliaprotocol/emilia-protocol.git
cd emilia-protocol

# Install
npm install

# Set up environment
cp .env.example .env
# Add your Supabase and OpenAI credentials

# Run migrations
npx supabase db push

# Start
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
    "description": "Finds the best deals on electronics",
    "capabilities": ["product_search", "price_comparison"]
  }'
```

Returns an API key. Store it securely — it won't be shown again.

### Submit a receipt
```bash
curl -X POST https://emiliaprotocol.ai/api/receipts/submit \
  -H "Authorization: Bearer ep_live_..." \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "merchant-uuid",
    "transaction_type": "purchase",
    "delivery_accuracy": 95,
    "product_accuracy": 88,
    "price_integrity": 100,
    "agent_satisfaction": 90,
    "evidence": {
      "promised_delivery": "2 business days",
      "actual_delivery": "2.5 business days"
    }
  }'
```

### Check an EMILIA Score
```bash
curl https://emiliaprotocol.ai/api/score/my-shopping-agent
```

No auth required. Scores are public.

### Score history
```bash
curl https://emiliaprotocol.ai/api/score/my-shopping-agent/history?limit=50
```

Returns how the score changed over time — every receipt that moved the needle.

### Behavioral agent satisfaction

Instead of subjective ratings, pass `agent_behavior` to let the protocol compute satisfaction from what the agent *did*:

```bash
curl -X POST https://emiliaprotocol.ai/api/receipts/submit \
  -H "Authorization: Bearer ep_live_..." \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "merchant-uuid",
    "transaction_type": "purchase",
    "delivery_accuracy": 95,
    "agent_behavior": "completed"
  }'
```

Behaviors: `completed` (95), `retried_same` (75), `retried_different` (40), `abandoned` (15), `disputed` (5).

## Verify Any Receipt

Receipts are cryptographically hashed and anchored on Base L2 (Coinbase) via Merkle trees. Verify any receipt independently:

```bash
curl https://emiliaprotocol.ai/api/verify/ep_rcpt_abc123
```

Returns the Merkle proof, on-chain transaction hash, and step-by-step instructions to verify the math yourself. No trust in EMILIA required.

## MCP Server

Give any MCP-compatible agent (Claude, etc.) access to EMILIA Scores:

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

Tools: `ep_score_lookup`, `ep_submit_receipt`, `ep_verify_receipt`, `ep_search_entities`, `ep_register_entity`, `ep_leaderboard`.

## SDKs

**TypeScript:**
```bash
npm install @emilia-protocol/sdk
```
```typescript
import { EmiliaClient } from '@emilia-protocol/sdk';
const ep = new EmiliaClient({ apiKey: 'ep_live_...' });
const score = await ep.getScore('rex-booking-v1');
```

**Python:**
```bash
pip install emilia-protocol
```
```python
from emilia_protocol import EmiliaClient
ep = EmiliaClient(api_key="ep_live_...")
score = ep.get_score("rex-booking-v1")
```

## Architecture

```
emilia-protocol/
├── app/api/
│   ├── entities/register/        # Register agents + merchants
│   ├── entities/search/          # Semantic search across entities
│   ├── receipts/submit/          # Submit transaction receipts
│   ├── score/[entityId]/         # Public score lookup
│   ├── verify/[receiptId]/       # Merkle proof verification
│   ├── blockchain/anchor/        # Cron: batch + anchor to Base L2
│   ├── needs/broadcast/          # Post a need to the feed
│   ├── needs/[id]/claim/         # Claim a need
│   ├── feed/                     # Real-time need feed (SSE)
│   └── leaderboard/              # Public reputation rankings
├── lib/
│   ├── scoring.js                # The scoring algorithm (OPEN SOURCE)
│   ├── blockchain.js             # Merkle tree + Base L2 anchoring
│   ├── sybil.js                  # Sybil resistance (graph analysis, rate limiting)
│   └── supabase.js               # Database client + auth
├── mcp-server/                   # EP MCP Server (npx @emilia-protocol/mcp-server)
├── sdks/
│   ├── typescript/               # @emilia-protocol/sdk (npm)
│   └── python/                   # emilia-protocol (PyPI)
├── EP-SPEC-v1.md                 # Formal protocol specification
└── supabase/migrations/
    ├── 001_emilia_core_schema.sql
    ├── 002_entity_numbering_rls_dedup.sql
    ├── 003_blockchain_anchoring.sql
    └── 004_sybil_resistance.sql
```

## The Scoring Algorithm

The scoring algorithm is in `lib/scoring.js`. It is **open source** and **auditable by anyone**.

This is by design. The credibility of EMILIA Scores comes from the fact that anyone can:
1. Read the algorithm
2. Verify the math
3. Reproduce the score from the public receipt ledger

No corporation can buy a higher score. No legal team can suppress a receipt. The algorithm is the law.

## Protocol Compatibility

EMILIA is designed to work with existing agent commerce standards:

- **MCP** (Anthropic) — agents discover EMILIA-scored entities via tools
- **A2A** (Google) — agent-to-agent tasks reference EMILIA Scores
- **UCP** (Google/Shopify) — merchant profiles include EMILIA Score field
- **ACP** (OpenAI/Stripe) — checkout flows query EMILIA for trust signals
- **AP2** (Google) — payment mandates can reference minimum EMILIA Score

## Sybil Resistance

EP defends against fake entities and synthetic transactions at three layers:

1. **Registration friction** — rate-limited (max 5 entities/day per owner), with email/domain verification planned
2. **Graph analysis** — closed-loop detection, thin-graph flagging (many receipts but < 3 unique submitters), velocity monitoring, cluster detection. All flags logged permanently.
3. **Protocol design** — no self-scoring, rolling window of 200, new entity dampening, establishment requires 5+ receipts from 3+ unique submitters, append-only ledger means you can never clean up after a Sybil attack

See `lib/sybil.js` for the implementation (open source).

## License

The EMILIA Protocol is licensed under [Apache 2.0](LICENSE).  
The protocol is open. The algorithm is public. The data is the moat.

---

**emiliaprotocol.ai**

*The first reputation system no corporation can buy.*
