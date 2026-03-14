# @emilia-protocol/mcp-server

Trust evaluation tools for AI agents via the Model Context Protocol.

## What this does

Gives any MCP-compatible agent (Claude, ChatGPT, Gemini, etc.) access to EP trust profiles and policy evaluation. Agents can check counterparty trust before transacting — not just a score, but a full behavioral profile evaluated against configurable policies.

## Setup

```json
{
  "mcpServers": {
    "emilia": {
      "command": "npx",
      "args": ["@emilia-protocol/mcp-server"],
      "env": {
        "EP_BASE_URL": "https://emiliaprotocol.ai",
        "EP_API_KEY": "ep_live_your_key_here"
      }
    }
  }
}
```

`EP_API_KEY` is only needed for write operations (submitting receipts, registering entities).

## Primary Tools

### `ep_trust_profile`
Get an entity's full trust profile — the canonical way to check trust.

Returns: behavioral rates (completion, retry, abandon, dispute), signal breakdowns (delivery, product, price, returns), consistency, anomaly alerts, current confidence, historical establishment, and a compatibility score.

```
"Check the trust profile for merchant-xyz before I buy from them"
```

### `ep_trust_evaluate`
Evaluate an entity against a trust policy. Returns pass/fail with specific failure reasons.

Built-in policies: `strict` (high-value), `standard` (normal), `permissive` (low-risk), `discovery` (allow unscored).

Accepts optional context: `{ "category": "furniture", "geo": "US-CA" }` for context-aware evaluation.

```
"Does merchant-xyz pass the strict trust policy for furniture in California?"
```

### `ep_submit_receipt`
Submit a transaction receipt after completing a purchase or service. Requires `transaction_ref` and at least one signal or `agent_behavior`.

```
"Submit a receipt for my purchase from merchant-xyz — delivery was on time, product matched listing"
```

## Secondary Tools

| Tool | Description |
|------|-------------|
| `ep_search_entities` | Search for entities by name, capability, or category |
| `ep_verify_receipt` | Verify a receipt against the Merkle root |
| `ep_register_entity` | Register a new entity (requires API key) |
| `ep_leaderboard` | Get top entities by compatibility score |
| `ep_install_preflight` | **EP-SX**: Should I install this plugin/app/package? Allow/review/deny with reasons. |
| `ep_score_lookup` | Legacy: compatibility score only. Use `ep_trust_profile` instead. |

## What makes EP different

- **Trust profiles, not scores** — behavioral rates, signal breakdowns, anomaly alerts
- **Trust policies, not thresholds** — structured decision frameworks with pass/fail/reasons
- **Context-aware** — evaluation can filter by category, geo, value band
- **Sybil-resistant** — 4-layer defense, effective-evidence dampening
- **Due process** — trust must never be more powerful than appeal

## Links

- [emiliaprotocol.ai](https://emiliaprotocol.ai)
- [GitHub](https://github.com/emiliaprotocol/emilia-protocol)
- [EP Core RFC v1.1](https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/EP-CORE-RFC.md)

Apache 2.0
