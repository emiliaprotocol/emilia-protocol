# EMILIA Protocol MCP Server

Trust decisions for AI agents — 29 tools covering trust profiles, policy evaluation, software install preflight, dispute filing, appeals, delegation chains, identity lineage, and pre-action commits.

## Install in Claude Desktop

Config file: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "emilia-protocol": {
      "command": "npx",
      "args": ["-y", "@emilia-protocol/mcp-server"],
      "env": {
        "EP_BASE_URL": "https://emiliaprotocol.ai",
        "EP_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

## Install in Cursor

Config file: `~/.cursor/mcp.json` (same format as above)

```json
{
  "mcpServers": {
    "emilia-protocol": {
      "command": "npx",
      "args": ["-y", "@emilia-protocol/mcp-server"],
      "env": {
        "EP_BASE_URL": "https://emiliaprotocol.ai",
        "EP_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

## Run Directly

```bash
npx @emilia-protocol/mcp-server
```

With an API key:

```bash
EP_API_KEY=ep_live_your_key_here npx @emilia-protocol/mcp-server
```

## Available Tools (29 total)

| Tool | Description | Auth Required |
|------|-------------|:---:|
| `ep_trust_profile` | Full trust profile — the canonical read surface | No |
| `ep_trust_evaluate` | Policy evaluation with Trust Decision (allow/review/deny) and failure reasons | No |
| `ep_trust_gate` | Pre-action trust check — call before irreversible actions | No |
| `ep_submit_receipt` | Record a behavioral outcome to the EP ledger | Yes |
| `ep_batch_submit` | Submit up to 50 receipts atomically | Yes |
| `ep_domain_score` | Per-domain trust scores (financial, code, comms, etc.) | No |
| `ep_search_entities` | Find entities by name, type, or capability | No |
| `ep_register_entity` | Register a new entity — returns first API key | No |
| `ep_leaderboard` | Top entities ranked by trust confidence | No |
| `ep_verify_receipt` | Verify a receipt against its Merkle proof | No |
| `ep_install_preflight` | Software trust check before installing plugins/packages | No |
| `ep_dispute_file` | Challenge an inaccurate or fraudulent receipt | Yes |
| `ep_dispute_status` | Check the status of a dispute | No |
| `ep_appeal_dispute` | Appeal a dispute resolution | Yes |
| `ep_report_trust_issue` | Human-accessible trust report (no auth required) | No |
| `ep_create_delegation` | Authorize an agent to act on a principal's behalf | Yes |
| `ep_verify_delegation` | Check that a delegation is valid for a specific action | No |
| `ep_principal_lookup` | Look up the enduring principal behind entities | No |
| `ep_lineage` | Entity lineage, predecessors, continuity, whitewashing flags | No |
| `ep_list_policies` | List all available trust policies | No |
| `ep_configure_auto_receipt` | Enable automatic behavioral receipt generation for this session | No |
| `ep_generate_zk_proof` | Generate a zero-knowledge proof for a score claim | No |
| `ep_verify_zk_proof` | Verify a zero-knowledge proof | No |
| `ep_delegation_judgment` | Score a principal's delegation history (excellent / good / fair / poor) | No |
| `ep_issue_commit` | Issue a signed EP Commit before a high-stakes action | Yes |
| `ep_verify_commit` | Verify a commit's signature, status, and validity | No |
| `ep_get_commit_status` | Get current state of a commit | Yes |
| `ep_revoke_commit` | Revoke an active commit | Yes |
| `ep_bind_receipt_to_commit` | Bind a post-action receipt to a commit | Yes |

## Environment Variables

| Variable | Description | Required |
|----------|-------------|:--------:|
| `EP_BASE_URL` | EP API base URL (default: `https://emiliaprotocol.ai`) | No |
| `EP_API_KEY` | API key for authenticated operations — required for submitting receipts, filing disputes, creating delegations, filing appeals | For writes |
| `EP_AUTO_RECEIPT_OPT_IN` | Set to `"true"` to enable automatic receipt generation at startup | No |
| `EP_AUTO_RECEIPT_ENTITY_ID` | Entity ID to attribute auto-generated receipts to | No |

Read-only operations — trust profiles, policy evaluation, trust gates, install preflight, search, leaderboard, dispute status, lineage — work without an API key.

## Get an API Key

Registration takes one tool call. No dashboard, no email verification:

```
ep_register_entity(
  entity_id="your-agent-name",
  display_name="Your Agent",
  entity_type="agent",
  description="What your entity does"
)
```

The response includes your first API key (`ep_live_...`). Save it immediately — EP does not store it in recoverable form.

## Quick Examples

### 1. Check trust before transacting

```
"Is acme-logistics trustworthy for a $5,000 freight booking?"
```

Calls `ep_trust_gate` then `ep_trust_profile` automatically.

### 2. Record a completed task

```
ep_submit_receipt(
  entity_id="freight-agent-7",
  transaction_ref="FRT-20241218-001",
  transaction_type="delivery",
  agent_behavior="completed",
  delivery_accuracy=96,
  price_integrity=100
)
```

### 3. Check if a plugin is safe to install

```
ep_install_preflight(
  entity_id="mcp_server:some-org/data-extractor",
  policy="mcp_server_safe_v1",
  context={
    "host": "mcp",
    "data_sensitivity": "private_workspace",
    "execution_mode": "persistent"
  }
)
```

## Links

- Homepage: [emiliaprotocol.ai](https://emiliaprotocol.ai)
- GitHub: [github.com/emiliaprotocol/emilia-protocol](https://github.com/emiliaprotocol/emilia-protocol)
- npm: [@emilia-protocol/mcp-server](https://www.npmjs.com/package/@emilia-protocol/mcp-server)
- Issues: [github.com/emiliaprotocol/emilia-protocol/issues](https://github.com/emiliaprotocol/emilia-protocol/issues)
- License: Apache-2.0
