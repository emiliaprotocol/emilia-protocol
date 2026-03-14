# EMILIA Protocol MCP Server

Trust layer tools for AI agents. Give any MCP-compatible client (Claude, etc.) the ability to check EMILIA Scores before transacting.

## Quick Start

```bash
npx @emilia-protocol/mcp-server
```

## Claude Desktop Config

Add to `~/.claude/claude_desktop_config.json`:

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

`EP_API_KEY` is only required for write operations (submit receipt, register entity). Score lookup and verification are public.

## Tools

| Tool | Auth | Description |
|------|------|-------------|
| `ep_score_lookup` | None | Check any entity's EMILIA Score |
| `ep_submit_receipt` | API Key | Submit a transaction receipt |
| `ep_verify_receipt` | None | Verify receipt against on-chain Merkle root |
| `ep_search_entities` | None | Search entities by name/capability |
| `ep_register_entity` | API Key | Register a new entity |
| `ep_leaderboard` | None | Get top-scored entities |

## Example Usage (in Claude)

> "Check the EMILIA Score for rex-booking-v1 before I book with them."

> "Submit a receipt for my last purchase from entity abc-merchant-v1. Delivery was on time (95), product matched the listing (88), price was honored (100)."

> "Find me a booking agent with an EMILIA Score above 80."

## Self-Hosted

Point `EP_BASE_URL` to your own EP implementation:

```json
{
  "env": {
    "EP_BASE_URL": "https://your-instance.example.com"
  }
}
```

## License

Apache-2.0
