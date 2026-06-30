# @emilia-protocol/fire-drill-mcp

[![npm version](https://img.shields.io/npm/v/@emilia-protocol/fire-drill-mcp)](https://www.npmjs.com/package/@emilia-protocol/fire-drill-mcp)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![MCP](https://img.shields.io/badge/protocol-MCP-5a5aff)](https://modelcontextprotocol.io)

**The Agent Action Firewall Test — as an MCP server.** A directory full of MCP servers, plus one whose job is to audit the others: point it at any MCP manifest, OpenAPI spec, or tool list and it tells you which dangerous actions an agent can take **without an accountable human receipt**.

> If your agent can take an irreversible action without a receipt, you do not have control. You have hope.

---

## What it does

`fire_drill_scan` flags every dangerous operation — money movement, data destruction, production deploy, permission change, bulk export, regulated override — that can run with no human in the loop, and returns an **Agent Action Firewall score (0–100)**, **EG-1 pass/fail**, the failing operations, and the fix.

It's a **static** assessment of a documented tool surface — not a live deployment scan and not a vulnerability report. The scoring logic is the exact same zero-dependency engine behind `npx @emilia-protocol/fire-drill` and the web tool at [emiliaprotocol.ai/fire-drill](https://www.emiliaprotocol.ai/fire-drill).

## Tools

| Tool | What it returns |
|---|---|
| `fire_drill_scan` | Score one target (`target` object, or `target_json` string): an MCP manifest, OpenAPI spec, or `{ tools: [...] }`. Auto-detects the shape. |
| `fire_drill_leaderboard` | The **Agent Action Safety Index** — a representative corpus of MCP servers pre-scored, worst first. |

## Install

```jsonc
// claude_desktop_config.json / any MCP client
{
  "mcpServers": {
    "fire-drill": {
      "command": "npx",
      "args": ["-y", "@emilia-protocol/fire-drill-mcp"]
    }
  }
}
```

Then ask your agent: *"Run fire_drill_scan on this MCP manifest"* and paste a server's `tools` list — or *"Show me the agent action safety leaderboard."*

## The fix

A failing score means an agent can act irreversibly with nobody accountable. Close it with [**EMILIA Gate**](https://www.emiliaprotocol.ai/gate) — deny-by-default enforcement that runs an action only with a valid, in-scope, non-replayed authorization receipt (proof a named human approved that exact action) — then earn **EG-1**.

- Protocol & receipts: [emiliaprotocol.ai](https://www.emiliaprotocol.ai) · IETF I-D `draft-schrock-ep-authorization-receipts`
- The guard server: [`@emilia-protocol/mcp-server`](https://www.npmjs.com/package/@emilia-protocol/mcp-server)

Apache-2.0.
