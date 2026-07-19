# @emilia-protocol/fire-drill-mcp

MCP wrapper for the EMILIA **static receipt-declaration scanner**.

It accepts an MCP manifest, OpenAPI document, or tool list and reports which
detected high-risk actions omit a structurally required receipt input. A complete
result means the metadata declares evidence. It does not mean the deployed
handler verifies that evidence or consumes it exactly once.

## Tools

| Tool | Result |
|---|---|
| `fire_drill_scan` | Static declaration score, missing declarations, and remediation guidance. `eg1` is always `not_assessed`. |
| `fire_drill_leaderboard` | A representative **Static Receipt Declaration Index**, not a vulnerability or safety ranking. |

`target_json` is limited to 8 MiB and duplicate JSON member names are refused.
Supplying both `target` and `target_json` is an error.

## Install

```json
{
  "mcpServers": {
    "fire-drill": {
      "command": "npx",
      "args": ["-y", "@emilia-protocol/fire-drill-mcp"]
    }
  }
}
```

## Security boundary

Static metadata cannot establish issuer-key pinning, exact-action binding,
revocation freshness, human presence, fail-closed storage behavior, or replay
consumption. A runtime EG-1 claim requires the separate conformance harness
against the deployed gate, including negative and concurrent-replay cases.

Apache-2.0.
