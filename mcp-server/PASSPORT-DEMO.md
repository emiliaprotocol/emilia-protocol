# EMILIA Passport — the MCP demo that makes an LLM adopt EMILIA on its own

A protected MCP tool (`release_payment`) that **refuses to run without an EMILIA
receipt**. An agent that wants the capability has no path but to obtain one — so
it reaches for EMILIA voluntarily. This is the difference between a guardrail
(imposed on the agent) and a passport (the agent *wants* it — it's the key).

## See it in a terminal (10 seconds)
```bash
node --no-warnings mcp-server/passport-client.mjs
```
A simulated agent talks to the server over real MCP stdio and runs the full loop:
`release_payment` (no receipt) → **402** → `emilia_authorize` → **401 signoff
required** → human approves → receipt → `release_payment` (with receipt) →
**released** → forged receipt → **rejected**.

## Watch *Claude* do it (the screen recording that starts the race)
Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "emilia-passport": {
      "command": "node",
      "args": ["--no-warnings", "/Users/imanschrock/Documents/GitHub.nosync/emilia-protocol/mcp-server/passport-demo.mjs"]
    }
  }
}
```
Restart Claude Desktop, then ask: **"Release a $50,000 payment to acct_9f12."**
Claude will call `release_payment`, hit the 402, read the instruction, call
`emilia_authorize`, discover it needs a human approver, ask *you* to approve, and
only then complete the payment — narrating every step. That recording — an LLM
*choosing* to obtain an accountability receipt — is the asset.

## The three tools
| Tool | Role |
|---|---|
| `release_payment` | Protected capability. No/invalid receipt → `402` with a machine-readable challenge. |
| `emilia_authorize` | Issues a receipt — but only after a **named human approver** is supplied (the real policy engine requires signoff for agent payments). |
| `verify_receipt` | Offline-verify any receipt against the trusted issuer key. |

## What's real vs. demo
- **Real:** the decision logic (`lib/guard-policies.js`), the Ed25519 signing, the
  offline verification (`@emilia-protocol/require-receipt`), the MCP transport.
- **Demo:** one server both issues and verifies (trusts its own key), and the
  payment is simulated. In production, **issuer ≠ verifier**: the counterparty
  pins trusted issuer keys from `/.well-known/ep-keys.json`, and `release_payment`
  is the counterparty's real endpoint. Folding `emilia_authorize` + a
  `requireEmiliaReceipt` guard into the main 34-tool server is the productization.

## Why this is the wedge
Every agent framework is racing to add "tools." The missing primitive is
**which tools an agent is allowed to fire, with proof a human was accountable.**
When one high-value MCP service demands a receipt, every agent touching it must
issue one — and EMILIA is the neutral, formally-verified standard for producing
one a stranger can verify. See [/agent-guard](https://www.emiliaprotocol.ai/agent-guard).
