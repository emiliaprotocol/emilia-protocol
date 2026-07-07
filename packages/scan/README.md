<!-- SPDX-License-Identifier: Apache-2.0 -->
# @emilia-protocol/scan

Collapses the integration overhead of putting EMILIA in front of an AI app's
consequential actions. Point it at what your agent can do; it tells you what
should require a named human, and hands you the config and the one wrap to add.

```bash
node cli.mjs --sample                        # see it work on a built-in sample
node cli.mjs ./tools.json --emit manifest.json    # your MCP tool list
node cli.mjs ./openapi.json --emit manifest.json  # your HTTP API surface

# generate drop-in files (dry-run by default; --apply to write, never overwrites)
node codemod.mjs ./tools.json --apply        # MCP -> guard.mjs (withMcpGuard)
node codemod.mjs ./openapi.json --apply      # OpenAPI -> http-guard.mjs (Express 428 receipt gate)
```

`emilia-harden` reads the surface and generates the matching guard: an MCP
`withMcpGuard` wrap for a tool list, or an Express middleware (`requireEmiliaReceipt`,
`428 Receipt-Required` per consequential route) for an OpenAPI spec.

It does exactly three things, and never more:

1. **Scan** the actions it can see (MCP tool list, OpenAPI spec, or a plain list).
2. **Classify** each one against the same risk packs the EMILIA Gate ships:
   money movement, bank-detail changes, production deploys, IAM grants, data
   export, record deletion, decision overrides. Each match carries an assurance
   tier (`class_a` or `quorum`) and the fields the receipt must bind.
3. **Report** — a proposed `agent-action-control` manifest, the wrap to add at
   your tool-call choke point, and an honest coverage report.

## What it will not do

- **It will not decide your risk model.** Which actions are consequential is a
  semantic judgment only you can make. It *proposes*; you confirm. Anything it
  cannot map to a known category but that mutates state is defaulted to
  **fail-closed** (require a receipt) and flagged for your review, never waved
  through.
- **It will not edit your code.** It emits the manifest and the wrap; you apply
  them after review.
- **It will never tell you that you are "protected."** It reports what it could
  not see (runtime-registered tools, risk that depends on argument values, and
  whether your organization will actually fail-closed on a denial — which is a
  decision, not a setting). Nothing is enforced until you add the wrap and pin
  your keys.

That honesty is the point. A tool that claimed to make AI safe by installing it
would be lying; risk is specific to your application, and only you know it. This
makes declaring it cheap, and keeps you in control of the declaration.

Part of [EMILIA Protocol](https://www.emiliaprotocol.ai). Apache-2.0.
