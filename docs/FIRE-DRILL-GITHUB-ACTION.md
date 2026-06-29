# EMILIA Fire Drill — GitHub Action

Make EG-1 *stick*. The Action runs the Agent Action Firewall Test in CI on every
push/PR, so a dangerous tool that can run without an accountable human receipt
**fails the build** — and a passing repo keeps its `EG-1 Enforced` badge honest.

## Usage

```yaml
# .github/workflows/fire-drill.yml
name: Agent Action Firewall
on: [push, pull_request]
jobs:
  fire-drill:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - uses: emiliaprotocol/emilia-protocol/.github/actions/fire-drill@main
        with:
          manifest: ./mcp-manifest.json   # MCP manifest, OpenAPI spec, or tool list (JSON)
          fail-on: fail                   # 'fail' (default) blocks the build; 'warn' only reports
```

`manifest` may be your MCP server's `list_tools` output, an OpenAPI spec, or a
tool array — the same inputs `npx @emilia-protocol/fire-drill` accepts.

## What it does

- Runs `npx @emilia-protocol/fire-drill <manifest> --json`.
- Sets outputs `score` (0-100) and `eg1` (`pass`/`fail`).
- With `fail-on: fail` (default), the job fails when any dangerous operation can
  run without a receipt — so a regression that exposes `delete_*` / `pay_*` /
  `deploy_*` without gating can't merge.
- Writes a one-line summary to the GitHub step summary.

## Wire the badge to the result

Once green, embed the badge in your README:

```md
[![EG-1 Enforced](https://www.emiliaprotocol.ai/badge/eg1?eg1=pass)](https://www.emiliaprotocol.ai/fire-drill)
```

## Fixing failures

The fire drill names the unguarded operations and the fix. To gate an MCP tool:

```js
import { createGate } from '@emilia-protocol/gate';
import { gateMcpTool } from '@emilia-protocol/gate/mcp';

const gate = createGate({ manifest, trustedKeys: [process.env.EMILIA_ISSUER] });
server.tool('release_payment', gateMcpTool(gate, { tool: 'release_payment' }, handler));
```

Or for a system of record, use a ready adapter:
`@emilia-protocol/gate/adapters/{github,stripe,supabase,aws,k8s,terraform,gcp,vercel,cloudflare,linear,jira,salesforce}`.

`npx @emilia-protocol/fire-drill <manifest> --pr` prints a ready pull-request body.
