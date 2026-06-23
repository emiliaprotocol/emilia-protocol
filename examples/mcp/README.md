# Canonical MCP examples — "no receipt, no irreversible action"

Three tiny MCP servers, each exposing one dangerous tool that **refuses to run
without an EMILIA authorization receipt**. Each is the same 60-second loop:

> agent calls the tool → **refused** → a named human signs the exact action →
> agent retries with the receipt → **tool runs** → the receipt verifies offline →
> a forged receipt is **rejected**.

Everything is fully offline — the real verifier from
[`@emilia-protocol/require-receipt`](https://www.npmjs.com/package/@emilia-protocol/require-receipt),
no API key, no account, no EP server trusted.

| Example | Dangerous tool | Action bound into the receipt |
|---|---|---|
| [`payment-server.mjs`](payment-server.mjs) | `release_payment` | `payment.release` |
| [`github-admin.mjs`](github-admin.mjs) | `delete_repo` / `change_permissions` | `github.repo.delete` |
| [`prod-deploy.mjs`](prod-deploy.mjs) | `deploy_production` | `deploy.production` |

## Run one

```bash
node examples/mcp/payment-server.mjs          # paced, for screen-recording
FAST=1 node examples/mcp/github-admin.mjs      # no pauses
node examples/mcp/prod-deploy.mjs
```

## Wiring this into a real MCP server

These demos call the verifier directly so they stay self-contained. In a real
server you wrap your existing tool dispatcher with
[`@emilia-protocol/mcp-guard`](https://www.npmjs.com/package/@emilia-protocol/mcp-guard) —
irreversible tools route through consent → Class-A signoff → an emitted
`EP-RECEIPT-v1`, and a presented receipt is verified offline before the tool runs:

```js
import { withMcpGuard } from '@emilia-protocol/mcp-guard';

const guarded = withMcpGuard(handleTool, {
  annotations: {
    release_payment:    { irreversible: true, action: 'payment.release' },
    delete_repo:        { irreversible: true, action: 'github.repo.delete' },
    deploy_production:  { irreversible: true, action: 'deploy.production' },
    search_repos:       { readOnlyHint: true },        // passes straight through
  },
  // adapters: requestConsent, requestClassASignoff, issueReceipt, verifyOpts
});
```

The guard **fails closed**: missing receipt, invalid signature, wrong action
binding, or a stale receipt → refusal, never a silent pass.
