# Canonical MCP examples — "no receipt, no irreversible action"

[![Receipt Required: RR-1](https://img.shields.io/badge/Receipt%20Required-RR--1-22c55e)](../../docs/RECEIPT-REQUIRED-CONFORMANCE.md)

These servers earn the **RR-1** badge in CI — the conformance harness
(`tests/receipt-required-conformance.test.js`) re-proves it on every push, so
the claim can't go stale. See [RECEIPT-REQUIRED-CONFORMANCE.md](../../docs/RECEIPT-REQUIRED-CONFORMANCE.md).


Three tiny MCP servers, each exposing one dangerous tool that **refuses to run
without an EMILIA authorization receipt**. The gate is manifest-driven: it reads
[`public/.well-known/agent-actions.json`](../../public/.well-known/agent-actions.json)
to learn which tools require proof and what assurance class they need.

Each server runs the same 60-second loop:

> agent calls the tool -> **428 Receipt Required** -> a named human signs the exact
> action -> agent retries with the receipt -> **tool runs** -> the same receipt is
> **replay-refused** -> a forged receipt is **rejected**.

Everything is fully offline — the real verifier from
[`@emilia-protocol/require-receipt`](https://www.npmjs.com/package/@emilia-protocol/require-receipt),
no API key, no account, no EP server trusted.

| Example | Dangerous tool | Action bound into the receipt |
|---|---|---|
| [`payment-server.mjs`](payment-server.mjs) | `release_payment` | `payment.release` |
| [`github-admin.mjs`](github-admin.mjs) | `delete_repo` / `change_permissions` | `github.repo.delete` |
| [`prod-deploy.mjs`](prod-deploy.mjs) | `deploy_production` | `deploy.production` |
| [`supabase-admin.mjs`](supabase-admin.mjs) | `run_destructive_sql` | `database.destructive_sql` |
| [`linear-export.mjs`](linear-export.mjs) | `export_customer_data` | `saas.data_export` |

## Run one

```bash
node examples/mcp/payment-server.mjs          # paced, for screen-recording
FAST=1 node examples/mcp/github-admin.mjs      # no pauses
node examples/mcp/prod-deploy.mjs
node examples/mcp/supabase-admin.mjs           # DROP TABLE invoices — blocked
node examples/mcp/linear-export.mjs            # bulk customer-data export — blocked
```

## Wiring this into a real MCP server

These demos call the verifier directly so they stay self-contained. The
implementation guide is here:
[`docs/guides/RECEIPT-REQUIRED-MCP.md`](../../docs/guides/RECEIPT-REQUIRED-MCP.md).

In a real server you wrap your existing tool dispatcher with
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
