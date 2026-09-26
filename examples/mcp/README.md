# Canonical MCP examples — "no receipt, no irreversible action"

[![Receipt Required: RR-1](https://img.shields.io/badge/Receipt%20Required-RR--1-22c55e)](../../docs/RECEIPT-REQUIRED-CONFORMANCE.md)

These servers earn the **RR-1** badge in CI — the conformance harness
(`tests/receipt-required-conformance.test.ts`) re-proves it on every push, so
the claim can't go stale. See [RECEIPT-REQUIRED-CONFORMANCE.md](../../docs/RECEIPT-REQUIRED-CONFORMANCE.md).


Five offline MCP dispatcher examples, each exposing one dangerous tool that **refuses to run
without an EMILIA authorization receipt**. The gate is manifest-driven: it reads
[`public/.well-known/agent-actions.json`](../../public/.well-known/agent-actions.json)
to learn which tools require proof and what assurance class they need.

Each server runs the same 60-second loop:

> agent calls the tool -> **428 Receipt Required** -> script creates a simulated
> signoff -> agent retries with the receipt -> **mock tool runs** -> the same receipt is
> **replay-refused** -> a forged receipt is **rejected**.

Everything is fully offline, using the real verifier from
[`@emilia-protocol/require-receipt`](https://www.npmjs.com/package/@emilia-protocol/require-receipt),
process-local generated signing keys, simulated WebAuthn-shaped assertions and
an in-memory consumption store. No funds move. No bank is connected and no real
human or device ceremony is performed. Receipt verification uses the demo's pinned
approver keys; the outer signing key is accepted inline for this demo only.

| Example | Dangerous tool | Action bound into the receipt |
|---|---|---|
| [`payment-server.mjs`](payment-server.mjs) | `release_payment` | `payment.release:sha256:<canonical payment digest>` |
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

## Payment binding and limits

The payment example accepts exactly these four fields:

```js
{
  amount_minor: 8200000, // $82,000.00 in this USD fixture
  currency: 'USD',
  vendor: 'Acme Industrial LLC',
  destination: 'acct_new_4471'
}
```

`amount_minor` must be a positive safe integer. `currency` must be an uppercase
three-letter token; the demo does not validate a currency registry or its minor
unit scale. Vendor and destination must be nonempty strings of at most 256
characters, without surrounding whitespace or control characters. Missing,
unknown, malformed, accessor-backed and non-JSON input is refused.

The shared `snapshotToolArguments` and `bindExecutorAction` helpers bind all
four fields using canonical JSON and SHA-256. The mock executor receives the
same frozen snapshot. Changes detected after receipt reservation but before
executor entry are refused; that receipt stays consumed. Changes to the
caller's object after entry cannot alter the executor's snapshot.

The runnable demo refuses a changed amount, currency, vendor and destination,
each with a fresh unused receipt, then executes the approved mock once and
refuses replay. These checks are exercised in
[`tests/mcp-payment-binding.test.ts`](../../tests/mcp-payment-binding.test.ts).
The other examples bind their identifying target only; this payment schema
does not extend their material-action coverage.

Replay protection here lasts within one server instance and is keyed by receipt
ID. This demo has no stable business operation ID, durable shared consumption
store or provider idempotency/reconciliation integration. A separately issued
receipt is not deduplicated as the same payment. A production adapter must bind
its own complete provider input, establish issuer and approver trust, and enforce
durable admission and operation identity at every covered executor path.
This example does not establish payee identity, bank-detail correctness, fraud
absence, an external payment effect or production readiness.

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
