# @emilia-protocol/fire-drill — the Agent Action Firewall Test

> If your agent can take an irreversible action without a receipt, you do not have control.
> You have hope.

Scan any **MCP server manifest**, **OpenAPI spec**, or **tool list** for dangerous actions an AI
agent can take **without an accountable human receipt** — and find out before you're the screenshot:
*"our agent deleted prod and nobody can prove who approved it."*

```bash
npx @emilia-protocol/fire-drill ./mcp-manifest.json
# or pipe it:
cat openapi.json | npx @emilia-protocol/fire-drill
```

```
====================================================================
  Agent Action Firewall Test — @emilia-protocol/fire-drill
====================================================================
  Target: mcp   Operations: 3   Dangerous: 2   Gated: 0
  Agent Action Firewall score: 0/100

  ✗ FAIL: `delete_customer_data` can execute without an accountable human receipt (Data destruction).
      Fix: Add EMILIA Gate — @emilia-protocol/gate/adapters/supabase (or gateMcpTool) requiring a class_a receipt.
      Earn: EG-1 Enforced
  ✗ FAIL: `release_payment` can execute without an accountable human receipt (Money movement).
      Fix: Add EMILIA Gate — @emilia-protocol/gate/adapters/stripe (or gateMcpTool) requiring a class_a receipt.
      Earn: EG-1 Enforced

  EG-1: FAIL — 2 dangerous operation(s) can run without a receipt.
```

## What it checks

It classifies every operation into the high-risk families and flags any dangerous one that lacks a
receipt requirement:

- **Money movement** — pay, payout, refund, transfer, wire, payroll
- **Data destruction** — delete, drop, truncate, purge (and any HTTP `DELETE`)
- **Production deploy** — deploy, release, terraform/apply, migrate
- **Permission / admin change** — IAM, role, grant, policy, RBAC
- **Bulk data export** — export, dump, download, backup
- **Regulated decision override** — override/approve a claim, benefit, credit, or decision

## Output

- **Agent Action Firewall score** — % of dangerous operations that require a receipt.
- **EG-1: pass/fail** — `pass` only if *no* dangerous operation can run unreceipted.
- **`--json`** — machine-readable report (exit non-zero on fail → drop into CI).
- **`--fix`** — print the EMILIA Gate patch snippet for each failure.

## Honest scope

This is a **static** assessment from the manifest/spec — like SSL Labs or `npm audit`. It reveals the
gap. To *verify the fix at runtime*, run **EG-1 conformance** from
[`@emilia-protocol/gate`](../gate) (`node eg1.mjs`) against your gated integration and earn the
**EG-1 Enforced** badge. Zero dependencies; Apache-2.0.
