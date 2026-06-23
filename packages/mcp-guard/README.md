# @emilia-protocol/mcp-guard

**EP-MCP middleware — accountability for irreversible MCP tool calls.**
Reference implementation, **experimental**.

It wraps the function your MCP server already uses to dispatch a tool call. If a
tool call is flagged **irreversible** (by policy or annotation), it routes
through **consent → Class-A signoff → an emitted EP-RECEIPT-v1 → an appended
provenance entry**, then runs the tool. Everything else **passes straight
through** with no added overhead.

It also ships the **demand hook**: a helper that enforces *"no irreversible tool
call without a valid receipt"* and returns a clear **402-style refusal object** —
so a well-behaved agent knows exactly what to bring and retries on its own.

```bash
npm install @emilia-protocol/mcp-guard @emilia-protocol/require-receipt
```

## What this is — and what it is NOT

- **Reference implementation.** It exercises the control flow, the 402 demand
  hook, the EP-RECEIPT-v1 emission *shape*, and an append-only provenance ledger
  — all in-process with pluggable adapters. Status: experimental.
- **The EP Core is FROZEN.** This package **never** mints, mutates,
  re-canonicalizes, or re-signs an `EP-RECEIPT-v1`. Issuance and consent/signoff
  are delegated to **caller-supplied adapters** (an EP host,
  [`@emilia-protocol/issue`](https://www.npmjs.com/package/@emilia-protocol/issue),
  a WebAuthn authenticator).
- **Composition, not ownership.** The "provenance entry" is an **additive
  composite** that *bundles references* to existing v1 receipts (by `receipt_id`
  + content hash). It is **not** a new wire format for receipts and changes
  nothing about Core. The full chained object (`EP-PROVENANCE-CHAIN-v1`) is a
  **spec proposal governed by a PIP** — this package only anchors the minimal
  in-process ledger.
- **No new trust.** Verification reuses
  [`@emilia-protocol/require-receipt`](https://www.npmjs.com/package/@emilia-protocol/require-receipt)
  (offline Ed25519, pinned issuer keys). Re-verifying provenance = re-verifying
  each linked v1 receipt + checking the append-only hash chain.
- **Fails closed.** Missing receipt, broken signature, wrong action binding,
  stale receipt, tampered ledger entry → **refusal**, never silent pass.
- **Agent identity is a CLAIM** (scoped, attestable) — this package does not
  assert EP proves strong agent identity. **Liability attestation** names an
  accountable owner; it is *evidence, not a legal determination*.

## The flow

```
MCP tool call ── classify ─┬─ reversible / read-only ─────────────────► run tool
                           │
                           └─ irreversible
                               ├─ receipt presented ─► demand hook (offline verify)
                               │                         ├─ invalid ─► 402 refusal (STOP)
                               │                         └─ valid ──► append provenance ─► run
                               └─ no receipt ─► consent ─► Class-A signoff ─► issueReceipt
                                                  │           │                  │
                                                  └─ deny ─► 402 refusal (STOP) ◄┘ (any stage)
                                                                                  │
                                       self-verify issued EP-RECEIPT-v1 (fail closed)
                                                                                  │
                                                          append provenance ─► run tool
```

## Wiring it into an MCP server's tool dispatch

`withMcpGuard` wraps the dispatcher the server already calls. It does **not**
touch transport, schemas, or the tool list.

```js
import { withMcpGuard, ProvenanceLedger } from '@emilia-protocol/mcp-guard';

// `handleTool(name, args, extra)` is your server's existing dispatcher.
const guardedHandleTool = withMcpGuard(handleTool, {
  // 1) Which tools are irreversible? (annotation > policy > default)
  annotations: {
    release_payment: { irreversible: true, action: 'payment.release' },
    delete_record:   { irreversible: true, action: 'record.delete' },
    search_entities: { readOnlyHint: true },           // passes through
  },
  policy: (name) => /^(release|delete|wire|transfer)_/.test(name),
  defaultIrreversible: false,

  // 2) Demand hook config (offline verify; pin the issuers you trust).
  verifyOpts: {
    trustedKeys: [process.env.EMILIA_ISSUER_PUBKEY],   // base64url SPKI
    maxAgeSec: 900,
    allowedOutcomes: ['allow', 'allow_with_signoff'],
  },

  // 3) Adapters — REQUIRED to exercise Path B (mint a new receipt).
  //    Without them the middleware fails closed at the first missing stage.
  requestConsent:       async (ctx) => ({ approved: await askUser(ctx) }),
  requestClassASignoff: async (ctx) => ({ approved: await webauthnAssert(ctx) }),
  issueReceipt:         async (ctx) => ({ receipt: await epHost.mint(ctx) }), // EP-RECEIPT-v1
});

// Then dispatch through the guarded function instead of the raw one.
const result = await guardedHandleTool(name, args, { _meta: request.params._meta });
```

> **Do not edit the shared mcp-server in this repo to adopt this.** The exact,
> minimal change is a one-line swap at the dispatch site
> (`handleTool(...)` → `guardedHandleTool(...)`) plus constructing the wrapper
> once at startup. See **"Exact wiring"** at the bottom.

## Live v1 enforcement with the SDK

If you want the system-of-record guarantee, use `withMcpReceiptGuard` with
`@emilia-protocol/sdk`. The MCP wrapper classifies the tool call; the SDK drives
the live v1 loop: create receipt → request signoff if required → consume before
the write → run the tool → emit execution attestation.

```js
import { EPClient } from '@emilia-protocol/sdk';
import { withMcpReceiptGuard } from '@emilia-protocol/mcp-guard';

const ep = new EPClient({
  apiKey: process.env.EP_API_KEY,
  baseUrl: process.env.EP_BASE_URL,
});

const guardedHandleTool = withMcpReceiptGuard(handleTool, {
  client: ep,
  executingSystem: 'acme-mcp-server',
  annotations: {
    release_payment: {
      irreversible: true,
      actionType: 'large_payment_release',
      targetResourceId: (args) => args.payment_id,
      afterState: (args) => ({ payment_id: args.payment_id, amount: args.amount, currency: args.currency }),
      amount: (args) => args.amount,
      currency: (args) => args.currency,
      approverId: 'ap_controller_jane',
      onSignoffRequired: async ({ signoff }) => waitForApprovedSignoff(signoff?.signoff_id),
    },
    search_payments: { readOnlyHint: true },
  },
});

// One-line dispatch swap:
const result = await guardedHandleTool(name, args, { _meta: request.params._meta });
```

If consume fails, `handleTool` is never called. If signoff is required and
`onSignoffRequired` is omitted, the SDK fails closed and the irreversible tool
does not run.

## The demand hook on its own

Use it anywhere you can read a tool call. Returns a verified result or a
ready-to-return 402-style refusal **object** (not an HTTP response), so it drops
into any MCP tool-dispatch path.

```js
import { demandReceipt } from '@emilia-protocol/mcp-guard';

const d = demandReceipt({
  action: 'payment.release',
  args,                                  // carries __ep.receipt / __ep.receipt_b64 / emilia_receipt
  meta: request.params._meta,            // or x-emilia-receipt header passthrough
  verifyOpts: { trustedKeys: [issuerPubKey], maxAgeSec: 900 },
});

if (!d.ok) return d.refusal;             // FAIL CLOSED — hand this back to the agent
// d.verified = { ok, outcome, subject, receipt_id, signer }
```

The refusal object (402-style, problem-details shape):

```json
{
  "ep_refused": true,
  "status": 402,
  "code": "emilia_receipt_required",
  "title": "EMILIA Receipt Required",
  "required": {
    "action": "payment.release",
    "header": "X-EMILIA-Receipt: base64(<EP-RECEIPT-v1 JSON>)",
    "retry_with": "__ep.receipt = <EP-RECEIPT-v1 JSON>  (or __ep.receipt_b64 = base64(JSON))",
    "how": "Gate this action first (ep_guard_action / the trust gate), obtain an EP-RECEIPT-v1, then retry this tool with __ep.receipt set."
  }
}
```

## Where the agent puts the receipt

The middleware looks, in order, at:

1. `args.__ep.receipt` — the EP-RECEIPT-v1 object inline
2. `args.__ep.receipt_b64` — `base64(JSON)`
3. `args.emilia_receipt` — object, body-style (matches require-receipt)
4. `_meta['x-emilia-receipt']` — `base64(JSON)`, header-style passthrough

EP control fields (`__ep`, `emilia_receipt`) are stripped before the real tool
runs.

## Classification rules (first hit wins)

1. **Per-call override** — `args.__ep.irreversible === true | false`
2. **Annotation** — `annotations[name].irreversible`, or the standard MCP
   `destructiveHint` / `readOnlyHint`
3. **Policy fn** — `policy(name, args) → boolean` (a throwing policy is treated
   as irreversible — fail safe)
4. **Default** — `defaultIrreversible` (false unless you set it)

## Provenance ledger

```js
import { ProvenanceLedger } from '@emilia-protocol/mcp-guard';

const ledger = new ProvenanceLedger();           // pass into withMcpGuard({ ledger })
// ... after some guarded irreversible calls:
ledger.verifyChain();   // { ok: true, length } or { ok:false, reason, index } — fails closed
ledger.entries;         // append-only EP-PROVENANCE-ENTRY-v1 records (references, not re-signed receipts)
```

Each entry references one v1 receipt (`receipt_id` + content hash), the verified
summary (outcome/subject/signer), the scoped **agent claim**, and the
**liability** owner. `verifyChain()` proves the ledger is untampered; it does
**not** replace per-receipt verification (that stays with require-receipt).

## What needs a live MCP host / signer to exercise

This is a reference implementation. The following require real infrastructure
and are intentionally adapter-shaped (no-op defaults **fail closed**):

| Capability | Needs | Adapter |
| --- | --- | --- |
| End-to-end tool dispatch | a running MCP host calling `handleTool` | wire `withMcpGuard` at the dispatch site |
| Real consent UX | a user-facing consent surface | `requestConsent` |
| Class-A signoff | a WebAuthn / hardware authenticator + a named approver | `requestClassASignoff` |
| Mint EP-RECEIPT-v1 | an EP host **or** `@emilia-protocol/issue` + signing keys | `issueReceipt` |
| Offline verify | pinned issuer public keys | `verifyOpts.trustedKeys` |

Without adapters you can still exercise: classification, the **demand hook**
against a pre-issued receipt, the **402 refusal** path, and the **provenance
ledger** chain verification — all offline, no network.

## Exact wiring (no edits to the shared mcp-server)

1. **Install** `@emilia-protocol/mcp-guard` and `@emilia-protocol/require-receipt`.
2. **At server startup**, build the wrapper once:
   ```js
   import { withMcpGuard } from '@emilia-protocol/mcp-guard';
   const guardedHandleTool = withMcpGuard(handleTool, { /* annotations, policy, verifyOpts, adapters */ });
   ```
3. **At the dispatch site** (inside the `CallToolRequestSchema` handler), change
   the single call:
   ```diff
   - const out = await handleTool(name, args, { _meta: req.params._meta });
   + const out = await guardedHandleTool(name, args, { _meta: req.params._meta });
   ```
   That single substitution is the whole adoption. Nothing else changes — the
   tool list, schemas, and transport are untouched.
4. **Return the refusal verbatim.** When the result is `{ ep_refused: true }`,
   surface it as the tool result so the agent can read `required.retry_with` and
   come back with a receipt.
5. **(Optional)** persist `guardedHandleTool.ledger.entries` and periodically
   call `.verifyChain()`.

Apache-2.0 · part of [EMILIA Protocol](https://www.emiliaprotocol.ai) ·
**reference implementation, experimental**
```
