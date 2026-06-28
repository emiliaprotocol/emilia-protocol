# @emilia-protocol/langchain

Guard [LangChain.js](https://js.langchain.com) tools with the **EMILIA Protocol** —
require an **offline-verifiable authorization receipt** (EP-RECEIPT-v1) before an
irreversible tool runs.

```
missing receipt  -> refused
valid receipt    -> runs
replayed receipt -> refused   (one-time consumption)
forged receipt   -> refused
```

Verification is offline Ed25519 over canonical JSON via
[`@emilia-protocol/require-receipt`](https://www.npmjs.com/package/@emilia-protocol/require-receipt)'s
canonical `makeReceiptGate` — **zero network, no vendor in the loop.** The approval
becomes portable evidence an auditor can check without trusting the operator.
*Necessary, not sufficient*: it composes with — never replaces — the tool's own checks.

> EMILIA proves **who authorized** a specific action. It is not an access-control
> runtime; it is the portable authorization receipt any runtime can emit.

## Install

```bash
npm install @emilia-protocol/langchain   # brings in @emilia-protocol/require-receipt
```

## Recommended: offline receipt gate

```js
import { requireReceiptForLangChainTool } from '@emilia-protocol/langchain';

const guarded = requireReceiptForLangChainTool(wireTransferTool, {
  action: 'payment.release',           // or actionFor: (input) => `payment.release:${input.to}`
  trustedKeys: [ISSUER_SPKI_B64URL],   // pin the issuer keys you trust
});

// The human-approved receipt travels as out-of-band call metadata:
await guarded.invoke(
  { to: 'acct_1', amount: 100 },
  { configurable: { emiliaReceipt: receipt } },
);
// missing/invalid/replayed/forged -> throws; valid + action-bound -> runs.
```

Per-call binding (recommended) means a receipt minted for one target can't drive a
different one. A transient tool failure does **not** burn the approval — it stays
retryable.

## Legacy: hosted policy gate

`guardAction` / `withGuard` call a hosted gate for an allow/deny/signoff decision.
Convenient, but the decision is the operator's word, not offline-verifiable evidence —
prefer the receipt gate above for anything irreversible.

## What it is / isn't

- **Is:** an offline gate that enforces *a named human authorized this exact action*
  and yields portable, third-party-verifiable evidence.
- **Isn't:** authentication, access control, or a hosted runtime. It composes on top.

Apache-2.0. Reference implementation, experimental. Part of the
[EMILIA Protocol](https://github.com/emiliaprotocol/emilia-protocol) — an open
IETF-track authorization-receipt standard (`draft-schrock-ep-authorization-receipts`).
