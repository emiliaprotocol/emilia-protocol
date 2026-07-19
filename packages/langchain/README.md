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
canonical `makeReceiptGate` — **zero network, no vendor in the loop.** The receipt
becomes portable evidence an auditor can check without trusting the runtime.
*Necessary, not sufficient*: it composes with — never replaces — the tool's own checks.

> The base gate proves an accepted issuer signed the exact action. To claim a
> named human was present, also require `class_a` and verify a WebAuthn ceremony
> against your pinned approver directory, RP ID, and origin allowlist.

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
  assuranceClass: 'class_a',
  approverKeys: ENROLLED_APPROVER_KEYS,
  rpId: 'approvals.example.com',
  allowedOrigins: ['https://approvals.example.com'],
  store: durableAtomicReceiptStore,    // { reserve, commit, release }
});

// The human-approved receipt travels as out-of-band call metadata:
await guarded.invoke(
  { to: 'acct_1', amount: 100 },
  { configurable: { emiliaReceipt: receipt } },
);
// missing/invalid/replayed/forged -> throws; valid + action-bound -> runs.
```

Per-call binding (recommended) means a receipt minted for one target cannot drive a
different one. Once the underlying tool is invoked, an exception is an indeterminate
effect: the approval is consumed and automatic retry with the same receipt is refused.
Only release a reservation when you can prove the external effect never began.

The default store is process-local. Production fleets must provide a shared,
ownership-fenced store whose `reserve` is an atomic insert-if-absent and whose
`commit`/`release` can be called only by the reservation owner.

## Legacy: hosted policy gate

`guardAction` / `withGuard` call a hosted gate for an allow/deny/signoff decision.
Convenient, but the decision is the operator's word, not offline-verifiable evidence —
prefer the receipt gate above for anything irreversible. Unknown, malformed, and
non-2xx responses deny. A `review`/signoff response runs the tool only when
`onSignoff` returns `{ approved: true }`; merely sending a notification never proceeds.

## What it is / isn't

- **Is:** an offline gate for exact-action issuer evidence, with optional pinned
  Class-A or quorum verification for named-human authorization.
- **Isn't:** authentication, access control, or a hosted runtime. It composes on top.

Apache-2.0. Reference implementation, experimental. Part of the
[EMILIA Protocol](https://github.com/emiliaprotocol/emilia-protocol) — an open
IETF-track authorization-receipt standard (`draft-schrock-ep-authorization-receipts`).
