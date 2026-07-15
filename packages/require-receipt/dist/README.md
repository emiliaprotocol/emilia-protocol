<!-- SPDX-License-Identifier: Apache-2.0 -->
# emilia-gate.mjs — the zero-dependency, copy-in Receipt-Required gate

One file. No npm package, no runtime dependency, nothing in your `package.json` to own.
Copy it into your repo and your service can refuse an irreversible action unless it
arrives with a valid, action-bound, non-replayed **EMILIA authorization receipt**
(proof a named human approved *this exact action*), verified **offline** (Ed25519 over
canonical JSON). Node built-in `crypto` only.

Built for maintainers who (reasonably) won't add a vendor dependency for one tool — you
take the file, you own it, there's no supply-chain surface.

## Get it

```bash
curl -O https://raw.githubusercontent.com/emiliaprotocol/emilia-protocol/main/packages/require-receipt/dist/emilia-gate.mjs
```

It's generated from `@emilia-protocol/require-receipt` — the same reviewed, tested
verifier as the published package, not a re-implementation. Regenerate any time with
`node build-drop-in.mjs` in that package. The banner carries the source version + a
content hash so you can tell exactly what you have.

## Use it

```js
import { makeReceiptGate } from './emilia-gate.mjs';

const gate = makeReceiptGate({
  action: 'db.records.delete',
  trustedKeys: [ISSUER_SPKI_B64URL],   // issuer keys you trust
});

// wrap the irreversible action — runs only if the receipt verifies, once
const r = await gate.run(receipt, { target: 'customers' }, async () => doDelete());
if (!r.ok) return reply(r.status, r.body);   // 428 Receipt-Required challenge
```

The gate verifies and atomically reserves the receipt before invoking your function.
After invocation it consumes the receipt even if the function throws, because the
external effect may have happened before its response was lost. Release is available
only for flows that can prove execution never began.

## Two things to get right in production

1. **Pass `trustedKeys`.** Don't rely on `allowInlineKey` for real actions — an inline
   key proves the receipt wasn't tampered with, not *who* authorized it.
2. **Use a durable store for one-time consumption.** The default consumed-store is
   in-memory (process-local). For restart-durable / multi-instance replay protection,
   pass a shared store:

   ```js
   makeReceiptGate({ /* … */, store: { reserve, commit, release } });
   ```

   `reserve` must be an ownership-fenced atomic insert-if-absent. An uncertain
   reservation remains closed until operator reconciliation.

## Conformance

This drop-in passes **EMILIA RR-1**: a Receipt-Required challenge on a missing receipt,
the action running on a valid action-bound receipt, replay of the same receipt refused,
and a forged receipt refused. Verify any MCP server with
[`npx @emilia-protocol/fire-drill`](https://www.emiliaprotocol.ai/fire-drill).

- Docs: https://www.emiliaprotocol.ai/gate
- Spec: `draft-schrock-ep-authorization-receipts` (IETF) · Apache-2.0
