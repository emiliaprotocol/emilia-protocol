<!-- SPDX-License-Identifier: Apache-2.0 -->
# Receipt Required for Eve

**Add accountable authorization to any [Vercel Eve](https://vercel.com/eve) tool in 10 minutes.**

> Vercel Eve makes agent tools easy to build. Arcade makes tool auth easier.
> **EMILIA makes dangerous tool execution accountable: no receipt, no mutation; if it runs, the proof travels.**

Eve is filesystem-first — a tool is a file in `agent/tools/`. That makes the integration point
obvious: wrap the *irreversible* tools so they can't mutate without a verifiable **EMILIA
authorization receipt** — cryptographic proof that a named human approved *this exact action*,
checkable offline, forever. It's the missing row in the stack: tokens/auth say *who's calling*;
EMILIA says *who authorized this specific action* — and leaves portable evidence.

This kit is a complete, runnable Eve agent with two gated tools.

```
agent/
  agent.ts                 # defineAgent (model)
  instructions.md          # "no receipt, no mutation"
  tools/
    release_funds.ts       # IRREVERSIBLE money movement — gated
    delete_repo.ts         # IRREVERSIBLE deletion — gated
  skills/
    receipt-required.md    # how the agent obtains + attaches a receipt
lib/
  emilia-gate.mjs          # the zero-dependency gate (Node crypto only)
  guards.mjs               # one gate per dangerous action
demo.mjs                   # prove the loop locally, no Eve runtime needed
```

## See it work (zero deps, ~5 seconds)

```bash
node demo.mjs
```
```
1. no receipt          -> BLOCKED (428) — funds NOT moved
2. human signs         -> RAN ONCE — released $5000 to acct-9931
3. replay same receipt -> BLOCKED (replay_refused)
4. receipt for another acct -> BLOCKED (action_mismatch)
PASS — no receipt, no mutation; if it runs, the proof travels.
```

## Add it to your own Eve tool in 10 minutes

1. **Drop in the gate (zero dependency — nothing added to your `package.json`):**
   ```bash
   mkdir -p lib && curl -o lib/emilia-gate.mjs \
     https://raw.githubusercontent.com/emiliaprotocol/emilia-protocol/main/packages/require-receipt/dist/emilia-gate.mjs
   ```
2. **Declare a gate for the dangerous action** (`lib/guards.mjs`):
   ```js
   import { makeReceiptGate } from './emilia-gate.mjs';
   export const releaseFundsGate = makeReceiptGate({
     action: 'funds.release',
     trustedKeys: (process.env.EMILIA_TRUSTED_KEYS || '').split(',').filter(Boolean),
   });
   ```
3. **Wrap the tool's `execute`** (`agent/tools/release_funds.ts`):
   ```ts
   import { defineTool } from 'eve/tools';
   import { z } from 'zod';
   import { releaseFundsGate } from '../../lib/guards.mjs';

   export default defineTool({
     description: 'Release funds. IRREVERSIBLE. Requires an EMILIA receipt bound to funds.release:<destination>.',
     inputSchema: z.object({
       amount: z.number().positive(),
       destination: z.string(),
       emilia_receipt: z.any().optional(),
     }),
     async execute({ amount, destination, emilia_receipt }) {
       const r = await releaseFundsGate.run(emilia_receipt, { target: destination }, async () => {
         return doTheTransfer(amount, destination); // your real mutation
       });
       return r.ok ? { ok: true, ...r.result } : { ok: false, receipt_required: true, challenge: r.body };
     },
   });
   ```
4. **Add the skill** so the agent knows the loop: copy `agent/skills/receipt-required.md`. Now when a
   tool returns `receipt_required`, the agent gets a human to authorize the exact action and retries
   with the receipt.

That's it. The mutation runs only on a valid, action-bound, non-replayed receipt — verified offline.

## Production notes (the two things to get right)

- **Set `EMILIA_TRUSTED_KEYS`** (issuer SPKI, comma-separated). Without it the kit falls back to
  `allowInlineKey` so the demo runs — but an inline key proves integrity, not *who* authorized. Never
  ship that for real money.
- **Use a durable consumed-store** for one-time consumption across Eve's durable restarts / multiple
  instances: `makeReceiptGate({ ..., store: { has: (id) => kv.has(id), add: (id) => kv.add(id) } })`.
  The default is in-memory (process-local).

## How it fits the rest of the stack

- **Model / auth:** AI Gateway + Vercel Connect / Arcade handle model access and delegated tokens.
- **Execution accountability:** EMILIA — the receipt, verified before the mutation.
- **Transparency:** an EMILIA receipt can also ride as a [SCITT](https://www.rfc-editor.org/rfc/rfc9943)
  Signed Statement, so the log records *who authorized*, not just *what happened*.

Docs: https://www.emiliaprotocol.ai/gate · Spec: `draft-schrock-ep-authorization-receipts` (IETF) · Apache-2.0
