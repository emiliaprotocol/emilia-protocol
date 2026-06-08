# @emilia-protocol/openai-guard

**Guard OpenAI-compatible tool calls with EMILIA Protocol.** Works with any
OpenAI-style tool-calling API — OpenAI, **xAI Grok**, Together, Fireworks, Groq.
Before an irreversible tool call runs, it routes through the EMILIA trust gate:
`allow` → run · `deny` → throw · `signoff_required` → wait for a named human, then run.
Zero dependencies.

```bash
npm install @emilia-protocol/openai-guard
```

## Try it offline (~5s)

```bash
node packages/openai-guard/example.mjs
# 1) $200 → released   2) $82k → human signoff → released   3) sanctioned → blocked
```

## Guard one tool

```js
import { withGuard } from '@emilia-protocol/openai-guard';

const releasePayment = withGuard(
  async ({ amount, destination }) => bank.wire(amount, destination),
  {
    action: 'payment.release',
    context: ({ amount, destination }) => ({ amount, destination }),
    apiKey: process.env.EP_API_KEY,
    onSignoff: async (decision) => waitForNamedHuman(decision), // return false to reject
  },
);

await releasePayment({ amount: 82000, destination: 'acct_9f12' });
// → throws "EMILIA requires human signoff for \"payment.release\"" until approved
```

## Guard a whole tool-calling loop (Grok / OpenAI)

```js
import OpenAI from 'openai';
import { runToolCalls } from '@emilia-protocol/openai-guard';

const client = new OpenAI({ apiKey: process.env.XAI_API_KEY, baseURL: 'https://api.x.ai/v1' }); // Grok
const res = await client.chat.completions.create({ model: 'grok-4', messages, tools });
const msg = res.choices[0].message;

const toolResults = await runToolCalls(msg.tool_calls, {
  lookup_invoice: { fn: lookupInvoice },                       // read-only → ungated
  release_payment: {                                          // irreversible → gated
    action: 'payment.release',
    context: (a) => ({ amount: a.amount, destination: a.destination }),
    fn: releasePaymentImpl,
  },
}, { apiKey: process.env.EP_API_KEY, onSignoff });

// feed `toolResults` (role:"tool" messages) back to the model and continue the loop.
```

Point it at OpenAI, Together, Fireworks, etc. by swapping the `baseURL` — the
guard layer is identical.

## Full signoff ceremony + Trust Receipt (`/receipt`)

For the real hosted flow — mint a pre-action receipt, require a **named** human's
signoff, and get a verifiable record — use the `/receipt` submodule (needs an EP
API key). Each function maps 1:1 to a live endpoint.

```js
import { mintReceipt, requestSignoff, approveSignoff, verifyReceipt } from '@emilia-protocol/openai-guard/receipt';

// 1. Mint a pre-action receipt — the server runs EMILIA's verified policy engine.
const receipt = await mintReceipt({
  apiKey: process.env.EP_API_KEY,
  organization_id: 'org_123',
  action_type: 'large_payment_release',   // a GUARD_ACTION_TYPES value
  target_resource_id: 'invoice_4421',
  amount: 84000,
});

if (receipt.signoff_required) {
  // 2. Request signoff on that receipt.
  const { signoff_id } = await requestSignoff({ apiKey: process.env.EP_API_KEY, receipt_id: receipt.receipt_id });

  // 3. A DIFFERENT, named human approves (EMILIA enforces separation of duty).
  await approveSignoff({ apiKey: process.env.APPROVER_EP_API_KEY, signoff_id });
}

// 4. Offline-verify a signed EP-RECEIPT-v1 (install @emilia-protocol/verify).
// const v = await verifyReceipt(signedReceiptDoc, issuerPublicKey);
```

The approval is an out-of-band human action — surface the `signoff_id` to your
dashboard or Slack and approve there. Endpoints: `/api/v1/trust-receipts`,
`/api/v1/signoffs/request`, `/api/v1/signoffs/{id}/approve`.

## Scope

EMILIA's formal proofs (26 TLA+ theorems / 35 Alloy facts) cover the policy
**engine** — no self-approval, no replay, money-destination + large releases
always gated. This package is the thin client that routes your tool calls to that
engine; the client itself is ordinary code. Apache-2.0.

End-to-end runnable Grok demo: [`examples/grok-guard.mjs`](../../examples/grok-guard.mjs).
