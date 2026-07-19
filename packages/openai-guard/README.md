# @emilia-protocol/openai-guard

**Guard OpenAI-compatible tool calls with EMILIA Protocol.** Works with any
OpenAI-style tool-calling API — OpenAI, **xAI Grok**, Together, Fireworks, Groq.
The production path verifies a pinned, exact-action authorization receipt
offline and consumes it before the tool runs. Missing, forged, wrong-action, or
replayed evidence is refused.

```bash
npm install @emilia-protocol/openai-guard
```

## Production: offline receipt gate

```js
import { requireReceiptForOpenAITool } from '@emilia-protocol/openai-guard';

const releasePayment = requireReceiptForOpenAITool(bank.wire, {
  actionFor: (args) => `payment.release:${args.destination}:${args.amount}`,
  trustedKeys: [ISSUER_SPKI_B64URL],
  assuranceClass: 'class_a',
  approverKeys: ENROLLED_APPROVER_KEYS,
  rpId: 'approvals.example.com',
  allowedOrigins: ['https://approvals.example.com'],
  store: durableAtomicReceiptStore,
});

await releasePayment({
  destination: 'acct_9f12',
  amount: 82000,
  __ep: { receipt },
});
```

`actionFor` should bind every material tool argument. The default replay store is
process-local; production fleets must provide a shared, ownership-fenced
`{ reserve, commit, release }` store.

## Try it offline (~5s)

```bash
node packages/openai-guard/example.mjs
# 1) $200 → released   2) $82k → human signoff → released   3) sanctioned → blocked
```

## Legacy hosted policy client

```js
import { guard } from '@emilia-protocol/openai-guard';

const result = await guard({
  action: 'payment.release',
  actor: 'ep:entity:agent-7',
  context: { value_usd: 82000, resource_ref: 'acct_9f12' },
}, { apiKey: process.env.EP_API_KEY });
```

This path accepts only a successful `allow` carrying a durable `commit_ref`.
Network errors, non-2xx responses, unknown verdicts, and malformed bodies deny.
It is still the operator's online decision, not portable authorization evidence;
use the receipt gate above for irreversible work.

## Guard a whole tool-calling loop (Grok / OpenAI)

```js
import OpenAI from 'openai';
import { runToolCalls } from '@emilia-protocol/openai-guard';

const client = new OpenAI({ apiKey: process.env.XAI_API_KEY, baseURL: 'https://api.x.ai/v1' }); // Grok
const res = await client.chat.completions.create({ model: 'grok-4', messages, tools });
const msg = res.choices[0].message;

const toolResults = await runToolCalls(msg.tool_calls, {
  lookup_invoice: { fn: lookupInvoice, readOnly: true },       // explicitly read-only
  release_payment: {                                          // irreversible → gated
    actionFor: (a) => `payment.release:${a.destination}:${a.amount}`,
    fn: releasePaymentImpl,
  },
}, {
  receipts: { [toolCallId]: receipt },
  trustedKeys: [ISSUER_SPKI_B64URL],
  assuranceClass: 'class_a',
  approverKeys: ENROLLED_APPROVER_KEYS,
  rpId: 'approvals.example.com',
  allowedOrigins: ['https://approvals.example.com'],
  store: durableAtomicReceiptStore,
});

// feed `toolResults` (role:"tool" messages) back to the model and continue the loop.
```

Point it at OpenAI, Together, Fireworks, etc. by swapping the `baseURL` — the
guard layer is identical.

## Legacy hosted software-approval flow (`/receipt`)

This submodule maps 1:1 to the hosted API-key endpoints. The approval route
authenticates a different principal and enforces separation of duty; it does
**not** by itself establish human presence, user verification, or a passkey
ceremony. Use the WebAuthn/mobile ceremony when a profile requires Class A.

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

  // 3. A DIFFERENT authenticated principal approves (software/API-key evidence).
  await approveSignoff({ apiKey: process.env.APPROVER_EP_API_KEY, signoff_id });
}

// 4. Offline-verify a signed EP-RECEIPT-v1 (install @emilia-protocol/verify).
// const v = await verifyReceipt(signedReceiptDoc, issuerPublicKey);
```

The approval is an out-of-band authenticated-principal action. A dashboard or
Slack UX does not upgrade it into cryptographic human-presence evidence.
Endpoints: `/api/v1/trust-receipts`,
`/api/v1/signoffs/request`, `/api/v1/signoffs/{id}/approve`.

## Scope

This package enforces receipt verification, exact-action binding, and one-time
consumption at the tool boundary. It does not prove business correctness or what
a person perceived, and it does not replace the resource owner's authorization,
fraud, safety, or legal controls. Apache-2.0.

End-to-end runnable Grok demo: [`examples/grok-guard.mjs`](../../examples/grok-guard.mjs).
