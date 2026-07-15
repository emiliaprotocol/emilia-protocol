# @emilia-protocol/openai-agents

## Add cryptographic approval receipts to OpenAI Agents in 10 minutes.

> **OpenAI pauses an agent and asks for approval. EMILIA makes that approval portable, offline-verifiable evidence** — proof that a *named* human accountably authorized *this exact* tool call, that anyone can check later without trusting OpenAI, your app, or a mutable log.

The OpenAI Agents SDK already pauses consequential tool calls and asks a human to approve them. That approval is a transient in-process boolean — the moment the run resumes, it is gone. This adapter turns each approval into an **EMILIA authorization receipt** (EP-RECEIPT-v1): a tamper-evident, Ed25519-signed artifact bound to the exact tool call, verifiable offline. It **composes with** OpenAI's approval primitive; it does not replace it.

---

## The confirmed OpenAI Agents SDK human-in-the-loop API

Grounded against the official docs (JavaScript/TypeScript, package `@openai/agents`):

- A tool requires approval when defined with **`needsApproval: true`** (or an async `needsApproval(context, args) => boolean`) on `tool({...})`.
- When such a tool is called, the run **pauses** and the pending approvals surface as **`result.interruptions`** — an array of **`RunToolApprovalItem`**, each with **`type: "tool_approval_item"`**.
- Each interruption exposes the **tool name** (`interruption.name` / `interruption.rawItem.name`), the **arguments** (`interruption.arguments` / `rawItem.arguments`, a JSON string), and the **call id** (`rawItem.callId` for `function_call`, or `rawItem.id` for hosted tools).
- You resolve each one with **`result.state.approve(interruption)`** or **`result.state.reject(interruption, { message })`**, then **resume by re-running** `run(agent, result.state)` with the same state.

Docs: https://openai.github.io/openai-agents-js/guides/human-in-the-loop (see also `.../classes/runstate` and `.../classes/streamedrunresult`).

This adapter is **framework-faithful**: it reads that exact interruption shape and drives those exact `state.approve` / `state.reject` calls, so a real integration is a thin wrapper — and the adapter is unit-testable **without** calling OpenAI.

---

## Install

```bash
npm install @emilia-protocol/openai-agents @emilia-protocol/require-receipt
# @openai/agents is a peer dependency (you already have it in an Agents app)
```

## Copy-paste integration

```js
import { Agent, run, tool } from '@openai/agents';
import { requireReceiptForOpenAIAgent } from '@emilia-protocol/openai-agents';
import z from 'zod';

const cancelOrder = tool({
  name: 'cancelOrder',
  description: 'Cancel an order',
  parameters: z.object({ orderId: z.number() }),
  needsApproval: true,                       // <- OpenAI pauses the run here
  execute: async ({ orderId }) => { /* ... */ },
});

const agent = new Agent({ name: 'Ops', tools: [cancelOrder] });

// One gate, configured once. actionFor maps a tool call -> the canonical EP
// action_type the receipt must be bound to. For real safety, bind to the
// SPECIFIC target the call acts on (not just the tool name) so a receipt for one
// resource can't authorize another — and fold in the call identity so the same
// receipt can't be reused across two different tool calls.
const gate = requireReceiptForOpenAIAgent({
  trustedKeys: [process.env.EMILIA_ISSUER_KEY], // base64url SPKI-DER issuer key(s) you trust
  maxAgeSec: 900,
  actionFor: (toolName, args) => `openai.tool.${toolName}:${args?.orderId ?? ''}`,
});

let result = await run(agent, 'Cancel order 4242');

while (result.interruptions?.length) {
  // `receipts` is whatever your app collected for these calls — keyed by callId
  // or tool name, or an array matched by action_type. A missing/invalid/replayed
  // receipt is REJECTED; only a valid action-bound receipt is APPROVED.
  const { approved, rejected, decisions } = await gate.resolve(result, { receipts });

  console.log(decisions); // audit trail: decision + reason + action + subject per call

  // gate.resolve already drove result.state.approve()/reject(); just resume:
  result = await run(agent, result.state);
}

console.log(result.finalOutput);
```

Per-interruption form, if you drive approvals yourself:

```js
const decision = await gate.decide(interruption, receiptForThisCall);
if (decision.decision === 'approve') result.state.approve(interruption);
else result.state.reject(interruption, { message: `EMILIA: ${decision.reason}` });
```

## The four checks it enforces

For every pending tool-approval interruption:

| Situation | Decision |
| --- | --- |
| **No receipt** for that interruption | **REJECT** — the tool stays blocked |
| **Valid** EP-RECEIPT-v1, action-bound to that exact tool call | **APPROVE** — the tool runs |
| **Replayed** receipt (`receipt_id` already consumed by the configured store) | **REJECT** |
| **Tampered / invalid** receipt (signature or action mismatch, untrusted issuer, expired) | **REJECT** |

## The six audit questions a receipt answers

1. **Who approved it?** — `payload.subject` / `claim.approver` (a named, accountable human).
2. **What exact action?** — `claim.action_type`, bound via `actionFor` to this specific tool call.
3. **Was it altered after approval?** — no: the receipt is Ed25519-signed over sorted-key canonical JSON; any change breaks the signature.
4. **Was it replayed?** — no: one-time consumption by `receipt_id` in the configured atomic store.
5. **Was it authorized for the right org / policy?** — pin `trustedKeys` to the issuers your policy accepts; only those verify.
6. **Verifiable without trusting OpenAI, your app, or mutable logs?** — yes: verification is offline Ed25519 over canonical JSON; anyone holding the issuer's public key can re-check the artifact.

## Production note

- **Pin `trustedKeys`** to your real issuer key(s). **Drop `allowInlineKey`** (it only proves integrity, never trust).
- **Bind to the target, not just the tool.** Make `actionFor` incorporate the specific resource the call touches (and ideally the `callId` / an args hash), so a receipt minted for one action can't be replayed against a different one.
- Consumption is durably committed **before** `state.approve()` is called. If that commit fails, the runtime is rejected and the tool cannot run.
- **Rejections are sanitized:** a reject decision carries only a machine-readable `reason` code, never the signer, the subject, or verifier internals.
- The default store is process-local. Production fleets must pass a shared, ownership-fenced `{ reserve, commit, release }` store. `reserve` must be atomic insert-if-absent; an uncertain commit remains closed until operator reconciliation.
- This is **necessary, not sufficient**. It composes with — and never substitutes for — the resource owner's own authorization and policy checks. It makes the human approval that OpenAI already asks for into auditable, portable evidence; it does not decide whether the action *should* be allowed.

## References

- `draft-schrock-ep-authorization-receipts` — EP authorization-receipt format (individual Internet-Draft, **not** an RFC).
- `draft-schrock-ep-enforcement-point` — EP enforcement-point profile (individual Internet-Draft, **not** an RFC).
- `@emilia-protocol/require-receipt` — the underlying offline verifier (`verifyEmiliaReceipt`).
- `@emilia-protocol/gate` — productized enforcement point with a shared consumed-store + assurance tiers.

Apache-2.0. Reference implementation, experimental.
