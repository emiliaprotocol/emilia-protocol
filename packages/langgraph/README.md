# @emilia-protocol/langgraph

Bind LangGraph and Agent Inbox human responses to exact, one-time EMILIA
authority.

Agent Inbox is a useful delivery and review surface. Its `accept`, `edit`,
`response`, and `ignore` values are application messages, not cryptographic
execution authority. This adapter enforces four boundaries:

```text
accept   + exact fresh receipt -> consume, then resume the frozen action
edit     + old/no receipt      -> require fresh authority for the edited action
response or ignore             -> pass as non-authorizing control flow
replay, forgery, drift         -> refuse
```

The exact action binding includes the action name, complete finite-JSON
arguments, and trusted LangGraph `threadId` plus `interruptId`. An edited field
therefore changes the receipt action. The adapter never treats a UI click or a
generic policy decision as authority.

## Install

```bash
npm install @emilia-protocol/langgraph
```

## Use

```js
import {
  bindLangGraphAction,
  createLangGraphApprovalAdapter,
} from '@emilia-protocol/langgraph';

const occurrence = {
  threadId: langGraphThread.thread_id,
  interruptId: langGraphInterrupt.id,
};

// Show this exact value to the approval service when requesting a receipt.
const action = bindLangGraphAction(interrupt.value.action_request, occurrence);

const adapter = createLangGraphApprovalAdapter({
  trustedKeys: [ISSUER_SPKI_B64URL],
  assuranceClass: 'class_a',
  approverKeys: ENROLLED_APPROVER_KEYS,
  rpId: 'approvals.example.com',
  allowedOrigins: ['https://approvals.example.com'],
  store: durableAtomicReceiptStore,
});

const decision = await adapter.resolve(
  interrupt.value,
  inboxResponse,
  receipt,
  occurrence,
);

if (decision.decision === 'resume') {
  // Resume only with the adapter's sanitized response. On accept this carries
  // the frozen interrupt action, never client-supplied replacement arguments.
  await client.runs.wait(threadId, assistantId, {
    input: { resume: [decision.response] },
  });
}
```

For `decision: "reauthorize"`, request a new receipt for `decision.action` and
present the edit again. Never reuse the receipt for the pre-edit action.

The default consumption store is process-local. Production fleets must provide
a shared, atomic, ownership-fenced store. A receipt proves a pinned issuer signed
the exact action. It does not prove the UI was honest, the action executed, or
the real-world outcome. Execution and outcome evidence remain separate.

Apache-2.0. Reference implementation, experimental.
