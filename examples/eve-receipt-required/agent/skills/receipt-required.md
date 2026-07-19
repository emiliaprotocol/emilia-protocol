---
name: receipt-required
description: How to authorize an irreversible tool (release_funds, delete_repo) when it returns a Receipt-Required challenge. Load this whenever a tool responds with receipt_required: true.
---

# Receipt Required — obtaining and attaching an EMILIA authorization receipt

Some tools in this agent are **irreversible** (they move money or destroy data). They refuse to run
unless the call carries a valid **EMILIA authorization receipt** — cryptographic proof that a named
human approved *this exact action*. This is not authentication and not permissions; it is portable,
offline-verifiable evidence of *who authorized what*.

## When to use this skill

Use it the moment an irreversible tool returns:

```json
{ "ok": false, "receipt_required": true, "status": 428, "challenge": { ... } }
```

Do **not** retry the tool with the same arguments and no receipt — it will refuse again. The action
did not happen; nothing was mutated.

## The loop

1. **Read the challenge.** `challenge.required.action` is the exact action the receipt must authorize
   (e.g. `funds.release:acct-9931` or `repo.delete:acme/payments`). The receipt must be bound to that
   exact target — a receipt for one destination cannot authorize another.
2. **Get a human to approve.** Ask the operator to authorize the exact action via your EMILIA issuer
   (the Gate endpoint, the `emilia-gate` CLI, or the device-signoff flow). A named human signs the
   exact `{ action, target, amount/details }` on their own device. You never mint the receipt
   yourself.
3. **Retry with the receipt.** Call the tool again with the same arguments **plus** `emilia_receipt`
   set to the returned `EP-RECEIPT-v1` object. The tool verifies it offline and, if valid and
   bound to this exact action, performs the mutation **once**.

## Rules

- **One receipt, one action.** A receipt is consumed on success; replaying it is refused. If you need
  to run the action again, obtain a new receipt.
- **Never fabricate or reuse.** Do not edit a receipt's fields, copy one from another action, or
  invent a key. Tampered or mismatched receipts are rejected by construction.
- **An error after invocation burns the approval.** The mutation may have happened before its response
  was lost, so automatic retry could duplicate it. Reconcile the downstream result and obtain a fresh
  receipt only if another execution is actually required.

The invariant: **no receipt, no mutation; if it runs, the proof travels.**
