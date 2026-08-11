# Dodo Payments refund Gate fixture

This synthetic compatibility fixture wraps the documented Dodo Payments
TypeScript call:

```js
client.refunds.create({ payment_id, items, metadata, reason })
```

It does not call Dodo Payments, use an API key, or claim Dodo endorsement or
interoperability. The in-memory store is suitable only for this demonstration.
A deployment requires durable shared consumption state and complete mediation
of the provider call.

Run from the repository root:

```sh
node examples/dodo-refund-gate-v1/demo.mjs
```

The fixture proves five bounded behaviors:

1. an exact current authority reaches one synthetic provider attempt;
2. a changed item amount is refused before provider entry;
3. stale authority is refused before provider entry;
4. accepted authority cannot be replayed; and
5. a provider timeout becomes `INDETERMINATE`, consumes the attempt, and cannot
   be blindly retried.

The request shape was checked against Dodo Payments' current Create Refund API
documentation on 2026-08-10. The documented request carries `payment_id`,
optional `items`, optional `metadata`, and optional `reason`; `amount` is a
response field, while a partial item refund carries its amount inside each
`items` entry.
