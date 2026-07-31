# Gate Allowance Stripe payout example

Run from the repository root:

```bash
node examples/gate-allowance/demo.mjs
```

The example exercises the public package entry points:

- `issueGateAllowance()` and `verifyGateAllowance()` from
  `@emilia-protocol/gate/allowance`;
- `createMemoryCapabilityStore()` from
  `@emilia-protocol/gate/capability-receipt`; and
- `guardStripeAllowanceMutation()` from
  `@emilia-protocol/gate/adapters/stripe`.

It demonstrates:

1. a customer-signed allowance for one bounded period;
2. a Stripe account identity obtained from the configured provider client and
   one root capability;
3. an unattended payout inside the target allowlist and per-action limit;
4. aggregate-budget depletion through atomic reserve and commit;
5. pre-effect refusal for a disallowed destination and oversized payout;
6. `INDETERMINATE` handling with no blind retry;
7. a newly signed successor allowance that binds the predecessor digest; and
8. mandatory local current-status verification refusing the retired revision.

The Stripe-compatible client is local and synthetic. It has the same
`stripe.payouts.create(params)` call shape used by the adapter, but it performs
no network request and moves no money. The in-memory capability store is a
reference/testing implementation, not production durability.

The customer-run process owns the client and credentials. No provider
credential is placed in an allowance, capability, receipt, or hosted message.
The hosted approval service discussed in the protocol document is an
architectural boundary, not a production service shipped by this example.
