# Indeterminate Effect Reconciliation

This runnable example demonstrates the failure mode that ordinary retry logic
gets wrong:

1. EMILIA Gate verifies a real issuer-signed receipt carrying a pinned,
   user-verified Class-A WebAuthn approval over the protected payment action.
2. The signed capability atomically reserves `25,000 USD`.
3. The mock external provider commits the exact action in its authoritative
   simulation, then loses its response by throwing.
4. `executeWithCapability()` commits the operation as `indeterminate`; it does
   not reopen the budget.
5. A blind retry with the same operation ID is refused as
   `operation_already_committed` before the provider can run again.
6. The provider returns an Ed25519-signed status statement. The reconciler
   verifies the pinned provider key, operation ID, exact canonical action
   digest, and effect fields before appending an immutable reconciliation
   record.

The provider execution count remains exactly one.

## Run

From the repository root:

```bash
node examples/indeterminate-effect-reconciliation/demo.mjs
node --test examples/indeterminate-effect-reconciliation/scenario.test.mjs
```

The tests also prove that:

- changing the signed provider evidence invalidates its signature;
- authentically signed evidence for a different destination cannot reconcile
  the expected action; and
- refused evidence never enters the reconciliation ledger.

## Files

- `demo.mjs` — executable terminal demonstration.
- `scenario.mjs` — real Gate, Class-A receipt, capability, and scenario wiring.
- `provider.mjs` — idempotent mock provider plus signed effect evidence.
- `reconciliation.mjs` — fail-closed evidence verification and append-only
  reconciliation record.
- `scenario.test.mjs` — decisive path and hostile evidence tests.

## Honest boundary

The mock provider and in-memory stores are deterministic local demonstration
components; no real funds move.

The generic capability API currently has no public
`reconcileCapabilityOperation()` transition. This example therefore preserves
the original capability operation as consumed and `indeterminate`, then records
the authenticated final outcome as a separate digest-bound reconciliation
artifact. It never mutates capability-store internals or relabels the original
uncertain observation. A production deployment must put both stores behind
durable, ownership-fenced persistence. The specialized Action Escrow kernel
already supplies its own provider reconciliation state transition.
