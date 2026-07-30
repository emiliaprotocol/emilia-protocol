# Bounded execution program demo

Run from the repository root:

```bash
node examples/bounded-execution-program/demo.mjs
```

The demo uses the real Gate package APIs to sign and register an
`EP-BOUNDED-EXECUTION-PROGRAM-v1` DAG, then execute synthetic `inspect ->
remediate -> verify` admissions. The remediate provider intentionally times out:
Gate recovers it as `INDETERMINATE`, refuses to unlock `verify`, accepts a
synthetic evidence-backed reconciliation, consumes the signed budgets, refuses
another occurrence after depletion, reads one closed program-to-date runtime
and retained-occurrence snapshot, signs and verifies its point-in-time report,
and installs a signed v2 supersession.

Everything is local and synthetic: ephemeral keys, fabricated evidence digests,
a non-responsive fake provider, and Gate's explicitly test-only in-memory
admission store. This demonstrates package behavior; it is not a deployment,
durability, provider, effect-truth, or production claim. Reconciliation reports
the synthetic evidence supplied to Gate and does not prove event order.
