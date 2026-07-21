# Formal models

These are bounded models of the settlement state machine, not proofs of the compiled EVM bytecode.

- `dtc_base_settlement.tla` explores reserve, provider-confirmed invoke, provider and party-agreement outcomes,
  indeterminate reconciliation, signer revocation, settlement pause, cancellation, and withdrawals. Its invariants
  cover value conservation, sticky receipt consumption, full-budget indeterminate locks, terminal allocation, and
  monotonic provider revocation. Deadlock checking is disabled because a terminal state after all claims are withdrawn
  is an intended quiescent endpoint; safety invariants are still checked over the complete reachable graph.
- `dtc_base_escrow.als` independently checks the relational transition shape, including no terminal outgoing
  settlement transition.

Use the repository-pinned TLC 1.7.4 and Alloy 6.2.0 binaries and checksums documented in the root formal workflows.
Do not mark these models verified until both tools have completed against the exact files and the outputs are retained.
