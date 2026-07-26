# EMILIA Autonomy Control Plane Profile v1

`EP-GATE-AUTONOMY-CONTROL-PLANE-PROFILE-v1` is a closed composition profile for autonomous agents that may derive goals, spend resources, propose code changes, and operate canaries. It compiles each exact child action into the existing Gate Trust Program Profile. It does not create a second authorization engine.

## Required bindings

A profile binds:

- a human Class-A signoff or initiator-excluding human quorum over the root objective;
- the root CAID, action digest, permitted action types, audiences, aggregate money/call budget, and expiry;
- each child goal to one parent, one CAID, one action digest, a narrowed action/audience/budget/expiry, and a pinned capability template;
- exact before/after digests and a sorted, nonempty changed-path set for code modifications;
- distinct proposer, evaluator, and executor identities;
- a pinned task-fitness suite, environment, policy, and freshness ceiling;
- bounded canary exposure before promotion;
- fresh suspension/revocation status; and
- rollback as a separately authorized action with a new CAID.

Sibling allocations are checked in aggregate, independently for cents and calls. The child graph must be acyclic. Unknown fields fail closed.

## Conservation boundary

For every accepted profile, each child action and audience is a subset of its parent, each child expires no later than its parent, and aggregate sibling budgets do not exceed the parent budget. The profile therefore rejects direct authority expansion in the typed fields it validates.

This statement does not establish that a natural-language child goal logically entails the root objective. It does not prove that a human understood an approval, a provider told the truth, a fitness suite was adequate, a deployment completed, or storage and clocks are correct. Those remain explicit relying-party acceptance roots.

## Execution shape

The compiler emits one `EP-GATE-TRUST-PROGRAM-PROFILE-v1` program per child. Its stages require:

1. human root-objective evidence;
2. bounded authority-allocation evidence;
3. exact execution/diff binding;
4. task-specific fitness evidence;
5. current non-suspended status;
6. canary evidence where applicable; and
7. new human authorization for rollback.

Production execution still requires the existing Gate, consequence-control, receipt consumption, reconciliation, and durable-store controls. Compiling a profile does not itself execute anything.

## Formal evidence

`formal/ep_autonomy_control_plane.tla` checks the finite control abstraction. The safe configuration checks that child authority never exceeds the root and that execution requires independent approval, fitness, and canary evidence while unsuspended. The deliberately unsafe configuration enables self-expansion and must produce a counterexample to `AuthorityNeverExpands`.
