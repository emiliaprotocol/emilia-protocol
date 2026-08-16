# AI Operations authority interface reference

This runnable example turns a five-part AI Operations management proposal into
a concrete, mechanism-neutral projection over existing EMILIA authority
primitives. It exposes:

1. the proposed action and exact target and parameters before execution;
2. authorization evidence bound to that exact action;
3. a structured signal when additional human authorization is required;
4. operator intervention, action history, and the reported resulting state; and
5. a configured autonomy mode and the pinned policy result used for this action.

Run it from the repository root:

```bash
npm run demo:ai-operations-authority
```

Run the ten hostile and lifecycle cases:

```bash
npm run test:ai-operations-authority
```

The network-operations example covers an action inside an automatic envelope,
an action requiring a two-person quorum, action substitution, pre-entry
operator cancellation, a prohibited action, a lost provider acknowledgement,
and a freeze that occurs after provider entry.

## Separation of responsibilities

This interface does not authorize an action. It displays separately verified
authorization evidence and the result of a pinned policy evaluation. It does
not execute an action. Enforcement still belongs at a protected Gate boundary.
It does not claim that signed history proves an external effect or the truth of
the reported resulting state. A post-entry intervention cannot be relabeled as
proof of non-entry, and an unknown provider outcome remains `INDETERMINATE`
until reconciled.

The example is deliberately an operator projection, not a new core protocol or
Internet-Draft. A domain protocol such as DMSC can carry required authorization
state without owning the broader management interface.

## Implementation status

The projection, state transitions, and ten tests are runnable. The example is
local and in-memory. It is not a production AI Operations service, a deployment
claim, or evidence of external implementation.
