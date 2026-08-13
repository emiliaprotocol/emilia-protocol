# Self-Modification Gate v1

This example applies existing EMILIA primitives to one consequential action: promoting a self-modified agent candidate into a live target.

It does not define a new protocol. It composes:

- a local CAID definition for the exact candidate, base artifact, change, evaluator profile, target, and policy;
- the existing Autonomy Control Plane compiler for human-rooted authority, bounded child actions, distinct proposer/evaluator/executor roles, fitness evidence, canary evidence, and rollback discipline;
- the existing Trust Program kernel for signed, freshness-bounded evidence stages and execution claim state;
- a BCR capability allowance for one `SELF_EDIT` promotion unit;
- Gate verification of an exact-action Class-A receipt before provider entry; and
- the existing capability state machine for reservation, one admitted provider attempt, replay fencing, and `INDETERMINATE` after a lost provider acknowledgement.

Run it:

```bash
npm run test:self-modification-gate
npm run demo:self-modification-gate
```

The demo emits a machine-readable six-case report. The executable hostile cases cover candidate substitution, evaluator-suite drift, candidate edits to the evaluator or Gate, a fresh operation identifier for an already promoted candidate, and an unknown provider outcome followed by a blind retry.

## Security boundary

The protected action is **promotion**, not candidate generation or benchmark execution. An evaluator can describe a candidate. It does not authorize deployment. Workload identity and attestation can establish facts about the current candidate or executor. They do not replace exact-action authority.

The example requires a separately controlled evaluator and refuses a candidate whose changed paths overlap the evaluator, Gate, trust roots, or the workflow that enforces promotion. An evaluator change is a separate meta-action with separate authority. This is a relying-party policy encoded in the pinned fitness policy, not a universal path taxonomy.

The exact promotion receipt is candidate-specific. The broader root objective and budgets constrain the surrounding loop but are not treated as approval of a future unknown candidate.

## Honest limits

- The stores are in-memory demonstration stores. The one-attempt claim applies only inside this one authority domain. Production requires the existing durable Gate and BCR stores.
- The example records one admitted provider attempt, not exactly-once physical execution.
- `INDETERMINATE` preserves uncertainty. It does not prove failure, success, or legal effect.
- Signed fitness evidence proves the configured verifier emitted the report. It does not prove the evaluator is adequate or truthful.
- The runtime capability accounts for one promotion occurrence. The Autonomy Control Plane profile statically checks both calls and cents, but this example does not demonstrate independent durable enforcement of a compute-cost ceiling. That requires a second capability or a separately conserved cost allocation.
- The local action definitions are experimental and are not registered CAID action types.
- This is an internal reference implementation, not external reproduction, adoption, or evidence of willingness to pay.

## Framework mapping

For DGM, AlphaEvolve, OpenEvolve, or another evolutionary loop, the integration point is after candidate selection and before a live alias, deployment, model pointer, prompt bundle, tool set, or agent scaffold changes. Framework-native evaluation remains an evidence input. EMILIA does not replace candidate search, evaluation, sandboxing, software provenance, or artifact signing.
