<!-- SPDX-License-Identifier: Apache-2.0 -->
# Cedulon Mizan leaked-refusal × EMILIA Outcome Binding v0.1

This fixture gives Cedulon and EMILIA one small, reproducible case to read in
their own formats. It copies the exact `leaked-refusal` policy and JSONL bytes
from Cedulon commit
`06c3119badc269ef5d6d3596ea3b3d48219d6ba4`, checks their pinned SHA-256
digests before parsing, and projects them through an EMILIA-owned adapter.

The source decision says `silent`, which the pinned Mizan adapter maps to
`deny`, while the sent log contains an effect on the same `id`. The EMILIA
projection is deliberately closed:

| Pinned source | EMILIA test projection |
| --- | --- |
| `verdict: "silent"` | `decision: "deny"` |
| refusal `id` | `target: "cedulon:mizan-ig:ref:<id>"` |
| refusal | `absent` predicate |
| sent-row `id` | the same namespaced observed-effect `target` |
| pinned Mizan class | `effect_type: "ig-dm-reply"` |
| SHA-256 of sent `text` | observed-effect `value` |

The adapter then creates two separate, fixture-only native inputs:

1. a deterministic test-signed Trust Receipt carrying only the
   reconciliation exercise and the mapped `absent` prediction; and
2. a deterministic test-signed `EP-OUTCOME-OBSERVATION-v1` with role
   `system_of_record`, not `independent_observer`.

`verifyOutcomeBindingSet` performs the full current Trust Receipt and Outcome
Observation verification. Both native signatures and their exact bindings
verify. The reconciled Outcome Binding verdict is `divergent` because one
matching effect exists where the mapped prediction requires none.

## Run

```bash
node --test conformance/composition/cedulon-mizan-leaked-refusal-v0.1/run.node-test.mjs
node conformance/composition/cedulon-mizan-leaked-refusal-v0.1/run.mjs --check
```

The result lock pins:

- Outcome Binding result:
  `sha256:80d9c6f5f2c6fd57eb0931044fc8d530c3fc34fbe11d8611c14aee9145486a15`
- complete harness report:
  `sha256:56eeb27a388ce7dbf7515cc85ec5bccb29a643ef097fb0d02b0385d26c8f8b37`

The tests also refuse source-byte drift, a decision/effect reference
substitution at the mapping seam, source-lock metadata tampering, and
post-projection target tampering. The synthetic signed action and harness
report bind the pinned upstream adapter and decision-profile hashes in
addition to the three fixture-file hashes.

## Claim boundary

- The policy and JSONL inputs are unsigned source bytes. Their SHA-256 locks
  establish byte identity to the reviewed commit, not authenticity,
  completeness, or live-system provenance.
- The EP keys are deterministic and publicly reproducible test keys. They
  protect no secret and prove no real approver or source identity. Cedulon did
  not sign the EP artifacts, and EMILIA did not verify a native Cedulon
  Decision Record.
- Artifact timestamps are derived after the fact from the 2023 fixture. This
  run proves no temporal precommitment.
- This is one shared raw fixture with two separately owned adapters. It is not
  translation-free or native-format interoperability.
- `divergent` and Cedulon's `effect-against-refusal` are profile-local labels
  for the same pinned case. Neither result identifies which runtime component
  allowed the effect or proves complete mediation.
- The synthetic Trust Receipt identifies and signs only this reconciliation
  exercise. Verification establishes authenticity, not admission or execution
  authority. It does not authorize, retroactively validate, or reproduce the
  original send decision.
