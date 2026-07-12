<!-- SPDX-License-Identifier: Apache-2.0 -->
# AEC safety-critical mutation status

Mutation testing is a regression oracle, not a proof of security or a
certification for any particular operational use. The enforced scope covers the
decision-bearing portions of:

- `packages/verify/evidence-chain.js`, including the public fail-closed wrapper
- `packages/gate/aec-execution.js`
- the atomic shared-head log in `packages/gate/evidence.js`

The ratcheted baseline, measured on 2026-07-11 with Stryker 9.6.1 over the full
ranges in `stryker.aec.config.js`, is:

| Measure | Result |
|---|---:|
| Instrumented mutants | 1,963 |
| Classified mutants | 1,713 |
| Killed | 1,361 |
| Timed out | 12 |
| Survived | 308 |
| No coverage | 32 |
| Total mutation score | 80.15% |
| Covered mutation score | 81.68% |

`stryker.aec.config.js` enforces an 80% breaking floor. The initial campaign
scored 47.77%; tests and fixes raised the complete-boundary score without
excluding decision mutations. String-literal mutations are excluded because
reason prose is not the decision, while selected refusal reasons and every
closed decision field are asserted exactly. Timeout mutants count as detected,
as Stryker specifies; the JSON report preserves their locations for review.

The campaign covers real-signature role substitution vectors, isolated
acceptance predicates, hostile native inputs, exact refusal envelopes,
constructor-pinned verifier registries, post-construction method replacement,
single-use execution under concurrency, indeterminate effects, exact logger
acknowledgments, and atomic-log fork, rollback, malformed-history, candidate
substitution, and response-loss cases. It does not prove
authenticator custody, registry honesty, storage durability, semantic action
faithfulness, or that every physical effect path traverses the gate.

Run the gate with:

```sh
npm run test:mutation:aec
```

The generated JSON report is intentionally untracked. CI is the durable record
of each run and uploads the report as an artifact.
