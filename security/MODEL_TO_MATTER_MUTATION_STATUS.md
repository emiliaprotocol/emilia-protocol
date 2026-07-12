<!-- SPDX-License-Identifier: Apache-2.0 -->
# Model-to-Matter mutation status

Mutation testing is a regression oracle, not proof of scientific safety,
physical truth, or fitness for any particular executor. The enforced scope is
the complete decision-bearing surface of `lib/frontier/model-to-matter.js`:
action and profile validation, evidence signing and acceptance, claim-to-action
joins, graph admission, challenge and action consumption, the constructor-pinned
executor, clearance verdicts, and executor effect statements.

The ratcheted baseline, measured on 2026-07-12 with Stryker 9.6.1 over the range
in `stryker.model-to-matter.config.js`, is:

| Measure | Result |
|---|---:|
| Instrumented mutants | 1,299 |
| Classified mutants | 953 |
| Killed | 765 |
| Timed out | 0 |
| Survived | 164 |
| No coverage | 24 |
| Total mutation score | 80.27% |
| Covered mutation score | 82.35% |

The initial full-range campaign scored 73.45%. Exact claim-to-action join,
timestamp, assurance, and closed-verdict oracles raised it above the enforced
80% floor without excluding decision mutations. String-literal mutations are
excluded; closed verdict values and selected refusal reasons are asserted
exactly. The generated JSON report remains the detailed record of surviving and
uncovered mutants.

The campaign does not establish that evidence issuers make correct judgments,
that revocation views are complete, that a backend's durability assertion is
true, that an approver understood the action, or that all physical paths
traverse the executor.

Run the gate with:

```sh
npm run test:mutation:model-to-matter
```

The JSON report is intentionally untracked. CI uploads it as a retained
artifact.
