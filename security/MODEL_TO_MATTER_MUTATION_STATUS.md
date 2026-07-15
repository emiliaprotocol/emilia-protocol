<!-- SPDX-License-Identifier: Apache-2.0 -->
# Model-to-Matter mutation status

Mutation testing is a regression oracle, not proof of scientific safety,
physical truth, or fitness for any particular executor. The enforced scope is
every executable function in `lib/frontier/model-to-matter.js`, from hashing
through executor effect verification: action and profile validation, CAID
computation and binding, evidence signing and acceptance, claim-to-action joins,
graph admission, challenge and CAID-keyed action consumption, the
constructor-pinned executor, clearance verdicts, and executor effect statements.

The ratcheted baseline, measured on 2026-07-14 with Stryker 9.6.1 over the
executable-function range in `stryker.model-to-matter.config.js`, is:

| Measure | Result |
|---|---:|
| Instrumented mutants | 1,430 |
| Excluded string-literal mutants | 378 |
| Classified mutants | 1,052 |
| Killed | 865 |
| Timed out | 0 |
| Survived | 149 |
| No coverage | 38 |
| Total mutation score | 82.22% |
| Covered mutation score | 85.31% |

An earlier truncated range reported 82.09%; a subsequent whole-module campaign
exposed that omission by scoring 77.12%. The enforced range now includes every
executable function, including CAID computation and the full effect verifier.
Static frozen protocol tables and export aggregation are outside the mutation
range because Vitest initializes those ESM values before per-mutant activation;
their exact values are asserted directly, including a byte-for-byte comparison
between the M2M CAID definition and the public registry. String-literal
mutations are excluded; closed verdict values and selected refusal reasons are
asserted exactly. Exact CAID, claim-to-action, timestamp, assurance,
evidence-graph, partial-freeze, and closed-verdict oracles keep the executable
surface above the enforced 80% floor. The generated JSON report remains the
detailed record of surviving and uncovered mutants.

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
