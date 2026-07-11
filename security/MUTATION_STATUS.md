<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security-kernel mutation status

Mutation testing is a regression oracle, not a proof of security. The enforced
scope is deliberately limited to the decision-bearing portions of:

- `packages/verify/reliance.js`
- `lib/authority/resolver.js`
- `packages/gate/store.js`

The ratcheted baseline, measured on 2026-07-10 with Stryker 9.6.1 over the full
decision ranges in `stryker.security.config.js`, is:

| Measure | Result |
|---|---:|
| Instrumented mutants | 1,662 |
| Classified mutants | 1,415 |
| Killed | 1,275 |
| Timed out | 0 |
| Survived | 132 |
| No coverage | 8 |
| Total mutation score | 90.11% |
| Covered mutation score | 90.62% |

`stryker.security.config.js` enforces a 90% breaking floor. Raising the floor
requires a checked-in test that kills meaningful decision mutations; excluding
a mutation merely to improve the score is not an acceptable change.
String-literal mutations are excluded because reason prose is not the security
decision; exact closed verdicts and selected refusal contracts are asserted by
the conformance and unit tests. The full security suite runs against every
mutant so table-driven protocol vectors cannot be under-attributed by per-test
coverage analysis. The bounded-delegation decrement mutation is now killed by
the exact seven-edge/eight-edge boundary oracle rather than timing out.

Run the gate with:

```sh
npm run test:mutation:security
```

The generated JSON report is intentionally untracked. CI is the durable record
of each run and uploads the report as an artifact.
