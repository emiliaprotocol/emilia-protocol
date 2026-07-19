<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security-kernel mutation status

Mutation testing is a regression oracle, not a proof of security. The enforced
scope is deliberately limited to the decision-bearing portions of:

- `packages/verify/reliance.js`
- `lib/authority/resolver.js`
- `packages/gate/breakglass.js`
- `packages/gate/execution-binding.js`
- `packages/gate/index.js`
- `packages/gate/key-registry.js`
- `packages/gate/store.js`

The ratcheted baseline, measured on 2026-07-16 with Stryker 9.6.1 over the full
decision ranges in `stryker.security.config.js`, is:

| Measure | Result |
|---|---:|
| Instrumented mutants | 2,023 |
| Classified mutants | 1,729 |
| Killed | 1,562 |
| Timed out | 0 |
| Survived | 154 |
| No coverage | 13 |
| Total mutation score | 90.34% |
| Covered mutation score | 91.03% |

`stryker.security.config.js` enforces a 90% breaking floor. Raising the floor
requires a checked-in test that kills meaningful decision mutations; excluding
a mutation merely to improve the score is not an acceptable change.
String-literal mutations are excluded because reason prose is not the security
decision; exact closed verdicts and selected refusal contracts are asserted by
the conformance and unit tests. The full security suite runs against every
mutant so table-driven protocol vectors cannot be under-attributed by per-test
coverage analysis. The bounded-delegation decrement mutation is now killed by
the exact seven-edge/eight-edge boundary oracle rather than timing out.
The Gate slice is pinned to the decision-bearing predicates for break-glass
policy and execution ordering, canonical execution binding, strict key-window
evaluation, and durable ownership-fenced permanent consumption. Its dedicated
oracles live in `tests/gate-security-remediation.test.js` and
`tests/gate-execution-binding-failclosed.test.js`.

Run the gate with:

```sh
npm run test:mutation:security
```

The generated JSON report is intentionally untracked. CI is the durable record
of each run and uploads the report as an artifact.
