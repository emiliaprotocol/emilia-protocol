<!-- SPDX-License-Identifier: Apache-2.0 -->

# Insight Oracle Swap v3 Crossing Lab

This is a deterministic, offline AEB Crossing Lab port for an Insight v3
oracle-safety receipt plus a version-2 swap authorization. It follows the
structure and trust boundaries of the CCS example in the adjacent directory.

## Focused fixes

- `mapAction`, `executeCrossing`, and the submitted call now use the same
  complete `evm-swap-exact-input-single.1` Action Object. They therefore return
  the same CAID and action digest instead of hashing different projections.
- A correctly signed authorization is accepted only when
  `authorizationVersion` is exactly `2`. Other versions, including `999`, are
  rejected with `UNSUPPORTED_AUTHORIZATION_VERSION`.

These findings did not demonstrate an unsigned authority bypass.

## Pinned bundle and restore

`adapter.mjs` is the sealed, single-file ESM adapter used by Crossing Lab. It
contains its runtime dependencies and makes no runtime network request or
dynamic sibling import. `package-lock.json` pins the build dependency graph;
`dependency-bundle.json` records the exact direct versions, input digests,
bundle digest, and byte size.

From this directory:

```sh
npm ci
npm run build
```

The generated digest in `adapter.sha256` and `dependency-bundle.json` must match
the `workspace.json` adapter pin. If the reviewed source or dependency graph is
deliberately changed, regenerate and reseal from the repository root:

```sh
node examples/aeb-crossing-lab/insight-oracle-swap-v3/prepare-workspace.mjs
node packages/verify/cli.js crossing-lab seal examples/aeb-crossing-lab/insight-oracle-swap-v3
```

## Verification

From the repository root:

```sh
node examples/aeb-crossing-lab/insight-oracle-swap-v3/regression-tests.mjs
node examples/aeb-crossing-lab/insight-oracle-swap-v3/aeb-contract-tests.test.mjs
node packages/verify/cli.js crossing-lab run examples/aeb-crossing-lab/insight-oracle-swap-v3
```

The standalone suite contains the original 15 checks plus focused regressions
for Action Object/CAID identity and the authorization-version pin. The contract
suite exercises the current repository AEB evaluator and verifier.

Before committing, the human contributor must use a DCO sign-off:

```sh
git commit -s
```

## Test-only disclosure and limits

All cryptographic keys are published synthetic Anvil test keys and must never
hold value or enter a production trust root. Times are fixed for deterministic
tests. Provider responses are mocked; no transaction is broadcast.

Passing this compatibility test does not establish transaction execution,
inclusion, finality, production deployment, certification, authorization, or
native-protocol equivalence.
