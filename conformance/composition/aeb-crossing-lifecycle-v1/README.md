# Canonical protected-consequence-boundary lifecycle

This deterministic profile sends two different native authority systems
through one Gate lifecycle contract:

- an authorization-server-issued OAuth transaction artifact; and
- an OASNT human-authorization artifact.

It proves exact-action mapping under relying-party pins, wrapper-independent
replay refusal, at-most-one provider entry, closed uncertainty, authenticated
reconciliation without reexecution, and preservation of native provenance.
It also verifies that a valid AEB Crossing Record remains nonauthorizing.

The profile does not assert that OAuth and OASNT have identical native
semantics. It shows that both can satisfy the same bounded verifier and
lifecycle contract while retaining different issuers, evidence roles,
constraints, signatures, and replay units.

## Run

```sh
npm --prefix packages/verify run build
npm --prefix packages/gate run build
npm run build:standalone-runtimes
node --test conformance/composition/aeb-crossing-lifecycle-v1/run.node-test.mjs
node conformance/composition/aeb-crossing-lifecycle-v1/run.mjs
```
