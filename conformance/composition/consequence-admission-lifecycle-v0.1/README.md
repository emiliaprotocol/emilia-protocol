# Consequence-admission lifecycle composition

This focused suite tests the work that remains **after** a native authority
system has already permitted one exact action. Four synthetic adapter-result
profiles enter the same residual lifecycle:

- AuthZEN/COAZ-MCP, where the native PDP and PEP own the authorization
  decision;
- AP2, where the native AP2 verifier and relying-party policy own mandate
  acceptance;
- an OAuth Transaction Token, where the Transaction Token Service issues the
  token and the accepting protected workload owns its authorization decision;
  and
- a locally verified Ed25519-signed mandate.

The runner does not turn AEB into another policy decision point. It consumes a
closed native verifier result, checks the synthetic handoff and exact bindings,
then exercises the consequence boundary: stable replay identity, atomic
reservation, provider entry, terminal or indeterminate outcome, and
authenticated reconciliation.

`vectors.json` is the shared synthetic corpus. It covers:

- exact-action admission and one-time use for every profile;
- material mutation, declared and undeclared normalization, and loss-aware
  mapping;
- audience, tenant, executor, provider, freshness, and revocation failures;
- tampering of the pinned local mandate signature;
- refreshed-wrapper replay and concurrent reservation;
- safe recovery before provider entry versus sticky uncertainty after entry;
- authenticated same-provider, same-operation, same-action reconciliation; and
- explicit disclosure of a known path outside the configured gate.

## Run

```sh
node --test conformance/composition/consequence-admission-lifecycle-v0.1/run.node-test.mjs
node conformance/composition/consequence-admission-lifecycle-v0.1/run.mjs
```

## Claim boundary

The AuthZEN, AP2, and OAuth inputs are synthetic closed results that begin after
native verification and authorization. This suite does not implement those
protocols, repeat their policy decisions, or establish native conformance,
adoption, deployment, certification, independent interoperability, provider
success, or exactly-once physical effect. It proves deterministic behavior of
the EMILIA reference lifecycle runner over these checked-in fixtures only.
