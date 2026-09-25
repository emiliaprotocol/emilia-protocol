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
then walks its own model of the consequence lifecycle: stable replay identity,
an exact-action fence, atomic reservation, provider entry, terminal or
indeterminate outcome, and authenticated reconciliation. The model derives the
replay unit from the pinned namespace, the native system, and the native
authority identifier; the profile label is not an input.

`run.mjs` is a standalone lifecycle model. It imports only Node.js built-ins
and implements its own in-memory store, handoff checks, and admission logic. It
does not import or execute `@emilia-protocol/verify` or `@emilia-protocol/gate`,
including `verifyAebNativeAuthorizationHandoff()` and
`createNativeConsequenceBoundary()`. Those packages are covered by their own
test suites, not by this corpus.

`vectors.json` is the shared synthetic corpus. It covers:

- exact-action admission and one-time use for every profile;
- material mutation, declared and undeclared normalization, and loss-aware
  mapping;
- audience, tenant, executor, provider, freshness, and revocation failures;
- tampering of the pinned local mandate signature;
- refreshed-wrapper replay and concurrent reservation;
- fresh native authority for an action whose first attempt is uncertain or
  already executed, which the exact-action fence refuses;
- one grant presented under a second pinned label, which is spent once;
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
this standalone lifecycle runner over these checked-in fixtures only. It is not
evidence about the shipped Verify or Gate packages.
