<!-- SPDX-License-Identifier: Apache-2.0 -->
# AuthZEN COAZ-MCP: local PEP/executor reference profile

This package tests the boundary between an AuthZEN policy decision and the
exact action a local executor sends to a provider. It contains a source-pinned
preflight model and a separate callback-based executor with adversarial tests.
It is an EMILIA proposal, not an OpenID specification or conformance certification.

## Run the complete package

From the repository root, with Node.js 24 or 26. No package installation,
credentials, network service, or unpublished compiler is required:

```sh
node --test conformance/composition/authzen-coaz-mcp-aeb-v0.1/run.node-test.mjs conformance/composition/authzen-coaz-mcp-aeb-v0.1/executor-profile.node-test.mjs
node conformance/composition/authzen-coaz-mcp-aeb-v0.1/check.mjs
```

The second command verifies the locked source bytes and compares both newly
executed reports with their checked-in references. It does not regenerate them.
The dedicated GitHub workflow runs the same commands on Node.js 24 and 26.

## The four enforcement questions

| Case | Executable check |
| --- | --- |
| Beneficiary provenance | The expected full action comes from a separately signed record whose digest, source key, audience, subject, client, operation, provider, mapping and validity window are pinned by the executor owner at construction. A changed beneficiary still receives the toy PDP's coarse allow, but never enters the provider callback. |
| Post-entry timeout | The reservation is made synchronously before invoking the callback. A timeout, thrown error, or unverifiable response leaves the operation `INDETERMINATE`. |
| Blind retry | Concurrent attempts and retries encounter the same non-reusable provider/operation reservation. Changing a call ID cannot create another entry. |
| Mismatched reconciliation | Reconciliation calls the captured provider interface, verifies its signature and exact bindings, and never invokes execution. Wrong-provider or wrong-action evidence leaves the original reservation unresolved. |

The tests also exercise source substitution, transaction-level configuration
spoofing, malformed evidence, stale evidence, pinned-key and interface changes,
and successful reconciliation. A signed `NOT_COMMITTED` result still does not
release the reservation for another attempt.

## What runs, and what is a model

`run.mjs` retains the nine translation/preflight/lifecycle-model cases. Its
strict `{ observation, attestation }` envelope binds the local PEP observation
to the full action, mapping and observed request/response. The published native
attestation bridge verifies the local signature and correspondence. The
published AEB evaluator reports evidence and role matching; an allow cannot
fill a named-human requirement. Native replay keys do not depend on a wrapper
reference.

The evaluation is deliberately unsigned: `valid:false` and
`evaluation_signature_required` remain visible. Its locally derived evidence
record is not an accepted credential or authorization. The consequence kernel
models lifecycle transitions over supplied state. Its authenticated
reconciliation flag is a fixture assumption, not provider-signature verification.

`executor-profile.mjs` supplies the separate executable check: it reserves
in local memory, invokes an instrumented callback, counts actual callback
entries, and verifies signed provider evidence. It reuses the published COAZ
mapping and toy PDP, not an external AuthZEN service. It does not turn the
preflight model into a deployed adapter.

## Trust and integration contract

`createExecutorProfile(config)` takes the trusted configuration once. Its
`source` contains the signed expected-action record and exact record digest.
Its `provider` contains the pinned evidence profile, identity, key, audience,
`invoke` callback and `reconcile` callback. The executor also captures the
machine context, clock, timeout and freshness bound. See `TEST_ONLY_fixture()`
for a runnable example; its names and keys are explicitly test-only.

The transaction interface accepts only `{ operation_id, call }`.
`reconcile(operationId)` retrieves evidence through the captured interface;
it does not accept a caller's `authenticated:true` assertion. Provider-specific
transport and evidence acquisition remain the deployment's responsibility.
The state transitions, verification and refusal behavior are in this profile.

The configured source must be controlled independently of the untrusted
caller/translator. A signature proves what that pinned source stated, not
whether the beneficiary is correct in the world. The same-team test fixture
creates both example inputs; it demonstrates separation and tamper refusal at
the API boundary, not organizational independence or independent beneficiary
truth. A deployment that lets the same untrusted adapter choose both the
expected action and its trust pins has not met this contract.

The reservation domain is **one live executor instance**. Recreating the
instance or restarting the process loses its memory. Production integration
must provide durable atomic custody shared by every execution path, retain
reservations across recovery, and prevent bypass. This package establishes
none of those deployment properties. Captured callback references prevent
configuration replacement; they do not attest the callback's implementation.

An AuthZEN allow remains machine-policy input, not human approval, authority
for an arbitrary material action, or proof of execution. An implementation
can omit this proposed profile, but then cannot claim its exact-action and
single-attempt properties based on AuthZEN compliance alone. No optional
profile can prevent a deployment from bypassing its own executor.

## Reproducibility and limits

`source-lock.json` records the public dependency base, inherited historical
OpenID source pins, mapping digest, and local dependency hashes. It does not
claim the upstream drafts or issue status are current. Both reference reports
are same-team results. No real payment, physical effect, deployed gateway,
independent implementation, distributed store, or standards acceptance is claimed.
The deterministic fixture keys are public and must never protect real operations.

Maintainers must review source changes before deliberately refreshing pins
and reports. These commands are not part of the checking path:

```sh
node conformance/composition/authzen-coaz-mcp-aeb-v0.1/refresh-source-lock.mjs
node conformance/composition/authzen-coaz-mcp-aeb-v0.1/check.mjs --emit
node conformance/composition/authzen-coaz-mcp-aeb-v0.1/check.mjs
```
