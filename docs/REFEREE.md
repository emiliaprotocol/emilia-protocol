<!-- SPDX-License-Identifier: Apache-2.0 -->

# EMILIA Referee / AEB-1 offline self-test contract

**Status:** same-day offline self-test harness; not a production adapter,
mediator, authorization service, execution service, sandbox, audit, or
certification

EMILIA Referee runs a locally selected protocol runner against AEB-1 cases and
reports whether the runner produced the expected, closed result. It is a test
harness over the evidence-to-effect boundary. It does not sit in a production
request path.

Production adapter semantics remain in
[`AEB-ADAPTER-v1`](protocol/aeb-adapter-contract-v1.md). Production consequence
custody remains in [Gate Qualification v2](protocol/gate-qualification-v2.md)
and `AdmissionStore`. Referee neither implements nor replaces those surfaces.

## 1. Exact claim

A Referee result means only:

> For this self-test case, this locally selected executable, with this fixed
> argument vector and executable SHA-256, returned this strict JSON result
> within the recorded limits.

The result always carries:

```json
{
  "claim_scope": "SELF_TEST",
  "execution_authorizing": false,
  "remote_atomicity_claimed": false
}
```

`CONFORMANT` is a test verdict. It is not a live `ALLOW`, `AUTHORIZED`,
`RESERVED`, `INVOKING`, or `EXECUTED` decision.

## 2. Four separate evidence dimensions

Runner reports MUST preserve these dimensions separately:

| Dimension | Question answered | Does not mean |
| --- | --- | --- |
| Native verification | Did the artifact verify under the native protocol? | The relying party accepts its signer, status, or trust path |
| RP acceptance | Does the runner claim the relying party accepted the verified result under the supplied pins? | The action matches or the evidence requirement is satisfied |
| CAID/action match | Do the reported CAID and normalized action digest match the expected exact action? | The required evidence set is complete |
| AEC satisfaction | Does the runner claim the pinned evidence requirement is satisfied? | Local authorization or permission to execute |

The four labels are reported independently:

```text
native_verification = VERIFIED
rp_acceptance      = ACCEPTED
caid_action_match  = MATCH
aec_satisfaction   = SATISFIED
```

Referee records and compares these claims; it does not perform native
verification, relying-party acceptance, or AEC evaluation itself. It also does
not infer one dimension from another. The aligned example above is not a
causal chain. A native `VERIFIED` result with rejected
or indeterminate RP acceptance cannot become `SATISFIED` merely because the
CAID matches.

CAID remains a typed content join key, not a capability. AEC remains evidence
composition, not authorization.

## 3. Local runner pin

The one-case core receives a closed `runner_pin` containing:

- an absolute executable path;
- the expected lowercase SHA-256 of the executable bytes; and
- a complete fixed argument vector.

The harness reads the executable, verifies that SHA-256 before each spawn, and
then invokes the absolute path directly. It does not use a shell or PATH lookup.
A missing file, digest mismatch, spawn failure, nonzero exit, timeout, abort,
malformed output, or output-schema failure produces a non-authorizing
`INDETERMINATE` result.

The pin identifies the command executable bytes checked for this local
self-test. It does not hash a script or module merely because that path appears
in `args`, eliminate replacement races between the read and spawn operations,
establish who authored the code, prove the source matches, or prove the same
bytes are deployed elsewhere.

The runner's protocol-specific evidence and trust inputs are opaque JSON in
the request's `input` member. The caller selects those inputs. Referee does not
discover trust roots, fetch status, choose a mapping profile, or turn keys
carried by an artifact into relying-party trust.

## 4. One-case strict JSON subprocess

The host starts one runner for one case:

```text
/absolute/path/to/runner [fixed arguments...]
```

It writes exactly one strict UTF-8 JSON document to stdin and closes stdin. The
runner writes exactly one strict UTF-8 JSON document to stdout. Stderr is
diagnostic only and is never evidence.

The transport rejects duplicate keys, invalid UTF-8, malformed JSON, unknown
top-level fields, schema-invalid values, trailing documents, output after a
nonzero exit, and I/O over the implemented byte ceilings. Process exit status
never becomes a semantic verdict; a native rejection is a normal JSON result
from a process that exits zero.

### Request

`EP-REFEREE-RUNNER-REQUEST-v1` is closed and contains only:

```json
{
  "version": "EP-REFEREE-RUNNER-REQUEST-v1",
  "case_id": "case:payment-release-1",
  "protocol_id": "protocol:example-v1",
  "expected_caid": "caid:1:payment.release.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "expected_action_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "aec_required": true,
  "execution_scope": "local_atomic",
  "input": {
    "artifact": "opaque-native-protocol-input",
    "relying_party_configuration": "opaque-runner-specific-input"
  }
}
```

`execution_scope` is `local_atomic` or `federated`. The request is
authoritative for the case, protocol, expected action, AEC requirement, and
scope. Echoed output metadata cannot replace it.

### Output

`EP-REFEREE-RUNNER-OUTPUT-v1` is closed and reports test dimensions only:

```json
{
  "version": "EP-REFEREE-RUNNER-OUTPUT-v1",
  "case_id": "case:payment-release-1",
  "protocol_id": "protocol:example-v1",
  "native_verification": "VERIFIED",
  "rp_acceptance": "ACCEPTED",
  "caid": "caid:1:payment.release.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "action_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "aec_satisfaction": "SATISFIED",
  "provider_outcome": "NOT_ASSESSED",
  "effect_relation": "NOT_ASSESSED",
  "execution_scope": "local_atomic"
}
```

The native, RP-acceptance, action-match, and AEC dimensions remain separate in
`EP-REFEREE-RESULT-v1`. Unknown output fields are refused. In particular, the
runner cannot add `authorized`, `authorization`, `executed`, an AdmissionStore
owner token, or an invocation capability.

The one-case core accepts these exact dimension values:

| Dimension | Values |
| --- | --- |
| `native_verification` | `VERIFIED`, `REJECTED`, `INDETERMINATE` |
| `rp_acceptance` | `ACCEPTED`, `REJECTED`, `INDETERMINATE` |
| derived action relation | `MATCH`, `MISMATCH`, `INDETERMINATE` |
| `aec_satisfaction` | `SATISFIED`, `NOT_SATISFIED`, `INDETERMINATE`, `NOT_ASSESSED` |

The governed external schema uses `FAILED` rather than `REJECTED` for its
native-verification negative value and `EXACT_MATCH` rather than `MATCH` for
its action relation. The harnesses do not silently interchange vocabularies.

Every runner failure maps to `INDETERMINATE`, with native verification, RP
acceptance, and action match indeterminate; required AEC indeterminate; and
provider/effect facts not assessed. The result remains `SELF_TEST` and
`execution_authorizing: false`.

## 5. Implemented transport ceilings

The one-case core enforces these exact constants:

| Resource | Implemented ceiling |
| --- | ---: |
| Serialized request written to stdin | 8 MiB |
| Combined stdout and stderr | 8 MiB |
| Invocation timeout | 300,000 ms |
| JSON nesting depth | 64 |
| Identifier | 512 UTF-8 bytes |
| Absolute executable path | 4 KiB |
| Runner arguments | 256 |
| One runner argument | 64 KiB |
| Complete argument vector | 1 MiB |

The caller selects a timeout from 1 through 300,000 ms. The child is terminated
on timeout or caller abort. The transport starts with `env: {}`, uses the
filesystem root as cwd, disables the shell, and captures stdout/stderr.

These controls are not an operating-system sandbox. Referee does **not** block
network access, filesystem access, syscalls, or child-process creation. A
runner has whatever access the operating-system identity and surrounding
deployment allow. The harness must therefore be used only with locally trusted
test executables in an appropriately isolated environment.

## 6. Governed AEB-1 manifest

The checked-in external self-test surface lives under
[`conformance/referee/`](../conformance/referee/):

- `AEB-1-REFEREE-MANIFEST-v1` contains the closed cases, expected results,
  schemas, and limits.
- `AEB-1-REFEREE-CASE-v1` is the JSON object written to the external runner.
- `AEB-1-REFEREE-RUNNER-RESULT-v1` is the required stdout object.
- `AEB-1-REFEREE-REPORT-v1` binds the manifest, command, deterministic reruns,
  per-case comparisons, summary, and fixed false claim boundary.

The current checked-in manifest contains 13 self-test cases and pins these
limits:

| Resource | Current manifest value |
| --- | ---: |
| Maximum cases | 32 |
| One case | 65,536 bytes |
| One runner result | 16,384 bytes |
| Stderr | 4,096 bytes |
| Complete report | 262,144 bytes |
| JSON nesting depth | 16 |
| One case timeout | 500 ms |
| Deterministic runs per case | 2 |

The cases exercise exact action match, RP-acceptance rejection, material loss,
wrong trust root, stale or unavailable status, stable replay identity, provider
timeout/crash, authenticated reconciliation, committed-plus-diverged effect,
and proven non-commit. They test the runner's reported behavior; they do not
perform a real provider call or production admission.

The Referee manifest is separate from
`conformance/conformance-manifest.json`. Its 13 cases MUST NOT be added to the
current cross-language suite/vector totals or to the external Rust baseline.

## 7. Provider outcome and observed effect

The self-test keeps provider commitment separate from observed effect:

- provider: `COMMITTED`, `PROVEN_NOT_COMMITTED`, `INDETERMINATE`, or not yet
  assessed/invoked;
- effect: `OBSERVED_AS_REQUESTED`, `DIVERGED`, `INDETERMINATE`, or not yet
  assessed/observed.

The fixture `committed-diverged` pins the valid combination `COMMITTED` plus
`DIVERGED`. A timeout or crash pins both axes to `INDETERMINATE`, requires
reconciliation, and refuses blind retry. `PROVEN_NOT_COMMITTED` does not become
an observed-effect claim.

These are expected self-test outputs. Referee does not contact a provider,
authenticate reconciliation evidence, or observe an effect itself.

## 8. `local_atomic` and federated scope

The governed AEB-1 manifest tests the `local_atomic` profile. This means the
runner is expected to report behavior consistent with one local consequence
owner's atomic custody boundary. A passing self-test does not prove that an
operated deployment has a linearizable, durable AdmissionStore or complete
mediation.

The one-case core may record `execution_scope: "federated"`, but every Referee
result fixes `remote_atomicity_claimed: false`. Referee does not implement
distributed atomic commit, cross-domain leases, financial release,
reconciliation, or global exactly-once execution.

In production, a federated design still needs one consequence-owning domain
whose final `beginInvocation()` is `local_atomic`. That production rule belongs
to Gate Qualification v2 and AdmissionStore, not to Referee.

## 9. No hosted code service and no production mediation

This repository does not expose Referee as a hosted arbitrary-code runner. The
implemented API is local and accepts a caller-selected executable. It MUST NOT
be placed behind an untrusted remote endpoint that lets users submit commands,
paths, arguments, packages, containers, repositories, URLs, or source code.

Referee does not:

- mediate a production request or prove complete mediation;
- perform native verification, RP acceptance, CAID mapping, or AEC composition
  on behalf of the runner;
- authorize, reserve, invoke, retry, reconcile, or remedy a live operation;
- hold AdmissionStore owner/invocation capabilities or provider credentials;
- sandbox network access, syscalls, files, or descendants; or
- issue an audit, certification, legal opinion, or deployment attestation.

Use [`AEB-ADAPTER-v1`](protocol/aeb-adapter-contract-v1.md) for production
adapter semantics and [Gate Qualification v2](protocol/gate-qualification-v2.md)
for the actual authorization/admission/custody boundary.

## 10. Claim boundary

A passing report proves only reproducible agreement with the exact manifest
and expected results under the recorded local command, executable digest,
inputs, limits, and run count. It does not prove code provenance, independence,
production deployment, complete mediation, durability, authorization,
provider truth, effect truth, safety, legality, wisdom, or adoption.

An independent party may re-run and provenance-bind the same manifest. That
separate evidence must name its party, exact executable digest, inputs, and
scope. Referee and AEB-1 do not appoint EMILIA as a certification authority.
