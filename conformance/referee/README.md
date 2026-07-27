<!-- SPDX-License-Identifier: Apache-2.0 -->

# AEB-1 Referee intake

This directory is the language-neutral intake surface for an AEB-1 Referee
self-test. A caller supplies a checked-in command as a JSON argv array. For
each pinned case, the harness writes exactly one strict JSON document to the
command's standard input and requires exactly one closed runner-result JSON
document on standard output.

The external command is invoked directly, never through a shell. Case bytes,
result bytes, standard error, JSON depth, execution time, argument count,
fixture count, report bytes, and deterministic repetitions are bounded by the
manifest. The caller pins the runtime executable's SHA-256; the harness
resolves and re-hashes those executable bytes immediately before every spawn.
The child receives an allowlisted environment without caller credential
variables.

Command arguments and the executable pin are recorded in the uploaded report.
They must never contain credentials; the Action does not accept or forward a
secret input.

These are deterministic self-test controls, not process isolation or a
production sandbox. A tested command may still access resources available to
its operating-system identity.

## Files

- `schemas/case.schema.json` closes the normalized Referee intake case.
- `schemas/runner-result.schema.json` closes one external result and keeps
  native verification, relying-party acceptance, exact-action relation,
  custody, provider commitment, and observed effect separate.
- `schemas/manifest.schema.json` closes the fixture and bounds manifest.
- `schemas/report.schema.json` closes the generated self-test report.
- `fixtures/manifest.json` pins 13 curated cases without adding them to the
  existing three-language conformance suite.
- `fixtures/reference-runner.mjs` is the checked-in self-test fixture command.

The fixtures cover exact match, exact-action mismatch, material-loss
indeterminacy, native verification under a wrong root, relying-party rejection,
stale and unavailable status, stable native replay identity across wrappers,
provider timeout, crash-to-indeterminate, authenticated reconciliation,
`COMMITTED` with `DIVERGED`, and `PROVEN_NOT_COMMITTED`.

## Protocol

The command receives one `AEB-1-REFEREE-CASE-v1` JSON document per process.
It must return one `AEB-1-REFEREE-RUNNER-RESULT-v1` document and no other
standard-output bytes. Diagnostic standard error is allowed only within its
bound and is never copied into the report.

The harness executes every case twice and compares canonical result bytes.
After validating all rows, it writes the report artifact and prints exactly:

```text
SELF_TEST
```

The report fixes `certification`, `authorization`, `production_deployment`,
and `production_sandbox` to `false`. `PROVEN_NOT_COMMITTED` closes the prior
custody record but requires a new admission; it never restores consumed
authority for a blind retry.

## Local reference run

Compute the SHA-256 of the Node executable at runtime, then invoke:

```sh
node scripts/run-referee-conformance.mjs \
  --manifest conformance/referee/fixtures/manifest.json \
  --report aeb-1-referee-report.json \
  --workspace . \
  --command-json '["node","conformance/referee/fixtures/reference-runner.mjs"]' \
  --executable-sha256 "sha256:<runtime-node-digest>"
```

The reusable Action additionally requires the command entrypoint to be a
non-symlink file tracked in the caller's checkout, present as argv position 0
or 1, and uploads the closed report as an artifact.
