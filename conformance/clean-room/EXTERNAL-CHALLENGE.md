# EMILIA clean-room implementation challenge

Build a verifier without using EMILIA implementation source. Passing earns a
machine-verifiable conformance result; an independently signed submission earns
an externally attested clean-room result.

Use the standalone `emilia-clean-room-kit-v1.tar.gz` release artifact. It is
built from an immutable source commit, contains no EMILIA reference
implementation, and ships with a sidecar manifest binding the archive and every
included file by SHA-256. This is the preferred input path; cloning the full
EMILIA repository is unnecessary and weakens the clean-room record.

## Inputs

Candidates receive only:

- `specification-bundle.v1.json` and every byte-pinned document it names;
- `bundle.v1.json` and every byte-pinned conformance suite it names;
- `submission.schema.json`; and
- the runner protocol documented in `README.md`.

Do not inspect, translate, generate from, or link against `packages/`, `lib/`,
`app/`, `conformance/runners/`, or any EMILIA package artifact. Public
standards and general-purpose cryptographic libraries are allowed and must be
listed in the submission.

## Deliverable

Submit an immutable public source commit, build instructions, an executable
implementing `EP-CONFORMANCE-FILE-RUNNER-v1`, and a manifest conforming to
`submission.schema.json`. The manifest pins the executable artifact and fixed
arguments by SHA-256; the evaluator refuses substitutions before execution.
The implementation must use a language or codebase
not authored by an EMILIA maintainer. The evaluator runs with network access
disabled.

The independence statement must be Ed25519-signed by an evaluator-pinned
attestor who is neither EMILIA nor the implementation organization. The
attestor verifies author identity, the source commit, the supplied input set,
and the absence of EMILIA reference-source access. This authenticates the
claim; it does not prove the claim or the implementation correct.

Accepted implementations are named in the conformance report as founding
external ports and remain identified by their own organization, source commit,
license, and release artifact. EMILIA does not absorb their code or relabel the
work as an EMILIA implementation.

## Acceptance

```sh
node scripts/verify-clean-room-submission.mjs \
  --require-external \
  --manifest submission.json \
  --trusted-attestors evaluator-pins.json \
  --emit evaluation.json \
  -- ./verifier
```

Acceptance requires all byte-pinned suites to pass, an immutable source commit,
`reference_source_access: "none"`, `emilia_affiliation: "none"`, an exact
specification-bundle hash, and a valid independent attestation. A same-team
port, self-attestation, missing suite result, extra result, crash, network
dependency, or unpinned input is refused.

## Differential hostility

Accepted implementations are then added as an external runner to
`npm run conformance:hostility`. Agreement with EMILIA's three one-team ports
is reported separately from independence. Neither result is described as a
security proof.
