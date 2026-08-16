# Current-bundle clean-room v2

The v2 clean-room infrastructure freezes the exact current conformance input
listed below. These pins move only when the current manifest changes; an
immutable source commit is supplied separately when the kit is built:

- 21 counted suites;
- 331 counted vectors;
- current manifest byte SHA-256
  `42a3a40114f30c03c828bd636d35341e9d859ad7a7879d1f572c57253f02bd32`;
- current manifest canonical claim SHA-256
  `ee114872a87fd467dcb4e521b0d1338f49273641e2c6200c666c1acff02f67c8`;
  and
- Authority Document execution companion SHA-256
  `121a358459ffed223a41a79570cc5307693eaa89a59b3ad330710c5e2f286959`.

This is conformance and intake infrastructure. It does not assert that any
implementation is external or independently constructed.

## Build the source-free kit

Run from an immutable repository checkout:

```sh
node --import ./scripts/ts-loader/register.mjs \
  scripts/build-clean-room-kit-v2.mts \
  --ref HEAD \
  --out /tmp/emilia-clean-room-kit-v2.tar.gz
```

The builder reads only an explicit 30-file allowlist. It refuses `app/`, `lib/`,
`packages/`, `scripts/`, and `conformance/runners/`; verifies every current
manifest, suite, and companion hash; writes the archive twice; requires
byte-identical SHA-256 values; and emits
`/tmp/emilia-clean-room-kit-v2.tar.gz.manifest.json`.

The kit contains the v2 instructions and schemas, the exact current conformance
manifest, the 21 suite files, and the separately counted Authority execution
companion. It contains no reference implementation or runner.

## Runner contract

The submitted artifact implements `EP-CONFORMANCE-FILE-RUNNER-v2`. It is
invoked once for every counted suite:

```text
/path/to/runner [fixed arguments...] /absolute/path/to/execution-suite.json
```

It writes only:

```json
[
  {
    "id": "vector-id",
    "result": {
      "valid": true
    }
  }
]
```

`result` is always a typed object, never a bare boolean. For each suite, the
evaluator requires every expected ID once, refuses missing, unknown, or
duplicate IDs, and compares the complete typed object. Extra or truncated
result fields are failures.

The public Authority Document catalogue remains the counted 26-vector suite.
The runner receives its byte-pinned execution companion so the result contract
includes the complete machine result plus proof, document-chain, and result
digests.

## Submission and runner immutability

The submission conforms to
`conformance/clean-room/v2/submission.schema.json`. It pins:

- an immutable source commit and source tree object;
- the runner artifact SHA-256 and fixed arguments;
- the v2 bundle hash;
- both current-manifest hashes; and
- the Authority Document execution companion hash.

The evaluator requires the runner to be a regular executable with no filesystem
write bits. It verifies the runner hash before and after every suite. It also
executes a read-only copy of each pinned suite and refuses suite mutation.

## Separate independent-attestor input

Construction acceptance is not embedded in the submission. A different file,
conforming to
`conformance/clean-room/v2/independent-attestation.schema.json`, binds the
canonical submission digest, implementation identity and team, immutable source
commit, runner artifact, bundle, manifest, and Authority companion.

The attestor signs the canonical JSON serialization of the complete attestation
object with `signature` omitted. The algorithm is Ed25519. The evaluator pins
the public key separately using
`conformance/clean-room/v2/trusted-attestors.schema.json`.

The evaluator refuses:

- unsigned construction claims;
- invalid or unpinned signatures;
- an attestor organization or team matching the implementation;
- EMILIA-affiliated implementation or attestor claims;
- any signed claim that differs from the submission; and
- any claim that does not state `reference_source_access: "none"` and
  `emilia_affiliation: "none"`.

Without the separate attestation, successful vector execution remains a
conformance result and `acceptance.accepted` remains `false`.

## Verify a submission

Conformance-only evaluation, with acceptance left false:

```sh
node --import ./scripts/ts-loader/register.mjs \
  scripts/verify-clean-room-submission-v2.mts \
  --manifest /path/to/submission.json \
  --runner /path/to/read-only-runner \
  --emit /tmp/evaluation.json
```

Require a separately signed and independently pinned construction claim:

```sh
node --import ./scripts/ts-loader/register.mjs \
  scripts/verify-clean-room-submission-v2.mts \
  --manifest /path/to/submission.json \
  --runner /path/to/read-only-runner \
  --attestation /path/to/independent-attestation.json \
  --trusted-attestors /path/to/evaluator-controlled-pins.json \
  --require-acceptance \
  --emit /tmp/evaluation.json
```

For a Git checkout and source-tree pin, use the external evaluator:

```sh
node --import ./scripts/ts-loader/register.mjs \
  scripts/evaluate-external-implementation-v2.mts \
  --manifest /path/to/submission.json \
  --source /path/to/implementation-checkout \
  --runner /path/to/read-only-runner \
  --attestation /path/to/independent-attestation.json \
  --trusted-attestors /path/to/evaluator-controlled-pins.json \
  --emit /tmp/external-evaluation.json
```

The resulting acceptance records a verified signature over a bounded
construction claim. It is not a security proof, certification, or proof that
the factual claim is true.
