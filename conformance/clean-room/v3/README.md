# Expectation-separated clean-room evaluator v3

Version 3 fixes an integrity defect in the v2 evaluator without
reinterpreting any historical v2 result. The v2 evaluator handed the
runner each complete vector, including `id`, `description`, and `expect`. A
runner could therefore pass by copying `expect` without implementing EMILIA.

V3 uses the same current 21-suite, 340-vector corpus as the v2 input kit but changes the evaluation
protocol:

- expectations and original vector IDs stay in evaluator memory;
- the runner receives only execution fields under fresh, random, run-scoped
  handles;
- presentation-only fields are removed and vector order is randomized;
- the runner returns `{ "handle": ..., "result": { ... } }` rows; and
- after the submitted runner entrypoint is hashed and observed without write
  bits, the evaluator creates 80 fresh canonicalization cases: 32
  valid/wrong-digest pairs (64 cases) plus 16 raw-text boundary cases, eight
  valid and eight invalid.

## Current challenge

The paired inputs exercise UTF-16 key ordering, nested objects, combining
characters without normalization, and string escaping. Each input appears
with its correct digest and an independently derived, uniformly shaped wrong
digest. Regression tests cover a code-point-sorting canonicalizer that passed
challenge v1 but fails these richer pairs.

The raw-text cases preserve duplicate keys, surrogate escapes, number tokens,
and nesting depth. They distinguish valid boundaries from invalid ones:
negative zero (`-0` and `-0.0`) is valid and canonicalizes to `0`; paired
surrogates are valid, lone surrogates are not; duplicate decoded keys are
refused even when escaped differently. Numbers must be safe integers and
container depth must not exceed 64. Those numeric and depth limits are the
EP profile, not general RFC 8785 requirements. Invalid raw cases deliberately
have matching permissive-parser digests, so digest comparison alone cannot
pass them.

`EP-CLEAN-ROOM-CANONICALIZATION-CHALLENGE-v2` versions the generator and its
PRNG domain only. The v3 runner protocol, schemas, pinned 335-vector corpus, and
historical reports (including the external Rust results) keep their meaning.
`replayPostBuildChallengesV1` is for historical replay, not current submission
acceptance. The completed report records `paired_cases: 64` and
`raw_boundary_cases: 16` separately, with the seed, generator contract and its
SHA-256, evaluator artifact hash, exact execution bytes and their hash, and
accepted results.

The fresh cases also reject the old expectation-copy fixture and a fixed table
that refuses unknown inputs. Assuming the paired digests are computationally
indistinguishable, a single blind one-digest-per-pair guess succeeds with
probability 2^-32. This describes that guessing strategy, not overall security;
repeated attempts accumulate chances and are not rate-limited. Passing checks
only this canonicalization challenge. It does not establish that the other
20 suites compute their results rather than use tables.

## Runner protocol

The evaluator invokes:

```text
runner [fixed arguments...] /absolute/path/to/execution-suite.v3.json
```

Local execution is refused unless the operator passes the explicit
`--allow-unsafe-local-execution` acknowledgement. That flag acknowledges the
absence of host and network isolation; it does not create isolation. The child
receives only `PATH`, `LANG`, `LC_ALL`, and `TZ`, not the evaluator's inherited
credential-bearing environment.

The input conforms to `execution-suite.schema.json`. A vector has only an
opaque `handle` and an `input` object. It never contains its catalogue ID,
expected result, description, failure class, or mutation label. The runner
writes only:

```json
[
  {
    "handle": "cr3_opaque-run-scoped-value",
    "result": {
      "valid": true
    }
  }
]
```

The evaluator resolves handles and compares results against expectations that
were never written to the runner input.

The pinned currency suite previously embedded its asserted `expect_status`
inside each execution case. V3 removes that field too: the runner returns the
computed `currency_status`, and the evaluator compares it to the catalogue
assertion held evaluator-side outside that invocation.

## Submission and attestation

Use `submission.schema.json` and protocol
`EP-CONFORMANCE-FILE-RUNNER-v3`. V3 continues to use the separate v2
independent-attestation and trusted-attestor formats because those documents
already bind the complete submission digest, runner hash, implementation
identity, source commit, corpus pins, and construction claim. A v2 runner or v2
submission is not accepted by the v3 evaluator.

## Boundaries

The September 6 corpus refresh includes the completed-signoff Quorum profile
and five additional cases. Existing external reports and construction
attestations remain bound to their original corpus hashes, not this refresh.
The repository's fixture runs do not establish an independent implementation.

This evaluator checks the runner entrypoint before and after every invocation
and checks that each read-only execution input was not changed. Those checks
detect persistent drift at the check boundaries; they do not exclude transient
directory-entry replacement between hash and execution. Only the entrypoint
file and fixed-argument values are hashed, not argument target bytes, the
interpreter, or dynamic dependencies. It does **not** sandbox the process,
block network access, restrict reads of other filesystem paths, prove the
construction claim, or prove independent implementation. When those controls
are required, run the external source-tree evaluator inside a separately
controlled offline sandbox.

See `docs/conformance/CLEAN-ROOM-V3.md` for commands and the full claim scope.
