# Expectation-separated clean-room evaluation v3

The v3 evaluator repairs the oracle channel in v2. It is a new protocol and
report version. Prior published v2 artifacts and reports remain pinned to
their original commit and hashes. The current input kits were refreshed on
September 6 for the Quorum repair; that does not upgrade any earlier result.

This is a partial integrity repair. It does not close issue #250 because it
does not isolate the runner from evaluator files, other host paths, or the
network.

V3 evaluates the same pinned 21-suite, 340-vector corpus. Before each runner
invocation it builds a new execution envelope that:

1. removes `expect`, the catalogue vector ID, descriptions, failure classes,
   and other top-level test commentary;
2. retains only the fields required to execute the case;
3. assigns an unpredictable 192-bit handle unrelated to the catalogue ID; and
4. shuffles the cases independently for that run.

The handle-to-ID and handle-to-expectation maps stay in evaluator memory during
runner invocation. The evaluator resolves returned handles, rejects unknown,
missing, or duplicate handles, and applies the complete typed expectation
itself. Completed reports disclose replay material only after execution.

One pinned suite needed an additional projection. Currency v2 stored
`expect_status` beside its execution arguments while its outer result was
always `valid: true`. V3 removes `expect_status` and requires the runner to
return the computed `currency_status`; only the evaluator compares that status
to the catalogue assertion.

## Post-build challenge

After the submitted runner entrypoint has been built, hashed, and observed
without write bits, the evaluator generates 80 fresh canonicalization cases:

- **64 paired cases:** 32 nonce-bearing inputs, each presented with its correct
  digest and an independently derived, uniformly shaped wrong digest. The
  inputs exercise UTF-16 key ordering, nested objects, combining characters
  without normalization, and string escaping.
- **16 raw-text boundary cases:** eight valid and eight invalid under the EP
  input profile. Raw JSON preserves number tokens, surrogate escapes, duplicate
  keys (including differently escaped names that decode to the same key), and
  container depth instead of losing those details through serialization.

Valid boundaries include `-0` and `-0.0`, both canonicalized to `0`, safe
integer-valued exponent forms, the largest safe integer, paired surrogates,
distinct escaped keys, and depth 64. Invalid boundaries include unsafe or
fractional numbers, an out-of-range exponent value, lone surrogates, duplicate
decoded keys, and depth 65. The safe-integer restriction and depth-64 limit
belong to the EP input profile; they are not general RFC 8785 requirements.
Every invalid raw case carries the digest a permissive parser and
canonicalizer would accept. A runner must reject the input itself, not pass
the test merely by finding a digest mismatch.

The current generator is `EP-CLEAN-ROOM-CANONICALIZATION-CHALLENGE-v2`.
This changes the challenge and its PRNG domain, not the v3 runner protocol,
schemas, or pinned 21-suite, 335-vector corpus. The exported
`replayPostBuildChallengesV1` function preserves historical challenge replay;
submission acceptance cannot select it. Historical reports, including the
external Rust results and their original pins, are not upgraded by this change.

Regression tests cover a Unicode code-point-sorting canonicalizer that passed
the v1 challenge but fails the current rich pairs, alongside normalization,
escaping, parser, and numeric-profile defects. The challenge also rejects the
old expectation-copy fixture and a fixed table that refuses unknown inputs.
Under the assumption that the paired digests are computationally
indistinguishable, a single blind one-digest-per-pair guess succeeds with
probability 2^-32. That is a bound on that guessing strategy, not a general
security guarantee. Repeated attempts accumulate chances; this evaluator does
not rate-limit runs. It does not establish dynamic computation for the other
20 suites; a hybrid runner could implement canonicalization and table-drive
the remaining known cases.

The completed report separates `paired_cases: 64` from
`raw_boundary_cases: 16`. It discloses the 256-bit seed, generator identity,
complete generator contract and its SHA-256, evaluator artifact hash, exact
execution bytes and their hash, and accepted results. Each ordinary session's
randomization seed is also disclosed. These fields support replay of the
completed invocation without giving the runner its answer mapping beforehand.

## Build the source-free kit

From an immutable repository checkout:

```sh
node --import ./scripts/ts-loader/register.mjs \
  scripts/build-clean-room-kit-v3.mts \
  --ref HEAD \
  --out /tmp/emilia-clean-room-kit-v3.tar.gz
```

The kit includes the public catalogue and expectations so an implementer can
develop and debug against the published conformance corpus. Those expectations
are not passed in an evaluation invocation. Publishing them means a determined
runner can still embed a content-based lookup table; the fresh challenge
reduces but does not eliminate that risk.

## Verify a submission

Conformance-only evaluation:

```sh
node --import ./scripts/ts-loader/register.mjs \
  scripts/verify-clean-room-submission-v3.mts \
  --manifest /path/to/submission.json \
  --runner /path/to/read-only-runner \
  --allow-unsafe-local-execution \
  --emit /tmp/evaluation.json
```

Require a separately signed construction claim:

```sh
node --import ./scripts/ts-loader/register.mjs \
  scripts/verify-clean-room-submission-v3.mts \
  --manifest /path/to/submission.json \
  --runner /path/to/read-only-runner \
  --attestation /path/to/independent-attestation.v2.json \
  --trusted-attestors /path/to/trusted-attestors.v2.json \
  --require-acceptance \
  --allow-unsafe-local-execution \
  --emit /tmp/evaluation.json
```

For an immutable external source checkout:

```sh
node --import ./scripts/ts-loader/register.mjs \
  scripts/evaluate-external-implementation-v3.mts \
  --manifest /path/to/submission.json \
  --source /path/to/implementation-checkout \
  --runner /path/to/read-only-runner \
  --attestation /path/to/independent-attestation.v2.json \
  --trusted-attestors /path/to/trusted-attestors.v2.json \
  --allow-unsafe-local-execution \
  --emit /tmp/external-evaluation.json
```

Both commands default to refusing local runner execution. The acknowledgement
flag is deliberately explicit because the runner is untrusted and no process,
filesystem, or network sandbox is installed. It does not weaken that boundary.
The evaluator scrubs its inherited environment and supplies only `PATH`,
`LANG`, `LC_ALL`, and `TZ` to the child, preventing ordinary credential
variables from being inherited.

## Exact limitations

- Random handles hide catalogue identity during the invocation; they do not
  hide the public vector content.
- The canonicalization challenge checks fresh inputs and selected raw-text
  boundaries in one result family. Passing is not proof of a complete
  implementation, nor does it establish dynamic computation in other suites.
- File modes and pre/post hashes detect persistent drift at the check
  boundaries. They do not exclude transient directory-entry replacement
  between hash and execution, or prove which bytes the kernel executed.
- Only the entrypoint file and fixed-argument values are hashed. Fixed-argument
  target bytes, the interpreter, imported files, and dynamic libraries are not
  content-addressed as one dependency closure.
- The evaluator starts a normal local process. It does not provide a network,
  filesystem, syscall, namespace, container, or virtual-machine sandbox.
- The pinned-tree export excludes relative untracked helpers, but a runner can
  still read or execute any absolute host path allowed to the evaluator account
  and can make network calls unless the operator supplies external isolation.
- A verified third-party signature is a bounded attestation check, not proof
  that the signed factual construction statement is true.
