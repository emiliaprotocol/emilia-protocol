# Expectation-separated clean-room evaluation v3

The v3 evaluator repairs the oracle channel in v2. It is a new protocol and
report version; the published v2 evaluator, bundle, schemas, and prior reports
remain historical bytes with their original meaning.

This is a partial integrity repair. It does not close issue #250 because it
does not isolate the runner from evaluator files, other host paths, or the
network.

V3 evaluates the same pinned 21-suite, 335-vector corpus. Before each runner
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

After the submitted runner entrypoint has been built, hashed, and observed
without write bits, the
evaluator generates 32 fresh canonicalization inputs from random values. Each
appears once with its computed digest and once with an independently derived,
uniformly shaped wrong digest. The paired cases prevent payload markers or a
fixed digest prefix from revealing the answer. This catches the v2 copy-oracle and a simple precomputed table whose
default is refusal. Under the standard assumption that the two SHA-256-shaped
digests are computationally indistinguishable, a single blind one-digest-per-
pair guess succeeds with probability 2^-32. Repeated attempts accumulate
chances because this evaluator does not rate-limit runs. It does not establish dynamic computation for the other 20
suites; a hybrid runner could implement canonicalization and table-drive other
known cases. The completed report discloses the 256-bit challenge seed,
complete generator contract and digest, evaluator artifact hash, exact
execution bytes, and accepted results. It also discloses each ordinary
session's randomization seed. That makes completed invocations reproducible
without revealing their mapping before execution.

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
- The canonicalization challenge proves only that one result family handled
  fresh semantic inputs.
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
