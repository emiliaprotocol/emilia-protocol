# Expectation-separated clean-room evaluator v3

Version 3 fixes an integrity defect in the published v2 evaluator without
changing v2 bytes or reinterpreting any v2 result. The v2 evaluator handed the
runner each complete vector, including `id`, `description`, and `expect`. A
runner could therefore pass by copying `expect` without implementing EMILIA.

V3 keeps the exact v2 21-suite, 335-vector corpus but changes the evaluation
protocol:

- expectations and original vector IDs stay in evaluator memory;
- the runner receives only execution fields under fresh, random, run-scoped
  handles;
- presentation-only fields are removed and vector order is randomized;
- the runner returns `{ "handle": ..., "result": { ... } }` rows; and
- after the submitted runner entrypoint is hashed and observed without write
  bits, the evaluator
  creates 32 fresh input pairs. Each input appears once with its correct
  digest and once with an independently derived, uniformly shaped wrong
  digest. The
  completed report reveals their seed, complete generator contract, exact
  execution bytes, and accepted results so the challenge can be replayed and
  audited after execution.

The fresh cases reject both the old expectation-copy fixture and a fixed table
that returns false for unknown inputs. Under the standard assumption that the
two SHA-256-shaped digests are computationally indistinguishable, a single
blind one-digest-per-pair guess succeeds with probability 2^-32. Repeated
evaluation attempts accumulate chances; this evaluator does not rate-limit
them.
Their scope is deliberately narrow: they show fresh canonicalization
computation, not that every other suite was implemented rather than
table-driven.

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
