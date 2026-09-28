# CAID differential fuzz

A seeded, deterministic fuzz of the JavaScript (`caid/impl/js`), vendored
Verify (`packages/verify/vendor/caid.mjs`), Python and Go implementations.
Every lane's outcome is compared with the spec oracle
(`caid/conformance/tools/oracle.mjs` and `mapping-oracle.mjs`), which is
built from the generated `caid/spec` constants and `core.json`. The oracle
is not a hand-written copy of the grammar.

```sh
sh caid/fuzz/ci.sh                  # full run, empty allow list; what CI runs
node caid/fuzz/run.mjs --quick      # about half the cases
node caid/fuzz/run.mjs --selftest   # the oracle as the implementation: must be 0 classes
node caid/fuzz/run.mjs --root DIR   # fuzz another tree (a git archive of main, say)
```

`CAID_PYTHON` names the Python interpreter (default `python3`).

## What runs

- `gen.mjs` writes about 88,000 cases from this checkout's corpora and
  registry (never from the tree under test), in families: `vec-core`,
  `vec-map`, `registry`, `grammar`, `code` (every named code format),
  `number`, `json`, `native`, `caidstr`, `defs`, `map-craft` and `pins`
  (definition digests, compute and verify with expected definition_sha256
  pins of every type, host definitions inside and outside the validation
  projection, and canonicalization). Every family draws from `--seed`.
  A native core vector runs as it stands, so one that builds more than 2^20
  values (a long array, shared arrays near or past the value count) is left
  to `npm run caid:conformance`, which runs it in every port and against
  the oracle; the oracle counts every path, so each costs seconds there.
- Objects under test travel as octets and go to each implementation's -04
  JSON text entry point; when they decode, the driver also runs the native
  entry point on the decoded value and reports any difference as a parity
  failure. `native` cases go to the native entry points.
- `run.mjs` groups every lane outcome that differs from the oracle into a
  class (`op | lane | cause | oracle=shape | lane=shape`) with its smallest
  reproducer, and names its root cause (`rootcauses.mjs`).
- `allow.json` is `[]`. With `--ci`, any class fails the run.

The Go driver is built in a scratch module whose `go.mod` replaces `caid`
with the tree under test; nothing is built in the repository. The typed Go
API cannot receive a non-object mapping profile, descriptor or side, so those
mapping cases are not compared in the Go lane.

## Measured

With node 24.18.0, Python 3.11.15 and go 1.26.4 on an M-class laptop, the
full run of 88,288 cases (seed 20260926) took 16 s wall (generate 0.7 s, Go
build 0.4 s, drivers in parallel: JavaScript 10.5 s, Python 11.8 s, Go
2.6 s), and the quick self-test 5 s. Every driver also runs the native parity check on
each decodable case. Hosted runners are typically two to four times slower.

Run against the pre-04 ports, the harness reports the known classes, among
them J1 (duplicate member names), J2 (invalid UTF-8), J3 (BOM), J6
(4,300-digit literals), J7 (depth), J8 (unpaired-surrogate escapes), N1 (host
values), M1-M6 (mapping), P1 (`unknown_suite` at parse), C1 (the code type)
and D1 (definition conformance).

Outputs under `--out` (default: `caid-fuzz/run` in the system temporary
directory, outside the checkout): `summary.json`, `classes.json`,
`rootcauses.json`.
