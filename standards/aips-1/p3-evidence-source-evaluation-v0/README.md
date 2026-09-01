# AIPS-1 P3 Evidence Source Evaluation Lab v0.1

Status: experimental public-comment package, not submitted

Prepared: 2026-09-01

Target: AIPS-1 v0.1, P3 Trigger Determinism

Published comment deadline: 2026-11-30

This package tests one narrow question: can a closed local predicate be
evaluated against declared, pinned, current JSON evidence without turning
missing or ambiguous evidence into a false answer?

It returns exactly three local trigger results:

- `SATISFIED`: every predicate was evaluable and true.
- `NOT_SATISFIED`: every predicate was evaluable and at least one was false.
- `INDETERMINATE`: at least one predicate could not be evaluated safely.

These are not AIPS-1 native verdicts. They do not decide authorization,
coverage, liability, claim acceptance, payout, or Policy Certificate status.
They also do not establish AIPS-1 conformance, review, adoption, endorsement,
or interoperability.

## Why this is a comment lab

AIPS-1 v0.1 requires predicates evaluable against declared Evidence Sources,
but it does not publish a normative Trigger predicate schema, predicate
language, predicate-outcome model, or reference verifier. Its schemas and
reference implementations are marked as planned or deferred to v0.2 in the
pinned upstream repository.

This package therefore defines a small repository-local dialect. It uses an
`ALL` combiner, RFC 6901 JSON Pointers, four closed operators, exact source and
content pins, a relying-party evaluation time, and conservative
`INDETERMINATE` handling. `SPECIFICATION.md` defines that dialect. Nothing here
is called native AIPS verification.

## What the evaluator checks

For supplied offline fixtures, the evaluator checks:

- closed profile and evidence-set structures;
- duplicate-member rejection before JSON is evaluated;
- exact source identifier, locator, revision, format, basis, and content-digest
  pins;
- observation availability and freshness at the profile's evaluation time;
- agreement between duplicate observations and between declared sources;
- rejection of a predicate supported only by `ISSUER_OPINION` observations;
- root-value selection and canonical array-index handling for JSON Pointers;
- strict safe-integer comparison with no string-to-number coercion; and
- input, profile, evidence-set, and source-snapshot binding in a stable report.

The evaluator does not fetch a URL, authenticate a source, verify a signature,
or prove that an `OBSERVED_FACT` label is true. Locator, revision, basis, and
timestamps are supplied fixture data. The `data_sha256` field binds parsed JSON
under this lab's canonical encoding; it is not a hash of the source's raw HTTP
response bytes.

File input is limited to 1 MiB. The local profile also caps nesting, collection
size, strings, sources, predicates, observations, and freshness windows. Those
limits protect this reference tool; they are not proposed as AIPS-1 limits.
JSON numbers are limited to signed safe integers. Decimal quantities must use a
fixed-point integer or a string with separately defined semantics.

## Package contents

- `COMMENT.md`: submission-ready comment text. It remains unsubmitted.
- `SPECIFICATION.md`: the exact local input, evaluation, and report rules.
- `SOURCES.md`: human-readable primary-source register and interpretation
  limits.
- `source-lock.json`: hashes and revision pins for the official site and the
  upstream GitHub repository.
- `evaluation-profile.schema.json`: schema for the local profile.
- `evidence-set.schema.json`: schema for supplied offline observations.
- `evaluation-report.schema.json`: schema for local evaluation reports.
- `corpus-report.schema.json`: schema for the generated aggregate report and
  its artifact bindings.
- `vector-corpus.schema.json`: schema for the paired vector corpus.
- `evaluate.mjs`: zero-dependency evaluator and CLI.
- `evaluate.selftest.mjs`: behavioral and hostile tests.
- `vectors/`: determinate controls and hostile cases.
- `generate-report.mjs`: deterministic aggregate report generator.
- `report.json`: generated report over the checked-in vectors.
- `CLAIM-EVIDENCE.md`: bounded claim ledger.

## Run

The evaluator and report generator have no runtime package dependency:

```sh
node evaluate.mjs <evaluation-case.json> --json
node generate-report.mjs
node generate-report.mjs --check
```

The self-test also validates the JSON Schemas with the repository's pinned Ajv
development dependency. From the repository root after `npm ci --ignore-scripts`:

```sh
node --test standards/aips-1/p3-evidence-source-evaluation-v0/evaluate.selftest.mjs
```

The evaluator writes one canonical JSON report to standard output. It exits
nonzero for file, parse, duplicate-member, resource-limit, or internal
evaluation failures. A structurally valid case may return `INDETERMINATE`
with exit zero; consumers must inspect the verdict and reason codes.

`generate-report.mjs` prints the regenerated report to standard output.
`generate-report.mjs --check` compares those bytes with checked-in
`report.json` and fails if it is missing or stale. The report binds the raw
bytes of `source-lock.json`, `corpus-report.schema.json`, `evaluate.mjs`, and
`generate-report.mjs`. It also records the upstream commit and tree from the
source lock, so a reader can reproduce the exact local evidence and code
boundary without trusting a filename.

The checked package has 44 passing self-tests and 20 vectors in 10 paired
control/hostile groups. The generated report records 10 `INDETERMINATE`, nine
`SATISFIED`, and one `NOT_SATISFIED` result, with no expectation mismatch. See
`CLAIM-EVIDENCE.md` for the exact boundary of those claims.

## Source and license boundary

The official-site PDF and the commit-pinned GitHub PDF both identify themselves
as AIPS-1 v0.1 but are not byte-identical. `source-lock.json` pins both and
`SOURCES.md` records the reviewed differences. The P3 passages used by this lab
have the same substantive wording in both copies.

The upstream AIPS-1 repository uses CC0 1.0 Universal (`CC0-1.0`). This package
is published under the EMILIA Protocol repository's Apache-2.0 license. It is
not an AEB adapter and does not map AIPS evidence into CAID, AEB, AEC, Gate, or
an execution decision.
