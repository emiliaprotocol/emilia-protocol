# Frozen interpretation and provenance note

Status: frozen before the first execution against the observed CAP-1 vectors.

## Construction source

The verifier was written from these two artifacts only:

- `draft-hillier-coverage-attestation-00`, SHA-256
  `7a9eeb1fbdb1fee95697622546d2ae7efba762fff193d6ee34765233539ac353`
- `CAP-1.schema.json`, SHA-256
  `4453f216089543780bfecc4295cc4a61462fdc585b88d1e35b7d1aba79716b4a`

Both were observed at Certisyn commit
`0980d3201aa2caab3cbad5c6e9bc99b422370b43`. The Certisyn JavaScript,
Python, and browser verifier implementations were not read, imported, invoked,
translated, or ported while constructing this verifier.

The Internet-Draft does not include a stable URI and digest that normatively
identifies its accompanying conformance objects. The runner therefore makes
the narrower claim that it evaluates the fifteen vector objects observed at
the pinned Certisyn commit. Their observed manifest has SHA-256
`170aa81efc74c5278a2fb6e3bcc22bc91fb1706e9fb8faf1ce6d575e5ce3d965`.

## Rule interpretation

- The accompanying JSON Schema is normative. Schema-required fields,
  additional-property closures, types, and patterns are enforced. A schema
  violation is mapped to the most specific named rule when the draft supplies
  one, such as R2 for the disposition enum or R5 for integer counts. Remaining
  schema failures are R0 shape failures.
- The draft names R0 through R8, which is nine rules. The mutation statement's
  phrase "eight rules" is read as R1 through R8. R0 remains enforced even
  though the published mutation claim does not describe an R0 mutant.
- R5 is treated as a precondition to R1. An invalid count is reported primarily
  under R5 before arithmetic reconciliation is interpreted. All observed
  violations are still returned.
- A non-empty string is required for `integrity.capped_to` when the run is
  incomplete. A present empty string does not state a usable capped verdict.
- CAP-1 conformance is internal consistency only. It does not authenticate the
  producer, establish the truth of the stated population, prove the population
  complete, prove technique or depth, or establish that examined units were
  distinct.

## Findings kept outside native CAP-1 conformance

The verifier preserves the published semantics, including their limits:

- `withheld` is structurally placed in `unexamined` but defined as examined.
  Native verification follows the published R1 arithmetic. The optional EMILIA
  examined-set control refuses this semantic conflict by name until the draft
  selects one meaning.
- Duplicate unit identifiers are not forbidden by CAP-1. Native verification
  therefore accepts a balanced document containing them. The optional
  examined-set control refuses duplicate eligible, examined-result, and
  unexamined identifiers.
- `aborted_before_dispatch`, `not_reached`, `not_sampled`, and `not_yet_due`
  are not in the closed disposition vocabulary. Native verification must
  refuse them under R2; this demonstrates an expressiveness boundary rather
  than a verifier defect.
- A derived population cannot be represented by the closed basis enum. Native
  verification must refuse `basis.kind: derived` under R4; this again records a
  specification boundary.
- Technique and depth are discussed as part of the problem statement but are
  absent from the normative object. Adding those fields to a stratum violates
  the schema's additional-property closure and is refused under R0.
- Section 9 says the digest algorithm MUST be stated, but
  `catalogue_digest` and `withheld_digest` are bare schema strings and the
  schema rejects the natural `{ "algorithm": ..., "value": ... }` form. The
  verifier accepts the bare digest demanded by the normative schema and does
  not infer its algorithm. This is recorded as a specification contradiction,
  not repaired by reinterpretation.
- A producer-selected declared denominator can be fixed after results are
  known and still conform. Native verification cannot detect that. An external
  precommitment or independently pinned population root belongs in a relying-
  party composition profile, not in a claim about CAP-1 conformance.

## EMILIA examined-set control

`verifyExaminedSetEvidence` is an optional relying-party control, not a CAP-1
rule. It requires a canonical commitment to the distinct eligible unit set, a
canonical commitment to the distinct examined unit set, and exactly one
digest-bound result for every examined unit. It also checks that examined and
unexamined units are disjoint and together equal the supplied eligible set.

Set commitments use SHA-256 over UTF-8 JSON arrays of unique unit identifiers
sorted by JavaScript code-unit order. The CAP-1 object digest reported by this
implementation uses SHA-256 over recursively key-sorted JSON. CAP-1 itself does
not define this canonicalization, so consumers must identify it as an EMILIA
profile rule rather than a native CAP-1 digest.

## Execution sequence

The verifier source, this note, the runner, and tests are hashed into
`source-lock.json` before the vector class is executed. Results are written to
a separate reference report and do not modify this frozen interpretation.
