# Local P3 Evidence Source Evaluation Profile

Version: `aips1-p3-evidence-source-evaluation-v0.1`

Status: experimental local profile for AIPS-1 v0.1 public comment

The words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are used in
their ordinary standards sense.

## 1. Scope

This profile evaluates repository-local Trigger predicates against supplied
offline JSON observations. It explores a possible concrete shape for AIPS-1
v0.1 P3 Evidence Source evaluation.

It is not an AIPS-1 predicate grammar, reference verifier, or conformance
suite. It does not parse a native Policy Certificate or evaluate the
Certificate's `evidenceRequired` field or status lifecycle. It is not an AEB
adapter and makes no authorization, coverage, liability, claim-acceptance,
settlement, or payout decision.

The local dialect identifier is
`emilia-aips1-p3-local-json-pointer-v0.1`. A report carries this identifier, a
digest of the dialect declaration in `evaluate.mjs`, and the authority label
`repository_local_proposal_not_aips1_v0.1`.

## 2. Evaluation case

An evaluation case contains:

| Field | Meaning |
|---|---|
| `case_id` | Stable local name for the case. |
| `profile` | The relying-party evaluation profile in Section 3. |
| `evidence_set` | Supplied offline observations in Section 4. |

The CLI accepts one JSON file containing this object. The programmatic API uses
`unnamed-case` when `case_id` is absent or empty.

## 3. Evaluation profile

The profile is a closed object. Unknown fields are invalid.

| Field | Rule |
|---|---|
| `profile_version` | MUST equal `aips1-p3-evidence-source-evaluation-v0.1`. |
| `profile_id` | MUST be a non-empty string. |
| `evaluation_time` | MUST be UTC with `Z`, using whole seconds or exactly three fractional digits. |
| `combiner` | MUST equal `ALL`. No other combiner is defined. |
| `sources` | MUST contain 1 to 32 source declarations. Repeated identifiers are ambiguous. |
| `predicates` | MUST contain 1 to 64 predicates. Repeated identifiers are ambiguous. |

### 3.1 Source declaration

Every source declaration has exactly these fields:

| Field | Rule |
|---|---|
| `source_id` | Non-empty identifier, unique within the profile. |
| `source_type` | Non-empty descriptive type. It does not confer trust. |
| `locator` | Non-empty opaque locator pin. Matching is exact string equality. |
| `revision` | Non-empty opaque revision pin. Matching is exact string equality. |
| `format` | Data format. This version supports only `application/json`. |
| `basis` | Relying-party pin: `OBSERVED_FACT` or `ISSUER_OPINION`. |
| `data_sha256` | `sha256:` plus 64 lowercase hexadecimal characters. It is computed over the local canonical encoding of parsed `data`. |
| `max_age_seconds` | Integer freshness limit from 0 through 31,536,000 seconds. |

`locator` and `revision` are not dereferenced or authenticated. `basis` is a
profile assertion, not proof of provenance or independence. `source_type` is
recorded but does not change evaluator behavior.

### 3.2 Predicate

Every predicate has exactly these fields:

| Field | Rule |
|---|---|
| `predicate_id` | Non-empty identifier, unique within the profile. |
| `source_ids` | Non-empty array of unique source identifiers. |
| `path` | RFC 6901 JSON Pointer into each source's `data`; the empty pointer selects the complete value. Array tokens use canonical non-negative indexes: `/0` is valid, while `/01`, `/-`, and `/length` are not array entries. |
| `operator` | One operator from Section 6. |
| `expected` | A bounded local JSON value. Numbers MUST be signed IEEE-754 safe integers. |

A source reference need not resolve during structural validation. An unresolved
reference is statically unevaluable and produces `SOURCE_UNPINNED`.

## 4. Evidence set

The evidence set is a closed object with two fields:

| Field | Rule |
|---|---|
| `evidence_set_version` | MUST equal `aips1-p3-evidence-set-v0.1`. |
| `observations` | Array of zero to 128 source observations. |

An observation permits exactly these fields:

| Field | Rule |
|---|---|
| `source_id` | REQUIRED non-empty string. |
| `locator` | REQUIRED non-empty string. |
| `revision` | REQUIRED non-empty string. |
| `availability` | REQUIRED; `AVAILABLE` or `UNAVAILABLE`. |
| `observed_at` | REQUIRED for `AVAILABLE`; the same strict UTC form as `evaluation_time`. |
| `format` | REQUIRED for `AVAILABLE`; non-empty string. |
| `basis` | REQUIRED for `AVAILABLE`; `OBSERVED_FACT` or `ISSUER_OPINION`. |
| `data` | REQUIRED for `AVAILABLE`; a bounded local JSON value using only signed safe integers for numbers. |

The last four fields MAY be omitted when `availability` is `UNAVAILABLE`. If
present, they MUST still satisfy their type and value rules.

`basis` is supplied metadata and MUST match the profile's `basis` pin. The
evaluator does not verify that an `OBSERVED_FACT` was independently observed or
that an `ISSUER_OPINION` came from the issuer.

## 5. Validation and source usability

Unknown fields, missing required fields, wrong version identifiers, duplicate
predicate source references, malformed timestamps, invalid JSON Pointers, and
invalid value types fail structural validation. The file loader rejects
duplicate JSON object members before evaluation. Repeated source or predicate
identifiers remain representable in JSON but are statically ambiguous and
produce `SOURCE_AMBIGUOUS` or `PREDICATE_ID_AMBIGUOUS`.

Programmatic input MUST be inert, plain JSON data. Accessor properties,
proxies, custom prototypes, symbols, sparse arrays, non-enumerable properties,
and extra array properties are rejected before values are evaluated. Accepted
programmatic input is snapshotted once so later reads cannot change a pin,
predicate value, digest, or report.

An invalid profile returns `INDETERMINATE` with `PROFILE_INVALID`. An invalid
evidence set returns `INDETERMINATE` with `EVIDENCE_SET_INVALID`. Detailed
sorted entries appear in `validation_errors`.

For each declared source used by a predicate, the evaluator applies these
checks in order:

1. The source identifier MUST resolve to a declaration in the profile.
2. At least one observation with that identifier MUST exist.
3. Multiple observations for one identifier MUST be identical under the local
   canonical encoding. Any difference, including metadata, is a conflict.
4. Observation `locator` and `revision` MUST exactly match their profile pins.
5. `availability` MUST be `AVAILABLE`.
6. Profile and observation format MUST match, and the format MUST be
   `application/json`.
7. Observation `basis` MUST exactly match the profile's basis pin.
8. `observed_at` MUST be no later than `evaluation_time`, and its age MUST be
   less than or equal to `max_age_seconds`.
9. The digest of parsed `data` under the local canonical encoding MUST equal
   `data_sha256`.
10. `path` MUST resolve to an own property or array entry in `data`. Inherited
   properties are ignored.

A failed check makes the predicate `INDETERMINATE`. The evaluator does not
convert missing, unavailable, stale, unsupported, conflicting, or unpinned
evidence into `NOT_SATISFIED`.

When a predicate declares multiple sources, the selected values MUST be equal
under the local canonical encoding. Disagreement returns `SOURCE_CONFLICT`.
Every source therefore supports one shared predicate fact; this version does
not evaluate a different operand from each source.

If every usable source has `basis=ISSUER_OPINION`, the predicate returns
`SOURCE_ISSUER_OPINION_ONLY`. Issuer opinion MAY be included when at least one
declared usable source has `basis=OBSERVED_FACT` and every selected value
agrees. This is a local rule, not an AIPS-1 definition of independence.

## 6. Operators

The closed operator set is:

| Operator | Meaning |
|---|---|
| `EQUALS` | Selected and expected JSON values are equal under the local canonical encoding. |
| `NOT_EQUALS` | Selected and expected JSON values are not equal under that encoding. |
| `NUMBER_GTE` | Both values are finite JSON numbers and selected is greater than or equal to expected. |
| `NUMBER_LTE` | Both values are finite JSON numbers and selected is less than or equal to expected. |

There is no type coercion. A numeric string is not a number. A numeric operator
over a non-number or non-safe integer returns `VALUE_TYPE_UNSUPPORTED`. Decimal
quantities use fixed-point safe integers or strings with profile-defined
semantics. Any other operator returns `PREDICATE_UNSUPPORTED`.

## 7. Canonical JSON and content pins

The evaluator's local canonical encoding:

- emits JSON primitives with the runtime's JSON encoding;
- accepts only signed safe integers as JSON numbers and rejects negative zero;
- preserves array order and rejects sparse arrays;
- sorts object member names lexicographically; and
- rejects non-finite numbers, non-JSON values, and cycles, while ignoring
  inherited object members.

This encoding exists to make local fixtures and reports byte-stable. It is not
claimed to be RFC 8785 JCS or an AIPS-1 canonicalization rule.

`data_sha256` is the lowercase SHA-256 digest of that encoding with the
`sha256:` prefix. It binds the parsed JSON value chosen by the profile author.
It does not authenticate the source, bind HTTP headers, or preserve the raw
source bytes.

## 8. Verdict composition

Each predicate report carries `static_evaluable`, `runtime_evaluable`, a
verdict, and reason codes.

- `static_evaluable=false` means the local operator, source reference, source
  format, source identifier, or predicate identifier is unsupported or
  ambiguous before observations are considered.
- `runtime_evaluable=false` means the supplied observations cannot determine
  the predicate.
- `SATISFIED` means the predicate was evaluable and its comparison was true.
- `NOT_SATISFIED` means the predicate was evaluable and its comparison was
  false.
- `INDETERMINATE` means the predicate could not be evaluated.

Overall `ALL` composition is deliberately conservative:

1. If any predicate is runtime-unevaluable, the case is `INDETERMINATE`.
2. Otherwise, if any predicate is `NOT_SATISFIED`, the case is
   `NOT_SATISFIED`.
3. Otherwise, the case is `SATISFIED`.

This makes indeterminacy dominate a determinate false predicate. That is a
local abstention policy, not an AIPS-1 Boolean-composition rule.

## 9. Reason codes

Top-level reason codes are sorted and deduplicated. Determinate predicate
results keep their result code on the predicate and do not copy it to the
top-level list.

| Code | Meaning |
|---|---|
| `CASE_INVALID` | Programmatic input was not an object. |
| `INPUT_UNREADABLE` | CLI input file could not be read. |
| `INPUT_MALFORMED` | CLI input was not valid JSON. |
| `INPUT_DUPLICATE_MEMBER` | CLI input repeated an object member name. |
| `INPUT_NUMBER_UNSAFE` | CLI or programmatic input used a decimal, exponent, negative zero, or integer outside the signed safe range. |
| `INPUT_LIMIT_EXCEEDED` | Input exceeded a declared parser or evaluator resource limit. |
| `EVALUATION_FAILURE` | An unexpected local evaluation or report-serialization failure was safely converted to abstention. |
| `PROFILE_INVALID` | Profile failed structural validation. |
| `EVIDENCE_SET_INVALID` | Evidence set failed structural validation. |
| `SOURCE_AMBIGUOUS` | More than one source declaration used the same source identifier. |
| `SOURCE_MISSING` | No observation exists for a declared source. |
| `SOURCE_UNAVAILABLE` | The observation declares the source unavailable. |
| `SOURCE_STALE` | The observation is future-dated or older than the allowed age. |
| `SOURCE_UNSUPPORTED` | Source or observation format is unsupported or mismatched. |
| `SOURCE_UNPINNED` | Source reference is undeclared, locator, revision, or basis pins mismatch, or the content digest mismatches. |
| `SOURCE_CONFLICT` | Duplicate observations differ or selected values disagree across sources. |
| `SOURCE_ISSUER_OPINION_ONLY` | Every usable supporting observation is labeled issuer opinion. |
| `VALUE_MISSING` | The JSON Pointer did not resolve. |
| `VALUE_TYPE_UNSUPPORTED` | A typed operator received the wrong JSON type. |
| `PREDICATE_UNSUPPORTED` | The operator is outside the closed local set. |
| `PREDICATE_ID_AMBIGUOUS` | More than one predicate used the same predicate identifier. |
| `PREDICATE_SATISFIED` | Determinate predicate comparison was true. |
| `PREDICATE_NOT_SATISFIED` | Determinate predicate comparison was false. |

## 10. Report

A report contains:

- `report_version`, fixed to `aips1-p3-evidence-source-report-v0.1`;
- `lab_profile`, fixed to the profile version;
- the local predicate-dialect identifier, digest, and authority label;
- `case_id`, `profile_id`, and the profile's `evaluation_time`;
- canonical digests for the parsed input, profile, and evidence set when those
  values exist;
- a bounded snapshot of every declared source pin and matching observation;
- case-level static and runtime evaluability;
- the three-state verdict;
- sorted reason codes and validation errors;
- per-predicate results; and
- the fixed scope statement.

`stableReportJson()` encodes the report with the local canonical JSON algorithm
and one trailing newline. For the same parsed input and evaluator version, the
bytes are deterministic.

The CLI rejects duplicate JSON members and invalid UTF-8. For valid JSON,
`input_digest` binds the canonical parsed object. When parsing cannot produce
an object, the report uses a digest of the bounded input bytes when available;
unreadable and over-size inputs leave that field null. The profile and evidence
digests remain null until those objects exist.

The report does not include or validate a Policy Certificate, source payload
signature, trust anchor, retrieval receipt, network response, coverage term,
claim record, or payment instruction.

## 11. Resource limits

This implementation caps input at 1,048,576 bytes, nesting at 32 levels,
total JSON nodes at 10,000, collection members at 256, strings at 8,192 code
units, identifiers at 256 code units, and locators at 2,048 code units. It also
caps sources at 32, predicates at 64, observations at 128, and freshness at one
year. A limit breach returns `INDETERMINATE` with `INPUT_LIMIT_EXCEEDED`.

Reports retain at most 64 validation diagnostics of at most 512 characters.
Truncated details are replaced by deterministic hashes, and overflow is
represented by a count and digest rather than silently discarded.

These are local denial-of-service controls, not proposed AIPS-1 requirements.

## 12. Mapping from the v0.1 worked example

Appendix A of AIPS-1 v0.1 contains one illustrative oracle predicate. This
profile maps its example concepts as follows:

| Appendix A concept | Local field |
|---|---|
| `type` | `sources[].source_type` |
| `sourceRef` | `predicates[].source_ids`, resolved to `sources[].locator` |
| `field` | `predicates[].path` as a JSON Pointer |
| `operator: eq` | `operator: EQUALS` |
| `value` | `predicates[].expected` |

The mapping is explanatory only. It does not make the local names native,
interpret Appendix A as a schema, or cover its `evidenceRequired` field.

## 13. Limits

This profile does not:

- retrieve, preserve, or authenticate external evidence;
- verify source identity, authority, independence, signatures, or truth;
- establish that `source_type`, `basis`, `revision`, or timestamps are honest;
- decide whether evidence is legally admissible or sufficient for a claim;
- evaluate P1, P2, P4, P5, Policy Certificate status, or an underlying Policy;
- assign coverage, liability, fault, negligence, claim acceptance, settlement,
  or payout;
- authorize an action or an insurance decision;
- implement CAID, AEB, AEC, Gate, or an execution adapter;
- establish AIPS-1 conformance, adoption, endorsement, or interoperability; or
- replace review by the insurer, policyholder, relying party, regulator, court,
  or other authorized decision-maker.
