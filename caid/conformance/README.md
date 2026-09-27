# CAID conformance

Shared corpora and runners for draft-schrock-canonical-action-identifier-04.
The JavaScript, Python and Go implementations in `caid/impl` are three ports
by one team in one repository. Passing these corpora is a consistency check
between them and against the spec oracle, not independent implementation.
An external party re-running them is a reproduction.

```sh
npm run caid:conformance   # every step below; exits 1 if any failed
npm run caid:corpus        # rebuild the three corpora after editing a builder
npm run caid:fuzz          # the differential fuzz (caid/fuzz)
```

## Files

| Path | What it is |
|---|---|
| `vectors.json` | Core corpus, version 5: 524 vectors (decode, parse, compute, verify, definition) |
| `grammar-vectors.json` | Grammar boundary corpus: 2,054 cases over 22 drivers |
| `mapping-vectors.json` | Mapping corpus, version 2: 64 vectors with exact reason lists |
| `history/vectors.v4.json` | The version 4 core corpus, byte for byte (`sha256:7a201c87…`) |
| `history/mapping-vectors.v1.json` | The version 1 mapping corpus, byte for byte (`sha256:6941463c…`) |
| `check-v4.mjs` | Proves from the files alone that version 5 carries version 4 forward |
| `run.mjs` | The `caid:conformance` orchestrator |
| `runners/run.mjs`, `runners/run.py`, `runners/go/` | Core and grammar runners for JavaScript, Python and Go |
| `runners/native.mjs` | The native-lane encoding (below) and the input-form reader |
| `tools/` | Dev-time builders and the spec oracle; nothing here ships in a package |

## The spec oracle

`tools/oracle.mjs` computes every expected result. It combines the dev-time
reference validator (`caid/spec/reference.mjs`, built from the generated
`caid/spec` constants and `core.json`) with a JSON text oracle
(`tools/strict-json.mjs`, the Section 2.4 rules with the `core.json` limits).
`tools/mapping-oracle.mjs` does the same for the Action-Mapping Profile from
`core.json` mapping data. The builders compute each expectation with the
oracle and fail if it contradicts what the case states by hand, so every
refusal list in the corpora is written down twice.

The oracle applies one rule the reference validator does not yet: a string
holding a Unicode noncharacter is outside the data model on every entry
point (RFC 8785 Section 3.1 requires I-JSON input, and RFC 7493 Section 2.1
excludes noncharacters). From JSON text it is `malformed_json`; as a host
value it is `unsupported_value`.

## Core corpus, version 5

Every compute and verify input is exact octets, in one of three forms:

- `input.json`: a string whose UTF-8 encoding is the JSON text;
- `input.json_b64`: the octets in base64 (invalid UTF-8, a BOM, UTF-16);
- `input.json_repeat`: `{prefix, unit, count, suffix}`, the UTF-8 of prefix,
  then `count` copies of unit, then suffix (the 32 MiB text limit, the
  16 MiB canonical limit and the 1 MiB adversarial code strings).

A runner calls the JSON text entry point, and when the octets decode it also
calls the native entry point on the decoded value and requires the same
result (Section 2.5 parity).

The **native lane** (`input.native`) carries host values that no conforming
decoder produces. A runner builds the host value and calls the native entry
point only. A native value is any JSON value, read as itself, except these
tagged objects:

| Tag | Host value |
|---|---|
| `{"$units": [u, ...]}` | a string of these UTF-16 code units (JS as is; Python `chr(u)` per unit; Go generalized UTF-8, which is not valid UTF-8) |
| `{"$object": [[k, v], ...]}` | an object with these members in this order; `k` may be a `$units` string |
| `{"$nest": {"depth", "container", "leaf"}}` | `depth` nested arrays, or objects whose only member is `a` |
| `{"$host": "nan" / "infinity" / "-infinity" / "negative_zero"}` | the binary64 value |
| `{"$host": "cyclic"}` | a reference to the nearest enclosing object or array |
| `{"$host": "opaque"}` | JS `new Map()`, Python `set()`, Go `struct{}{}` |

The review's D1 ordering case is `native-order-number-then-surrogate-key`:
a lone-surrogate member name and a member holding 1.5 give
`unsupported_number, unsupported_value` whatever the traversal order.

Options: compute passes `input.suite` as given (absent means no suite, so
`unknown_suite`), the vector's `definitions` as given, and the envelope's
`enum_snapshots` (the five registry value sets). Verify also passes
`input.expected_definition_sha256` when present. An option of the wrong
type counts as absent.

Expectations: compute is `{caid, digest, definition_sha256}` or `{refusals}`;
verify is `{valid, reasons, details}` plus `definition_sha256` when a
conforming definition resolved; parse is `{ok, caid}` or `{ok, refusals}`;
decode is `{ok}` or `{ok, refusals: ["malformed_json"]}`; definition is
`{definition_sha256}` or `{refusals: ["invalid_definition"]}`. Results are
compared as JSON, member order aside. `relation` pins two computed CAIDs as
equal or different; `time_budget_ms` bounds the JSON text entry-point call.

What version 5 adds, by group: 66 decode vectors (duplicates in escaped and
surrogate-pair spellings, BOM, UTF-16/32, overlong and surrogate UTF-8,
unpaired-surrogate and noncharacter escapes, control characters, trailing
content, non-JSON literals and numbers, depth 64 and 65); the size limits at
the octet boundary; number edges (midpoints, 400 and 5000 digits, `-0`,
`1e-400`, 2^53); 29 native-lane vectors; every pair of compute phases and
the verify ranks; 27 malformed or conflicting definitions refused as
`invalid_definition`, and 11 more definition cases (equal duplicates, open
entry members, deprecated status, unregistered types and formats, field
names); 11 `definition_sha256` vectors; 82 code-format vectors including a
1 MiB adversarial string per format under a 2 s budget; 21 timestamps; 29
parse vectors (audit Appendix D, `unknown_suite` at parse); and one vector
per registry type (62: each of the 53 active types computes; each of the 9
deprecated types resolves and refuses only its unpinned enum field).

**Version 4 carries forward.** Every version 4 vector keeps its id, with its
object as the version 4 tokens. All 22 version 4 CAIDs are expected
unchanged. Six results change, each by a named rule: three unpaired-surrogate
vectors are `malformed_json` from text (their native twins keep
`unsupported_value`), and the three unregistered-suite vectors from #815 are
`unknown_suite` at parse. `check-v4.mjs` proves this from the files.

## Grammar corpus

Each ABNF rule a port enforces has a driver that places the case string into
a one-field type definition and action object (compute) or a CAID string
(parse), so the corpus tests the ports' public entry points, never their
generated regular expressions. Cases are an even spread of the membership
cases `caid/spec/abnf-check.mjs` generates, plus astral, lone-surrogate
(native lane), invalid-UTF-8 (byte lane), noncharacter and long (4 Ki and
70 Ki character) cases. `grammar` is the ABNF interpreter's verdict for the
case string; `expect` is the exact result, which the driver's other rules
can decide first (registry, digest syntax, calendar, format registration).

## Mapping corpus, version 2

Version 2 keeps the version 1 layout that `caid/impl/*/run-mapping-vectors`
read. Every expectation is the exact reason list in the -04 stage order: A
(profile checks; a shape failure is exactly `invalid_mapping_profile`), B
(appended, in rank order), C (one reason per rule, in rule order), D
(`mapped_action:` reasons in compute order), then `left:` before `right:`.
New vectors cover the registered profile extension
(`omitted_source_fields`, `declared-source-semantic-loss`,
`sha256-hex-to-digest`), UTF-8 octet limits, field-name targets such as
`@version`, the review's D2-D9 cases, and each stage boundary. One version 1
vector changes because -04 widens `target_field` to the field-name rule.

## Entry points the runners call

| | JavaScript | Python | Go |
|---|---|---|---|
| decode | `decodeCaidJson(bytes)` | `decode_caid_json(data)` | `DecodeCaidJSON([]byte)` -> `{OK, Value, Refusals}` |
| compute from text | `computeCaidJson(bytes, opts)` | `compute_caid_json(data, opts)` | `ComputeCaidJSON([]byte, ComputeOptions)` |
| verify from text | `verifyCaidJson(bytes, caid, opts)` | `verify_caid_json(data, caid, opts)` | `VerifyCaidJSON([]byte, string, VerifyOptions)` |
| native | `computeCaid`, `verifyCaid` | `compute_caid`, `verify_caid` | `ComputeCaid`, `VerifyCaid` |
| parse | `parseCaid` | `parse_caid` | `ParseCaid` |
| definition digest | `definitionSha256` (or `definitionDigest`) | `definition_sha256` (or `definition_digest`) | `DefinitionSha256` |
| options | `{suite, definitions, enumSnapshots, expectedDefinitionSha256}` | `{"suite", "definitions", "enum_snapshots", "expected_definition_sha256"}` | `ComputeOptions{Suite, Definitions, EnumSnapshots}`, `VerifyOptions{..., ExpectedDefinitionSha256}` |

The Go runner touches the implementation only in `runners/go/port.go`.
Each runner's `--legacy-front-end` (Go: `-tags legacy`) measures a pre-04
implementation through a host JSON parser and never passes.

## Rebuilding

The corpora are generated and checked in; edit the builders, not the JSON:

```sh
node caid/conformance/tools/build-core.mjs      # vectors.json (cases in tools/core-cases.mjs)
node caid/conformance/tools/build-grammar.mjs   # grammar-vectors.json
node caid/conformance/tools/build-mapping.mjs   # mapping-vectors.json
```

Each builder's `--check` fails unless the checked-in file is its output, and
each refuses to write a corpus that its own strict decoder rejects.
