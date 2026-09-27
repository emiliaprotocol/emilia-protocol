# Validation record

Validated on 2026-09-28. The source applies every confirmed finding of the
pre-filing review, and every finding of the first through fifth audits of
those fixes, to the previously staged -04, which carried the
amount-string ABNF and the suite and unused-bit parsing changes over -03
and keeps both.

## Rendering

- `xmllint --noout` passes for the source.
- `xml2rfc 3.34.0` renders the TXT (`--text`) and, with `--no-external-js`,
  the HTML (`--html`). Trailing spaces and tabs in the generated HTML are
  removed with `perl -pe 's/[ \t]+$//'` before checksums are recorded.
- `xml2rfc` reports two informational warnings and nothing else: the
  source omits `submissionType`, as -03 does, because this individual
  draft belongs to no document stream, so `xml2rfc` uses its IETF default
  and sets `consensus="true"` for a Standards Track document.
- `check-caid-04` renders the source again with `xml2rfc 3.34.0` whenever
  it is on PATH, with the flags and the trailing-space strip above, and
  fails unless both renders equal `RENDERS/` byte for byte and `xml2rfc`
  gives no warning beyond those two. `--renders` (and `--prefiling`) fails
  when that `xml2rfc` is absent; run it before upload. It passes on this
  tree.
- No table row of the TXT is split across a page, and `check-caid-04`
  fails if one is. Table 2 lists the reasons of phases 3 and 4 without
  their `:<name>` parameter, which the paragraph above it states, so its
  "Refused when" column is 31 columns wide; the paragraph that follows the
  table in the earlier draft now precedes it, and the table sits on one
  page (page 35). Table 1 runs from page 15 to page 16: page 15 ends on the
  border below its Code system row, and page 16 begins with its Action type
  row. The Code system row now precedes the Action type row: with the
  scope the Integer magnitude row now states, the earlier order put the
  page break inside the Action type row. The sentence on definitions
  read from JSON text that nest deeper than 64 now opens the paragraph
  after the table instead of closing the one before it, which keeps the
  nesting row on one page.
- Every sourcecode line is at most 69 columns. Long example lines are folded
  as specified in RFC 8792 (single backslash strategy), and
  `check-caid-04` unfolds them before recomputing. Appendix D is two
  definition lists, not tables, because a 64-digit digest does not fit a
  table row. `xml2rfc` keeps each term (the type, its status and, for a
  deprecated type, its successor) on the page of its description (the
  digest), and `check-caid-04` fails if a page of the TXT separates an
  entry's name line from its digest line, or if a term is long enough to
  wrap.
- Non-breaking hyphens (`&#8209;`) appear only in SHA-384 and
  SHA-512/256. `xml2rfc` renders them as ASCII hyphens in the TXT, which is
  ASCII only, but the HTML keeps U+2011, so a type name or file path copied
  from it would not be the real string. The file paths
  (`action-types.json`, `history/action-types.v4.json`, `value-sets/`) and
  emilia.mobile.authorized-action.1 are ASCII in the source and in both
  renders, and the sentences around them are worded so that the TXT breaks
  none of them. `check-caid-04` fails if a non-breaking hyphen appears
  anywhere else in the source, if the HTML carries U+2011 in those names,
  or if the TXT breaks an action type at a hyphen, "action-types", or
  "value-sets". It also fails if a line of the TXT, across a page break
  included, ends inside any closed-set value that contains a hyphen: the
  field types, transforms, loss policies, code formats and parameter kinds
  of `caid/spec/core.json` and the suites of `caid/registry/suites.json`.
  The Section 14.2 item on the mapping profile extension and the Section
  12.5 registration template are worded so that "sha256-hex-to-digest",
  "declared-source-semantic-loss" and "field-name" stay whole; before this
  revision the TXT printed "sha256-hex-to- digest" and, across the page 59
  break, "field- name". [CAID-REGISTRY] targets the raw registry file URL, whose
  octets the digest covers, so the TXT prints it as the reference's URL in
  angle brackets, where line breaks are the only whitespace inside it, and
  the HTML links it. `xml2rfc` 3.34.0 refuses an `<eref>` in `<refcontent>`,
  and in an `<annotation>` it refills a broken URL or `<tt>` path with a
  stray space ("action- types", "history/ action-types"); `check-caid-04`
  fails on either.
- `idnits 3.1.0 -m submission` reports `PASS - No nit found` for the TXT
  rendering (97 pages). `check-caid-04` fails unless that page count is the
  last page of the TXT.
- `idnits 3.1.0` in its default mode reports one error,
  `DOWNREF_TO_LOWER_STATUS` for RFC 8785, which is an Informational RFC on
  the Independent Stream and not in the Downref Registry. Any IETF Last
  Call for this document must call out that downward reference, as BCP 97
  requires. Its warnings are the RFC 6234 downref, which the Downref
  Registry lists, a suggestion to cite BCP 14 by name, and eight lines it
  misreads as appendix titles: four table-of-contents lines and four body
  lines that begin with "Appendix".
- The TXT and the XML contain no U+2013 or U+2014. The only double hyphens
  in the TXT are the arrows of the Section 1.2 figure and table borders.
  `check-caid-04` fails on "adopted", "adoption", "quantum-safe",
  "FIPS-compliant", or "SCITT-integrated" anywhere in the XML or TXT, and
  on "independent implementation" or "endorse" outside the three
  disclaimers of Section 13 and the endorsement disclaimer of the
  Acknowledgments. Tool names are not listed in the public script: before
  upload, grep the XML and TXT for them by hand, from outside the
  repository.

## check-caid-04

`node scripts/check-caid-04.mjs --renders` passes every check on this
tree. The filing gate, `node scripts/check-caid-04.mjs --prefiling`, fails
on this tree, as it must until `feat/caid-04-prefiling` merges. This branch
has merged main at `dedd9a24d` (pull request #823), which is the remote
main, and `--prefiling` now fails unless `git rev-parse origin/main` equals
`git ls-remote origin refs/heads/main`, so a stale fetch cannot pass it.
Against that main its first checks hold: main carries registry version 5,
`caid/spec/caid.abnf`, ports that name -04, and the [CAID-REGISTRY]
commit. Its last check does not: 34 files differ between this branch and
main, 33 under `caid/` and the vendored copy
`packages/verify/vendor/caid.mjs`, among them the JavaScript mapping
stage B fix that Section 8.3 states, the Go
back-reference fix that Sections 2.2 and 2.5 state, the JavaScript fix,
in `caid/impl/js/caid.mjs` and the vendored copy, that reads a host array
of 2^24 or more elements within the value count of Section 2.5, the
conditional cbor-sha256 vectors and the runners that skip them, which
Section 13 describes, the value-count, boundary, long-array and cycle
vectors, the native `$fill` tag and the mapping runners' `host` and `fill`
mutations that express some of them, and the `caid.abnf` comment that
Appendix A carries. The failure message names Sections 2.2, 2.5, 8.3 and
13 and Appendix A, and the paths it compares, under `caid/` or
`packages/verify/vendor/caid.mjs`. The gate passes only when
origin/main holds this branch's `caid/` tree and
`packages/verify/vendor/caid.mjs` byte for byte and the working tree
matches HEAD there; it lists every differing file. The checks it runs on
this tree:

- Appendix A equals `caid/spec/caid.abnf` byte for byte (160 lines). The
  Appendix A.5 comment on `format-name` changed in both, so it names the
  formats of this document instead of "the registered formats".
- Appendix B, the verification detail table, the limits table (13 rows,
  with nesting and value-count rows that name the reason for a host action
  object and defer to the reading step for every other value), and the
  IANA tables equal the tables generated from `caid/spec/core.json`,
  `caid/registry/suites.json`, and the compiled code formats.
- The value count as the three ports and the spec oracle apply it: an
  object or array nested deeper than 64 counts as one value and nothing
  inside it is counted, and a reference back to an enclosing object or
  array counts as one value and nothing beyond it is counted or examined,
  while acyclic shared references count by their expansion down to depth
  64 (Sections 2.2, 2.5 and 5, Table 1 and Section 14.1). Past the count a
  host action object yields unsupported_value and no unsupported_number,
  and phases 3 and 4 still run (Sections 2.2, 2.5 and 5, Table 1 and
  Section 14.1, none of which says "alone" any more), and every rule that
  names unsupported_number is scoped the same way, to a number that an
  object or array at depth 64 or less holds in a value within the count:
  the phase 6 line of the Section 1.2 figure, the closing paragraph of
  Section 2.2, the Section 2.3 bullet on fractional, NaN, infinite and
  out-of-range values, the first requirement of Section 2.5 and its
  sentence on NaN or 1.5 and on a host number beyond 2^53-1, the Integer
  magnitude row of Table 1 (whose refusal column, like the nesting and
  value-count rows, now defers to the reading step for any value but an
  action object), the integer and object entries of Section 4.3, and the
  Table 2 phase 6 row. Each says what happens past the count, and the
  Section 4.3 object entry no longer says "alone"; a host definition,
  mapping profile or mapping source past the count gets the reason of the
  step that reads it (Sections 2.2, 2.5, 2.6 and 14.1). The script requires
  that text and bans the wording each round replaced.
  `native-fraction-in-object-field`, `native-deep-fraction-in-object-field`,
  `native-value-count-fraction-in-object-field` and
  `native-value-count-integer-beyond-range-in-integer-field` pin the two
  Section 4.3 entries, and vectors at exactly 33,554,432 values and one
  more (`native-value-count-3355443{2,3}-{acyclic,cyclic}` and their verify
  twins, and
  `native-definition-value-count-3355443{2,3}-default-optional-fields`,
  whose projection count includes the default optional_fields) pin the
  boundary, so a port that counts with >=, leaves the root out, counts a
  back-reference as zero or skips the default fails them. Until this round
  the JavaScript port, and so the vendored copy, refused a host array of
  2^24 or more elements, which V8 cannot list the keys of at once
  (`Reflect.ownKeys` throws a `RangeError`), as a value outside the data
  model, although it is within the count and the Python and Go ports and
  the oracle read it; it now lists such a container through `Object.keys`
  and `Object.getOwnPropertySymbols`. Before that change it failed exactly
  the five `native-*-16777216-*` core vectors, the relation of the
  definition one, and the two `*-16777216-*` mapping vectors, and passed
  their `16777215` twins and every boundary vector. Until this round the Go port followed
  a cycle down to the nesting limit, so a branching cycle beside 1.5 passed
  the count and gave `[unsupported_value]` where the JavaScript and Python
  ports and the oracle gave `[unsupported_number, unsupported_value]`; Go
  now counts the reference as one value. The vectors
  `native-value-count-stops-at-depth-64`,
  `native-value-count-straddles-depth-64`,
  `native-value-count-with-phase-3-and-4` and its verify twin,
  `native-cyclic-{branching-object,single-object,branching-array,three-way-array,single-array}-with-fraction`
  and their verify twins, `native-definition-value-count-in-projection`,
  `native-definition-value-count-outside-projection`,
  `profile-value-count-abstains` and
  `stage-b-source-value-count-not-canonicalizable` pin the behavior in all
  three ports and the vendored copy. Before the Go change, its runner
  failed exactly the six branching-cycle vectors (compute and verify for
  the branching object, the branching array and the three-way array) and
  passed the single back-reference ones.
- Appendix D, "Action Types of Reference Registry Version 5", lists all 62
  types of registry version 5 once, with their `definition_sha256` values:
  D.1, the 54 initial IANA entries (45 active, 9 deprecated), and D.2, the
  8 entries of the script's `IANA_EXCLUDED`, each with its reason confirmed
  against the registry entry. Section 12.2, both subsections and the
  `ed-iana` change item state those counts, and Section 14.4 keeps the
  counts of the whole registry (62, 53 active, 9 deprecated). Section 12.2
  says each of the 9 deprecated initial entries has a required enum with no
  pinned snapshot, so none of them produces or verifies a CAID, and that
  four of them hold as enums values their successors carry as code fields;
  the script derives both from the registry.
- Appendix C recomputes under registry version 5 with its enum snapshots:
  the C.1 object gives 230 canonical octets, digest `sha256:9622c6f6...3b56`
  and the CAID ending `...arxrO1Y` under jcs-sha256, and 207 CBOR octets,
  digest `sha256:edb04ef2...d4b2f6` and the CAID ending `...-200vY` under
  cbor-sha256, with `definition_sha256` `sha256:3a5ad4c0...ff12`; C.2
  through C.6 recompute as before.
- The Section 4.2 example, with its line breaks read as spaces and its one
  folded line unfolded, is the registry version 5 entry for
  payment.release.1 and hashes to the C.1 `definition_sha256`.
- The Section 4.7 registration, read the same way, is the registry version
  5 entry for tool.call.1 member for member, summary, notes, and
  digest_notes included, so the draft and the file IANA is asked to store
  give one text for it. Sections 12 and 12.2 and the Appendix D
  introduction no longer carve tool.call.1 out of "the entry with that
  name in the registry file", and the Section 4.7 prose names the
  `base:sha256:<hex>` strings that the entry's digest_notes name.
- Section 12.2 applies the 128-bit entropy criterion to registrations made
  after the document and says where the reason for the initial entries is
  stated; Section 4.7 keeps the 128-bit occurrence_id requirement; Section
  12.2 and Appendix D.2 limit later registration to the seven
  specification-defined D.2 types, and the expert registers an
  organization-specific first segment only with that organization as
  change controller, which Appendix D.2 applies to
  emilia.mobile.authorized-action.1; Sections 12 and 12.1 let the IESG act
  for another change controller only when that controller cannot be
  reached or does not respond, and `caid/registry/suites.json` says the
  same; and `caid/registry/GOVERNANCE.md` section 7.1 lists the D.2
  entries, carries the organization-specific rule, and no longer states
  either absolute that the audit refuted.
- Section 12.2 says each snapshot file records its source and its
  `enum_snapshot_files` entry in `action-types.json` records what is known
  of its terms; the script checks both for all five snapshots (the ISO 4217
  file itself carries no terms member).
- Every digest field of the C.1, C.2 and C.5 objects is the SHA-256 of a
  short example string the script names ("test" for beneficiary_account,
  "patient-0042" for patient_ref), and the C.6 digests recompute from the
  C.6 source through the profile's transforms, so the Section 11 sentence
  that the digest-typed values of Appendix C can be recovered by guessing
  holds for each. The C.5 patient_ref was a digest of an unrecorded
  preimage; it is now sha256("patient-0042"), and the C.5 CAID
  (`...j7WskhX5...ra57U`) and digest (`sha256:8fb5ac92...e7b5`) recompute
  through the reference validator, the JavaScript and Python ports, and a
  plain sorted-key JSON encoding, which equals RFC 8785 for that object.
- Appendix D.2 says its 8 entries stay in registry version 5 unchanged
  member for member from registry version 4, with identical RFC 8785
  encodings; the script compares each against
  `history/action-types.v4.json`. The two files differ in layout, so the
  entries are not the same octets, and the draft no longer says "byte for
  byte" there. Two files on main declared registry version 4: the one at
  `2c0cd467f` (SHA-256 `2becee28...`) and the one at `61e8d58b3`
  (`73a31f4a...`), which adds the unresolved_external_enums member and a
  snapshot_sha256 to each enum_snapshot_files entry; all 52 types have the
  same definition_sha256 in both.
  `history/action-types.v4.json` is the later one, byte for byte; Section
  14.4 names it as the last file that declared registry version 4, which
  `digests.json` pins by its SHA-256, and the script checks that the file
  hashes to that pin. The -03 packet pins neither file.
- Section 13 says the next major release vendors caid.mjs without
  mapping; `packages/verify/vendor/caid.mjs` is a byte copy of
  `caid/impl/js/caid.mjs` and defines no mapping function.
- Section 13 says none of the three implementations implements
  cbor-sha256 and each skips the vectors that apply only to an
  implementation of it. The script runs the JavaScript, Python and Go core
  and grammar runners and fails unless each fails nothing and skips
  exactly those vectors (2 core, 0 grammar); a missing toolchain is a note,
  and a failure with `--prefiling`. It also requires the Section 2.5
  sentence that a host number beyond 2^53-1 with a finite correctly
  rounded value is refused by phase 6 alone, the sentence that NaN or 1.5
  in an integer field is mistyped_field and unsupported_number, and the
  Section 13 sentences that each implementation refuses cbor-sha256 as
  unknown_suite and that the JavaScript implementation uses only the
  platform's cryptographic library and the Python and Go implementations
  only their standard libraries; for the last it reads the imports of
  every port module (`node:crypto` and the sibling module in JavaScript,
  `sys.stdlib_module_names` in Python, no `require` in `go.mod` and no
  import path with a dot in Go).
- The limits the prose restates (the value count in Sections 2.5 and
  14.1, the JSON text limit in Sections 2.4, 10.7 and 14.1, the canonical
  limit and the nesting depth in Section 2.2, Table 2 and Section 14.1,
  and 2^53-1 in Section 2.3) are the values of `caid/spec/core.json`, and
  every comma-grouped number in the source is one of those values, 2^53-1,
  or the amount counterexample "1,000".
- Section 12.2 carries the whole 128-bit clause of the material-fields
  test and the rule that a new version of a registered type name is
  registered by the change controller of its earlier versions or with that
  controller's written agreement, and `caid/registry/GOVERNANCE.md`
  section 5 carries the 128-bit criterion with its exception and the
  snapshot-file and terms duty.
- The change log states what the text states: `chg-deprecated` says a
  deprecated type computes and verifies wherever its fields resolve, which
  none of the 9 deprecated initial entries does (Section 12.2);
  `ed-logging` says the Section 11 logging rule reverses the -03
  recommendation (a SHOULD) that identifiers be treated as public values;
  `ed-type-entropy` keeps the SHOULD and the Section 12.2 exception; and
  `ed-iana` records that the IESG may act for a change controller that
  cannot be reached and that a new version of a type name is registered
  by, or with the written agreement of, the change controller of its
  earlier versions, neither of which -03 had. The script requires each
  wording and bans the one it replaces.
- Each change since -03 appears in one list: Section 14.5 lists every
  requirement the new text places on issuers, type authors, registrants,
  executors, carrying protocols, relying parties, deployments and
  applications, among them the verifier rules for several CAIDs,
  signature coverage, truncation, the occurrence identifier, message
  bounds, number literals, logging, type entropy, keyed commitments,
  identifier normalization and snapshot files, and the Security and
  Privacy items of Section 14.6 describe text alone.
- Section 12.8 gives the utility of the scheme (RFC 7595, Section 3.1)
  against an ni URI (RFC 6920) and a URN namespace (RFC 8141), with the
  wording read against those RFCs (below), and the `ed-uri-utility` item
  records it. Section 11 says a CAID is meant to be recomputed by parties
  that already hold the action object and is not designed as a
  correlation identifier for parties that do not, and `ed-privacy`
  records it. Its sentence on sequential system-of-record identifiers
  now requires that the other members can be guessed too, since
  payment.release.1 has an optional free-text memo and order.place.1
  requires items_digest, whose preimage is generally not guessable.
- Section 2.2 states the canonical-size condition as "at most 16,777,216
  octets" where it said "within this limit", whose nearest antecedent had
  become the value count.
- [CAID-REGISTRY] targets the raw `action-types.json` at commit
  `cea10b85e`, names no blob URL, and that commit's file hashes to registry
  version 5 (`1e30ddd3...2551a`); the TXT prints that URL once, in angle
  brackets.
- All 43 `chg-` items of "Changes since -03" map to vector ids that exist
  in the core corpus v5, the mapping corpus v2, or the interoperability
  corpus (`CHANGES-VECTORS.json`). New or extended: `chg-refused-depth`,
  `chg-refused-json-text`, `chg-data-model`, `chg-host-values`,
  `chg-mapping-stage-b`, `chg-enum-snapshot-shape`, and `chg-cbor-suite`.
- Every BCP 14 keyword outside code is marked with `<bcp14>`, the wording
  that each confirmed finding removes is gone, and the text each requires
  is present. The references, the registries the Abstract and Section 12
  name, the prose examples against the ABNF, both renders, and
  `SHA256SUMS.txt` check.

## Conformance and generated sources

- `npm run caid:conformance` passes: 613 core, 1966 grammar, 86 mapping,
  and 100 consequential-interoperability vectors against the spec oracle,
  with the generated-sources and registry checks. In JavaScript, Python,
  and Go each runner reports 611 of the 613 core vectors run and passed
  (2 skipped) and all 1966 grammar cases: six vectors apply only where
  cbor-sha256 is, or is not, implemented, and each runner skips those
  whose condition does not hold.
- `node caid/spec/gen.mjs --check` passes (4 generated files match), and
  `node caid/spec/abnf-check.mjs` reports 0 failures.
- `npm run check:llm-context` passes.
- `node scripts/check-caid-03.mjs` still passes for the posted -03 packet.

## Claims checked outside the script

Run on 2026-09-27 on darwin/arm64 (node, Python 3, go1.26.4, swift):

- The C.1 cbor-sha256 values: Python `cbor2` 6.1.4 with `canonical=True`
  and an encoder written for this check from RFC 8949 Sections 3 and 4.2.1
  produce the same 207 octets, digest
  `sha256:edb04ef20891696de205147e0ba719167aa446300f4f04cf32bbf077edb4d2f6`,
  and CAID
  `caid:1:payment.release.1:cbor-sha256:7bBO8giRaW3iBRR-C6cZFnqkRjAPTwTPMrvwd-200vY`;
  decoding gives the key order memo, amount, currency, action_type,
  beneficiary_account, payment_instruction_id. The script's own encoder
  and the corpus vector `compute-cbor-sha256-appendix-c1` agree.
- The Section 2.5 host-value rule, with a local definition that has an
  integer field and optional amount-string, digest, string, and object
  fields. JavaScript: 1.5, NaN, and Infinity in the integer field give
  `[mistyped_field:n, unsupported_number]`; 2^53 and `Number.MAX_VALUE`
  give `[unsupported_number]`; a BigInt gives
  `[mistyped_field:n, unsupported_value]`; "1" followed by U+D800 gives
  `[invalid_amount:a, unsupported_value]` in the amount-string field,
  "sha256:" followed by U+D800 gives `[mistyped_field:d, unsupported_value]`
  in the digest field, and a lone surrogate gives `[unsupported_value]` in
  the string field; a Map or a Date in the object field gives
  `[mistyped_field:o, unsupported_value]`. Python: the same for 1.5, NaN,
  2**53, the strings, and a set; 10**400 and 2**1024-2**970 give
  `[mistyped_field:n, unsupported_number]`, and 2**1024-2**970-1 gives
  `[unsupported_number]`; `decimal.Decimal` and `fractions.Fraction`
  give `[mistyped_field:n, unsupported_value]`. JavaScript `new Number(5)`
  and the BigInts 5n, 2n**60n, and 10n**400n give
  `[mistyped_field:n, unsupported_value]`, and `[unsupported_value]` as a
  member no field declares. Go: `int`, `int64`, `float64`, and
  `json.Number` are numbers, so `int64(1)<<60` and `math.MaxInt64` give
  `[unsupported_number]` and `json.Number("1e400")` gives
  `[mistyped_field:n, unsupported_number]`; `int32`, `int8`, `uint`,
  `uint64` (5 and 1<<60), `float32`, and `*big.Int` give
  `[mistyped_field:n, unsupported_value]` in the integer field and
  `[unsupported_value]` elsewhere. Section 2.5 and Section 6.1 state this
  as a property of the binding. The corpus vectors `native-*` pass in all
  three ports.
- The Section 8.3 stage B source descriptor rule, with the C.6 profile and
  source and a descriptor that adds a NaN member, a 1.5 member, a member
  nested 70 deep, or a lone surrogate in media_type: JavaScript, Python,
  and Go each report exactly `[source_format_mismatch]`.
- The Section 10.6 number differential: in node, `Number()` of
  3999.99999999999999999 and of 4000.0000000000001 is 4000, of
  3999.9999999999995 and 4000.0000000000005 is not an integer, and of
  1e-400 is 0.
- The Section 10.6 member-name differential: Go's `encoding/json`
  unmarshals `{"amount":"1.00","Amount":"99999.00"}` into a struct field
  tagged `json:"amount"` as 99999.00, and Swift's `==` is true for
  "caf" + U+00E9 and "cafe" + U+0301.
- Section 12.2: every currency field of the 54 initial entries is an enum
  pinned to the ISO 4217 snapshot, and the DNS, the two JOSE, and the
  ISO 3166-1 alpha-2 snapshot files record an IANA registry as their
  source (`enum_snapshot_files` in `action-types.json`).
- Section 13: `npm view @emilia-protocol/verify version` is 5.0.0,
  published 2026-09-25; `packages/verify/CHANGELOG.md` lists 6.0.0 as
  "Unreleased", and the vendored `caid.mjs` implements -04 (the script
  checks both).
- `caid` is absent from the IANA URI Schemes registry
  (`uri-schemes-1.csv`, 439 lines, fetched on 2026-09-27).
- The HCPCS and UTS #39 reference URLs return HTTP 200. The other code
  system references carry no URL.
- The Datatracker API, queried on 2026-09-27, reports revision 03 as the
  latest of draft-schrock-canonical-action-identifier, and the IETF
  archive URL for -04 returns 404, so -04 is the next revision. It reports
  draft-schrock-ep-authorization-receipts-13,
  draft-schrock-action-evidence-boundary-07,
  draft-schrock-ep-authorization-evidence-chain-06,
  draft-thallapelly-oasnt-caid-01, draft-lee-orprg-permit-receipts-00, and
  draft-morrow-sogomonian-exec-outcome-attest-00 as the latest revisions of
  the cited drafts; the last expires on 2026-10-06.

Re-run for the second audit of the fixes, on the same day and machine:
`npm view @emilia-protocol/verify version` is still 5.0.0; the Datatracker
API reports the same latest revisions for this draft (03) and every cited
draft; `xml2rfc 3.34.0` refuses an `<eref>` inside `<refcontent>` as
invalid, which is why [CAID-REGISTRY] now targets the raw URL; and the
value-count vectors of this round pass in all three ports through
`npm run caid:conformance`, which is where the Section 2.5 and 2.6 text
about the count below depth 64 and about host documents comes from.
`npx tsc -p tsconfig.rest.json --incremental false`, the CI type gate for
scripts and `caid/`, reports no error in `scripts/check-caid-04.mjs`.

Re-run for the third audit of the fixes, on the same day and machine:

- `npm view @emilia-protocol/verify version` is still 5.0.0, and the
  Datatracker API reports the same latest revisions for this draft (03)
  and every cited draft; the IETF archive URL for -04 still returns 404.
- RFC 6920, RFC 8141 and RFC 7595 were fetched from rfc-editor.org and
  read for the Section 12.8 utility paragraph. RFC 6920 Section 3: the
  digest algorithm is named from the registry of its Section 9.4 (the
  Named Information Hash Algorithm Registry), and the value is the hash of
  its defined input, which defaults to the object's octets; Section 2:
  other than for a public key, the input is left to other
  specifications, and a comparison considers only the digest algorithm
  and value, never the authority or parameters. RFC 8141 Section 3.1:
  URN-equivalence lowercases "urn" and the NID and ignores the r-, q- and
  f-components, and a namespace's additional rules can only remove false
  negatives, never make URN-equivalent names different. RFC 7595 Section
  3.1: a scheme specification SHOULD discuss the utility of the scheme.
- The Section 14.2 stage B history, run against the JavaScript mapper at
  `cea10b85e` with the `ep-action-v1` profile under a declared loss: a
  profile outside the data model through profile_id 1.5 or a lone
  surrogate still read both members (`invalid_mapping_profile`,
  `mapping_profile_unpinned`, `declared_source_semantic_loss`); a member
  nested 70 deep, a Map, a BigInt, a shared array past the value count, a
  cycle, or an undefined member made it read neither
  (`invalid_mapping_profile`, `mapping_profile_unpinned`,
  `source_format_mismatch`). The current JavaScript mapper matches Python
  and Go on the vectors that pin stage B.
- The value-count and cycle vectors of this round pass in JavaScript,
  Python, Go and the vendored copy through `npm run caid:conformance` and
  the vendored lane, with the same reason lists and verification details
  as the oracle.

Re-run for the fourth audit of the fixes, on the same day and machine:

- `npm view @emilia-protocol/verify version` (the registry's latest) is
  still 5.0.0, the Datatracker API reports the same latest revisions for
  this draft (03) and every cited draft, and the IETF archive URL for -04
  still returns 404.
- The scoping of Sections 2.3 and 2.5 and the Table 2 phase 6 row, with a
  local definition that has a required string field s, an array field a
  and an integer field n, and a shared array of 2^26 - 1 values in a:
  JavaScript, Python and Go each give `[mistyped_field:n,
  unsupported_value]` for 1.5 and NaN in n, as do an infinity in
  JavaScript and Go and the Python int 10**400, and `[unsupported_value]`
  for 2^53 and for a larger finite host number (`Number.MAX_VALUE`, the
  Python int 2**1024-2**970-1, Go `math.MaxInt64`); the same objects with
  a shared array of 15 values give `[mistyped_field:n,
  unsupported_number]` and `[unsupported_number]`.
- The four new stage B mapping vectors pass in the three ports and fail
  against the JavaScript mapper at `cea10b85e`, as the Section 14.2
  history sentence says of it; the Python and Go runners were checked to
  build a real cycle (a member that is its own profile, an array that
  holds itself) and a value of no JSON kind.

Carried from the earlier validation of this packet on the same day, and
not re-run for this revision, because the text they support did not
change: the preimage statement of Section 11 for the tool.call.1 example
(4000 candidates; the Appendix C digests are checked by the script), the
`(a|a){1,99}` timings behind Section 10.8, the cost figures behind
Section 10.7, the document encoding limit results, the
RFC 7493 Section 2.1 and 2.3 reading, and the
`draft-thallapelly-oasnt-caid-01` Section 6.4 reading.

Datatracker has not published this packet. Submission is held; see
`README.md`.
