# Validation record

Validated on 2026-09-27. The source applies every confirmed finding of the
pre-filing review, and every finding of the first and second audits of
those fixes, to the previously staged -04, which carried the amount-string
ABNF and the suite and unused-bit parsing changes over -03 and keeps both.

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
  page. Table 1 spans two pages and breaks between two rows.
- Every sourcecode line is at most 69 columns. Long example lines are folded
  as specified in RFC 8792 (single backslash strategy), and
  `check-caid-04` unfolds them before recomputing. Appendix D is two
  definition lists, not tables, because a 64-digit digest does not fit a
  table row. `xml2rfc` keeps each term (the type, its status and, for a
  deprecated type, its successor) on the page of its description (the
  digest), and `check-caid-04` fails if a page of the TXT separates an
  entry's name line from its digest line, or if a term is long enough to
  wrap.
- Non-breaking hyphens (`&#8209;`) keep `action-types.json`,
  `history/action-types.v4.json`, `value-sets/`, SHA-384 and SHA-512/256
  on one line. `xml2rfc` renders them as ASCII hyphens, and the TXT is
  ASCII only. [CAID-REGISTRY] targets the raw registry file URL, whose
  octets the digest covers, so the TXT prints it as the reference's URL in
  angle brackets, where line breaks are the only whitespace inside it, and
  the HTML links it. `xml2rfc` 3.34.0 refuses an `<eref>` in `<refcontent>`,
  and in an `<annotation>` it refills a broken URL or `<tt>` path with a
  stray space ("action- types", "history/ action-types"); `check-caid-04`
  fails on either.
- `idnits 3.1.0 -m submission` reports `PASS - No nit found` for the TXT
  rendering (94 pages). `check-caid-04` fails unless that page count is the
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
commit. Its last check does not: 22 files under `caid/` differ between
this branch and main, among them the JavaScript mapping stage B fix that
Section 8.3 states, the conditional cbor-sha256 vectors and the runners
that skip them, which Section 13 describes, the value-count vectors, and
the `caid.abnf` comment that Appendix A carries. The gate passes only when
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
- The value count as the three ports apply it: an object or array nested
  deeper than 64 counts as one value and nothing inside it is counted
  (Sections 2.2, 2.5 and 5, and Table 1), and a host definition, mapping
  profile or mapping source past the count gets the reason of the step
  that reads it (Sections 2.2, 2.5, 2.6 and 14.1). The script requires that
  text; the vectors `native-value-count-stops-at-depth-64`,
  `native-value-count-straddles-depth-64`,
  `native-definition-value-count-in-projection`,
  `native-definition-value-count-outside-projection`,
  `profile-value-count-abstains` and
  `stage-b-source-value-count-not-canonicalizable` pin the behavior in all
  three ports.
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
  rounded value is refused by phase 6 alone.
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

- `npm run caid:conformance` passes: 579 core, 1966 grammar, 78 mapping,
  and 100 consequential-interoperability vectors against the spec oracle,
  with the generated-sources and registry checks. In JavaScript, Python,
  and Go each runner reports 577 of the 579 core vectors run and passed
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

Carried from the earlier validation of this packet on the same day, and
not re-run for this revision, because the text they support did not
change: the preimage statement of Section 11 (4000 candidates for the
tool.call.1 example), the `(a|a){1,99}` timings behind Section 10.8, the
cost figures behind Section 10.7, the document encoding limit results, the
RFC 7493 Section 2.1 and 2.3 reading, and the
`draft-thallapelly-oasnt-caid-01` Section 6.4 reading.

Datatracker has not published this packet. Submission is held; see
`README.md`.
