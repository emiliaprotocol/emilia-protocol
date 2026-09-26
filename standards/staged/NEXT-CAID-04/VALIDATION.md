# Validation record

Validated on 2026-09-26, starting from the published -03 source.

- The starting XML is `../NEXT-CAID-03/UPLOAD-THIS/`, byte-identical to the
  IETF archive copy of -03.
- `xmllint --noout` passed for the XML source.
- `xml2rfc 3.34.0` generated the TXT rendering and, with `--no-external-js`,
  the HTML rendering. The generated HTML's non-semantic trailing spaces were
  normalized before checksums were recorded. The same procedure applied to
  the unchanged -03 source reproduced its checked-in TXT and HTML byte for
  byte, and applied to the amount-string revision of this packet before the
  parsing edits, reproduced that revision's TXT and HTML byte for byte.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found` for the TXT
  rendering.
- The source omits `submissionType`, as -03 does, because this remains an
  individual draft with no adopted document stream. `xml2rfc` uses its IETF
  rendering default and emits an informational warning.

## Amount-string ABNF

- The ABNF accepts exactly the strings that the JavaScript, Python, and Go
  amount checks accept, over all 111,111 strings of up to five characters
  drawn from digits 0, 1, and 9, "-", ".", "+", "e", space, line feed, and
  comma. This was rerun after the Python whole-string fix (#811) merged;
  the 171 Python differences recorded before it are gone.
- `node scripts/check-caid-04.mjs` checks the ABNF in the source, the TXT
  rendering, and `caid/DESIGN.md`, and compares the JavaScript reference with
  a matcher written from the ABNF over the draft's examples and all 7,381
  strings of up to four characters from a nine-character alphabet. Separate
  mutations of the reference that admit a leading zero, a final line feed,
  or a leading "+", or that report a non-matching string as
  `mistyped_field`, each make the check fail.

## Identifier parsing

- The identifier ABNF block and the Parsing section are identical, after
  whitespace normalization, in -00, -01, -02, and -03. This revision changes
  only the unknown-suite item of the Parsing section (and adds the paragraph
  after it), the suite and digest description in Identifier Syntax,
  Computation step 5, and Verification step 3.
- `node scripts/check-caid-04.mjs` checks the suite ABNF in the source, the
  TXT rendering, and `caid/DESIGN.md`; that every suite in
  `caid/registry/suites.json` matches it; the new parsing, computation,
  verification, and change-record text; and that the source and TXT list the
  16 final characters derived from 43 characters carrying a 32-octet digest.
  It then compares `parseCaid` with a parser model written from the ABNF,
  the suite registry, and the digest rules over 3,029 identifiers: every
  suite of up to four characters from `a z 0 9 - A _`, named cases (`1x`,
  `x--y`, `x-`, `jcs-sha512`, uppercase, trailing hyphen), and for the
  registered suites and `jcs-sha512`, a canonical digest with each of the 64
  base64url characters and six non-alphabet characters as its final
  character, plus 42-, 44-, and padded lengths.
- Separate mutations of the JavaScript reference each make the check fail:
  admitting an unregistered suite, main's behavior of admitting any suite
  matching `[a-z0-9]+(-[a-z0-9]+)*` without a digest-length check, ignoring
  the unused bits, checking only the 43-character length (main's digest
  check), and dropping `cbor-sha256` from the registered suites. Restoring
  a separate suite pattern that differs from the ABNF makes no difference,
  because every name it could admit or refuse differently is unregistered;
  the ports therefore rely on registry membership and the check verifies
  that the registered names match the ABNF.
- `npm run caid:conformance` passed the registry identity and enum-coverage
  checks, the Go unit tests, and all 96 core (corpus version 4), 25 mapping,
  and 100 consequential-action vectors in JavaScript, Python, and Go.
- The version 4 corpus run against the version 3 ports (main at
  `d9ad6ab4c`) fails the same six vectors in each language:
  `refuse-suite-leading-digit`, `refuse-suite-unregistered`,
  `refuse-suite-unregistered-unchecked-digest`,
  `refuse-digest-nonzero-unused-bits`, `verify-malformed-unregistered-suite`
  (reported `unknown_suite`), and `verify-malformed-nonzero-unused-bits`
  (reported `digest_mismatch`). The other two new vectors,
  `parse-registered-suite-not-implemented` and `refuse-digest-too-long`,
  pass on both and guard the boundary.
- `node scripts/check-caid-03.mjs` still passes for the published -03
  packet.

Datatracker has not published this packet. Submission is held; see
`README.md`.
