# AEC -08 validation

Prepared on 2026-10-04 from
`../NEXT-AEC-07/UPLOAD-THIS/draft-schrock-ep-authorization-evidence-chain-07.xml`
(SHA-256 `bfcf111687d6b48cd6b32b829144673c6b70cb340209316dc5a1945a1a62d1e6`).
The IETF archive copy,
`https://www.ietf.org/archive/id/draft-schrock-ep-authorization-evidence-chain-07.xml`,
fetched on 2026-10-04, has the same SHA-256, so this packet starts from the
posted -07 bytes.

## Source

`SHA256SUMS.txt` pins the three files. The source SHA-256 is
`0769cc6c7c49c992ca62d2eb96ad4e255f06c2e16b36f75b874466b94004e9f4`.

Changed relative to -07: `docName`, the `seriesInfo` value and the date
(4 October 2026); Section 4 (the requirement profile digest covers the
expression as stored); Section 8 (rewritten, with subsections 8.1 to 8.7);
Section 9 (new step 4, whole-expression validation; step 6 evaluates that
tree); Section 10 (`EP-AEC-EVALUATOR-08-v1` and the replay migration rules);
Section 14 (parser differentials); Section 18 (Changes in -08, new);
Implementation Status; the normative RFC 7405 reference; CAID cited at -05;
and the informative `AEC-EXPRESSION-VECTORS` reference. Everything else is
the -07 text.

## Rendering

- `xmllint --noout`: PASS.
- Renders produced next to the source and then moved, run from this packet
  directory with xml2rfc 3.34.0, as for -07:

  ```
  cd UPLOAD-THIS
  xml2rfc --text --html draft-schrock-ep-authorization-evidence-chain-08.xml
  perl -pi -e 's/[ \t]+$//' draft-schrock-ep-authorization-evidence-chain-08.html
  mv draft-schrock-ep-authorization-evidence-chain-08.html \
     draft-schrock-ep-authorization-evidence-chain-08.txt ../RENDERS/
  ```

  xml2rfc prints no warnings. `node scripts/check-aec-08.mjs --render`
  repeats this on a copy of the source in a scratch directory and the TXT
  and HTML reproduce byte for byte. The `-o` path caveat recorded in
  `../NEXT-AEC-07/VALIDATION.md` applies unchanged.
- The source and TXT are printable ASCII, contain no en or em dash, and no
  TXT line exceeds 72 columns.
- `idnits 3.1.0 -m submission` on the TXT: `PASS - No nit found`. On the XML
  source it reports one error, `SUBMISSION_TYPE_UNEXPECTED`, as for -06 and
  -07 (the document has no stream on Datatracker; Datatracker accepted both).
- `idnits 3.1.0` default mode on the TXT: three `POSSIBLE_DOWNREF` findings
  for the normative CAID, Quorum and Authorization Receipts drafts, the same
  three retained for -06 and -07.
- `idnits 3.1.0` default mode on the XML: six errors, the same six types
  recorded for -07 (the three `POSSIBLE_DOWNREF`,
  `SUBMISSION_TYPE_UNEXPECTED`, `INVALID_REFERENCES_NAME`,
  `MISSING_REQLEVEL_REF`), and 88 `MISSING_BCP14_TAGS` comments (69 for
  -07; the new text adds BCP 14 keywords).
- `shasum -a 256 -c SHA256SUMS.txt`: PASS.

## Checks

- `npm run check:aec-08` and `node scripts/check-aec-08.mjs --render`: PASS.
  Each was also run against injected faults and failed with the expected
  message: a changed Table 1 value, a changed corpus SHA-256 in Section 8.7,
  a changed inline parse identity, the "does not guarantee matching
  verdicts" sentence turned into a guarantee, a changed vector count,
  "consume all input" weakened, and `AEC_EVALUATOR_REVISION` set back to
  `EP-AEC-EVALUATOR-07-v1` in `packages/verify/src/evidence-chain.ts`.
- `npm run check:aec-07`, `npm run check:standards-staged`: PASS.
- `node --test scripts/ci/change-lane.node-test.mjs`: 17 of 17 pass, with
  `scripts/check-aec-08.mjs` added to the kept-checker list.
- `node conformance/run.mjs`: all 21 live suites and the
  `EP-AEC-EXPRESSION-v1` profile suite agree across the JavaScript, Python
  and Go ports (104 of 104 corpus vectors in each).
- `packages/verify`: `node --test aec-expression.test.js` 16 of 16, including
  the four mutation tests that keep the parse identity while corrupting
  precedence, operator evaluation, role matching and FAILED-fact
  eligibility. `packages/python-verify`: `pytest tests/test_aec_expression.py`
  5 passed. `packages/go-verify`: `go test ./...` PASS.

## Claims in the draft and their evidence

- "The JavaScript, Python, and Go reference parsers of -07 already read
  every vector of the corpus ... this way" (Sections 8 and 18): the
  origin/main (`62a4310b8`) expression parsers were run on all 104 vectors
  for syntax validity and Boolean value: JavaScript
  `__aecSecurityInternals.evalRequirement` from `packages/verify/dist`,
  Python `emilia_verify._eval_requirement`, Go `aecEvalRequirement`. Each
  agreed on 104 of 104.
- Go legacy trimming (Implementation Status): origin/main
  `packages/go-verify/evidence_chain.go` line 492 sets
  `pinned := strings.TrimSpace(opts.Requirement)`. The length units: Go
  `len(s)` (octets), Python `len(expr)` (code points), JavaScript
  `expr.length` (UTF-16 units) on origin/main.
- "@emilia-protocol/verify 6.0.0, implements EP-AEC-EVALUATOR-07-v1":
  `npm view @emilia-protocol/verify version` returns 6.0.0, and
  `dist/evidence-chain.js` of that version on unpkg contains
  `EP-AEC-EVALUATOR-07-v1` only. The branch leaves `packages/verify` at
  6.0.0 with the -08 entry under "Unreleased" in its CHANGELOG. PyPI
  `emilia-verify` is 2.8.6, the version `packages/python-verify` still
  declares.
- Construction refusal, replay comparison, `authorization_decision: false`:
  `packages/verify/src/evidence-chain.ts` (`validateAecRequirement`,
  `replay`), exercised by `packages/verify/aec-expression.test.js`.
- Corpus locator: the commit-pinned URL returned HTTP 200 on 2026-10-04 and
  its bytes hash to
  `927e3663299bd6c11836d4ad22a6dd398b85d16478100921bf68cf03ed459d4b`, the
  value in Section 8.7 and in `conformance/vectors/aec-expression.v1.SHA256SUMS`.
- Counts in Section 8.7 (104 vectors, 47 valid, 57 invalid): computed from
  the corpus by `scripts/check-aec-08.mjs`.

## Cited revisions (Datatracker API, queried 2026-10-04)

- AEC: latest revision 07, posted 2026-09-28T13:23:04Z;
  `draft-schrock-ep-authorization-evidence-chain-08.txt` is not in the IETF
  archive (HTTP 404). -08 is the next revision.
- `draft-schrock-canonical-action-identifier-05`, posted
  2026-10-02T19:53:38Z, header date 2 October 2026. -07 cited -04. Its
  Section 8.3 still defines the verdicts EQUIVALENT_UNDER_PROFILE,
  NOT_EQUIVALENT and INDETERMINATE that Section 7 uses, and its Section 8
  is still the Action-Mapping Profile.
- `draft-schrock-ep-authorization-receipts-13`, posted
  2026-09-12T15:05:02Z (unchanged from -07).
- `draft-schrock-ep-quorum-04`, posted 2026-09-06T17:27:51Z (unchanged).
- `draft-schrock-action-evidence-boundary-07`, posted
  2026-09-26T00:11:40Z (unchanged).
- `draft-schrock-agent-qualification-statements-00`, posted
  2026-07-28T07:02:20Z (unchanged).
