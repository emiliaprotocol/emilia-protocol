# AEC -08 validation

Prepared on 2026-10-04 from
`../NEXT-AEC-07/UPLOAD-THIS/draft-schrock-ep-authorization-evidence-chain-07.xml`
(SHA-256 `bfcf111687d6b48cd6b32b829144673c6b70cb340209316dc5a1945a1a62d1e6`).
The IETF archive copy,
`https://www.ietf.org/archive/id/draft-schrock-ep-authorization-evidence-chain-07.xml`,
fetched again on 2026-10-04, has the same SHA-256, so this packet starts from
the posted -07 bytes.

## Source

`SHA256SUMS.txt` pins the three files. The source SHA-256 is
`d0aac6f5366abf180507d13e1dea7239c553d5e61ed279d6a959034225f227c3`; the TXT
render is `eaffa47ba035908028ac393fced0c0713bbbf2c5b3f34316296dc0464ac416f2`.

Changed relative to -07: `docName`, the `seriesInfo` value and the date
(4 October 2026); Section 4 (the requirement profile digest is named as the
evidence digest of the requirement object and covers the expression as
stored); Section 5 (the expression size is no longer a relying-party resource
limit); Section 8 (rewritten, with subsections 8.1 to 8.7); Section 9 (new
step 4, whole-expression validation; step 6 evaluates that tree); Section 10
(`EP-AEC-EVALUATOR-08-v1`, the `evaluator_profile_digest` member in the
record template with what it identifies and the limits of that definition,
the evaluator profile in the replay determinism inputs, and the replay
migration rules); Section 14 (parser differentials); Section 18 (Changes in
-08, new); Implementation Status; the normative RFC 7405 reference; CAID
cited at -05; and the informative `AEC-EXPRESSION-VECTORS` reference.
Everything else is the -07 text.

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
  `../NEXT-AEC-07/VALIDATION.md` applies unchanged. A literal backslash-u
  escape in running text is unescaped by xml2rfc, so Section 8.4 describes
  JSON escapes in words.
- The source and TXT are printable ASCII, contain no en or em dash, and no
  TXT line exceeds 72 columns. The TXT has 35 pages.
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
  Each was run against injected faults and failed with the expected message:
  a changed Table 1 value, a changed corpus SHA-256 in Section 8.7, a changed
  inline parse identity, the "does not guarantee matching verdicts" sentence
  turned into a guarantee, a changed vector count, "consume all input"
  weakened, `AEC_EVALUATOR_REVISION` set back to `EP-AEC-EVALUATOR-07-v1` in
  `packages/verify/src/evidence-chain.ts`, the exact-limits sentence
  weakened, the token-completion rule removed from Section 8.4, the Section
  10 scope sentence on replay digests turned into a promise, and the -07
  parser agreement sentence altered.
- `npm run check:aec-07`, `npm run check:standards-staged`: PASS.
- `node --test scripts/ci/change-lane.node-test.mjs`: 17 of 17 pass, with
  `scripts/check-aec-08.mjs` in the kept-checker list.
- `node conformance/run.mjs`: all 21 live suites and the
  `EP-AEC-EXPRESSION-v1` profile suite agree across the JavaScript, Python
  and Go ports (104 of 104 corpus vectors in each).
- `packages/verify`: `node --test aec-expression.test.js` 24 of 24. Four
  tests keep the parse identity while corrupting precedence, operator
  evaluation, role matching and FAILED-fact eligibility. Six cover the
  genuine -07 record in `conformance/vectors/aec-replay-07.v1.record.json`
  (SHA-256
  `de32112e9e9f47925e6ad6b3e05d039fb26901471033f9980bcfc03bb2306365`),
  which the published `@emilia-protocol/verify` 6.0.0 made with
  `EP-AEC-EVALUATOR-07-v1` over the real Class-A WebAuthn receipt of
  `aec-role.v1.json` `accept_pinned_human_receipt`, and which 6.0.0's own
  `replay()` matches. The -08 `replay()` reports it `UNSUPPORTED_REVISION`
  with `matches` false and leaves its bytes unchanged; re-evaluation under
  -08 is SATISFIED and differs from it only in `algorithm_revision` and
  `evaluator_profile_digest`, so its replay digest is new; edited -07
  records stay `UNSUPPORTED_REVISION`, never `MISMATCH`; relabeled as -08 the
  record is `MISMATCH`; and the only digest comparison in `replay()`, in
  source and compiled output, sits behind the same-revision check.
  `npm run check:aec-08` replays the same record. Two pin the Section
  8.4 refusal order (a lone `&` or `|` where the 257th token would start is a
  syntax refusal; completing a 257th token is a limit refusal; a lone
  surrogate counts three octets) and the structured constructor's strict JSON
  refusal of a requirement that is not I-JSON. `packages/python-verify`:
  `pytest tests/test_aec_expression.py` 6 passed. `packages/go-verify`:
  `go test ./...` and `go vet ./...` PASS.
- Source mutants injected one at a time into
  `packages/verify/src/evidence-chain.ts`, rebuilt, and run against
  `aec-expression.test.js`; every one failed the file (failing tests in
  brackets): AND and OR swapped on the tree (5), case-folded role lookup (4),
  a FAILED fact credited as eligible (2), precedence read from the text while
  the correct tree is fingerprinted (5), the operator check folded to
  uppercase (8), the length measured in UTF-16 units (1), the legacy pinned
  requirement trimmed (2), replay comparing across revisions (3, re-run
  after the genuine -07 tests were added), the
  requirement digest taken over a trimmed expression (1), a token limit of
  257 (3), a depth limit of 31 (8), NO-BREAK SPACE treated as whitespace (4),
  and the constructor accepting an invalid expression (2).

## Claims in the draft and their evidence

- "The JavaScript reference parser that accompanied -07 and its Python and
  Go ports already agree with every vector of the corpus ... on syntax
  validity and Boolean value" (Sections 8 and 18): the published
  `@emilia-protocol/verify` 6.0.0 tarball's `dist/evidence-chain.js`
  `__aecSecurityInternals.evalRequirement` agreed on 104 of 104; its parser
  text is byte-identical to the one on origin/main `62a4310b8`. Python
  `emilia_verify._eval_requirement` and Go `aecEvalRequirement` at
  origin/main agreed on 104 of 104 each, and their parser text is the same
  at `1aedbffc4`, the main commit current when -07 was posted. The -07
  parsers report no refusal class, canonical parse or parse identity, so the
  claim covers validity and value only.
- Go legacy trimming (Implementation Status): origin/main
  `packages/go-verify/evidence_chain.go` line 492 sets
  `pinned := strings.TrimSpace(opts.Requirement)`, and running that code
  returns `Satisfied=true` for the pinned requirements `" a"`,
  `" a"`, `"a\v"` and `"\fa"` with an eligible `a`. The length units on
  origin/main: Go `len(s)` (octets), Python `len(expr)` (code points),
  JavaScript `expr.length` (UTF-16 units).
- "`evaluator_profile_digest`, which the -07 reference evaluator already
  emitted" (Sections 10 and 18): 6.0.0 `dist/evidence-chain.js` line 1091
  puts it in every replay record, and line 1064 computes it from the
  algorithm revision, the resource limits and the per-type native verifier
  profile, trust snapshot, mapping profile and status age.
- "the strict JSON error when the requirement is not I-JSON, as with a lone
  surrogate" (Implementation Status): on this tree,
  `createAuthorizationChainEvaluator` with expression `"a\ud800"` throws
  `TypeError: value is outside the strict canonical JSON domain at
  $.expression: unpaired Unicode surrogate`; `aec-expression.test.js` pins
  it. RFC 8785 Section 3.1 requires JSON string data to be expressible as
  Unicode.
- "@emilia-protocol/verify 6.0.0, implements EP-AEC-EVALUATOR-07-v1": npm
  `latest` is 6.0.0 (published 2026-09-28T13:24:43Z), and its
  `dist/evidence-chain.js` line 667 sets `EP-AEC-EVALUATOR-07-v1`. The branch
  leaves `packages/verify` at 6.0.0 with the -08 entry under "Unreleased" in
  its CHANGELOG. PyPI `emilia-verify` is 2.8.6, the version
  `packages/python-verify` still declares; the newest Go module tag,
  `packages/go-verify/v2.4.5`, predates this branch.
- Construction refusal, replay comparison, `authorization_decision: false`:
  `packages/verify/src/evidence-chain.ts` (`validateAecRequirement`,
  `replay`), exercised by `packages/verify/aec-expression.test.js`.
- Corpus locator: the commit-pinned URL returned HTTP 200 on 2026-10-04 and
  its bytes hash to
  `927e3663299bd6c11836d4ad22a6dd398b85d16478100921bf68cf03ed459d4b`, the
  value in Section 8.7 and in `conformance/vectors/aec-expression.v1.SHA256SUMS`.
  The repository's `main merge queue` ruleset merges with
  `merge_method: MERGE`, which keeps commit `2ebba2d84` reachable from `main`.
- Counts in Section 8.7 (104 vectors, 47 valid, 57 invalid): computed from
  the corpus by `scripts/check-aec-08.mjs`.

## Clean-room comparison

A same-team clean-room parser was written only from Sections 8.1 to 8.6 of
an earlier render of this draft (TXT SHA-256
`960fe4df576289677d2a9461b978b74da17de44ba624b2c55d33e0e57fc7b82e`), before
its author opened any repository parser or evaluator code. It produced every
field of all 104 vectors and agreed with the seven public entry points of the
ports (JavaScript diagnostic, structured and legacy; Python diagnostic and
legacy; Go diagnostic and legacy). It is a consistency check by the same
team, not an independent implementation.

It reported seven sentences a careful implementer could read two ways. None
of them changed a verdict or refusal class of the ports; each is now fixed in
the text:

1. Section 8.4 measured the length of "the expression as stored", which
   could mean the JSON bytes. It now measures the decoded string value.
2. Section 8.4 did not say how a lone surrogate counts. It now counts three
   octets and is an invalid character.
3. Section 8.2 rule 3 and Section 8.4 did not say which refusal wins when a
   lone `&` or `|` sits where the 257th token would start. Section 8.4 now
   says a token counts once it is complete and the invalid character is a
   syntax refusal where it is met.
4. Section 8.1 "or part of an operator" read alone admitted a lone `&`. It
   now names `&&` and `||`.
5. Section 4 named no hash or prefix for the requirement profile digest. It
   is now the evidence digest of the requirement object.
6. The Section 10 template omitted `evaluator_profile_digest`, which the
   reference evaluator emits, and Section 8.4 required configured limits to
   be part of an evaluator profile that no member carried. The template now
   shows the member, Section 10 says what it identifies, the replay
   determinism inputs include the evaluator profile, and Section 10 states
   that the document defines neither a portable serialization of that profile
   nor a closed list of further fact members.
7. Section 8.4 allowed a tighter expression limit whose results were "not a
   result of the fixed profile" but offered no other revision value. The
   limits are now exact, and Section 5 no longer lists the expression size
   as a relying-party limit.

Re-run against this tree, whose TXT render is `eaffa47b...` (the clean-room
parser was not rewritten from the new text; the seven changes state readings
it already took, and the 40 new cases below exercise them): the clean-room
parser produces all six assertions of all 104 vectors. The seeded case files regenerate byte for byte
(seed 20261004, 30,000 cases, `280d1d85...`; seed 1004, 20,000 cases,
`ff28cc8e...`). Over 398,261 inputs (the 104 vectors, the 32 hand-written
cases, 40 new cases for items 2 to 4, the 50,000 seeded cases and the
348,085-case code-point sweep), the seven entry points and the clean-room
parser disagree nowhere, except that the chain entry points cannot express
five vectors whose eligible sets exceed their configuration caps (component
types over 128 characters for vectors 78 and 80, more than 64 components for
89, 90 and 91); the diagnostic entry points agree on every field of those
five. Seven faults injected into the clean-room parser are each caught on the
seed-20261004 cases (1,809, 306, 511, 463, 316, 339 and 1,025 cases); for the
first three (AND read as OR, case-folded roles, an ineligible type credited)
the parse identity matched on every catching case.

## Cited revisions (Datatracker, queried 2026-10-04)

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
