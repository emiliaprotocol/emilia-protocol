# AEC -07 validation

Prepared on 2026-09-27 from `standards/posted/draft-schrock-ep-authorization-evidence-chain-06.xml`
(SHA-256 `69fef7053014c053e274f6396afdc9ea77943b6538876c8e49707d51796c1585`,
the value `../NEXT-AEC-06/SHA256SUMS.txt` records for the posted source).
Revised on 2026-09-28 (see "Revision of 2026-09-28" below); the source,
renders and checksums were regenerated and every check below was re-run on
that date.

## The defect

The posted -06 text rendering, lines 183-190, defines the native verifier as
checking "syntax, signatures, issuer, audience, validity, and format-specific
semantics under pinned trust inputs" and VERIFIED as "The native verifier
accepted an artifact under the selected native profile". Section 6 (-06 TXT
line 427) then makes VERIFIED equal to "its native verifier succeeds", and
Section 5 lists the trust anchors among the inputs of that verifier. -06 has
no term for an artifact that is intact but not trusted; Section 11 needed
the phrase "A valid quorum under presenter-selected keys ... is ineligible"
for exactly that case. Each of the six -06 sentences that
`scripts/check-aec-07.mjs` first forbade was found in the posted -06
rendering by a string search run for this record, and the script confirms
that none of them survives in either -07 file. The four -06 phrases added to
the forbidden list on 2026-09-28 (Section 12's combined validation, the
mapping input, the splicing example and the acknowledgment) were found in
the posted -06 rendering the same way.

## Rendering

- `xmllint --noout`: PASS.
- The renders are produced next to the source and then moved, run from this
  packet directory with xml2rfc 3.34.0:

  ```
  cd UPLOAD-THIS
  xml2rfc --text --html draft-schrock-ep-authorization-evidence-chain-07.xml
  perl -pi -e 's/[ \t]+$//' draft-schrock-ep-authorization-evidence-chain-07.html
  mv draft-schrock-ep-authorization-evidence-chain-07.html \
     draft-schrock-ep-authorization-evidence-chain-07.txt ../RENDERS/
  ```

  xml2rfc prints no warnings. On 2026-09-28 this procedure produced the
  committed TXT and HTML byte for byte, both in `UPLOAD-THIS/` and on a copy
  of the source under the same file name in a scratch directory. Rendered
  this way, the HTML inlines xml2rfc's metadata script, as the -06 HTML
  does. Writing the HTML to another directory with `-o` leaves that script
  out and does not reproduce the committed file; the TXT is the same either
  way. The HTML committed on 2026-09-27 reproduces with `xml2rfc --html -o
  ../RENDERS/draft-schrock-ep-authorization-evidence-chain-07.html` run in
  `UPLOAD-THIS/` (plus the `perl` step) and not with this procedure, so it
  lacked the script; it was replaced by the render from this procedure. The `perl` step removes
  trailing spaces and tabs, as the CAID-04 and AE Challenge -08 packets do,
  so `git diff --check` is clean.
- Applied to the -06 source without the `perl` step, the same `xml2rfc`
  command reproduces the TXT and HTML in `../NEXT-AEC-06/RENDERS/` byte for
  byte; the committed -06 HTML keeps xml2rfc's trailing whitespace.
- The source and the TXT rendering are printable ASCII, contain no en or em
  dash, and no TXT line exceeds 72 columns.
- `idnits 3.1.0 -m submission` on the TXT rendering: `PASS - No nit found`.
  On the XML source it reports one error, `SUBMISSION_TYPE_UNEXPECTED`: the
  source sets `submissionType="IETF"` and the existing document has no stream
  on Datatracker. The posted -06 XML gets the same error in the same mode,
  and Datatracker accepted -06, so it does not block upload.
- `idnits 3.1.0` in its default mode on the TXT rendering: three
  `POSSIBLE_DOWNREF` findings, for the normative CAID, Quorum and
  Authorization Receipts Internet-Drafts. They are the same three findings
  the -06 record retained, for the same reason: those dependencies stay
  normative because the selected profiles require their rules.
- `idnits 3.1.0` in its default mode on the XML source: six errors, the same
  six the posted -06 XML gets in that mode. They are the three
  `POSSIBLE_DOWNREF` findings above, `SUBMISSION_TYPE_UNEXPECTED` (see the
  submission-mode line), `INVALID_REFERENCES_NAME` (the source wraps its
  Normative and Informative References in one `references` element named
  "References", which this idnits check does not expect), and
  `MISSING_REQLEVEL_REF` (the check finds the BCP 14 boilerplate and no
  reference it recognizes as BCP 14; the source cites RFC 2119, RFC 8174 and
  a `BCP14` entry). It also reports 69 `MISSING_BCP14_TAGS` comments, because
  the keywords are not wrapped in `bcp14` elements. The posted -06 XML adds a
  `DOC_DATE_IN_PAST` warning and 57 of those comments.
- `shasum -a 256 -c SHA256SUMS.txt`: PASS.

## Checks

- `npm run check:aec-07`: every text, render, checksum and posted -06 check
  passes; the script then fails by design on this branch, because
  `packages/verify/src/evidence-chain.ts` here emits `EP-AEC-EVALUATOR-05-v1`
  and lacks the Section 21 evaluator (see `README.md`). The same script, with
  the pending branch's `evidence-chain.ts` in place of this tree's and
  nothing else changed, prints PASS.
- `npm run check:standards-staged`, `npm run check:repository-boundary`,
  `npm run check:public-conformance-claims`, `npm run check:authority-claims`,
  `npm run check:llm-context`, `npm run check:standalone-runtimes` and
  `node scripts/check-caid-04.mjs`: PASS.
- On 2026-09-28 the `check:aec-07` run with the pending branch's
  `evidence-chain.ts` (branch head `92f1874e5`) was repeated after this
  revision in a scratch tree holding only the script, this packet, the
  posted -06 XML and that file: PASS.
- `node --test scripts/ci/change-lane.node-test.mjs`: 12 of 12 pass, with
  `check-aec-\d+` added to the kept-checker pattern.

## Cited revisions (Datatracker API, queried 2026-09-27)

- AEC: latest revision 06, posted 2026-09-06T17:33:02Z; -07 is the next
  revision.
- `draft-schrock-canonical-action-identifier-03`, posted
  2026-09-26T16:30:22Z, header date 26 September 2026. Its Section 8.3 still
  names the verdicts EQUIVALENT_UNDER_PROFILE, NOT_EQUIVALENT and
  INDETERMINATE that Section 7 uses.
- `draft-schrock-ep-authorization-receipts-13`, posted 2026-09-12T15:05:02Z,
  header date 11 September 2026. Section 6 is still "Pre-Execution
  Authorization Bundle" and Section 7.2 "The Trust Receipt", as Section 11
  cites them.
- `draft-schrock-ep-quorum-04`, posted 2026-09-06T17:27:51Z.
- `draft-schrock-action-evidence-boundary-07`, posted 2026-09-26T00:11:40Z,
  header date 25 September 2026. Its Section 3 defines VERIFIED as "One
  native artifact passed its native verifier under relying-party-selected
  trust inputs", which the new Section 13 sentence maps to VERIFIED and
  ACCEPTED here.
- `draft-schrock-agent-qualification-statements-00`, posted
  2026-07-28T07:02:20Z, header date 27 July 2026. Its title is "Portable
  Agent Qualification Statements for Consequential Actions"; the -06
  reference entry gave a shorter title and no day, both corrected.

## Section 11 requirement level

Posted -06 Section 11 stated three built-in requirements with BCP 14
keywords: the bundle's native verifier "MUST validate" its inputs, the
ep-receipt built-in "MUST accept only" a Trust Receipt under a pinned
profile, and the ep-quorum built-in "MUST compare" the presented and pinned
policies. -07 keeps each as a MUST on the result it decides ("MUST report
VERIFIED only when", "MUST report ACCEPTED only when"). The part of the -06
bundle requirement that named the exact expected action moved to MATCH, as
"Changes in -07" says. The ep-receipt paragraph now also states its VERIFIED
condition: signoff signatures under the keys their `approver_key_id` values
resolve to, and the log checkpoint under the relying party's pinned log key.
The receipts -13 offline verification algorithm (Section 7.3, staged render
lines 1463-1487) takes the trusted log public key as an input and verifies
the checkpoint signature against it, so that check combines a trust input
with cryptography and falls under the Section 6 rule for failures that
cannot be attributed. The -13 example checkpoint carries a `log_key_id`, so
the text does not claim that the format leaves the log key unidentified.
`scripts/check-aec-07.mjs` requires the keyword sentences and forbids the
unkeyed ones.

The ep-quorum paragraph now also states its VERIFIED condition as a MUST:
the quorum structure is intact, every member context commits to the quorum
`action_hash`, and every member signoff verifies under the public key that
member carries. That is what `quorumIntegrity` in
`packages/verify/src/evidence-chain.ts` on `feat/verify-aec-07-evaluator`
(head `92f1874e5`, lines 863-882) checks: a policy object, a non-empty
`action_hash`, a non-empty and bounded member list, and for each member an
`approver_public_key`, a signoff context whose `action_hash` equals the
quorum's, and a WebAuthn signoff that verifies under that key in
offline-integrity mode (no RP ID or origin pins, which stay ACCEPTED
inputs). Before this revision the ep-quorum VERIFIED condition was stated
only in Section 21, so the "Changes in -07" bullet about Section 11 claimed
more than Section 11 said.

The `receiptIntegrity` comment on that branch says a Trust Receipt names its
log key "not at all". The -13 example checkpoint carries `log_key_id`, so
the comment is wrong; it is on the evaluator branch, and the draft text does
not rely on it. The draft keeps the receipts -13 Section 7.3 input model
(the trusted log public key is an input) and states the limit in
Section 14. Resolving the log key by `log_key_id`, which would move "pinned
for this role" into ACCEPTED, is left for a later revision.

## Revision of 2026-09-28

- Section 12: the capability a `bounded-capability-operation` record
  references and that capability's issuance authorization must each be
  VERIFIED and ACCEPTED under the relying party's pins for their own roles;
  the component is not VERIFIED unless all three artifacts are, and not
  ACCEPTED unless all three are; a combined native check that cannot
  attribute a failure falls under the Section 6 rule. -06 and the earlier
  -07 said only that the native verifier "validates" them under the pins.
  No reference built-in exists for this component type (the evaluator
  branch's `evidence-chain.ts` has no `bounded-capability` code), so the
  sentence is a requirement on custom native verifiers, not an
  implementation claim. "Changes in -07" now has a Section 12 bullet.
- Section 7 step 4 maps the "VERIFIED and ACCEPTED native payload" (was
  "verified native payload"); Section 14's splicing example says "VERIFIED
  and ACCEPTED artifacts" (was "valid artifacts"); the Acknowledgments say
  "native verification, relying-party acceptance" (was "native validity").
- Section 13 says that FAILED and INDETERMINATE in the lifecycle are
  execution outcomes of the AEB draft, distinct from the
  `native_verification` value FAILED (Section 10) and the CAID verdict
  INDETERMINATE (Section 7). "Changes in -07" says so.
- Section 11: the ep-quorum VERIFIED requirement described above.

## Replay record revision value

Section 10 now defines `algorithm_revision` for this revision as
`EP-AEC-EVALUATOR-07-v1`, the value `AEC_EVALUATOR_REVISION` has in
`packages/verify/src/evidence-chain.ts` on the pending evaluator branch. On
main the constant is `EP-AEC-EVALUATOR-05-v1`.

## Implementation claims in Section 21

The Section 21 paragraph describes the pending branch
`feat/verify-aec-07-evaluator`, which is not on this branch or on main. Each
sentence is backed by a test in `packages/verify/aec-current-profile.test.ts`
on that branch:

- separate `verified` and `accepted` results, recorded per fact as
  `native_verification` and `acceptance`: "AEC07 a verified artifact outside
  the pinned trust inputs is VERIFIED and not ACCEPTED" and "AEC07 a broken
  signature is not VERIFIED and acceptance is never evaluated";
- refusal of ACCEPTED without VERIFIED and of the earlier combined field:
  "AEC07 refuses the 5.x combined valid field, inconsistent results and
  non-Boolean results by name";
- ep-quorum integrity under carried keys: "AEC07 built-in ep-quorum: an
  attacker quorum is VERIFIED under its carried keys and not ACCEPTED";
- ep-receipt, ep-authorization-bundle and platform attestation: the
  "AEC07 built-in" tests for those types show a pin mismatch as VERIFIED and
  not ACCEPTED, a broken signature as FAILED, an unresolvable key reference as
  NOT_EVALUATED (`native_key_unresolved`), a compromised, out-of-window,
  wrong-class or wrong-principal directory entry as VERIFIED and REJECTED, and
  a trusted artifact for another action as VERIFIED, ACCEPTED and
  NOT_EQUIVALENT (`material_action_not_matched`);
- the receipt checkpoint sentence: `receiptIntegrity` in
  `packages/verify/src/evidence-chain.ts` passes the relying party's log key
  to `verifyTrustReceipt`, whose checkpoint check fails when the signature
  does not verify under that key, and returns key-unresolved when no log key
  is configured;
- a result that could not evaluate VERIFIED: "AEC07 a native result that
  could not evaluate VERIFIED is NOT_EVALUATED, never FAILED".

The action-matching change was also checked with the probe that found it
(valid-two-of-three bundle vector, `action_type` changed): before the fix
VERIFIED, REJECTED, INDETERMINATE, `native_acceptance_refused`; after it
VERIFIED, ACCEPTED, NOT_EQUIVALENT, `material_action_not_matched`.

Test runs on the pending branch: `node --test aec-current-profile.test.js
evidence-chain.test.js` passes 53 of 53 (37 profile tests, 13 of them AEC-07
tests, and 16 legacy-API vector tests). This was re-run on 2026-09-28 against
the branch head, exported with `git archive` (`packages/verify` and
`conformance/vectors`), on node v26.5.0; the branch's source and that test
file are unchanged since its evaluator change, and its later commits only
re-pin evidence. The totals below were recorded when the evaluator change was
made and were not re-run on 2026-09-28. `npm test` in `packages/verify`
passes 1,256 of 1,257 node tests with 1 skipped, then 32 of 32 and 62 of 62
in its two `tsx` suites, after `npm run build` and `npm run
build:standalone-runtimes`. The eight AEC vitest suites under `tests/`
(safety-critical, role conformance, platform attestation, mutation oracles,
isolated refusals, role non-substitution, execution gate, fleet assurance)
pass 120 of 120. `node conformance/composition/authzen-coaz-mcp-aeb-v0.1/check.mjs`
passes after the documented refresh, and its two node test files pass 49 of
49.

## Pins the evaluator branch changes

Three files pin the SHA-256 of `packages/verify/src/evidence-chain.ts`
(`8539bfde...` before the change, `f3d47a09...` after it), and two of them also
pin `packages/verify/dist/evidence-chain.js`. All are refreshed on
`feat/verify-aec-07-evaluator` with the repository's own commands:

- `conformance/composition/authzen-coaz-mcp-aeb-v0.1/source-lock.json` and
  `report.reference.json`: `refresh-source-lock.mjs`, `check.mjs --emit`,
  then `check.mjs`, in the evaluator change itself.
- `formal/results/formal-runtime-scenario-conformance.v2.json`:
  `npm run sync:formal-traces` with the pinned TLC jar (SHA-256
  `936a2620...`, the value the record pins), 78 scenarios, PASS.
- `security/security-case.json`: `npm run security-case:emit`, then
  `npm run check:security-case`: OK, 35 executable claims, 264 hashed
  evidence files, execution passed.
- Derived from those: `conformance/conformance-manifest.json`, the v2 and v3
  clean-room bundle pins and the generated LLM context
  (`npm run conformance:manifest`, `npm run sync:clean-room-pins`,
  `npm run sync:llm-context`); their checks pass.

## This branch's own evidence pins

The `check:aec-07` script added to `package.json` changed a file that the
scenario conformance record pins, so this branch also re-pins it
(`npm run sync:formal-traces`), re-emits the security case and regenerates the
LLM context. On this branch `npm run check:formal-traces`,
`npm run check:security-case` (OK, 35 claims, 264 files, execution passed),
`npm run check:llm-context`, `npm run conformance:manifest:check` and
`npm run check:clean-room-pins` pass.

## Not run

`npm run check:proof-stats` was not re-run for this revision.

Datatracker has not published this packet. Upload is held; see `README.md`.
