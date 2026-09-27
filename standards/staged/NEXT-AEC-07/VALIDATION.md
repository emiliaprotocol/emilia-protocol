# AEC -07 validation

Prepared on 2026-09-27 from `standards/posted/draft-schrock-ep-authorization-evidence-chain-06.xml`
(SHA-256 `69fef7053014c053e274f6396afdc9ea77943b6538876c8e49707d51796c1585`,
the value `../NEXT-AEC-06/SHA256SUMS.txt` records for the posted source).

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
`scripts/check-aec-07.mjs` forbids was found in the posted -06 rendering by
a string search run for this record, and the script confirms that none of
them survives in either -07 file.

## Rendering

- `xmllint --noout`: PASS.
- `xml2rfc 3.34.0 --text` and `--html`: PASS with no warnings. Applied to the
  -06 source, the same two commands reproduce the TXT and HTML in
  `../NEXT-AEC-06/RENDERS/` byte for byte. For -07, trailing spaces and tabs
  are then removed from the HTML with `perl -pe 's/[ \t]+$//'`, as the
  CAID-04 and AE Challenge -08 packets do, so `git diff --check` is clean.
- The source and the TXT rendering are printable ASCII, contain no en or em
  dash, and no TXT line exceeds 72 columns.
- `idnits 3.1.0 -m submission` on the TXT rendering: `PASS - No nit found`.
  On the XML source it reports one error, `SUBMISSION_TYPE_UNEXPECTED`: the
  source sets `submissionType="IETF"` and the existing document has no stream
  on Datatracker. The posted -06 XML gets the same error in the same mode,
  and Datatracker accepted -06, so it does not block upload.
- `idnits 3.1.0` in its default mode: three `POSSIBLE_DOWNREF` findings, for
  the normative CAID, Quorum and Authorization Receipts Internet-Drafts. They
  are the same three findings the -06 record retained, for the same reason:
  those dependencies stay normative because the selected profiles require
  their rules.
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
