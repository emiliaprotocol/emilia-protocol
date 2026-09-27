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
- `idnits 3.1.0 -m submission`: `PASS - No nit found`.
- `idnits 3.1.0` in its default mode: three `POSSIBLE_DOWNREF` findings, for
  the normative CAID, Quorum and Authorization Receipts Internet-Drafts. They
  are the same three findings the -06 record retained, for the same reason:
  those dependencies stay normative because the selected profiles require
  their rules.
- `shasum -a 256 -c SHA256SUMS.txt`: PASS.

## Checks

- `npm run check:aec-07`: PASS.
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

## Implementation claims in Section 21

The new Section 21 paragraph describes commit `52882ef6d`. Each sentence is
backed by a test in `packages/verify/aec-current-profile.test.ts`:

- separate `verified` and `accepted` results, recorded per fact as
  `native_verification` and `acceptance`: "AEC07 a verified artifact outside
  the pinned trust inputs is VERIFIED and not ACCEPTED" and "AEC07 a broken
  signature is not VERIFIED and acceptance is never evaluated";
- refusal of ACCEPTED without VERIFIED and of the earlier combined field:
  "AEC07 refuses the 5.x combined valid field, inconsistent results and
  non-Boolean results by name";
- ep-quorum integrity under carried keys: "AEC07 built-in ep-quorum: an
  attacker quorum is VERIFIED under its carried keys and not ACCEPTED";
- ep-receipt, ep-authorization-bundle and platform attestation: the three
  "AEC07 built-in" tests for those types, each showing a pin mismatch as
  VERIFIED and not ACCEPTED and a broken signature or unknown key as not
  VERIFIED.

Test runs on this tree: `node --test aec-current-profile.test.js
evidence-chain.test.js` passes 50 of 50 (34 profile tests, 10 of them new,
and 16 legacy-API vector tests). `npm test` in `packages/verify` builds with
`tsc` and passes 1,253 of 1,254 node tests with 1 skipped, then 32 of 32
and 62 of 62 in its two `tsx` suites. The eight AEC vitest suites under `tests/` (safety-critical,
role conformance, platform attestation, mutation oracles, isolated refusals,
role non-substitution, execution gate, fleet assurance) pass 120 of 120.

## Not run

`npm run check:security-case` needs the pinned TLC jar, which is not on
this machine; the check refused to run without it. `security/security-case.json`
pins the SHA-256 of `packages/verify/src/evidence-chain.ts`, which the code
commit changes, so the security case must be re-emitted (or re-pinned by the
evidence workflow) before the code change merges.

Datatracker has not published this packet. Upload is held; see `README.md`.
