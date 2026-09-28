# Validation record

Revised on 2026-09-27 from the candidate staged on 2026-08-27 (repository
main `dedd9a24d`), which was prepared from the byte-verified published -07
XML. `scripts/check-ae-challenge-08.mjs` still pins that published -07
source at SHA-256
`2bfb675ec652487bd90addbb95dda15551e69f4c022fc83a45195fee6d8d8e34`.
Revised again on 2026-09-28 ("Changes since -07" wording, render procedure
and idnits scope; see below); the source, renders and checksums were
regenerated and the checks below re-run on that date.

## Rendering

- `xmllint --noout`: PASS.
- The renders are produced next to the source and then moved, run from this
  packet directory with xml2rfc 3.34.0:

  ```
  cd UPLOAD-THIS
  xml2rfc --text --html draft-schrock-ae-challenge-08.xml
  perl -pi -e 's/[ \t]+$//' draft-schrock-ae-challenge-08.html
  mv draft-schrock-ae-challenge-08.html draft-schrock-ae-challenge-08.txt ../RENDERS/
  ```

  xml2rfc prints no warnings. On 2026-09-28 this procedure produced the
  committed TXT and HTML byte for byte, both in `UPLOAD-THIS/` and on a copy
  of the source under the same file name in a scratch directory. Rendered
  this way, the HTML inlines xml2rfc's metadata script. Writing the HTML
  with an `-o` path whose directory part contains a `.` or `..` segment (for
  example `../RENDERS/<name>.html`, or an absolute path through `..`) leaves
  that script out and does not reproduce the committed file: xml2rfc 3.34.0
  inlines the script only when the script path it resolves under that
  directory still begins with the directory as written. An `-o` path without
  such a segment, absolute or into a subdirectory, keeps the script and
  reproduces the committed HTML. The TXT is the same either way. The HTML
  committed on 2026-09-27 reproduces with `xml2rfc --html -o
  ../RENDERS/draft-schrock-ae-challenge-08.html` run in `UPLOAD-THIS/` (plus
  the `perl` step) and not with this procedure, so it lacked the script; it
  was replaced by the render from this procedure.
- Applied to the 2026-08-27 source (repository main `dedd9a24d`) under the
  same file name, the same procedure reproduces that candidate's TXT and
  HTML byte for byte; the only difference seen when rendering a renamed copy
  is the source file name in the HTML `link` element.
- Every TXT line fits 72 columns. The four example lines that exceeded it in
  the 2026-08-27 candidate are folded as RFC 8792 Section 7 specifies.
  Unfolding both folded examples and parsing them as JSON gives the original
  64-digit digests; every folded example line is at most 69 characters.
- The source and the TXT rendering are printable ASCII (the AIMS author name
  uses a character reference and an `asciiFullname`) and contain no en or em
  dash.
- `idnits 3.1.0 -m submission`: `PASS - No nit found`, on both the XML
  source and the TXT rendering. The 2026-08-27 candidate passed with one
  warning for the over-long lines.
- `idnits 3.1.0` in its default mode on the TXT rendering: no errors and two
  warnings, `PREFER_BCP14_REF` and `SECTION_TITLE_HAS_UNEXPECTED_INDENTATION`
  for the Appendix line of the table of contents. The
  `MULTIPLE_REFERENCES_SECTION_TITLES` error the earlier two-section layout
  produced in the TXT is fixed by one References section with Normative and
  Informative subsections.
- `idnits 3.1.0` in its default mode on the XML source: two errors.
  `TABS_NOT_ALLOWED` counts 600 tab characters in the source; the posted -07
  XML has 653 and gets the same error, and Datatracker accepted it.
  `INVALID_REFERENCES_NAME` is caused by the single References wrapper that
  fixed the TXT error above: this idnits check expects each `references`
  element to be named Normative or Informative, and the posted -07, which
  had two such sections, does not get it. It also reports 240
  `MISSING_BCP14_TAGS` comments (keywords not wrapped in `bcp14` elements;
  the posted -07 XML gets 208). Submission mode passes on both files.
- The Implementation Status and "Changes since -07" sections are marked
  `removeInRFC`, so xml2rfc states that each is removed before publication.
- `shasum -a 256 -c SHA256SUMS.txt`: PASS.

## Checks

- `npm run check:ae-challenge-08`: PASS. The script now requires the
  restated AEC outcome terms, the closed reason set, the Implementation
  Status section marked `removeInRFC`, the RFC 7942, RFC 8792 and AIMS
  references, the single References section and the RFC 8792 fold header,
  and forbids the previous outcome values, `unverifiable_evidence` and the
  KLRC reference. Each newly forbidden string occurs in the 2026-08-27
  source, so the check fails on it. It also requires the
  `evidence_not_evaluated` reason, the live-policy SATISFIED definition, the
  keyed policy-change rule, the complete list of where the reference is
  narrower, and the split model description, and forbids the wording each
  replaced. Since 2026-09-28 it also requires the folded outcome-terms
  bullet and the withdrawal sentence in "Changes since -07", and forbids
  the separate SATISFIED bullet they replaced.
- `npm run check:standards-staged`, `npm run check:repository-boundary`,
  `npm run check:public-conformance-claims`, `npm run check:authority-claims`
  and `npm run check:llm-context`: PASS.
- With the pinned TLC jar (SHA-256 `936a2620...`): `npm run
  check:formal-traces` PASS and `npm run check:security-case` OK (35
  executable claims, 264 hashed evidence files, execution passed). On
  2026-09-28 this branch merged `feat/verify-aec-07-evaluator` and origin/main
  `2d8bde58c`, and its derived evidence was regenerated from main's files
  with the repository's writers; the commands and results are in
  `../NEXT-AEC-07/VALIDATION.md` ("Merged branch"), and both checks above
  were re-run on the merged tree. `npm run check:proof-stats` was not
  re-run.

## Sources checked for the new text

- Datatracker API, 2026-09-27: `draft-schrock-ae-challenge` latest revision
  07 (2026-08-11T05:02:01Z). `draft-ietf-wimse-aims` revision 00, posted
  2026-09-15T14:40:51Z, stream IETF, group WIMSE, IETF stream state "WG
  Document". `draft-klrc-aiagent-auth` is in state "Replaced", and
  `draft-ietf-wimse-aims` has a "replaces" relation to it. Latest cited
  revisions: `draft-schrock-canonical-action-identifier-03`,
  `draft-schrock-action-evidence-boundary-07`,
  `draft-schrock-ep-bounded-capability-receipts-06`,
  `draft-schrock-ep-authorization-receipts-13`,
  `draft-dunbar-dmsc-gw-scenarios-gap-analysis-04` and
  `draft-rosomakho-oauth-txn-challenge-00`. The AEC draft's latest posted
  revision is 06; this candidate cites the staged -07 (`../NEXT-AEC-07/`),
  which must be posted first.
- `draft-ietf-wimse-aims-00` from the IETF archive: the abstract says it
  describes how existing standards "can be applied or extended" to agent
  authentication and authorization; Section 10.7 says user confirmations
  solicited during task execution "do not by themselves constitute
  authorization and MUST be bound to a verifiable authorization grant issued
  by the authorization server". Appendix A cites it only for that.
- RFC 9457 Section 4.2: the HTTP Problem Types registry policy is
  Specification Required. RFC 8726 Section 2: Independent Stream documents
  follow the policy of the registry they allocate from, and IETF Review and
  Standards Action registries are not available to them. RFC 7942
  Section 1: Independent Stream drafts are out of scope of its process, which
  the Implementation Status introduction states.
- The sentence that the reference does not implement the lineage profile:
  outside `standards/`, `AE-EVALUATION-LINEAGE` appears only in
  `scripts/check-ae-challenge-08.mjs`.

## Implementation Status trace

The -07 paragraphs about an owner state machine, a PostgreSQL transaction
backend, limits of 65536 octets and 64, 16 and 32 items, collation-safe
capacity rows, stale-worker fencing, a Model-to-Matter path and a
114-scenario harness were removed: no code outside `standards/` supports
them. Searched: `git grep` for the AE-CHALLENGE identifiers outside
documentation lists `lib/negotiate/evidence-challenge.ts` as the only
challenge module, and it has no owner, capacity or reservation logic and no
65536 constant. `scripts/check-ae-challenge-08.mjs` now forbids those
sentences.

Each sentence of the rewritten section traces to code read on `dedd9a24d`
or a command run on this tree:

- Minting, required-evidence derivation, the smaller OR branch, freshness,
  status, profiles, proof predicates, the 18-octet default nonce, and the
  follow-up policy check: `lib/negotiate/evidence-challenge.ts`
  (`mintChallengeForDigest`, `missingTypes`, `deriveRequiredEvidence`,
  `createFollowupEvidenceChallenge`).
- Store requirements, production capability check, register-before-return,
  consume-before-evaluation, the refusals before and after consumption,
  follow-up registration, and error propagation:
  `requireChallengeStore`, `createRegisteredEvidenceChallenge`,
  `evaluateRegisteredPresentation`, `createRegisteredFollowupEvidenceChallenge`
  in the same file.
- Insert-if-absent registration, compare-and-set consumption on the body
  digest, and the (challenge_id, nonce) storage key:
  `packages/gate/src/challenge-store.ts`. The PostgreSQL adapter:
  `packages/gate/src/store-postgres.ts` (`addIfAbsent`, `compareAndSet`,
  `has`).
- HTTP helpers: `createEvidenceChallengeProblem` and
  `parseEvidenceChallengeProblem` read and write already decoded objects and
  perform no raw parsing.
- Where the reference is narrower: `DURABLE_NONCE_RE` is
  `/^[A-Za-z0-9_-]{16,128}$/`, `SHA256_DIGEST_RE` has the `i` flag, `audience`
  is added only when configured and `validateAudience` compares it with
  `opts.expected_audience` as a string, and the module has no `retry_timing`,
  capacity or lineage code. It has no issuer or presenter authentication.
  `evaluateRegisteredPresentation` takes no current proposed action: it
  compares the presentation's action digest with the stored
  `challenge.action_digest`, after `store.consume`.
  `createFollowupEvidenceChallenge` passes `challenge.action_digest` to
  `mintChallengeForDigest` instead of rederiving it.
- Tests: `npx vitest run tests/evidence-challenge.test.ts
  tests/evidence-challenge-durable.test.ts` passes 44 of 44. The durable file
  contains the 100-worker registration case, the restart case, the
  64-presentation PostgreSQL case (against `createLocalPostgresHarness`, an
  in-process emulation of the adapter's SQL statements), and the production
  capability case.
- Bounded model: `node formal/check-evidence-challenge-lifecycle.mjs` prints
  PASS with 17 obligations verified, each with "unsafe counterexample:
  found": 11 over 1,024 states and 6 over 1 state each. The 1,024 states are
  every combination of the model's ten `REGISTRATION_FIELDS` flags
  (`enumerateChallengeConfigurations` in
  `formal/evidence-challenge-lifecycle.model.mjs`): four storage capabilities
  (`durable_storage`, `atomic_registration`, `body_bound_storage`,
  `permanent_consumption`) and six challenge bindings. The draft says so.

## Changes since -07

The section compares with the posted -07, not with the unposted 2026-08-27
candidate. The posted -07 XML (the pinned source above) contains neither
`SATISFIED` nor `policy_unsatisfied` (0 matches each), so the SATISFIED
scope and the `policy_unsatisfied` limit are part of the new outcome
vocabulary, not a change to -07 text; the separate bullet that described
them as a change is folded into the outcome-terms bullet. The
implementation bullet now says what is withdrawn from -07 Section 2.6.2
("Reference Evidence Boundary", posted XML lines 851-895): the owner store
with capacity accounting, generation-bound reservations and deadline-gated
recovery, and its challenge-size and item-count limits. In
`lib/negotiate/evidence-challenge.ts` a case-insensitive search for
capacity, reserv, recover, generation and 65536 finds nothing, and the only
length limits are per-field string caps (512, 256 and 128 characters). The
bullet does not say the reference lacks a PostgreSQL store or a bounded
model: `packages/gate/src/store-postgres.ts` is the adapter the
Implementation Status names, and the -07 scenario-harness count is replaced
by the bounded-model description, not withdrawn without replacement.

## Outcome and reason terms

- SATISFIED is defined under the relying party's authenticated live policy,
  matching Section 2.2 ("MUST use its authenticated live policy") and the
  "Stale facts" consideration. Only the lineage profile requires a fresh
  challenge when policy changes, and that rule is now a MUST.
- `evidence_not_evaluated` separates a verification that could not be
  evaluated (for example an unresolvable key) from `evidence_not_verified`,
  as AEC -07 separates NOT_EVALUATED (`key_unresolved`) from FAILED.
- "Evaluation time" is stated to be AEC's "verification time".

## Unchecked

Runtime and conformance implementation of the lineage profile is not
claimed. The existing formal evidence-challenge lifecycle does not by itself
prove evaluation-lineage immutability or policy-transition properties.

## Filing revision, 2026-09-28

CAID -04 was posted on 2026-09-28 (Datatracker, 07:24:09Z), so the [CAID]
reference now names draft-schrock-canonical-action-identifier-04 dated
28 September 2026, and the document date moves to 28 September 2026. The
renders were regenerated with the in-place procedure above and SHA256SUMS.txt
refreshed. The rendered TXT differs from the 2026-09-27 render only in the
date, the expiry line and the [CAID] reference. `idnits -m submission`
passes on the new TXT, and the packet check passes.
