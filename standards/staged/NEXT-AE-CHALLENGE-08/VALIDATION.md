# Validation record

Revised on 2026-09-27 from the candidate staged on 2026-08-27 (repository
main `dedd9a24d`), which was prepared from the byte-verified published -07
XML. `scripts/check-ae-challenge-08.mjs` still pins that published -07
source at SHA-256
`2bfb675ec652487bd90addbb95dda15551e69f4c022fc83a45195fee6d8d8e34`.

## Rendering

- `xmllint --noout`: PASS.
- `xml2rfc 3.34.0 --text` and `--html`, with trailing spaces and tabs removed
  from the HTML by `perl -pe 's/[ \t]+$//'`: PASS with no warnings. Applied to
  the 2026-08-27 source under the same file name, the procedure reproduces
  that candidate's TXT and HTML; the only difference seen when rendering a
  renamed copy is the source file name in the HTML `link` element.
- Every TXT line fits 72 columns. The four example lines that exceeded it in
  the 2026-08-27 candidate are folded as RFC 8792 Section 7 specifies.
  Unfolding both folded examples and parsing them as JSON gives the original
  64-digit digests; every folded example line is at most 69 characters.
- The source and the TXT rendering are printable ASCII (the AIMS author name
  uses a character reference and an `asciiFullname`) and contain no en or em
  dash.
- `idnits 3.1.0 -m submission`: `PASS - No nit found`. The 2026-08-27
  candidate passed with one warning for the over-long lines.
- `idnits 3.1.0` in its default mode: no errors and two warnings,
  `PREFER_BCP14_REF` and `SECTION_TITLE_HAS_UNEXPECTED_INDENTATION` for the
  Appendix line of the table of contents. The `MULTIPLE_REFERENCES_SECTION_TITLES`
  error the earlier two-section layout produced is fixed by one References
  section with Normative and Informative subsections.
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
  source, so the check fails on it.
- `npm run check:standards-staged`, `npm run check:repository-boundary`,
  `npm run check:public-conformance-claims`, `npm run check:authority-claims`
  and `npm run check:llm-context`: PASS.
- `npm run check:proof-stats` on the committed tree ran the governed test
  measurement to completion and then stopped at the security-case step,
  which needs the pinned TLC jar that is not on this machine.

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
  is added only when configured, and the module has no `retry_timing`,
  capacity or lineage code.
- Tests: `npx vitest run tests/evidence-challenge.test.ts
  tests/evidence-challenge-durable.test.ts` passes 44 of 44. The durable file
  contains the 100-worker registration case, the restart case, the
  64-presentation PostgreSQL case (against `createLocalPostgresHarness`, an
  in-process emulation of the adapter's SQL statements), and the production
  capability case.
- Bounded model: `node formal/check-evidence-challenge-lifecycle.mjs` prints
  PASS with 17 obligations verified over 1,024 configurations, each with
  "unsafe counterexample: found".

## Unchecked

Runtime and conformance implementation of the lineage profile is not
claimed. The existing formal evidence-challenge lifecycle does not by itself
prove evaluation-lineage immutability or policy-transition properties.
