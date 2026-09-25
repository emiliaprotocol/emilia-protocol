# Validation

Checks run on 2026-09-25 (UTC) against the candidate in this directory. Each
entry gives the command and a summary of its output.

## Integrator revision (2026-09-25 UTC)

After the checks below first ran, the source was revised so that Sections
5.10 and 5.11 match the reference Gate change on branch
`fix/pr788-followups`:

- A refusal for an occupied or closed action key happens before provider
  entry and must not consume the refused attempt's native authority (was:
  before consumption or reservation).
- A key closed by EXECUTED may be reported as
  `native_action_already_executed`; `native_action_in_flight` stays required
  for an occupied key.
- Occupying the action key is an atomic write that detects conflicts. The
  fence and the authority reservation may be one atomic step or several atomic
  writes, provided provider entry waits for all of them and releases are
  confirmed by an authenticated durable read (was: one atomic step).
- The Changes section and this packet's README say the same.

Re-run on the revised source: `xmllint --noout` PASS; `xml2rfc 3.34.0 --text`
and `--html` PASS with the same inherited submissionType warning, and a second
render into a scratch directory is byte-identical (`cmp`); `idnits 3.1.0 -m
submission` on the TXT and on the XML: PASS, no nits; ASCII check on the XML
and TXT: no byte above 0x7F; `shasum -a 256 -c SHA256SUMS.txt`: PASS. The
structural checker's F3 condition tested for the phrase "atomic transition"
in Section 5.10; it was revised to test for the new requirement ("atomic write
that detects conflicts"). With that revision, -07 passes 32 of 32 and -06
passes 3 of 32 (the same three regression guards). The sections below
describe the first run and were not otherwise repeated.

## Base revision and provenance

- Datatracker API `api/v1/doc/document/draft-schrock-action-evidence-boundary/`:
  `rev` 06, posted 2026-09-25T02:15:03Z. `https://www.ietf.org/archive/id/draft-schrock-action-evidence-boundary-07.txt`
  returns 404. -07 is the next revision number.
- `shasum -a 256` of the IETF archive copies of -06 XML and TXT:
  `82eaf5ee...` and `988c8e50...`, equal to
  `standards/staged/NEXT-AEB-06/SHA256SUMS.txt` at
  `69cc928eeb3b39cb8878c9af328da8c3599e86a6`. The -07 candidate is built from
  that XML.

## Source and renders

- `xmllint --noout UPLOAD-THIS/draft-schrock-action-evidence-boundary-07.xml`:
  PASS.
- `xml2rfc 3.34.0 --text` and `xml2rfc 3.34.0 --html`: PASS; produced the files
  in `RENDERS/`. Each run emits the one informational warning inherited from
  -06: the source has no `submissionType`, so xml2rfc uses the IETF stream.
  Adding `submissionType="IETF"` was tried and removed, because idnits then
  reports SUBMISSION_TYPE_UNEXPECTED (Datatracker records no stream for the
  existing draft).
- Re-rendering the XML with the same xml2rfc version into a scratch directory
  reproduces both files in `RENDERS/` byte for byte (`cmp`).
- `idnits 3.1.0 -m submission RENDERS/draft-schrock-action-evidence-boundary-07.txt`:
  PASS, no nits.
- `idnits 3.1.0 -m submission UPLOAD-THIS/draft-schrock-action-evidence-boundary-07.xml`:
  PASS, no nits. Datatracker was reachable, so the checks against the
  existing document record ran.
- ASCII: the XML and the text render contain no non-ASCII byte. The HTML
  render contains xml2rfc-generated pilcrows and non-breaking spaces, as the
  -06 HTML render does. The XML contains no double hyphen outside artwork.
- `shasum -a 256 -c SHA256SUMS.txt`: PASS for the XML, text, and HTML files.

## Defect checks, -06 versus -07

A structural checker parsed each XML source and tested 32 conditions taken
from the -06 review findings:

- the same-action fence: refusal reason, scope, durability, release rules,
  instance field, and security text;
- replay identity: the Section 5.9 to Section 8.5 cross-reference, the
  exclusion of the operation identifier and of system and profile labels,
  the derivation inputs, and the shared-namespace default;
- AuthZEN and COAZ projection coverage;
- material field defined without CAID;
- handoff contents, verification order, and trust statement, and the
  Implementation Status description of the direct path;
- Section 7.3 Permit text, `any_of`, reference revisions, COAZ pins, KLRC
  removal, AIMS citation, acronym expansion, and removal of "AEB custody";
- the normative reference set; and
- ASCII and double hyphens.

Results:

- -06: 3 of 32 pass. The three that pass are regression guards: AIMS cited as
  `draft-ietf-wimse-aims-00`, the normative reference set, and no double
  hyphen in prose. All 29 defect conditions fail on -06, and ASCII fails
  because the -06 AIMS reference spells an author name with U+00E7.
- -07: 32 of 32 pass.

## Reference currency and targets

- Datatracker API, every Internet-Draft cited in the -07 XML: all 12 cite the
  latest revision (AEC -06, Authorization Receipts -13, WIMSE HTTP Signatures
  -07, CAID -02, WPT -02, Transaction Tokens -11, AIMS -00, SCITT Permit
  profile -01, WIMSE authorization evidence -01, OAuth transaction challenge
  -00, PEDIGREE -00, AEG -00).
- `curl -L` on every reference target URL: all 20 return HTTP 200, including
  the openid/authzen blobs at `78a5165a0048895a345e4ac5b0f2b9c7904bb110` and
  the emilia-protocol paths at `69cc928eeb3b39cb8878c9af328da8c3599e86a6`.
- The COAZ-MCP statements in Section 7.2 were checked against the pinned
  source: the PEP Behavior operation-binding step and the "Authorization
  Granularity and Omitted Inputs" security consideration. The AuthZEN
  statements were checked against the Authorization API 1.0 Final page: the
  Decision object (boolean `decision`, optional `context`), optional response
  signing (Section 11.6), and the PEP-generated request identifier (Section
  10.1.3). No decision identifier, expiry, or one-time-use term appears in
  that specification.

## Implementation Status evidence

The Section 15 statements about commit
`69cc928eeb3b39cb8878c9af328da8c3599e86a6` were checked by reading
`packages/verify/src/aeb-native-authorization-handoff.ts` (replay unit
derived over system, profile, issuer, and authorization identifier) and
`packages/gate/src/consequence-boundary.ts` (reservation keyed on operation
identifier, action digest, and replay key only; no action-level key; the
provider-entry status recheck; the native store must expose `state()`), and
`packages/gate/src/aeb-consumption-store.ts` (no `state()`). A same-team
execution probe against that commit reproduced both gaps named in Section 15;
a same-authorization control was refused with `native_replay_conflict`. The
corpus claims were checked against
`conformance/composition/consequence-admission-lifecycle-v0.1/` (23 case
identifiers; the runner imports only Node.js built-in modules).

## What these checks do not establish

They show that the candidate parses, renders, passes the submission nits
check, and states the listed requirements. They are not evidence of IETF
submission, publication, working-group adoption, protocol-owner review,
implementation conformance, interoperability, or deployment.
