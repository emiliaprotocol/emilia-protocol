# Validation

Checks run on 2026-09-25 (UTC) against the candidate in this directory. Each
entry gives the command and a summary of its output.

## Round-five revision (2026-09-25 UTC)

A round-four attack review of branch `fix/pr788-followups` at `5176290f1`
found that the reference Gate, when it could not read an attempt record
after an unconfirmed write that enters DISPATCH_PENDING, sent a not-entered
transition from DISPATCH_PENDING and could still dispatch when a later read
showed DISPATCH_PENDING, so a delayed not-entered write made an attempt that
entered look never entered and one grant reached the provider twice; that
the composed boundary without a provider-outcome verifier released the
action key on its adapter's unverified FAILED; that a verifier that
restates the context it is given still turned a "not found" lookup into a
terminal FAILED; that two boundaries of the same kind sharing one store
with the same attempt identifier could claim each other's records; and
that Section 5.10 still listed a crash before the attempt record among the
stops that MUST have a recovery operation, although the same section says
that such records stay held. The source was revised as follows:

- Section 5.10: a crash after the action key is occupied but before the
  attempt is recorded is no longer in the list of stops that MUST have a
  recovery operation. Its records cannot be shown not entered and stay
  held, and a boundary SHOULD record the attempt first so that the case
  cannot arise.
- Section 5.12: a boundary that has sent a write that could record an
  attempt as not entered, including one whose result it did not receive,
  MUST NOT dispatch that attempt afterwards, whatever a later read shows.
  An attempt left in DISPATCH_PENDING without a dispatch is INDETERMINATE
  and is closed only by reconciliation with terminal evidence that
  forecloses any execution, now or later, under its provider idempotency
  key, as the verifier decides; a point-in-time absence of the operation
  does not qualify. Otherwise it stays held.
- Section 5.13: the verification requirement applies to every boundary and
  evidence path, including the result that the dispatch itself returns; an
  adapter's classification is not verification. Presented evidence carries
  its kind in the boundary's own input, and reconciliation and pre-entry
  recovery each refuse the other kind before the verifier runs. The
  presenter and the verifier carry separate obligations that the boundary
  cannot check.
- Section 5.14: the attempt identity is scoped to the boundary. It includes
  an identifier of the boundary, the same for every instance of one
  boundary, and, across kinds, a component that distinguishes them, in
  every record keyed by the attempt and in the authorization scope, but
  never in the action key.
- Security Considerations: "Evidence-agnostic verification" no longer says
  that telling the verifier the purpose solves the problem; it states the
  residual that the boundary cannot detect (a verifier that affirms a
  purpose it did not evaluate, and evidence presented under the wrong
  kind). New "Unverified adapter results" paragraph; "Lost
  acknowledgements" covers a delayed not-entered write; "Recovery
  credential scope" covers same-kind boundaries.
- Section 15 was rewritten to describe the round-five code: no provider
  call after a not-entered write, a verifier required on both boundaries
  and applied to the dispatch's own result, evidence kinds, and a claim
  scope that names a boundary identifier. The integrator checked every
  Section 15 statement against the round-five code, removed the review
  comments, and re-pinned `EP-NATIVE-HANDOFF` and `EP-LIFECYCLE-CORPUS` to
  `82490c9ff50a2d2a2d24f2c47024932fbae8490a`, the branch commit that
  carries that code and its docs.
- Changes since -06 and `README.md` were updated to match. `README.md`
  item 2 no longer accepts "no attempt record exists" as proof of
  non-entry, and item 6 now states both the Section 4 minimum
  normalization and the full list the reference verifier applies.

Checks on the revised source:

- `xmllint --noout`: PASS.
- `xml2rfc 3.34.0 --text` and `--html`: PASS with the same inherited
  submissionType warning. A second render into a scratch directory is
  byte-identical to `RENDERS/` (`cmp`).
- `idnits 3.1.0 -m submission` on the TXT and on the XML: PASS, no nits.
- ASCII: no byte above 0x7F in the XML, the text render, `README.md`, or this
  file. No double hyphen in XML prose outside comments.
- `shasum -a 256 -c SHA256SUMS.txt`: PASS for all three files.
- Structural checker, version 6: condition I2 now requires Section 15 to
  say that both boundaries require the verifier and apply it to their own
  provider result, and 11 conditions were added for the Section 5.10
  crash-before-record case, no dispatch after a not-entered write, the
  undispatched DISPATCH_PENDING record, verification on every boundary,
  evidence kinds, the residual-trust statement, the boundary-scoped
  attempt identity (two conditions), unverified adapter results, Section
  15, and the Changes section (73 in total). The revised -07 passes 73 of
  73. The -07 source as it stood before this revision passes 61 of 73; the
  12 failures are exactly I2 and the 11 new conditions. The posted -06
  passes 3 of 73 (the same three regression guards).
- Datatracker API (2026-09-25T16:08Z, after the re-pin):
  `draft-schrock-action-evidence-boundary` is still at rev 06, and the
  archive URL for -07 returns 404. For each of the 12 other Internet-Drafts
  cited with a revision in the XML, the Datatracker record is at the cited
  revision and the archive URL of the next revision returns 404.

As before, these checks show that the text states the requirements, not that
the reference code meets them. The candidate is staged, not submitted.

## Round-four revision (2026-09-25 UTC)

A round-three attack review of branch `fix/pr788-followups` at `9c93ea1a2`
found that the reference Gate inferred that an attempt never entered the
provider from a released attempt record without provider evidence, so an
attempt store that does not return stored evidence let one authorization
enter the provider twice; that a "not found" lookup presented as a terminal
outcome against a live attempt opened the action key on the composed
boundary, and on the native boundary when the verifier ignored the purpose
of the check; that a recovery claim without a scope reached the authorizer
unchecked, while Section 15 said the store refused it; that a native and a
composed attempt with the same attempt identifier on one store could claim
each other's records; and that several refusals reported a clean refusal
while a write they made could still be held. The source was revised as
follows:

- Section 5.10: every not-entered transition records an explicit
  not-entered marker in the same atomic write. Only that marker, or a
  durable read of a pre-dispatch state, shows non-entry. The absence of
  evidence is never proof: a closed record without the marker or terminal
  provider evidence is INDETERMINATE, is never treated as a pre-entry stop,
  and releases nothing. Release item 3 and the recovery proof require the
  recorded marker.
- Section 5.11: a refusal whose writes are not all confirmed released is
  reported as INDETERMINATE, not as a final refusal.
- Section 5.13: a terminal outcome that commits or releases the records of
  a dispatched attempt is accepted only after a relying-party-configured
  verifier authenticates it for that attempt, including its provider
  idempotency key. The boundary tells the verifier the purpose of each
  check and counts only a result that affirms that purpose for that
  attempt. A "not received" lookup is evidence only for pre-entry recovery.
  A boundary without such a verifier keeps a dispatched attempt
  INDETERMINATE.
- Section 5.14: reconciliation evidence is verified for the terminal
  purpose. A recovery claim that names no attempt is refused before its
  authorization is evaluated, and the attempt identity includes a
  component that distinguishes boundaries of different kinds sharing one
  store.
- Security Considerations: new "Inferred non-entry" and "Evidence-agnostic
  verification" paragraphs; "Recovery credential scope" covers scope-less
  claims and shared stores.
- Section 15: both reference boundaries record the marker; the native
  boundary requires a purpose-affirming verifier, and the composed boundary
  uses one when configured and otherwise refuses terminal reconciliation
  but still closes a run on its adapter's form-checked result, which
  Section 15 scopes as meeting Section 5.13 only if that adapter
  authenticates what it returns; the PostgreSQL store
  refuses a claim without a recovery scope and names the boundary kind in
  the scope; the reference Gate fences the earlier release's replay key for
  every pinned source label, and its documentation requires that the
  earlier release not share a store with the current code. The
  integrator checked every Section 15 statement against the round-four
  code, removed the `PR790-R4-CONFIRM` comments, added that the reference
  code cannot tell whether a verifier evaluated the evidence and that the
  composed boundary has no recovery for an evaluation reservation made
  before its attempt record, and re-pinned `EP-NATIVE-HANDOFF` and
  `EP-LIFECYCLE-CORPUS` to `ebb4084b81d0e0bb544494c92c171dcebda7dab3`, the
  branch commit that carries that code and its docs.
- Section 5.10 (integrator): the recovery proof no longer accepts the
  absence of an attempt record, because a live attempt may not yet have
  written it; a record held without an attempt record stays held, and a
  boundary SHOULD record the attempt before it occupies the action key. The
  Changes entry for the marker says the same.
- Changes since -06 and `README.md` were updated to match. `README.md`
  item 3 now uses the Section 5.11 ownership wording, so a durable owner
  marker or creation without hand-back also proves current ownership.

Checks on the revised source:

- `xmllint --noout`: PASS.
- `xml2rfc 3.34.0 --text` and `--html`: PASS with the same inherited
  submissionType warning. A second render into a scratch directory is
  byte-identical to `RENDERS/` (`cmp`).
- `idnits 3.1.0 -m submission` on the TXT and on the XML: PASS, no nits.
- ASCII: no byte above 0x7F in the XML, the text render, `README.md`, or this
  file. No double hyphen in XML prose outside comments.
- `shasum -a 256 -c SHA256SUMS.txt`: PASS for all three files.
- Structural checker, version 5: condition L9 no longer requires Section 15
  to say that the composed boundary delegates evidence verification, and 13
  conditions were added for the marker, verifier purpose, scope-required
  claims, boundary-kind identity, unconfirmed refusals, Section 15, and
  security (62 in total). The revised -07 passes 62 of 62. The -07 source
  as it stood before this revision passes 49 of 62; the 13 failures are
  exactly the new conditions. The posted -06 passes 3 of 62 (the same three
  regression guards).
- Datatracker API (2026-09-25T11:38Z, re-run by the integrator at
  12:46Z): `draft-schrock-action-evidence-boundary` is still at rev 06, and
  the archive URL for -07 returns 404. For each of the 12 other
  Internet-Drafts cited with a revision in the XML, the Datatracker record
  is at the cited revision and the archive URL of the next revision returns
  404.

As before, these checks show that the text states the requirements, not that
the reference code meets them.

## Round-three revision (2026-09-25 UTC)

A round-two attack review of branch `fix/pr788-followups` at `aa08efd46`
found that a pre-entry recovery that lost its transition to a live attempt
could reuse its pre-entry lookup as a terminal FAILED and release the action
key while the first provider call was in flight, that the composed Gate
boundary released its fence holder before its terminal attempt transition,
that recovery claims were not bound to the claimed record, that a recovery of
one attempt could commit another attempt's evaluation reservation, that a
truthy non-`true` store answer counted as success, and that one exact issuer
under two declared namespaces could spend one grant twice. Section 15 also
said that each reference boundary keys every record it can release by the
attempt, which the composed boundary does not do. The source was revised as
follows:

- Section 5.10: pre-entry recovery is a separate operation that never
  continues into reconciliation, and its authorization is bound to exactly
  one attempt. Recovery's own atomic not-entered transition is the
  linearization point; once it succeeds, the original attempt cannot enter
  DISPATCH_PENDING, must not use what it writes afterwards, and releases it
  only after it confirms the not-entered close. A recovery
  that loses the transition treats the attempt as INDETERMINATE, releases
  nothing, and never uses its lookup result as outcome evidence. Records are
  released only after the not-entered transition is confirmed.
- Section 5.11: an atomic transition succeeds only on the store's affirmative
  result; any other answer is a failure resolved through a durable read. A
  record that successive attempts can hold is released, closed, or committed
  only for an attempt proven to be its current owner. When an attempt record
  exists, the attempt's records are released, closed, or committed only
  after its terminal or not-entered transition has succeeded and been
  confirmed, by a durable read where the store has one and otherwise by the
  affirmative result.
- Section 5.12: a non-affirmative result of the write that enters
  DISPATCH_PENDING releases nothing; the boundary reads the record and either
  dispatches as its proven owner or treats the attempt as INDETERMINATE,
  closes a record still in its earlier state as not entered before releasing,
  and, when the record cannot be read, may attempt that not-entered
  transition directly and release only on its affirmative result, and
  otherwise holds everything.
- Section 5.14: recovery authorization is bound to exactly one attempt, never
  only to a shared value such as an operation identifier, and every claimed
  record must be derived from that attempt. Reconciliation records and
  confirms the terminal state, after freezing a non-terminal record as
  INDETERMINATE, before it releases or commits anything.
- Section 4 (pins): one issuer has exactly one authority namespace in a pin
  set. Two declared namespaces for one issuer value are refused. The minimum
  normalization adds URI scheme case, a trailing dot on a URL host, and an
  http or https URL written without "//".
- Section 8.7 hostile vectors, Security Considerations (relabelled authority,
  recovery racing a live attempt, lost acknowledgements and non-affirmative
  answers, record ownership, recovery credential scope), and the Changes
  section were updated to match.
- Section 15: the composed boundary is scoped exactly. It keys its
  occupation of the action key by attempt and its evaluation reservation by
  evaluation, commits that reservation only on proof that the attempt still
  owns it and leaves it untouched in pre-entry recovery, checks only the form
  of provider evidence, and delegates evidence verification to the
  operator's provider adapter and recovery authorization process. Where its
  attempt or consumption store has no durable read, it confirms only by the
  exact affirmative result, not by the durable read that Section 5.11
  requires, and a run that loses the race with recovery keeps the action key
  occupied. Section 15 also says that the reference Gate fences a key over
  the carried wire `replay_unit` in addition to the replay identity, never
  alone. The integrator checked every Section 15 statement against the
  round-three code, removed the `PR790-R3-CONFIRM` comments, and re-pinned
  `EP-NATIVE-HANDOFF` and `EP-LIFECYCLE-CORPUS` to
  `b929810bbb6cba642f0ef3dbc4b6954ac3c481e7`, the branch commit that carries
  that code and its docs.

Checks on the revised source:

- `xmllint --noout`: PASS.
- `xml2rfc 3.34.0 --text` and `--html`: PASS with the same inherited
  submissionType warning. A second render into a scratch directory is
  byte-identical to `RENDERS/` (`cmp`).
- `idnits 3.1.0 -m submission` on the TXT and on the XML: PASS, no nits.
- ASCII: no byte above 0x7F in the XML, the text render, `README.md`, or this
  file. No double hyphen in XML prose outside comments.
- `shasum -a 256 -c SHA256SUMS.txt`: PASS for all three files.
- Structural checker, version 4: condition R6 was rewritten for the
  one-namespace-per-issuer rule, and L1 to L10 were added for the recovery,
  release-ordering, affirmative-answer, ownership, claim-binding, lost
  acknowledgement, namespace, Section 15, and security conditions (49 in
  total). The revised -07 passes 49 of 49. The -07 source as it stood before
  this revision passes 38 of 49; the 11 failures are exactly R6 and L1 to
  L10. The posted -06 passes 3 of 49 (the same three regression guards).
- Datatracker API: `draft-schrock-action-evidence-boundary` is still at rev
  06 (posted 2026-09-25T02:15:03Z), and the archive URL for -07 returns 404.
  For each of the 12 other Internet-Drafts cited with a revision in the XML,
  the Datatracker record is at the cited revision and the archive URL of the
  next revision returns 404.

As before, these checks show that the text states the requirements, not that
the reference code meets them.

## Second review revision (2026-09-25 UTC)

A post-integration review of branch `fix/pr788-followups` found that the
fence could lock an action permanently after a stop before provider entry,
that an error path could release a record another attempt owned, that the
composed Gate path had no fence, that one issuer spelled two ways could spend
one grant twice, and that the fence compares exact bytes. The source was
revised as follows:

- Section 5.10: the fence is required on every evidence path (the SHOULD for
  non-native paths is removed); the release list adds the boundary's own
  confirmed pre-entry release and authorized pre-entry recovery; a recovery
  operation with proof of non-entry is required, and without that proof the
  attempt is treated as INDETERMINATE; action digests and effecting target
  identities are compared exactly, and profiles define canonical forms.
- Section 5.11: a boundary releases or closes only records whose ownership it
  can prove; an operation-identifier match is not proof.
- Section 5.14: one recovery authorization bound to an attempt suffices for
  every record of that attempt; a pre-entry stop is never reconciled to
  EXECUTED or FAILED.
- Sections 2, 4, 5.9, and 8.5: the native replay identity is derived from the
  authority namespace (default: the verified issuer value) and the native
  authorization identifier; a declared namespace replaces the issuer value.
  Pins whose issuer values differ but are equal after normalization must all
  declare the same namespace or the pin set is refused; a namespace change
  requires draining first.
- Section 8.7 hostile vectors, Section 9 deployment statement, Security
  Considerations (relabelled authority, namespace rotation, pre-entry stops,
  record ownership, action-digest scope), the Introduction figure, the
  Abstract, and the Changes section were updated to match.
- Section 15 was not changed in this revision; it was re-pinned in the
  round-two integration revision above.

Checks on the revised source:

- `xmllint --noout`: PASS.
- `xml2rfc 3.34.0 --text` and `--html`: PASS with the same inherited
  submissionType warning. A second render into a scratch directory is
  byte-identical to `RENDERS/` (`cmp`).
- `idnits 3.1.0 -m submission` on the TXT and on the XML: PASS, no nits.
- ASCII: no byte above 0x7F in the XML or the text render. No double hyphen
  in the XML.
- `shasum -a 256 -c SHA256SUMS.txt`: PASS for all three files.
- Datatracker API: `draft-schrock-action-evidence-boundary` is still at rev
  06 (posted 2026-09-25T02:15:03Z), and the archive URL for -07 returns 404.
  Every Internet-Draft cited in the XML still cites the latest revision.
- Structural checker, version 3: conditions R4 and R6 were rewritten for the
  new namespace rule, and R7, F7, F8, F9, F10, O1, and O2 were added (39 in
  total). The revised -07 passes 39 of 39. The -07 source as it stood before
  this revision passes 30 of 39; the nine failures are exactly the new or
  rewritten conditions. The posted -06 passes 3 of 39 (the same three
  regression guards).

These checks show that the text states the requirements. They do not show
that the reference code meets them; that is Section 15's job after the
re-pin.

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

## Round-two integration revision (2026-09-25 UTC)

The source was revised after the reference fixes on branch
`fix/pr788-followups` were integrated:

- Section 5.10, fence release item 3 and the pre-entry recovery paragraph: a
  record that the boundary closed as not entered, through an atomic
  transition that no dispatch of the attempt can follow, counts as proof of
  non-dispatch alongside a record that never reached DISPATCH_PENDING. This
  matches Section 5.8, which closes an attempt as not entered when the
  provider-entry recheck fails. A recovery that finds a record from which the
  original attempt could still dispatch must first close it that way, so the
  original attempt cannot dispatch after the release.
- Section 15 was re-pinned to commit
  `46b5ec92745d50ea7163301b1141eedd2091fc6e` and rewritten. It says that both
  reference Gate boundaries implement Section 5.10 and its recovery, that the
  composed boundary recovers only with a durable attempt-state read, that the
  reference code cannot tell whether a provider lookup exists, that the
  composed boundary does not verify provider evidence itself, that Gate has
  no material-field inventory, and that the wire `replay_unit` still covers
  the labels while the verifier derives its own replay identity. The corpus
  paragraph now counts 26 cases.
- The Changes section names both reference Gate boundaries.

Checks on the revised source:

- `xmllint --noout`: PASS.
- `xml2rfc 3.34.0 --text` and `--html`: PASS with the same inherited
  submissionType warning. A second render into a scratch `RENDERS/`
  directory is byte-identical to `RENDERS/` (`cmp`).
- `idnits 3.1.0 -m submission` on the TXT and on the XML: PASS, no nits.
- ASCII: no byte above 0x7F in the XML or the text render. No double hyphen
  in the XML.
- `shasum -a 256 -c SHA256SUMS.txt`: PASS for all three files.
- Structural checker, version 3: 39 of 39.
- Datatracker API: `draft-schrock-action-evidence-boundary` is still at rev
  06 (posted 2026-09-25T02:15:03Z), and the archive URL for -07 returns 404.
  For each of the 13 Internet-Drafts cited with a revision in the XML, the
  archive URL of the next revision returns 404.

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

## Round-five wording correction (closure of an attempt left INVOKING without dispatch)

Section 5.12 now requires terminal evidence that forecloses any execution, now
or later, under the attempt's provider idempotency key, and states that a
point-in-time absence of the operation, even when authenticated, does not
foreclose execution while a dispatcher may still be live. Re-checked on the
revised source:

- `xmllint --noout`: PASS.
- `xml2rfc 3.34.0 --text` and `--html`: PASS; renders replaced in `RENDERS/`.
- `idnits 3.1.0 -m submission` on the TXT and on the XML: PASS, no nits.
- `SHA256SUMS.txt` regenerated for the XML and both renders.

## Filing pin (2026-09-25)

`EP-NATIVE-HANDOFF` and `EP-LIFECYCLE-CORPUS` now pin
`b1b268e7d0538a9e22e379ddb06f55149d352c3b`, the merge of PR #790 on main,
replacing the branch commit `82490c9ff50a2d2a2d24f2c47024932fbae8490a`. Both
pinned URLs return HTTP 200. The front-page date is 2026-09-25. Re-checked on
the revised source: `xmllint --noout` PASS; `xml2rfc 3.34.0 --text` and
`--html` PASS, renders replaced; `idnits 3.1.0 -m submission` on the TXT and
the XML PASS, no nits; `SHA256SUMS.txt` regenerated.

## Publication check

Checked on 2026-09-25 after posting:

- The Datatracker submission API lists submission 169495 for
  `draft-schrock-action-evidence-boundary` revision 07 in state `posted`, and
  the document record shows revision 07 at 2026-09-26T00:11:40Z, the time of
  its "New version available" event.
- The IETF archive XML has SHA-256
  `938f4d6538dc5e9b40da7934090013fa91906638d587e7dec05c940922ad6045` and the
  archive text has SHA-256
  `58c7d004193deed53550177ab5a69e1066ed12f5c8a7427aa77c8c7acdc4b04a`. Both
  match `SHA256SUMS.txt` byte-for-byte.
- The archive HTML differs from the retained render. The archive rendered it
  with xml2rfc 3.34.1 and its delivery path injects request-specific Cloudflare
  markup, so the retained render stays the checksum-pinned local form.

Publication is not working-group adoption, RFC status, protocol-owner review,
implementation interoperability, or deployment evidence.
