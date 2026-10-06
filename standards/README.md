# EMILIA Standards Work

This directory contains published individual Internet-Draft snapshots and
their public supporting material for an evidence architecture for consequential
agent actions.

Start here:

- [`PORTFOLIO.md`](PORTFOLIO.md) is the human-readable architecture and filing
  narrative.
- [`STATUS.json`](STATUS.json) is the machine-readable source of truth for
  published revisions, roles, consolidation, retired work, and
  partner-triggered profiles.
- [`../caid`](../caid) contains the CAID identifier, Action-Mapping Profile,
  registry, three same-team reference ports, and shared vectors.

## Status language

A draft published on the IETF Datatracker is an **active individual
Internet-Draft**. It is not an RFC, not an adopted working-group item, and not
IETF endorsement. New revisions are ordinarily prepared in `staged/`.
`STATUS.json` records each current snapshot path; sole-authored published
snapshots live in `posted/`, GRACE-00 remains in its checksum-pinned profile
packet, and superseded history lives in `archive/`.

Published snapshots are checked byte-for-byte against the immutable IETF
archive before their local path is recorded as current. Where retained, exact
submitted bytes, checksums, and local review renders remain under `staged/` or
the document's recorded profile packet as provenance. The IETF archive is
authoritative for rendered forms and live status.

## Cohesive architecture

The portfolio keeps five decisions separate:

1. `VERIFIED`: a native artifact passed its own verifier.
2. `MATCH`: verified artifacts denote the same material action.
3. `SATISFIED`: the bundle fills a relying-party evidence requirement.
4. `AUTHORIZED`: local policy permits execution.
5. `EXECUTED`: an executor reports an effect.

CAID owns typed material-action identity and profile-bounded matching. Receipts
and Quorum provide named evidence profiles. AEC evaluates evidence
satisfaction. Challenge, enforcement, outcome, revocation, and preservation
remain separate lifecycle transitions.

## Canonical four-document PRESENTATION surface

The reader-facing canonical surface is:

1. **Authorization Receipts** —
   [`draft-schrock-ep-authorization-receipts-13`](posted/draft-schrock-ep-authorization-receipts-13.xml):
   one action-bound organizational approval-evidence profile. The -13 XML is
   byte-identical to the IETF archive copy.
2. **Human Authorization Binding** —
   [`draft-schrock-human-authorization-binding-00`](posted/draft-schrock-human-authorization-binding-00.xml):
   the host-agnostic binding of named-human authorization evidence into an
   adjacent agent-action record.
3. **Authority Introduction** —
   [`draft-schrock-ep-authority-introduction-03`](posted/draft-schrock-ep-authority-introduction-03.xml):
   relying-party-pinned trust-root introduction and scoped authority.
4. **Authorization Evidence Chain (AEC)** —
   [`draft-schrock-ep-authorization-evidence-chain-06`](posted/draft-schrock-ep-authorization-evidence-chain-06.xml):
   composition of verified, action-matched evidence against a relying-party
   requirement.

`STATUS.json.canonical_four_document_surface` records the exact revisions,
source paths, Datatracker URLs, and snapshot SHA-256 digests. This is a
presentation surface, not a consolidation or Datatracker relationship. It does
not retire, merge, replace, update, obsolete, or subordinate any active draft;
the distinct profile and lifecycle portfolio remains intact.

Change the Authorization Receipts `source` and `revision` in that record only
after the new revision is mirrored into `posted/`. The `/spec` page
(`app/spec/page.tsx`) renders only
`standards/posted/draft-schrock-ep-authorization-receipts-<revision>.xml` and
returns 404 when that file does not exist. It logs a `source` value that names
any other path, and `tests/site-spec-route.test.ts` fails on any source other
than that posted path.

## Separate portfolio and runtime views

The presentation surface does not replace the active profile portfolio. The
complete active portfolio is the 26 records in
`STATUS.json.active_datatracker`, including 21 sole-authored records and five
coauthored records, each with its own scope and revision history. Each record
also carries a maintenance status (`maintenance_status`, defined in
`STATUS.json.status_language`) and its Datatracker expiry date; the
human-readable table is in [`PORTFOLIO.md`](PORTFOLIO.md#maintenance-status).

The separate runtime execution spine is **Architecture-03 -> CAID-05 ->
AEC-06 -> AEB-07**: architecture and decision boundaries, exact material-action
identity and matching, evidence satisfaction, then executor-side admission and
one-time consequence custody. This runtime path is not the four-document
presentation surface and does not retire, merge, or demote any active profile.
`STATUS.json.runtime_execution_spine` records its auditable document metadata.

## August 3 published wave

These six revisions were published as active individual Internet-Drafts on
August 3, 2026:

1. `draft-schrock-ep-authorization-evidence-chain-05`
2. `draft-schrock-action-evidence-boundary-03`
3. `draft-schrock-model-to-matter-03`
4. `draft-schrock-ep-reliance-agreement-00`
5. `draft-schrock-ep-bounded-capability-receipts-01`
6. `draft-schrock-ep-bounded-execution-program-00`

Their publication snapshots remain in `posted/` or, after supersession,
`archive/`. The exact submitted-byte packet remains in `staged/UPLOAD-THIS/`
with rendered forms, submission-mode
`idnits` results, checksums, and Datatracker Additional Resources metadata for
publication provenance. The retained packet is not an upload queue.

## August 6 maintenance revisions

Four maintenance revisions were published and checked byte-for-byte against
the immutable IETF archive on August 6, 2026, in dependency order:

1. `draft-schrock-canonical-action-identifier-02`
2. `draft-schrock-ep-authorization-receipts-10`
3. `draft-schrock-ep-bounded-capability-receipts-02`
4. `draft-schrock-model-to-matter-04`

CAID-02 was posted first so Receipts-10's normative reference resolved to the
current CAID revision at publication time. Their isolated packets remain under
`staged/NEXT-*` as publication provenance, not upload candidates.

## August 10 maintenance revision

`draft-schrock-ep-authorization-receipts-11` was published and checked
byte-for-byte against the immutable IETF archive on August 10, 2026. It makes
the Authorization Bundle transport-neutral and moves OAuth RAR into an
optional binding profile. Its isolated packet remains under
`staged/NEXT-AUTHORIZATION-RECEIPTS-11` as publication provenance.

## August 11 maintenance revision

`draft-schrock-ep-bounded-capability-receipts-04` was published on August 11,
2026. Its XML and TXT were checked byte-for-byte against the immutable IETF
archive. Revision -04 adds immutable scope-comparison semantics, composition
proof provenance, bounded provider-entry recovery, atomic issuance
registration, and an operation-bound Ed25519 holder method while retaining
explicit shared-domain and implementation limits. Its isolated packet remains
under `staged/NEXT-BOUNDED-CAPABILITY-04` as publication provenance.

## August 16 maintenance revisions

`draft-schrock-action-evidence-boundary-04` and
`draft-schrock-ep-authorization-receipts-12` were published on August 16,
2026. Their exact submitted XML was checked byte-for-byte against the immutable
IETF archive. AEB-04 adds a generic, relying-party-pinned field-origin assertion
input while keeping `EP-FIELD-ORIGIN-v0.1` informative. Receipts-12 adds the
acceptance-prefix integrity property, states the offline anti-backdating limit,
and separates historical acceptance from current policy and status acceptance.
Their isolated packets remain under `staged/NEXT-*` as publication provenance.

## August 22 GRACE publication

The coauthored GRACE application profile
`draft-schrock-kintzele-grid-curtailment-00` was published as an active
individual Internet-Draft on August 22, 2026. The retained XML and TXT under
`profiles/NEXT-GRID-CURTAILMENT-00/` were checked byte-for-byte against the
immutable IETF archive. Publication is not implementation evidence, deployment
evidence, working-group adoption, RFC status, or IETF endorsement.

## August 31 AEB maintenance revision

`draft-schrock-action-evidence-boundary-05` was published through Datatracker
submission 168394. Its XML and TXT match the immutable IETF archive
byte-for-byte. The posted HTML is a whitespace-normalized local xml2rfc 3.34.0
render because the archive delivery path injects request-specific Cloudflare
markup; the checksum-pinned exact render remains in the provenance packet.
Revision -05 makes AEB a neutral native-compilation target while requiring
explicit semantic-loss disclosure, exact-action binding, a stable native replay
unit, and preservation of the AEB lifecycle axes. Native-owner review and the
complete multi-profile conformance gate remain open.

## September 6 AEC corrective revision

`draft-schrock-ep-authorization-evidence-chain-06` was posted through
Datatracker submission 168689 (Datatracker time 2026-09-06T17:33:02Z) as one of
the four September 6 corrective revisions. Its XML and TXT match the immutable
IETF archive byte-for-byte, and the snapshot was mirrored into `posted/` on
2026-09-26. The posted HTML follows the same whitespace-normalized local render
rule as AEB-06. Revision -06 adds an explicit pre-execution Authorization
Bundle component, kept separate from the terminal Trust Receipt component,
updates implementation status for the structured requirement, native facts,
role constraints, required bindings, and replay contract, and updates
references without changing the EP-AEC-v1 envelope or converting evidence
satisfaction into execution authority. It is an individual Internet-Draft, not
a working-group item, and posting is not protocol-owner review.

## September 6 Architecture corrective revision

`draft-schrock-ep-architecture-03` was posted through Datatracker submission
168691 (Datatracker time 2026-09-06T17:31:40Z) as one of the four September 6
corrective revisions. Its XML and TXT match the immutable IETF archive
byte-for-byte, and the snapshot was mirrored into `posted/` on 2026-09-26. The
posted HTML follows the same whitespace-normalized local render rule as AEC-06.
Revision -03 makes provider entry the transition that converts reserved
authority to consumed authority before provider invocation, defines
admission-control domains and monotonic epochs without overloading
witness-independence control domains, and defines serialized emergency freeze,
restoration, and reconciliation behavior for the three freeze-versus-entry
races. It states the disconnected-edge stale-admission window, rejects
immediate global-freeze claims, and adds idempotency, wrong-holder,
receipt-absence, and unsigned-event claim boundaries. The abstract is
unchanged from -02. It is an individual Internet-Draft, not a working-group
item, and posting is not protocol-owner review.

## September 6 Quorum corrective revision

`draft-schrock-ep-quorum-04` was posted through Datatracker submission 168688
(Datatracker time 2026-09-06T17:27:51Z) as one of the four September 6
corrective revisions. Its XML and TXT match the immutable IETF archive
byte-for-byte, and the snapshot was mirrored into `posted/` on 2026-09-27. The
posted HTML is the IETF archive HTML with the per-request Cloudflare challenge
script removed, checked on 2026-09-28.
Revision -04 replaces the context-only chronology claim with the versioned
`EP-QUORUM-SIGNOFF-CHAIN-v1` profile: a successor signs a digest of the
completed predecessor signoff, including its signature, and legacy
context-only chains cannot satisfy the profile. It does not establish trusted
wall-clock time or human comprehension. It is an individual Internet-Draft, not
a working-group item, and posting is not protocol-owner review.

## September 12 Receipts and Presentation Binding revisions

`draft-schrock-ep-authorization-receipts-13` (submission 168935, Datatracker
time 2026-09-12T15:05:02Z) and `draft-schrock-ep-presentation-binding-01`
(submission 168936, Datatracker time 2026-09-12T15:06:51Z) were posted through
Datatracker. Their XML and TXT match the immutable IETF archive byte-for-byte,
and the snapshots were mirrored into `posted/` on 2026-09-27. Each posted HTML
is the IETF archive HTML, rendered by xml2rfc 3.34.1, with the per-request
Cloudflare challenge script removed, checked on 2026-09-28. Receipts-13
adds Section 13.13, "What Successful Verification Does Not Establish."
Presentation Binding-01 adds Section 6.1, "Receipt and Presentation Evidence
Remain Distinct." Both are individual Internet-Drafts, not working-group items,
and posting is not protocol-owner review.

## September 24 AEB maintenance revision

`draft-schrock-action-evidence-boundary-06` was posted through Datatracker
submission 169466 (Datatracker time 2026-09-25T02:15:03Z). Its XML and TXT
match the immutable IETF archive byte-for-byte. The posted HTML follows the
same whitespace-normalized local render rule as -05. Revision -06 places AEB
after the native identity and authorization decision: CAID is used only for a
cross-format join, AEC only for a multi-leg evidence requirement, and no second
PDP is required. It keeps stable replay identity, durable consume or reserve
before provider entry, and authenticated reconciliation without blind retry.
It is an individual Internet-Draft, not a working-group item, and posting is
not protocol-owner review. Native-owner review and the complete multi-profile
conformance gate remain open.

## September 25 AEB maintenance revision

`draft-schrock-action-evidence-boundary-07` was posted through Datatracker
submission 169495 (Datatracker time 2026-09-26T00:11:40Z). Its XML and TXT
match the immutable IETF archive byte-for-byte. The posted HTML follows the
same whitespace-normalized local render rule as -06. Revision -07 keeps the -06
structure and adds a durable same-action in-flight fence, which refuses a new
attempt for an action whose earlier attempt is still in flight or uncertain,
even when fresh authority is presented. An attempt that stopped before provider
entry is released only with proof that it never entered. Terminal provider
evidence is accepted only after a relying-party-configured verifier affirms it
for the attempt and the stated purpose. One native replay identity is derived
from the relying-party-pinned authority namespace and the native authorization
identifier, and the revision specifies what a native authorization handoff
attests and how the boundary verifies it, leaving the encoding to deployment
pins. It is an individual Internet-Draft, not a working-group item, and posting
is not protocol-owner review. Native-owner review and the complete
multi-profile conformance gate remain open.

## September 26 CAID maintenance revision

`draft-schrock-canonical-action-identifier-03` was posted through Datatracker
submission 169526 (Datatracker time 2026-09-26T16:30:22Z). Its XML and TXT
match the immutable IETF archive byte-for-byte. The posted HTML is the
provenance packet's local xml2rfc 3.34.0 render, which was recorded with its
trailing whitespace already removed. Revision -03 makes enum validation
replayable: an external enum reference requires a snapshot or edition label, a
SHA-256 pin over the complete JCS values array, exact local resolution, and a
verified membership check, and bare, unresolved, digest-mismatched, and
out-of-set values fail closed. It makes the enum definition forms exact,
defines required-field presence as a member of the action object itself, and
makes explicit the refusal of unpaired surrogates that RFC 8785 already
requires. The reference registry advances from version 3 to version 4:
existing Action Objects whose codes are in the pinned ISO 4217 snapshot keep
the same CAID bytes, a code outside it is refused, and eleven active types
cannot produce a CAID until their external value sets are pinned. The Action
Object, identifier syntax, digest suites, and mapping algorithm are unchanged.
It is an individual Internet-Draft, not a working-group item, and posting is
not protocol-owner review. -04 superseded it on 2026-09-28, and its snapshot
moved to `archive/`.

## September 27 posted mirror

Five published revisions were mirrored into `posted/` on 2026-09-27. Quorum-04,
Authorization Receipts-13, and Presentation Binding-01 are described in the
September 6 and September 12 sections above and keep their submitted sources in
`staged/` provenance packets. Bounded Capability Receipts-06 (Datatracker
submission 168817) and Agent Operation Continuity-00 (Datatracker submission
169086) had no source in this repository. Their XML and TXT were fetched from
the immutable IETF archive on 2026-09-27 and committed unchanged, with digests
recorded in `STATUS.json.september_27_2026_posted_mirror`. The superseded
Authorization Receipts-12, Presentation Binding-00, Quorum-03, and Bounded
Capability Receipts-04 snapshots moved to `archive/`. Checked against the
Datatracker API on 2026-09-28, `posted/` holds the current revision of every
active sole-authored draft.

## September 28 CAID revision

`draft-schrock-canonical-action-identifier-04` was posted through Datatracker
submission 169585 (Datatracker time 2026-09-28T07:24:09Z). Its XML and TXT
match the immutable IETF archive byte-for-byte and were mirrored into
`posted/` the same day, with digests recorded in
`STATUS.json.september_28_2026_caid_wave`. The posted HTML is the IETF archive
HTML with the per-request Cloudflare challenge script removed. -04 is a
substantive revision that makes the processing model complete and checkable:
a strict I-JSON input profile, host values that are refused and never
rewritten, one data model with one table of limits, definition conformance and
`definition_sha256`, the `code` field type with named code formats, the
monotone enum advance, a fixed reason order with verification details, and
normative mapping stages A through D. The suites, the digest, and the canonical
form of every object that both -03 and -04 accept do not change; the
identifier syntax changes only by refusing the forms its Section 14.1 lists,
and some action objects whose CAIDs were valid under -03 are now refused. The
reference registry advances to version 5: 62 type versions, 53 active, all of
which compute, and 9 deprecated. -04 adds Privacy Considerations and an
Implementation Status section, revises Security Considerations, and requests
seven IANA registries and the unregistered `caid` URI scheme. It is an
individual Internet-Draft, not a working-group item, and posting is not
protocol-owner review. CAID-03 moved to `archive/`.

## October 2 CAID revision and October 5 URI registration

`draft-schrock-canonical-action-identifier-05` was posted through Datatracker
submission 169802 at 2026-10-02T19:53:38Z. Its XML and TXT match the immutable
IETF archive byte-for-byte. -05 changes the complete identifier from the
unregistered `caid:` form to `canactid:` without changing the action object,
canonicalization, suite, digest bytes, mapping algorithm, or registry version.
The two complete identifier strings are not equal. Signed legacy identifiers
are never rewritten, and accepting them requires an explicit -04 verification
profile.

IANA provisionally registered the `canactid` URI scheme on 2026-10-05 with
CAID-05 as its reference. Provisional registration is not permanent
registration, an RFC, working-group adoption, IETF endorsement, certification,
implementation evidence, or deployment evidence.

## New-filing freeze

A 90-day freeze on new Internet-Draft names and `-00` filings is in effect from
2026-08-04 through 2026-11-01, inclusive. Maintenance revisions under an
existing active draft name remain allowed. The standing exception requires a
wire-level gap demonstrated by a named external implementer or deployment,
recorded evidence, and a recorded overlap review. GRACE-00 is the sole recorded
one-time governance override, and it does not claim that the standing exception
was satisfied. No active draft is retired or merged by this freeze, and the
distinct active profile portfolio remains intact.

## Directory layout

- `posted/`: canonical source snapshots for revisions already on Datatracker.
- `archive/`: superseded revisions and retired standalone candidates.
- `profiles/`: application-profile packets; each packet states its own live
  publication status and claim boundary.
- `staged/`: revision work plus the explicitly labeled, retained August 3
  publication-provenance packet.
- `observatory/`: revision-pinned source catalog and generated comparison data.

Use `STATUS.json` and then Datatracker for filing status. Local staging is not
publication; only a Datatracker submission creates a published revision.
