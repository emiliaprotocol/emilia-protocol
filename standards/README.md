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
archive before their local path is recorded as current. Exact submitted bytes,
checksums, and local review renders remain retained under `staged/` or the
document's recorded profile packet as provenance. The IETF archive is
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
   [`draft-schrock-ep-authorization-receipts-12`](posted/draft-schrock-ep-authorization-receipts-12.xml):
   one action-bound organizational approval-evidence profile.
2. **Human Authorization Binding** —
   [`draft-schrock-human-authorization-binding-00`](posted/draft-schrock-human-authorization-binding-00.xml):
   the host-agnostic binding of named-human authorization evidence into an
   adjacent agent-action record.
3. **Authority Introduction** —
   [`draft-schrock-ep-authority-introduction-03`](posted/draft-schrock-ep-authority-introduction-03.xml):
   relying-party-pinned trust-root introduction and scoped authority.
4. **Authorization Evidence Chain (AEC)** —
   [`draft-schrock-ep-authorization-evidence-chain-05`](posted/draft-schrock-ep-authorization-evidence-chain-05.xml):
   composition of verified, action-matched evidence against a relying-party
   requirement.

`STATUS.json.canonical_four_document_surface` records the exact revisions,
source paths, Datatracker URLs, and snapshot SHA-256 digests. This is a
presentation surface, not a consolidation or Datatracker relationship. It does
not retire, merge, replace, update, obsolete, or subordinate any active draft;
the distinct profile and lifecycle portfolio remains intact.

## Separate portfolio and runtime views

The presentation surface does not replace the active profile portfolio. The
complete active portfolio remains the 24 records in
`STATUS.json.active_datatracker`, including 20 sole-authored records and four
coauthored records, each with its own scope and revision history.

The separate runtime execution spine is **Architecture-02 -> CAID-02 ->
AEC-05 -> AEB-04**: architecture and decision boundaries, exact material-action
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
