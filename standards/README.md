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
IETF endorsement. New revisions are prepared in `staged/`, while immutable
published snapshots and superseded history live in `posted/` and `archive/`.

The six August 3 publication snapshots were checked byte-for-byte against the
immutable IETF archive before promotion to `posted/`. Their exact submitted
bytes, checksums, and local review renders remain retained under
`staged/` as provenance. The IETF archive is authoritative for rendered forms
and live status.

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
   [`draft-schrock-ep-authorization-receipts-09`](posted/draft-schrock-ep-authorization-receipts-09.xml):
   one action-bound organizational approval-evidence profile.
2. **Human Authorization Binding** —
   [`draft-schrock-human-authorization-binding-00`](posted/draft-schrock-human-authorization-binding-00.xml):
   the host-agnostic binding of named-human authorization evidence into an
   adjacent agent-action record.
3. **Authority Introduction** —
   [`draft-schrock-ep-authority-introduction-02`](posted/draft-schrock-ep-authority-introduction-02.xml):
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
complete active portfolio remains the 22 records in
`STATUS.json.active_datatracker`, including 20 active `draft-schrock-*` records
and two coauthored records, each with its own scope and revision history.

The separate runtime execution spine is **Architecture-02 -> CAID-01 ->
AEC-05 -> AEB-03**: architecture and decision boundaries, exact material-action
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

Their canonical current snapshots are in `posted/`. The exact submitted-byte
packet remains in `staged/UPLOAD-THIS/` with rendered forms, submission-mode
`idnits` results, checksums, and Datatracker Additional Resources metadata for
publication provenance. The retained packet is not an upload queue.

## New-filing freeze

A 90-day freeze on new Internet-Draft names and `-00` filings is in effect from
2026-08-04 through 2026-11-01, inclusive. Maintenance revisions under an
existing active draft name remain allowed. The only exception requires a
wire-level gap demonstrated by a named external implementer or named external
deployment, recorded evidence of that demonstration, and a recorded overlap
review showing that no active draft or adjacent specification already owns the
gap. No active draft is retired or merged by this freeze, and the distinct
active profile portfolio remains intact.

## Directory layout

- `posted/`: canonical source snapshots for revisions already on Datatracker.
- `archive/`: superseded revisions and retired standalone candidates.
- `profiles/`: held application profiles that are not in the filing lane.
- `staged/`: revision work plus the explicitly labeled, retained August 3
  publication-provenance packet.
- `observatory/`: revision-pinned source catalog and generated comparison data.

Use `STATUS.json` and then Datatracker for filing status. Local staging is not
publication; only a Datatracker submission creates a published revision.
