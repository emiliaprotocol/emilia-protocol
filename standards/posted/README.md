# Posted Draft Snapshots

This directory keeps local source snapshots for revisions already published on
the IETF Datatracker. It contains the current published revision of all 20
active `draft-schrock-*` records represented in this repository, plus the
locally retained coauthored Memory Projection Record snapshot. Datatracker is
authoritative for current revisions and status; see
[`../STATUS.json`](../STATUS.json) for the complete 22-record active inventory,
including the two coauthored records.

Do not upload a file from this directory as a new draft. Maintenance revisions
may be prepared in `../staged/`, rendered and tested, then filed through the
Datatracker by a human. The six XML files in `../staged/UPLOAD-THIS/` are the
exact submitted-byte provenance packet for revisions published on August 3,
2026. Despite that retained directory name, they are not upload candidates or
a filing queue.

Posted snapshots are immutable publication records. Implementation-status text
inside a posted revision reflects the state described when that revision was
filed; current repository behavior may have advanced since then and is tracked
in `../STATUS.json`.

"Posted" means an individual Internet-Draft was published. It does not mean
working-group adoption, RFC status, or IETF endorsement.

## Published snapshot inventory

The canonical active/replaced classification is `standards/STATUS.json`;
superseded snapshots move to `../archive/`. The July 29-30 XMLs and the six
August 3 XMLs were checked byte-for-byte against the immutable IETF archive
before promotion. TXT and HTML snapshots are conveniences; the archive is
authoritative for rendered forms.

- `draft-ferro-schrock-memory-projection-record-00`
- `draft-schrock-ae-challenge-01`
- `draft-schrock-action-evidence-boundary-03`
- `draft-schrock-action-remedy-receipts-00`
- `draft-schrock-agent-qualification-statements-00`
- `draft-schrock-canonical-action-identifier-01`
- `draft-schrock-emilia-eye-00`
- `draft-schrock-ep-architecture-02`
- `draft-schrock-ep-authority-introduction-02`
- `draft-schrock-ep-authorization-evidence-chain-05`
- `draft-schrock-ep-authorization-receipts-09`
- `draft-schrock-ep-bounded-capability-receipts-01`
- `draft-schrock-ep-bounded-execution-program-00`
- `draft-schrock-ep-evidence-record-01`
- `draft-schrock-ep-outcome-binding-00`
- `draft-schrock-ep-presentation-binding-00`
- `draft-schrock-ep-quorum-03`
- `draft-schrock-ep-reliance-agreement-00`
- `draft-schrock-ep-revocation-statement-01`
- `draft-schrock-human-authorization-binding-00`
- `draft-schrock-model-to-matter-03`

## Canonical four-document presentation surface

For reader navigation, the canonical evidence path is:

1. [Authorization Receipts-09](draft-schrock-ep-authorization-receipts-09.xml)
   defines the action-bound approval-evidence profile. The current posted
   revision is -09 and the exact posted source matches the Datatracker submission.
2. [Human Authorization Binding-00](draft-schrock-human-authorization-binding-00.xml)
   binds a named-human authorization artifact into an adjacent host record.
3. [Authority Introduction-02](draft-schrock-ep-authority-introduction-02.xml)
   establishes relying-party-pinned trust roots and scoped authority.
4. [Authorization Evidence Chain-05](draft-schrock-ep-authorization-evidence-chain-05.xml)
   evaluates whether natively verified, action-matched evidence satisfies the
   relying party's requirement; it never returns `AUTHORIZED`.

This is a presentation surface, not a consolidation or Datatracker
relationship. It does not merge, retire, replace, update, obsolete,
subordinate, or demote any active draft.

## Separate runtime execution spine

The runtime path is [Architecture-02](draft-schrock-ep-architecture-02.xml) →
[CAID-01](draft-schrock-canonical-action-identifier-01.xml) →
[AEC-05](draft-schrock-ep-authorization-evidence-chain-05.xml) →
[AEB-03](draft-schrock-action-evidence-boundary-03.xml): system boundaries,
exact material-action matching, evidence satisfaction, then executor-side
admission and one-time consequence custody.

This spine is a separate navigation view. It is not the four-document
presentation surface or a replacement portfolio. AEC appears in both views
because evidence satisfaction feeds runtime admission, not because the views
are equivalent. The complete active portfolio remains the 22-record inventory
in [`../STATUS.json`](../STATUS.json), with each draft's scope and revision
history preserved.

## July 21, 2026 publication set

The following XML sources were verified byte-for-byte against the corresponding
immutable artifacts in the IETF archive:

- `draft-schrock-action-evidence-boundary-00`
- `draft-schrock-canonical-action-identifier-01`
- `draft-schrock-ep-architecture-02`
- `draft-schrock-ep-authorization-evidence-chain-04`
- `draft-schrock-ep-authorization-receipts-08`
- `draft-schrock-ep-revocation-statement-00`
- `draft-schrock-model-to-matter-01`

The superseded `draft-schrock-ae-challenge-00` snapshots moved to `../archive/`.
The longer-named `draft-schrock-authorization-evidence-challenge-00`, Agent
Action Manifest, Action Evidence Graph, and Enforcement Point series also moved
to `../archive/` because Datatracker marks them replaced rather than active.

## July 29-30, 2026 publication set

The XML sources for AEB-02, AE Challenge-01, Revocation Statement-01,
Authority Introduction-02, Agent Qualification Statements-00, Action Remedy
Receipts-00, Outcome Binding-00, Model-to-Matter-02, and Memory Projection
Record-00 were verified byte-for-byte against the immutable IETF archive on
August 1, 2026.

## August 3, 2026 publication set

The following current XML snapshots were verified byte-for-byte against the
immutable IETF archive before promotion into this directory:

- `draft-schrock-action-evidence-boundary-03`
- `draft-schrock-ep-authorization-evidence-chain-05`
- `draft-schrock-ep-bounded-capability-receipts-01`
- `draft-schrock-ep-bounded-execution-program-00`
- `draft-schrock-ep-reliance-agreement-00`
- `draft-schrock-model-to-matter-03`

Their exact submitted bytes remain in `../staged/UPLOAD-THIS/` as publication
provenance, not as upload candidates. Authorization Receipts-08 remains the
current posted receipt revision in this inventory.
