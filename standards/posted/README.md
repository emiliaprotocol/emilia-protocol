# Posted Draft Snapshots

This directory keeps local source snapshots for revisions already published on
the IETF Datatracker. Datatracker is authoritative for current revisions and
status; see [`../STATUS.json`](../STATUS.json) for the last verified local
inventory.

Do not upload a file from this directory as a new draft. New substantive
revisions are prepared in `../staged/`, rendered and tested, then filed through
the Datatracker by a human.

Posted snapshots are immutable publication records. Implementation-status text
inside a posted revision reflects the state described when that revision was
filed; current repository behavior may have advanced since then and is tracked
in `../STATUS.json`.

"Posted" means an individual Internet-Draft was published. It does not mean
working-group adoption, RFC status, or IETF endorsement.

## Published snapshot inventory

This directory preserves the current published snapshot for every tracked
active series. The canonical active/replaced classification is
`standards/STATUS.json`; superseded snapshots move to `../archive/`. Current
July 29-30 XMLs were checked byte-for-byte against the immutable IETF archive
on August 1. TXT and HTML snapshots are conveniences; the archive is
authoritative for rendered forms.

- `draft-ferro-schrock-memory-projection-record-00`
- `draft-schrock-ae-challenge-01`
- `draft-schrock-action-evidence-boundary-02`
- `draft-schrock-action-remedy-receipts-00`
- `draft-schrock-agent-qualification-statements-00`
- `draft-schrock-canonical-action-identifier-01`
- `draft-schrock-emilia-eye-00`
- `draft-schrock-ep-architecture-02`
- `draft-schrock-ep-authority-introduction-02`
- `draft-schrock-ep-authorization-evidence-chain-04`
- `draft-schrock-ep-authorization-receipts-08`
- `draft-schrock-ep-bounded-capability-receipts-00`
- `draft-schrock-ep-evidence-record-01`
- `draft-schrock-ep-outcome-binding-00`
- `draft-schrock-ep-presentation-binding-00`
- `draft-schrock-ep-quorum-03`
- `draft-schrock-ep-revocation-statement-01`
- `draft-schrock-human-authorization-binding-00`
- `draft-schrock-model-to-matter-02`

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
