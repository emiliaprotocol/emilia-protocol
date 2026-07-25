# Posted Draft Snapshots

This directory keeps local source snapshots for revisions already published on
the IETF Datatracker. Datatracker is authoritative for current revisions and
status; see [`../STATUS.json`](../STATUS.json) for the last verified local
inventory.

Do not upload a file from this directory as a new draft. New substantive
revisions are prepared outside the public repository, rendered and tested, then
filed through the Datatracker by a human.

Posted snapshots are immutable publication records. Implementation-status text
inside a posted revision reflects the state described when that revision was
filed; current repository behavior may have advanced since then and is tracked
in `../STATUS.json`.

"Posted" means an individual Internet-Draft was published. It does not mean
working-group adoption, RFC status, or IETF endorsement.

## Published snapshot inventory

This directory preserves the current published snapshot for every tracked
`draft-schrock-*` series. The canonical active/replaced classification is
`standards/STATUS.json`; a published snapshot remains here when a series is
replaced so its historical bytes are not confused with unpublished source. The
seven XML sources published on July 21 were checked byte-for-byte against the
corresponding immutable IETF archive artifacts. Earlier TXT and HTML snapshots
are historical conveniences; the archive is authoritative for rendered forms.

- `draft-schrock-agent-action-manifest-00`
- `draft-schrock-ae-challenge-00`
- `draft-schrock-authorization-evidence-challenge-00`
- `draft-schrock-action-evidence-boundary-00`
- `draft-schrock-canonical-action-identifier-01`
- `draft-schrock-emilia-eye-00`
- `draft-schrock-ep-action-evidence-graph-00`
- `draft-schrock-ep-architecture-02`
- `draft-schrock-ep-authority-introduction-01`
- `draft-schrock-ep-authorization-evidence-chain-04`
- `draft-schrock-ep-authorization-receipts-08`
- `draft-schrock-ep-bounded-capability-receipts-00`
- `draft-schrock-ep-enforcement-point-00`
- `draft-schrock-ep-evidence-record-01`
- `draft-schrock-ep-presentation-binding-00`
- `draft-schrock-ep-quorum-03`
- `draft-schrock-ep-revocation-statement-00`
- `draft-schrock-human-authorization-binding-00`
- `draft-schrock-model-to-matter-01`

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

The active `draft-schrock-ae-challenge-00` XML, TXT, and HTML snapshots were
verified byte-for-byte against the immutable IETF archive on July 24, 2026.
The longer-named `draft-schrock-authorization-evidence-challenge-00` series is
a separate historical record that Datatracker marks replaced by AEB.
