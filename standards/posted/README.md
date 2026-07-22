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

## Current active snapshot inventory

On July 21, 2026, the live Datatracker inventory contained 16 active
`draft-schrock-*` series. This directory contains the current published
revision of every one. Each XML source and TXT rendering was checked against
the corresponding immutable IETF archive artifact. The EMILIA Eye TXT was
replaced with the exact archived rendering after the audit found that its
locally rendered bibliography still named an older Authorization Receipts
revision.

- `draft-schrock-agent-action-manifest-00`
- `draft-schrock-authorization-evidence-challenge-00`
- `draft-schrock-canonical-action-identifier-00`
- `draft-schrock-emilia-eye-00`
- `draft-schrock-ep-action-evidence-graph-00`
- `draft-schrock-ep-architecture-01`
- `draft-schrock-ep-authority-introduction-01`
- `draft-schrock-ep-authorization-evidence-chain-03`
- `draft-schrock-ep-authorization-receipts-07`
- `draft-schrock-ep-bounded-capability-receipts-00`
- `draft-schrock-ep-enforcement-point-00`
- `draft-schrock-ep-evidence-record-01`
- `draft-schrock-ep-presentation-binding-00`
- `draft-schrock-ep-quorum-03`
- `draft-schrock-human-authorization-binding-00`
- `draft-schrock-model-to-matter-00`

## July 19, 2026 publication set

The following local snapshots were verified byte-for-byte against the
corresponding TXT artifacts in the IETF archive:

- `draft-schrock-canonical-action-identifier-00`
- `draft-schrock-ep-architecture-01`
- `draft-schrock-ep-authority-introduction-01`
- `draft-schrock-ep-authorization-receipts-07`
- `draft-schrock-ep-quorum-03`
- `draft-schrock-ep-bounded-capability-receipts-00`
- `draft-schrock-ep-authorization-evidence-chain-03`
- `draft-schrock-model-to-matter-00`
