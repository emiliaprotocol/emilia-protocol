# Posted Draft Snapshots

This directory keeps local source snapshots for revisions already published on
the IETF Datatracker. It contains the current published revision of all 20
active `draft-schrock-*` records represented in this repository, plus the
locally retained coauthored Memory Projection Record snapshot. Datatracker is
authoritative for current revisions and status; see
[`../STATUS.json`](../STATUS.json) for the complete 23-record active inventory,
including the three coauthored records.

Do not upload a file from this directory as a new draft. Maintenance revisions
may be prepared in `../staged/`, rendered and tested, then filed through the
Datatracker. The August 3 packet, four isolated August 6 packets, two isolated
August 8 packets, and the isolated Authorization Receipts-11,
AE-CHALLENGE-05, AE-CHALLENGE-06, and Bounded Capability Receipts-04 packets
from August 10-11 are
retained exact-submission provenance. Despite retained `UPLOAD-THIS` directory
names, they are not upload candidates or a filing queue.

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

- `draft-ferro-schrock-memory-projection-record-01`
- `draft-schrock-ae-challenge-07`
- `draft-schrock-action-evidence-boundary-04`
- `draft-schrock-action-remedy-receipts-00`
- `draft-schrock-agent-qualification-statements-00`
- `draft-schrock-canonical-action-identifier-02`
- `draft-schrock-emilia-eye-00`
- `draft-schrock-ep-architecture-02`
- `draft-schrock-ep-authority-introduction-03`
- `draft-schrock-ep-authorization-evidence-chain-05`
- `draft-schrock-ep-authorization-receipts-12`
- `draft-schrock-ep-bounded-capability-receipts-04`
- `draft-schrock-ep-bounded-execution-program-00`
- `draft-schrock-ep-evidence-record-01`
- `draft-schrock-ep-outcome-binding-00`
- `draft-schrock-ep-presentation-binding-00`
- `draft-schrock-ep-quorum-03`
- `draft-schrock-ep-reliance-agreement-00`
- `draft-schrock-ep-revocation-statement-01`
- `draft-schrock-human-authorization-binding-00`
- `draft-schrock-model-to-matter-04`

## Canonical four-document presentation surface

For reader navigation, the canonical evidence path is:

1. [Authorization Receipts-12](draft-schrock-ep-authorization-receipts-12.xml)
   defines the action-bound approval-evidence profile. The current posted
   revision is -12 and the exact posted source matches the Datatracker submission.
2. [Human Authorization Binding-00](draft-schrock-human-authorization-binding-00.xml)
   binds a named-human authorization artifact into an adjacent host record.
3. [Authority Introduction-03](draft-schrock-ep-authority-introduction-03.xml)
   establishes relying-party-pinned trust roots and scoped authority.
4. [Authorization Evidence Chain-05](draft-schrock-ep-authorization-evidence-chain-05.xml)
   evaluates whether natively verified, action-matched evidence satisfies the
   relying party's requirement; it never returns `AUTHORIZED`.

This is a presentation surface, not a consolidation or Datatracker
relationship. It does not merge, retire, replace, update, obsolete,
subordinate, or demote any active draft.

## Separate runtime execution spine

The runtime path is [Architecture-02](draft-schrock-ep-architecture-02.xml) →
[CAID-02](draft-schrock-canonical-action-identifier-02.xml) →
[AEC-05](draft-schrock-ep-authorization-evidence-chain-05.xml) →
[AEB-04](draft-schrock-action-evidence-boundary-04.xml): system boundaries,
exact material-action matching, evidence satisfaction, then executor-side
admission and one-time consequence custody.

This spine is a separate navigation view. It is not the four-document
presentation surface or a replacement portfolio. AEC appears in both views
because evidence satisfaction feeds runtime admission, not because the views
are equivalent. The complete active portfolio remains the 23-record inventory
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

The following XML snapshots were verified byte-for-byte against the
immutable IETF archive before promotion into this directory:

- `draft-schrock-action-evidence-boundary-03`
- `draft-schrock-ep-authorization-evidence-chain-05`
- `draft-schrock-ep-bounded-capability-receipts-01`
- `draft-schrock-ep-bounded-execution-program-00`
- `draft-schrock-ep-reliance-agreement-00`
- `draft-schrock-model-to-matter-03`

Their exact submitted bytes remain in `../staged/UPLOAD-THIS/` as publication
provenance, not as upload candidates. Authorization Receipts-12 is the current
posted receipt revision in this inventory.

## August 6, 2026 maintenance set

The following current XML snapshots were verified byte-for-byte against the
immutable IETF archive before promotion into this directory:

- `draft-schrock-canonical-action-identifier-02`
- `draft-schrock-ep-authorization-receipts-10`
- `draft-schrock-ep-bounded-capability-receipts-02`
- `draft-schrock-model-to-matter-04`

The isolated `../staged/NEXT-*` packets retain the exact submitted bytes,
review renders, checksums, and validation records as publication provenance.

## August 8, 2026 maintenance set

The following XML snapshots were verified byte-for-byte against the
immutable IETF archive before promotion into this directory:

- `draft-schrock-ae-challenge-03`
- `draft-schrock-ep-bounded-capability-receipts-03`

The retained `../staged/NEXT-AE-CHALLENGE-03` and
`../staged/NEXT-BOUNDED-CAPABILITY-03` packets preserve the exact submitted
XML, review renders, validation records, and correspondence text as publication
provenance.

## August 10, 2026 maintenance set

The following current XML snapshots, and the AE Challenge TXT snapshot, were
verified byte-for-byte against the immutable IETF archive before promotion
into this directory:

- `draft-schrock-ep-authorization-receipts-11`
- `draft-schrock-ae-challenge-07`

The retained `../staged/NEXT-AUTHORIZATION-RECEIPTS-11`,
`../staged/NEXT-AE-CHALLENGE-05`, and `../staged/NEXT-AE-CHALLENGE-06`
packets preserve the exact submitted XML, review renders, validation records,
and checksums as publication provenance through -06. The -07 current XML, TXT,
and HTML snapshots were fetched from the immutable IETF archive and verified
locally. The superseded
`draft-schrock-ep-authorization-receipts-10`,
`draft-schrock-ae-challenge-03`, and `draft-schrock-ae-challenge-05`
snapshots, together with `draft-schrock-ae-challenge-06`, are retained in
`../archive/`.

## August 11, 2026 maintenance set

The `draft-schrock-ep-bounded-capability-receipts-04` XML and TXT snapshots
were verified byte-for-byte against the immutable IETF archive before
promotion. The retained HTML is a whitespace-normalized local xml2rfc 3.34.0
render because the archive delivery path injected transient Cloudflare
markup. The `../staged/NEXT-BOUNDED-CAPABILITY-04` packet preserves the exact
submitted XML, checksum-pinned review renders, validation record, and
checksums. Revision -03 is retained in `../archive/`.

## August 16, 2026 maintenance set

The following current XML, TXT, and HTML snapshots were fetched from the
immutable IETF archive after posting. The XML snapshots were verified
byte-for-byte against the exact submitted source before promotion:

- `draft-schrock-action-evidence-boundary-04` (submission 167790)
- `draft-schrock-ep-authorization-receipts-12` (submission 167791)

The retained `../staged/NEXT-ACTION-EVIDENCE-BOUNDARY-04` and
`../staged/NEXT-AUTHORIZATION-RECEIPTS-12` packets are publication provenance,
not upload candidates. Revisions AEB-03 and Authorization Receipts-11 are
retained in `../archive/`.
