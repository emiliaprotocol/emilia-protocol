# CAID-03 publication provenance packet

Status: posted on 2026-09-26 as
`draft-schrock-canonical-action-identifier-03` through Datatracker submission
169526 (Datatracker time 2026-09-26T16:30:22Z). It is an active individual
Internet-Draft. It is not a working-group item, an RFC, or IETF endorsement,
and posting is not review by any referenced protocol owner.

The XML under `UPLOAD-THIS/` is the exact submitted -03 source and matches the
immutable IETF archive byte-for-byte. The text under `RENDERS/` also matches
the archive byte-for-byte. The packet is retained for publication provenance,
not as an upload candidate. The posted snapshot is
[`../../posted/draft-schrock-canonical-action-identifier-03.xml`](../../posted/draft-schrock-canonical-action-identifier-03.xml);
CAID-02 is retained in `../../archive/`. The publication check is recorded at
the end of `VALIDATION.md`.

## Changes from -02

Section 12 of the posted text, "Changes since -02", lists these changes:

- Enum validation is replayable. An external enum reference requires a
  snapshot or edition label, a SHA-256 pin over the complete JCS values array,
  exact local resolution, and a verified membership check. Bare, unresolved,
  digest-mismatched, and out-of-set values fail closed.
- The enum definition forms are exact: a null member is present and malformed,
  compact inline members are trimmed of U+0020 SPACE only, a values array
  beside a compact inline reference must equal it, an embedded values array
  beside an external reference is the pinned array, and values outside a
  compact inline list fail closed.
- Required-field presence means a member of the action object itself. Strings
  and member names containing an unpaired surrogate are refused as
  `unsupported_value`, making explicit the refusal that RFC 8785 already
  requires. A registry may correct an existing value-set pin in a new registry
  version under the narrow conditions in Section 4.1.
- The reference registry advances from version 3 to version 4. It pins the
  SIX ISO 4217 List One snapshot published 2026-09-17 for every currency field
  and pins the Dispense As Written codes of `rx.dispense.1` inline. Existing
  Action Objects whose code is in that snapshot produce the same CAID bytes; a
  code that version 3 accepted but the snapshot omits is refused. Eleven
  active types require an external value set that has no pinned snapshot yet
  and cannot produce a CAID under version 4 until one is published. Historical
  v3 decisions are not relabeled v4.

The revision does not change the Action Object, identifier syntax, digest
suites, or mapping algorithm, and changes canonicalization only by making the
unpaired-surrogate refusal explicit.

## Layout

`UPLOAD-THIS/` contains the exact submitted XML source. `RENDERS/` contains the
text and HTML produced from that source by xml2rfc 3.34.0; the HTML's trailing
spaces were removed before its checksum was recorded. `SHA256SUMS.txt` covers
all three files. `VALIDATION.md` records the checks run before submission and
the publication check.
