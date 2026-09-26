# AEC-06 publication provenance packet

Status: posted on 2026-09-06 as
`draft-schrock-ep-authorization-evidence-chain-06` through Datatracker
submission 168689 (Datatracker time 2026-09-06T17:33:02Z), one of the four
September 6 corrective revisions. It is an active individual Internet-Draft.
It is not a working-group item, an RFC, or IETF endorsement, and posting is not
review by any referenced protocol owner.

The XML under `UPLOAD-THIS/` is the exact submitted -06 source and matches the
immutable IETF archive byte-for-byte. The text under `RENDERS/` also matches
the archive byte-for-byte. The packet is retained for publication provenance,
not as an upload candidate. The posted snapshot, mirrored on 2026-09-26, is
[`../../posted/draft-schrock-ep-authorization-evidence-chain-06.xml`](../../posted/draft-schrock-ep-authorization-evidence-chain-06.xml);
AEC-05 is retained in `../../archive/`. The publication check is recorded at
the end of `VALIDATION.md`.

## Changes from -05

Section 18 of the posted text lists three changes:

- an explicit pre-execution Authorization Bundle component, kept separate from
  the terminal Trust Receipt component;
- updated implementation status for the structured requirement, native facts,
  role constraints, required bindings, and replay contract;
- updated references, without changing the EP-AEC-v1 envelope or converting
  evidence satisfaction into execution authority.

The legacy string-requirement API remains a separate interface. The structured
evaluator captures relying-party configuration before evaluating native
evidence. The revision introduces no new component receipt type, authorizes no
action, and claims no independent implementation.

## Layout

`UPLOAD-THIS/` contains the exact submitted XML source. `RENDERS/` contains the
text and HTML produced from that source by xml2rfc; the HTML records xml2rfc
3.34.0. `SHA256SUMS.txt` covers all three files.
