# Architecture-03 publication provenance packet

Status: posted on 2026-09-06 as `draft-schrock-ep-architecture-03` through
Datatracker submission 168691 (Datatracker time 2026-09-06T17:31:40Z), one of
the four September 6 corrective revisions. It is an active individual
Internet-Draft. It is not a working-group item, an RFC, or IETF endorsement,
and posting is not review by any referenced protocol owner.

The XML under `UPLOAD-THIS/` is the exact submitted -03 source and matches the
immutable IETF archive byte-for-byte. The text under `RENDERS/` also matches
the archive byte-for-byte. The packet is retained for publication provenance,
not as an upload candidate. The posted snapshot, mirrored on 2026-09-26, is
[`../../posted/draft-schrock-ep-architecture-03.xml`](../../posted/draft-schrock-ep-architecture-03.xml);
Architecture-02 is retained at
[`../../archive/draft-schrock-ep-architecture-02.xml`](../../archive/draft-schrock-ep-architecture-02.xml).
The publication check is recorded at the end of `VALIDATION.md`.

## Changes from -02

Section 14 of the posted text, "Changes from -02", lists five changes:

- provider entry is the transition that converts reserved authority to
  consumed authority before provider invocation;
- admission-control domains and monotonic epochs are defined without
  overloading witness-independence control domains;
- serialized emergency freeze, restoration, and reconciliation behavior is
  defined for the three freeze-versus-entry races;
- the disconnected-edge stale-admission window is stated, and immediate
  global-freeze claims are rejected;
- idempotency, wrong-holder, receipt-absence, and unsigned-event claim
  boundaries are added.

The abstract is unchanged from -02. Section 8.2 describes Emergency Authority
Freeze as a consequence-owner control inside one authoritative atomic state
domain, not an agent-termination protocol, and states that it does not stop
computation, undo effects, or cover provider paths that bypass the consequence
owner.

## Layout

`UPLOAD-THIS/` contains the exact submitted XML source. `RENDERS/` contains the
text and HTML produced from that source by xml2rfc; the HTML records xml2rfc
3.34.0. `SHA256SUMS.txt` covers all three files. `VALIDATION.md` records the
checks run before submission and the publication check.
