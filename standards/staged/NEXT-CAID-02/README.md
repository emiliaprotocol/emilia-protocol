# CAID revision 02 working packet

This directory stages `draft-schrock-canonical-action-identifier-02` for
review. It was published on 2026-08-06 and is retained as exact-submission
provenance.

- The submitted file was
  `UPLOAD-THIS/draft-schrock-canonical-action-identifier-02.xml` to
  Datatracker before the receipts-10 revision was posted.
- `RENDERS/` contains the TXT and HTML review renderings generated from that
  XML.
- `SHA256SUMS.txt` pins the source and both renderings.
- `VALIDATION.md` records the checks and the exact hold state.

Revision -02 moves the small shared CAID profile to Standards Track, fixes the
cross-profile comparison rule, registers a target-bound `tool.call.1`, and
distinguishes a real CAID from framework-local executor-binding strings.

The packet cites authorization-receipts-09 as the then-current informative
example. Datatracker posted CAID-02 before receipts-10, whose normative CAID
reference is pinned to -02. This removed the former circular filing instruction.
