# AE Challenge revision 02 working packet

This directory stages `draft-schrock-ae-challenge-02` for submission and
Independent Stream review.

- `UPLOAD-THIS/` contains the authoritative XML to submit to Datatracker.
- `RENDERS/` contains the TXT and HTML review renderings generated from that
  XML.
- `SHA256SUMS.txt` pins the source and both renderings.
- `VALIDATION.md` records the completed checks and current external-state gate.
- `ISE-SUBMISSION.md` contains the submission note to stage after Datatracker
  publishes revision -02.

Revision -02 does not change the challenge protocol or wire format. It names
the Independent Stream as the intended publication path, replaces the closed
provisional-registration attempt with the complete permanent standards-tree
media-type registration, updates the EP-AEC citation, and removes a reference
to a replaced individual draft.

The target remains
`application/authorization-evidence-challenge+json` in the standards tree.
The earlier direct request, IANA ticket #1456851, was closed without a merits
decision because the document had not reached a publication-stage review.
