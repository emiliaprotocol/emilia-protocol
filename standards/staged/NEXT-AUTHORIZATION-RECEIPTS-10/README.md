# Authorization Receipts -10 upload packet

This is the isolated candidate packet for
`draft-schrock-ep-authorization-receipts-10`. Nothing in this directory has
been filed.

Upload only:

- `UPLOAD-THIS/draft-schrock-ep-authorization-receipts-10.xml`

File this packet immediately after Datatracker shows
`draft-schrock-canonical-action-identifier-02`. Its normative CAID reference is
pinned to -02.

Revision -10:

- replaces the unverifiable faithful-rendering claim with the optional,
  fail-closed `EP-PRESENTATION-BINDING-v1` profile;
- moves CAID to Normative References for cross-artifact action comparison;
- distinguishes the detailed `EP-AUTHORIZATION-RECEIPT-v1` profile from the
  frozen generic `EP-RECEIPT-v1` envelope;
- requests `application/ep-authorization-receipt+json`; and
- credits and composes natively with OASNT `dsp` without treating a digest as
  a substitute for OASNT verification.

The document remains an individual Internet-Draft. Submission would not make
it an RFC, a working-group document, IETF consensus, or IETF endorsement.
