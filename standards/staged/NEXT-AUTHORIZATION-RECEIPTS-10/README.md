# Authorization Receipts -10 upload packet

This is the isolated candidate packet for
`draft-schrock-ep-authorization-receipts-10`. It was published on 2026-08-06
after CAID-02 and is retained as exact-submission provenance.

Submitted file:

- `UPLOAD-THIS/draft-schrock-ep-authorization-receipts-10.xml`

Datatracker showed `draft-schrock-canonical-action-identifier-02` before this
revision was filed. Its normative CAID reference is pinned to -02.

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
