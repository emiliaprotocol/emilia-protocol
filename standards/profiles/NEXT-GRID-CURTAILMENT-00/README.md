# GRACE curtailment -00 publication packet

This directory retains the checksum-pinned source and renders for the
coauthored `draft-schrock-kintzele-grid-curtailment-00`, published as an active
individual Internet-Draft on August 22, 2026.

The source was rewritten from the current executable GRACE flow. It now covers the exact action,
dimensioned participation envelope, two distinct Class-A approvals, one-attempt executor admission,
indeterminate execution, authenticated actuator and meter claims, Outcome Binding, Action State,
single-use settlement admission, and the optional Ed25519 plus ML-DSA-65 artifact envelope.

The claim boundary is deliberate. Verification establishes integrity and deterministic results
relative to pinned inputs. It does not establish physical meter truth, baseline correctness, tariff
eligibility, actual payment, complete mediation, utility adoption, or a physical deployment.

## Packet contents

- `REVIEW-SOURCE/draft-schrock-kintzele-grid-curtailment-00.xml`: editable RFCXML source.
- `RENDERS/draft-schrock-kintzele-grid-curtailment-00.txt`: xml2rfc text rendering.
- `RENDERS/draft-schrock-kintzele-grid-curtailment-00.html`: xml2rfc HTML rendering.
- `RENDERS/draft-schrock-kintzele-grid-curtailment-00.pdf`: convenience PDF printed from the
  xml2rfc HTML rendering.
- `VALIDATION.md`: exact local verification receipt and claim limits.
- `SHA256SUMS.txt`: digests of the source and three renders.

## Publication record

The intended Datatracker name returned HTTP 404 on 2026-08-21, so filing created a new individual
`-00`. The repository's ordinary 90-day new-name freeze runs through 2026-11-01. On 2026-08-21,
founder Iman Schrock explicitly authorized a one-time override for this document after the final
RFCXML and renders passed the complete local verification gates and the coauthor approved the exact
submission metadata.

This override is an internal publication decision. It does not claim that the separate
named-external-implementation exception was satisfied. It does not establish external
implementation, deployment, working-group adoption, IETF review, or IETF endorsement.

Justin D Kintzele approved submission as coauthor and confirmed the exact published metadata
`Justin D Kintzele`, `J Diesel NY, LLC`, and `jkintzele@jdieselny.com` by email on 2026-08-21. The
single upload source is
`REVIEW-SOURCE/draft-schrock-kintzele-grid-curtailment-00.xml`, whose digest is pinned in
`SHA256SUMS.txt`. There is intentionally no duplicate `UPLOAD-THIS` copy that could drift from the
reviewed source.

Datatracker submission 167956 was accepted and revision `-00` was posted on 2026-08-22. As verified
that day, the [Datatracker record](https://datatracker.ietf.org/doc/draft-schrock-kintzele-grid-curtailment/)
lists the document as an active individual Internet-Draft. The retained XML and TXT match the
immutable IETF archive byte-for-byte:

- XML: `sha256:0c656d9cbdb0701a23668420460a6d1143efcf74db8919f4a9c24f4fd5697ba6`
- TXT: `sha256:8dd61f1f66077d64bb185c3a7a5354f46bb19f0d2f28beb9e2ff728a049adb87`

Accepted submission, Datatracker posting, and archive-byte verification are separate recorded
facts. None establishes an implementation, deployment, working-group adoption, RFC status, or IETF
endorsement.
