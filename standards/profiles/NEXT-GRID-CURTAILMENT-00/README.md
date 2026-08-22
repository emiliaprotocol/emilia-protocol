# GRACE curtailment -00 partner-review packet

This directory contains the rebuilt coauthored review candidate for
`draft-schrock-kintzele-grid-curtailment-00`.

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

## Publication decision

The intended Datatracker name returned HTTP 404 on 2026-08-21, so filing creates a new individual
`-00`. The repository's ordinary 90-day new-name freeze would run through 2026-11-01. On
2026-08-21, founder Iman Schrock explicitly authorized a one-time override for this document after
the final RFCXML and renders passed the complete local verification gates and the coauthor approved
the exact submission metadata.

This override is an internal publication decision. It does not claim that the separate
named-external-implementation exception was satisfied. It does not establish external
implementation, deployment, working-group adoption, IETF review, or IETF endorsement.

Justin D Kintzele approved submission as coauthor and confirmed the exact published metadata
`Justin D Kintzele`, `J Diesel NY, LLC`, and `jkintzele@jdieselny.com` by email on 2026-08-21. The
single upload source is
`REVIEW-SOURCE/draft-schrock-kintzele-grid-curtailment-00.xml`, whose digest is pinned in
`SHA256SUMS.txt`. There is intentionally no duplicate `UPLOAD-THIS` copy that could drift from the
reviewed source.
