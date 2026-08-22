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

## Hold status

This is a partner-review packet, not a Datatracker upload packet. There is intentionally no
`UPLOAD-THIS` directory.

The intended Datatracker name returned HTTP 404 on 2026-08-21. Filing it would therefore create a
new `-00`. The repository's 90-day new-name filing freeze remains in effect through 2026-11-01.
Before filing, one of these conditions must be true:

1. the freeze has expired and a fresh overlap and claim-boundary review passes; or
2. the documented exception is satisfied by a named external implementer or deployment that
   demonstrates the wire-level gap, with the evidence and overlap review recorded.

Justin D Kintzele approved submission as coauthor and confirmed the exact published metadata
`Justin D Kintzele`, `J Diesel NY, LLC`, and `jkintzele@jdieselny.com` by email on 2026-08-21.
After the repository filing
gate clears, regenerate from the reviewed source, rerun the tests and document checks, and create a
separate isolated `UPLOAD-THIS` packet from the exact approved bytes.
