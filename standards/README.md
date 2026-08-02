# EMILIA Standards Work

This directory contains published individual Internet-Draft snapshots and
their public supporting material for an evidence architecture for consequential
agent actions.

Start here:

- [`PORTFOLIO.md`](PORTFOLIO.md) is the human-readable architecture and filing
  narrative.
- [`STATUS.json`](STATUS.json) is the machine-readable source of truth for
  published revisions, roles, consolidation, retired work, and
  partner-triggered profiles.
- [`../caid`](../caid) contains the CAID identifier, Action-Mapping Profile,
  registry, three same-team reference ports, and shared vectors.

## Status language

A draft published on the IETF Datatracker is an **active individual
Internet-Draft**. It is not an RFC, not an adopted working-group item, and not
IETF endorsement. New revisions are prepared in `staged/`, while immutable
published snapshots and superseded history live in `posted/` and `archive/`.

The current July 29-30 publication snapshots were checked against the immutable
IETF archive on 2026-08-01. Earlier rendered snapshots remain historical
conveniences; the IETF archive is authoritative for rendered forms and live
status.

## Cohesive architecture

The portfolio keeps five decisions separate:

1. `VERIFIED`: a native artifact passed its own verifier.
2. `MATCH`: verified artifacts denote the same material action.
3. `SATISFIED`: the bundle fills a relying-party evidence requirement.
4. `AUTHORIZED`: local policy permits execution.
5. `EXECUTED`: an executor reports an effect.

CAID owns typed material-action identity and profile-bounded matching. Receipts
and Quorum provide named evidence profiles. AEC evaluates evidence
satisfaction. Challenge, enforcement, outcome, revocation, and preservation
remain separate lifecycle transitions.

## August 1 submission-ready wave

Only these XML sources are upload candidates:

1. `draft-schrock-ep-authorization-evidence-chain-05`
2. `draft-schrock-action-evidence-boundary-03`
3. `draft-schrock-model-to-matter-03`
4. `draft-schrock-ep-reliance-agreement-00`

They are in `staged/UPLOAD-THIS/`; rendered forms, submission-mode `idnits`
results, checksums, and Datatracker Additional Resources entries are kept next
to them. Nothing in `posted/`, `archive/`, or `profiles/` is an upload candidate.

## Directory layout

- `posted/`: source snapshots for revisions already on Datatracker.
- `archive/`: superseded revisions and retired standalone candidates.
- `profiles/`: held application profiles that are not in the filing lane.
- `observatory/`: revision-pinned source catalog and generated comparison data.

Use `STATUS.json` and then Datatracker for filing status. Local staging is not
publication; only a Datatracker submission creates a published revision.
