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
IETF endorsement. Active successor drafts, review packets, and filing schedules
are prepared outside this public repository. Intentionally public retired
sources and partner-triggered profiles remain here with explicit dispositions.

The July 21 publication set was verified against the immutable IETF archive on
2026-07-21. Each of its seven XML sources is byte-for-byte identical to the
archive copy. Earlier rendered snapshots remain historical conveniences; the
IETF archive is authoritative for rendered forms and live status.

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

## Current July 21 published wave

1. `draft-schrock-action-evidence-boundary-00`
2. `draft-schrock-canonical-action-identifier-01`
3. `draft-schrock-ep-architecture-02`
4. `draft-schrock-ep-authorization-evidence-chain-04`
5. `draft-schrock-ep-authorization-receipts-08`
6. `draft-schrock-ep-revocation-statement-00`
7. `draft-schrock-model-to-matter-01` (Experimental application profile; no
   deployment or partner claim)

These revisions advance the thin protocol line without collapsing evidence,
authorization, revocation, and execution into one claim. Model-to-Matter
remains an experimental executor profile with explicit non-goals.

## Directory layout

- `posted/`: source snapshots for revisions already on Datatracker.
- `archive/`: superseded revisions and retired standalone candidates.
- `profiles/`: remaining application or commercial profiles that need an
  external validating partner before they re-enter the filing lane.
- `observatory/`: revision-pinned source catalog and generated comparison data.

Active successor drafts and filing packets remain outside this public
repository. Intentionally public retired and partner-triggered sources are not
submission queues. Use `STATUS.json` and then Datatracker for filing status.
