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
IETF endorsement. Unsubmitted draft sources and filing schedules are prepared
outside this public repository.

The July 19 publication set was verified against the IETF archive on
2026-07-19. Each archived IETF TXT is byte-for-byte identical to its local
snapshot under `posted/`. The exact inventory and revision numbers are in
`STATUS.json`; the IETF Datatracker remains the authority for live status.

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

## July 19 published wave

1. `draft-schrock-canonical-action-identifier-00`
2. `draft-schrock-ep-architecture-01`
3. `draft-schrock-ep-authority-introduction-01`
4. `draft-schrock-ep-authorization-receipts-07`
5. `draft-schrock-ep-quorum-03`
6. `draft-schrock-ep-bounded-capability-receipts-00`
7. `draft-schrock-ep-authorization-evidence-chain-03`
8. `draft-schrock-model-to-matter-00` (Experimental application profile; no
   deployment or partner claim)

The first seven documents form the protocol line. Model-to-Matter demonstrates
the architecture at an executor boundary and carries explicit non-goals.

## Directory layout

- `posted/`: source snapshots for revisions already on Datatracker.
- `archive/`: superseded revisions and retired standalone candidates.
- `staged/`: public staging policy only; unsubmitted draft sources stay private.
- `profiles/`: remaining application or commercial profiles that need an
  external validating partner before they re-enter the filing lane.
- `observatory/`: revision-pinned source catalog and generated comparison data.

Do not infer filing status from a file's directory alone. Use `STATUS.json` and
then verify against Datatracker.
