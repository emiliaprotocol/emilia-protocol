# EMILIA Standards Work

This directory contains individual Internet-Drafts and candidate drafts for an
evidence architecture for consequential agent actions.

Start here:

- [`PORTFOLIO.md`](PORTFOLIO.md) is the human-readable architecture and filing
  narrative.
- [`STATUS.json`](STATUS.json) is the machine-readable source of truth for
  revisions, roles, consolidation, the July 19 post-blackout wave, the July 27
  lifecycle wave, retired work, and partner-triggered profiles.
- [`../caid`](../caid) contains the CAID identifier, Action-Mapping Profile,
  registry, three same-team reference ports, and shared vectors.

## Status language

A draft published on the IETF Datatracker is an **active individual
Internet-Draft**. It is not an RFC, not an adopted working-group item, and not
IETF endorsement. Candidate and staged files in this repository have not been
filed.

The Datatracker was last checked on 2026-07-14. It listed thirteen active
`draft-schrock-*` documents plus one coauthored composition document. The exact
inventory and revision numbers are in `STATUS.json`; Datatracker remains the
authority for live status.

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

## July 19 post-blackout candidate wave

1. `draft-schrock-canonical-action-identifier-00`
2. `draft-schrock-ep-architecture-01`
3. `draft-schrock-ep-authorization-evidence-chain-03`
4. `draft-schrock-ep-authorization-receipts-07`
5. `draft-schrock-model-to-matter-00` (Experimental application profile,
   filed last to establish the name; no deployment or partner claim)

The first four documents are the cohesive core. Model-to-Matter demonstrates
that core at an executor boundary and carries its own JavaScript implementation,
deterministic public vectors, and explicit non-goals. Outcome Binding is
conditional on its independent gate. Revocation is the
mandatory July 27 lifecycle filing; other former holds are now retired,
absorbed, or partner-triggered. Filing is a human Datatracker action and occurs
only after render, claim-tracing, conformance, test, and build gates pass.

## Directory layout

- `posted/`: source snapshots for revisions already on Datatracker.
- `archive/`: superseded revisions and retired standalone candidates.
- `staged/`: complete candidates that have not been filed.
- `profiles/`: remaining application or commercial profiles that need an
  external validating partner before they re-enter the filing lane.
- `observatory/`: revision-pinned source catalog and generated comparison data.

Do not infer filing status from a file's directory alone. Use `STATUS.json` and
then verify against Datatracker.
