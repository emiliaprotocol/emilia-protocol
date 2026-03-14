# EMILIA Protocol — Governance

## Status

EMILIA Protocol is currently maintained by its founding team with the intent to transition to neutral, community-governed stewardship under the Agentic AI Foundation (AAIF) or an equivalent vendor-neutral home.

This document describes the governance model we are building toward.

## Principles

1. **No single company controls truth.** The scoring algorithm, receipt schema, and trust profile format are defined by the spec, not by any single implementation.
2. **Trust must never be more powerful than appeal.** Every negative trust effect must be explainable, challengeable, and reversible.
3. **Open by default.** The spec, reference implementation, conformance suite, and governance process are all public and Apache-2.0 licensed.
4. **Implementations over opinions.** Protocol changes require a working implementation, conformance tests, and demonstrated need — not just theoretical arguments.

## Governance Structure (Target)

### Working Group

- **Chair:** Rotating annually. Initial chair: EMILIA Protocol founding team.
- **Members:** Open to any organization or individual contributing to EP.
- **Meetings:** Biweekly, open to all members. Minutes published.
- **Decisions:** Consensus-seeking. If consensus cannot be reached, the chair calls a vote. Simple majority of active members.

### Spec Process

1. **Proposal:** Anyone can submit a spec change proposal as a GitHub issue or pull request.
2. **Discussion:** 14-day comment period minimum.
3. **Reference Implementation:** Proposal must include a working implementation that passes the conformance suite.
4. **Review:** Working group reviews the proposal, implementation, and test coverage.
5. **Merge:** If approved, the spec, reference implementation, and conformance suite are updated together.

### Versioning

- **Major versions** (v2.0, v3.0): Breaking changes to receipt schema, trust profile format, or policy interface. Require supermajority (2/3) of working group.
- **Minor versions** (v1.1, v1.2): Backward-compatible additions. Require simple majority.
- **Patch versions** (v1.1.1): Bug fixes, clarifications, test additions. Chair approval sufficient.

## Conformance

An implementation is EP-conformant if it:

1. Passes all hash determinism fixtures in `conformance/fixtures.json`
2. Passes all policy evaluation fixtures
3. Passes all confidence level fixtures
4. Passes all establishment rule fixtures
5. Implements the canonical receipt schema (all required fields)
6. Exposes at minimum: trust profile read, policy evaluation, receipt submission

Conformance is self-certified against the published suite. The working group maintains the canonical fixtures.

## Intellectual Property

- All contributions to the EP spec and conformance suite are licensed under Apache-2.0.
- Contributors retain copyright to their contributions.
- No contributor can claim exclusive rights over the protocol specification.
- The spec is a shared standard, not a product.

## Code of Conduct

EP contributors follow the [Contributor Covenant](https://www.contributor-covenant.org/) Code of Conduct.

## Transition Timeline

| Phase | Status |
|-------|--------|
| Single-maintainer development | Current |
| Conformance suite published | Current |
| AAIF working group proposal submitted | Pending |
| First external implementation | Pending |
| Working group established | Target Q2 2026 |
| Governance transfer to neutral home | Target Q3 2026 |

## Contact

- **GitHub:** https://github.com/emiliaprotocol/emilia-protocol
- **Email:** team@emiliaprotocol.ai
- **AAIF Proposal:** See `docs/AAIF-PROPOSAL-v2.md`
