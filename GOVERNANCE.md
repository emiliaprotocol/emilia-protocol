# EMILIA Protocol — Governance

## Status

EMILIA Protocol is independently stewarded by its founding team (EMILIA Protocol, Inc.) and is open under the Apache-2.0 license. The wire format is standardized in the open through the IETF as individual-submission Internet-Drafts (`draft-schrock-ep-*`) — a path that requires no assignment of the project's trademarks, repositories, or packages.

The project may adopt a vendor-neutral governance home in the future, but only under terms — reviewed by counsel — that preserve the project's brand, repositories, packages, and commercial products. No such transfer is planned or committed today.

This document describes the open governance model we are building toward.

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
| IETF Internet-Drafts filed (receipts, quorum, evidence-chain) | Current |
| First external implementation | Independent verification reported (June 2026) |
| Open working group established | Future |
| Vendor-neutral governance home | Future — only on counsel-approved terms |

## Contact

- **GitHub:** https://github.com/emiliaprotocol/emilia-protocol
- **Email:** team@emiliaprotocol.ai
- **Standards:** IETF datatracker — `draft-schrock-ep-authorization-receipts`, `draft-schrock-ep-quorum`, `draft-schrock-ep-authorization-evidence-chain`
