# PIP-000: Protocol Improvement Proposal Process

**Status:** Active  
**Type:** Process  
**Created:** 2026-04-07  

---

## What is a PIP?

A Protocol Improvement Proposal (PIP) is a design document describing a new feature, process, or informational guideline for the EMILIA Protocol. PIPs are the primary mechanism for proposing changes to EP, collecting community input, and documenting design decisions.

PIPs are modeled on Bitcoin's BIP process and Ethereum's EIP process.

## PIP Types

- **Core:** Changes to EP Core objects (Receipt, Profile, Decision). Require major version bump if breaking.
- **Extension:** New protocol capabilities built on the Core layer. Must not break Core.
- **Interface:** Changes to API surfaces, serialization formats, or discovery mechanisms.
- **Process:** Changes to governance, contribution, or operational procedures.
- **Informational:** Design guidelines, best practices, or ecosystem observations.

## PIP Lifecycle

```
Draft → Review → Accepted → Final
                 → Rejected (with rationale)
                 → Withdrawn (by author)
```

## PIP Format

Every PIP must include:

```markdown
# PIP-NNN: Title

**Status:** Draft | Review | Accepted | Final | Rejected | Withdrawn
**Type:** Core | Extension | Interface | Process | Informational
**Created:** YYYY-MM-DD
**Author(s):** Name <email>
**Requires:** PIP-NNN (if any)

## Abstract
One paragraph summary.

## Motivation
Why is this needed? What problem does it solve?

## Specification
Technical specification. Must be precise enough for independent implementation.

## Rationale
Design decisions and alternatives considered.

## Backwards Compatibility
Impact on existing implementations. Core PIPs require migration plan.

## Reference Implementation
Link to implementation (required for Final status).

## Security Considerations
Security implications and mitigations.
```

## Core Freeze Rule

EP Core v1.0 objects (Trust Receipt, Trust Profile, Trust Decision) are frozen. Changes to Core objects require:
1. A Core-type PIP
2. 90-day review period
3. Consensus among active maintainers
4. Major version bump (EP v2.0)
5. 24-month deprecation window for the prior version

Extensions can be added at any time without modifying Core.
