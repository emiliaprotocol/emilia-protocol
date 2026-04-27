# Government Pilot Proposal

## Proposal title
EP for government payment integrity, benefit redirect prevention, and operator override control

## Executive summary
Government programs increasingly face fraud and unauthorized action inside approved-looking workflows. Authentication alone is not enough. EP creates the trust-control layer between authentication and execution by binding actor identity, authority, policy, and exact action context before a high-risk action is allowed to proceed.

## Recommended pilot
Choose one workflow:
- payment destination change
- benefit redirect
- operator override
- delegated case action

## What the pilot proves
- reduction in replay and reuse risk
- stronger action-level authorization
- clearer accountability and event traceability
- optional Accountable Signoff when policy requires named human ownership

## Core capabilities

### Accountable Signoff
Named human principals own high-risk decisions. The signoff flow enforces challenge/attest/consume semantics with cryptographic binding to the exact action being approved. Each signoff token is scoped to a single action context and cannot be replayed, reused, or transferred. This prevents approval laundering, where an approval obtained for one action is silently applied to a different one.

### Audit evidence export
EP Cloud provides dedicated endpoints for generating inspection-ready evidence packages:
- `/api/cloud/audit/export` — exports raw event streams, policy snapshots, and signoff records for a specified time range or workflow
- `/api/cloud/audit/report` — generates formatted evidence packages ready for IG and GAO review, including control-to-event traceability and policy compliance summaries

### Government Reference Pack
Pre-built policy configurations for common government workflows:
- **Payment destination change controls** — require signoff before modifying payment routing, with identity and authority verification at each step
- **Benefits redirect controls** — prevent unauthorized changes to benefit delivery targets, with mandatory Accountable Signoff
- **Operator override constraints** — scope operator overrides to specific actions, enforce time-limited authority, and log every override with full context
- **PIV/CAC/Login.gov identity integration (roadmap)** — pilot-track work; not yet implemented. Pilots needing federal-credential integration today get it scoped as part of the engagement.
- **FISMA/FedRAMP compliance mapping (roadmap)** — control-family mapping documents are not yet published. EP enforcement satisfies action-level accountability requirements that map onto multiple NIST 800-53 controls; the formal mapping document is on the roadmap.

## Proof points
- 3,430 automated tests across 129 files
- 20 TLA+ safety properties verified (T1–T20, TLC 2.19, 7,857 states, 0 errors); 6 additional EP-IX properties (T21–T26) specified, model run pending
- 85 red team cases cataloged in `docs/conformance/RED_TEAM_CASES.md`
- Zero write discipline exceptions
- Append-only event store with DB-level immutability triggers

## Pilot outputs
- control mapping for the selected workflow
- pilot policy pack
- verification and signoff flow
- event and evidence export
- success metrics and implementation notes
