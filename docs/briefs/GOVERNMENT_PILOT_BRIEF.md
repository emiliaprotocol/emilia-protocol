# Government Pilot Brief

## Problem
Government fraud and unauthorized action often occur inside approved-looking workflows. Authentication alone is not enough.

## Best first workflow
- payment destination change
- benefit redirect
- operator override
- delegated case action

## What EP proves before action
- actor identity
- authority chain
- exact action binding
- policy version and hash
- replay resistance
- one-time consumption
- accountable signoff when required

## What the agency gets
- decision record
- event chain
- policy snapshot
- signoff trace if required
- reconstruction-ready export

## Operational evidence
- Full 7-step Accountable Signoff chain proven end-to-end under load (0% error rate)
- Atomic transactions: single Postgres RPC, no partial state
- 1,500+ automated tests, 85 red team cases, 31 security findings remediated
- Explicit supported-band and overload-band operating envelopes published
- Fast 503 backpressure under overload — no timeout collapse, no silent failures

## 30-day pilot outcome
- One payment destination change workflow protected
- Event export produced for oversight review
- Accountable signoff visible to supervisors
- Reconstruction-ready audit packet available

## Who buys this internally
- Payment integrity
- Program integrity
- Fraud operations
- Security / architecture
- Compliance / oversight

## 30–60 day success metric
Demonstrate that one selected workflow now requires policy-bound, replay-resistant, attributable control before execution.
