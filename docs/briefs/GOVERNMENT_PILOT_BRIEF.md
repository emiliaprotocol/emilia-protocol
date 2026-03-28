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
- Atomic handshake creation: single Postgres transaction, 249ms floor latency
- Load tested at 500 concurrent users: 95.4% success rate
- 1,500+ automated tests, 85 red team cases, 31 security findings remediated
- Zero partial-state writes — every mutation is all-or-nothing with mandatory event logging

## 30–60 day success metric
Demonstrate that one selected workflow now requires policy-bound, replay-resistant, attributable control before execution.
