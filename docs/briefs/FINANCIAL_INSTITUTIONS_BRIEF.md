# Financial Institutions Brief

## Problem
Many of the most expensive failures in finance happen inside approved-looking workflows. EP strengthens the final mile of authorization before execution.

## Best first workflow
- beneficiary change
- payout destination change
- remittance update
- treasury release approval

## What EP proves before action
- actor identity
- authority chain
- exact transaction binding
- policy version and hash
- replay resistance
- one-time consumption
- accountable signoff when required

## Proof points

| Metric | Result |
|--------|--------|
| Automated tests | 1,500+ across 60+ files |
| Formal verification | 19 TLA+ safety theorems, 32 Alloy facts, 15 assertions |
| Red team cases | 85 documented |
| Security findings | 31 identified and remediated |
| Signoff chain | Full 7-step Accountable Signoff proven end-to-end under load |
| Load-test chains | 329 complete, zero correctness violations |
| DB integrity | 11/11 post-load-test checks passing |
| Data discipline | Zero duplicate consumptions, zero orphaned bindings, zero missing events |
| Transaction model | All endpoints use single-roundtrip atomic RPCs |
| Database isolation | 46 EP-only tables, zero foreign artifacts |

## Why it matters
This reduces ambiguity in approvals, improves evidence quality, and creates stronger control over high-risk financial changes.
