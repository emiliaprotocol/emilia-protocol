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
| **Independent code audit** | **100/100** (2026-04-02, all 10 categories at maximum) |
| Automated tests | 3,277 across 125 files |
| Formal verification | 20 TLA+ properties verified (TLC 2.19, 7,857 states, 0 errors); 32 Alloy facts + 15 assertions (Alloy 6.1.0, 0 counterexamples) — both enforced in CI |
| Mutation testing | ≥80% kill threshold on protocol core (Stryker.js) |
| Red team cases | 116 documented |
| Security findings | 31 identified and remediated |
| Signoff chain | Full 7-step Accountable Signoff proven end-to-end under load |
| Load-test chains | 329 complete, zero correctness violations |
| DB integrity | 11/11 post-load-test checks passing |
| Data discipline | Zero duplicate consumptions, zero orphaned bindings, zero missing events |
| Transaction model | All endpoints use single-roundtrip atomic RPCs; handshake p95 87ms at 500 VUs |
| Database isolation | 46 EP-only tables, zero foreign artifacts |
| CI / supply chain | 27 quality gates, all Actions SHA-pinned, SBOM + provenance on every release |

## Why it matters
This reduces ambiguity in approvals, improves evidence quality, and creates stronger control over high-risk financial changes.
